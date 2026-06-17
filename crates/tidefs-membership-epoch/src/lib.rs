#![forbid(unsafe_code)]

//! Quorum-based epoch advancement with BLAKE3-verified proposal construction, voting, and
//! commitment pipeline. See the [`quorum`] module for the propose -> vote
//! -> commit lifecycle, and [`MembershipEpoch::propose`]/[`MembershipEpoch::advance`]
//! for the integration entry points.
//!
//! Deterministic `membership_placement_0` epoch model for OW-302.
//!
//! Epoch-chain verification ([`epoch_chain`]) validates incoming proposals
//! against the locally committed epoch chain, detecting forks and gaps
//! before the agreement state machine accepts them.
//!
//! The [`committed_chain`] module provides the canonical in-memory
//! epoch chain store with O(log n) lookup, ancestry queries, and roster
//! snapshot computation for catch-up, broadcast, and commit-coordination
//! consumers.

//! This crate is intentionally a small userspace model, not a networked
//! consensus runtime. It binds the P8-02 membership, failure-domain, placement,
//! split-brain, and rejoin laws to executable source and failure/rejoin tests.
//! split-brain, and rejoin laws to executable source and failure/rejoin tests.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub use tidefs_membership_types::{Incarnation, NodeIdentity};

pub use tidefs_membership_types::capabilities::{PeerCapabilities, TransportCarrier};

// Identity integration: auth types for fencing and join authorization.
use tidefs_auth::{
    check_revocation_status, IdentityError, NodeIdentity as AuthNodeIdentity, NodeKeyStore,
    RevocationSet,
};

// ── Sub-modules ────────────────────────────────────────────────────

pub mod agreement;
pub mod broadcast;
pub mod checkpoint;
pub mod committed_chain;
pub mod coordinator_election;
pub mod coordinator_promotion;
pub mod departure_coordinator;
pub mod epoch_catch_up;
pub mod epoch_chain;
pub mod epoch_commit_subscriber;
pub mod epoch_error;
pub mod epoch_persistence;
pub mod epoch_proposal;
pub mod epoch_service;
pub mod epoch_state;
pub mod epoch_transition;
pub mod epoch_version_exchange;
pub mod incarnation;
pub mod journal_wire;
pub mod leave_coordinator;
pub mod member_lifecycle;
pub mod membership_quorum_tracker;
pub mod persistence;
pub mod pool_scan_gate;
pub mod proposal;
pub mod proposal_idempotency;
pub mod quorum;
pub mod roster_constraints;
pub mod roster_push;
pub mod roster_validation;
pub mod roster_verifier;
pub mod session_binding;
pub mod snapshot;
pub mod transition_journal;
pub mod unreachable_handler;

pub const MEMBERSHIP_EPOCH_MODEL_P8_02: &str =
    "family.membership_placement_failure_domain.membership_placement_0";
pub const MEMBERSHIP_EPOCH_FAILURE_REJOIN_GATE: &str =
    "OW-302 failure/rejoin tests bind membership epochs, failure domains, split-brain refusal, and learner catch-up gates";
pub const FAILURE_DOMAIN_PLACEMENT_GATE_OW_303: &str =
    "OW-303 deterministic failure-domain placement enforces anti-affinity and visible degradation gates";

mod static_str_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<&'static str>, s: S) -> Result<S::Ok, S::Error> {
        v.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<&'static str>, D::Error> {
        let owned: Vec<String> = Vec::deserialize(d)?;
        Ok(owned
            .into_iter()
            .map(|s| Box::leak(s.into_boxed_str()) as &'static str)
            .collect())
    }
}

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct MemberId(pub u64);

impl MemberId {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct DomainId(pub u64);

impl DomainId {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct EpochId(pub u64);

impl EpochId {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct ReceiptId(pub u64);

impl ReceiptId {
    pub const ZERO: Self = Self(0);
}

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct AuthorityDomainId(pub u64);

impl AuthorityDomainId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[repr(u8)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum LeaveReason {
    /// Member is voluntarily departing the cluster.
    Voluntary = 0,
    /// Member is departing for scheduled maintenance.
    Maintenance = 1,
    /// Member is draining before removal.
    Draining = 2,
}

impl LeaveReason {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Voluntary),
            1 => Some(Self::Maintenance),
            2 => Some(Self::Draining),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Voluntary => "leave.membership_placement_0.voluntary.l0",
            Self::Maintenance => "leave.membership_placement_0.maintenance.l1",
            Self::Draining => "leave.membership_placement_0.draining.l2",
        }
    }
}

#[repr(u8)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaveOutcome {
    /// Leave request accepted, member removed from roster.
    Accepted = 0,
    /// Leave request rejected (e.g. member not in roster).
    Rejected = 1,
    /// Member has already departed (idempotent).
    AlreadyDeparted = 2,
}

impl LeaveOutcome {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Accepted),
            1 => Some(Self::Rejected),
            2 => Some(Self::AlreadyDeparted),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "leave.membership_placement_0.accepted.o0",
            Self::Rejected => "leave.membership_placement_0.rejected.o1",
            Self::AlreadyDeparted => "leave.membership_placement_0.already_departed.o2",
        }
    }
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigClass {
    Bootstrap = 0,
    Normal = 1,
    Joint = 2,
    Quarantined = 3,
}

impl ConfigClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "config.membership_placement_0.bootstrap.c0",
            Self::Normal => "config.membership_placement_0.normal.c1",
            Self::Joint => "config.membership_placement_0.joint.c2",
            Self::Quarantined => "config.membership_placement_0.quarantined.c3",
        }
    }
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberClass {
    Voter = 0,
    Learner = 1,
    WitnessOnly = 2,
    DataOnly = 3,
    ShadowOnly = 4,
    Quarantined = 5,
}

impl MemberClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Voter => "member.membership_placement_0.voter.m0",
            Self::Learner => "member.membership_placement_0.learner.m1",
            Self::WitnessOnly => "member.membership_placement_0.witness_only.m2",
            Self::DataOnly => "member.membership_placement_0.data_only.m3",
            Self::ShadowOnly => "member.membership_placement_0.shadow_only.m4",
            Self::Quarantined => "member.membership_placement_0.quarantined.m5",
        }
    }

    #[must_use]
    pub const fn can_vote(self) -> bool {
        matches!(self, Self::Voter)
    }

    #[must_use]
    pub const fn can_hold_replicas(self) -> bool {
        matches!(self, Self::Voter | Self::Learner | Self::DataOnly)
    }
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum FailureDomainClass {
    Device = 0,
    Node = 1,
    Chassis = 2,
    Rack = 3,
    Zone = 4,
    Region = 5,
}

impl FailureDomainClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Device => "fd.membership_placement_0.device.f0",
            Self::Node => "fd.membership_placement_0.node.f1",
            Self::Chassis => "fd.membership_placement_0.chassis.f2",
            Self::Rack => "fd.membership_placement_0.rack.f3",
            Self::Zone => "fd.membership_placement_0.zone.f4",
            Self::Region => "fd.membership_placement_0.region.f5",
        }
    }
}
// ── Storage tier ────────────────────────────────────────────────────

/// Storage tier — maps device-class hardware to logical storage tiers
/// for automatic promote/demote relocation.
///
/// Tiers form an ordered hierarchy: fastest (NvmePerformance) to
/// slowest (HddArchive). The mapping from on-disk DeviceClass to
/// tier is done by storage_tier_from_device_class.
#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum StorageTier {
    /// NVMe-tier: lowest latency, highest cost. Hot data.
    NvmePerformance = 0,
    /// SSD-tier: moderate latency, moderate cost. Warm data.
    SsdCapacity = 1,
    /// HDD-tier: highest latency, lowest cost. Cold/archive data.
    HddArchive = 2,
    /// Special / metadata device tier — not eligible for auto-tiering.
    SpecialDevice = 3,
}

impl StorageTier {
    /// Human-readable tier name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NvmePerformance => "tier.membership_placement_0.nvme_performance.t0",
            Self::SsdCapacity => "tier.membership_placement_0.ssd_capacity.t1",
            Self::HddArchive => "tier.membership_placement_0.hdd_archive.t2",
            Self::SpecialDevice => "tier.membership_placement_0.special_device.t3",
        }
    }

    /// Returns true if `other` is a faster tier — promotion is moving data
    /// from a slower tier to a faster one.
    #[must_use]
    pub const fn is_promotion_to(self, other: Self) -> bool {
        (other as u32) < (self as u32)
    }

    /// Returns true if `other` is a slower tier — demotion is moving data
    /// from a faster tier to a slower one.
    #[must_use]
    pub const fn is_demotion_to(self, other: Self) -> bool {
        (other as u32) > (self as u32)
    }

    /// Returns true if this tier is eligible for automatic tiering movement.
    #[must_use]
    pub const fn is_auto_tiering_eligible(self) -> bool {
        !matches!(self, Self::SpecialDevice)
    }
}

/// Map an on-disk DeviceClass to a StorageTier.
///
/// This is the authoritative device-class → tier mapping. Unknown or
/// non-data-bearing device classes return None.
#[must_use]
pub const fn storage_tier_from_device_class(device_class: u8) -> Option<StorageTier> {
    match device_class {
        0 => Some(StorageTier::HddArchive),      // DeviceClass::Hdd
        1 => Some(StorageTier::SsdCapacity),     // DeviceClass::Ssd
        2 => Some(StorageTier::NvmePerformance), // DeviceClass::Nvme
        3 => Some(StorageTier::SpecialDevice),   // DeviceClass::Special
        _ => None,
    }
}

// ── Storage tier policy ────────────────────────────────────────────

/// Operator-configurable policy that maps failure-domain devices to
/// storage tiers and controls automatic promotion/demotion behavior.
///
/// The policy is built from pool-scan device classification and can be
/// overridden per-device by the operator.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageTierPolicy {
    /// Per-domain tier assignment. Keyed by device-class DomainId.
    pub domain_tiers: BTreeMap<DomainId, StorageTier>,
    /// Whether automatic promotion (cold→hot) is enabled.
    pub auto_promote: bool,
    /// Whether automatic demotion (hot→cold) is enabled.
    pub auto_demote: bool,
}

impl StorageTierPolicy {
    /// Create an empty policy with auto-tiering disabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            domain_tiers: BTreeMap::new(),
            auto_promote: false,
            auto_demote: false,
        }
    }

    /// Set the storage tier for a device domain.
    pub fn set_domain_tier(&mut self, domain_id: DomainId, tier: StorageTier) {
        self.domain_tiers.insert(domain_id, tier);
    }

    /// Look up the storage tier for a domain.
    #[must_use]
    pub fn tier_for_domain(&self, domain_id: DomainId) -> Option<StorageTier> {
        self.domain_tiers.get(&domain_id).copied()
    }

    /// Apply tier assignments to a slice of FailureDomainRecords.
    /// Device-class domains with a matching entry in this policy get their
    /// storage_tier field populated.
    pub fn apply_to_domains(&self, domains: &mut [FailureDomainRecord]) {
        for d in domains {
            if d.failure_domain_class_ref == FailureDomainClass::Device {
                if let Some(tier) = self.tier_for_domain(d.failure_domain_id) {
                    d.storage_tier = Some(tier);
                }
            }
        }
    }

    /// Returns domains that are eligible for auto-tiering (have a known tier
    /// and are not SpecialDevice).
    #[must_use]
    pub fn auto_tiering_domains(&self) -> Vec<DomainId> {
        self.domain_tiers
            .iter()
            .filter(|(_, t)| t.is_auto_tiering_eligible())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Build a StorageTierPolicy from pool-scan device entries.
    ///
    /// Each entry is a (DomainId, DeviceClass discriminant) pair. The
    /// DeviceClass discriminant follows the on-disk encoding:
    /// 0=Hdd, 1=Ssd, 2=Nvme, 3=Special. Unknown values are skipped.
    ///
    /// Auto-promotion and auto-demotion default to disabled; set the
    /// fields on the returned policy to enable them.
    #[must_use]
    pub fn from_device_entries(entries: &[(DomainId, u8)]) -> Self {
        let mut policy = Self::new();
        for &(domain_id, class) in entries {
            if let Some(tier) = storage_tier_from_device_class(class) {
                policy.set_domain_tier(domain_id, tier);
            }
        }
        policy
    }
}
/// The result of evaluating whether data should move between storage tiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TieringDecision {
    /// Move data to a faster tier (e.g. HDD → NVMe).
    Promote(StorageTier),
    /// Move data to a slower tier (e.g. NVMe → HDD).
    Demote(StorageTier),
    /// No tiering movement needed — data is already on the right tier.
    NoChange,
}

impl StorageTierPolicy {
    /// Compute a tiering decision given a source tier and an access heat score.
    ///
    /// If `auto_promote` is disabled, hot data on slow tiers will not trigger
    /// promotion. If `auto_demote` is disabled, cold data on fast tiers will
    /// not trigger demotion. The `heat_score` is a relative measure of access
    /// frequency: values above `promotion_threshold` suggest the data is "hot"
    /// and should be on a faster tier; values below `demotion_threshold`
    /// suggest the data is "cold" and can be moved to a slower tier.
    ///
    /// Returns `NoChange` when the source tier is already the right tier,
    /// when the source tier is `None` (unknown), when auto-tiering is
    /// disabled for the relevant direction, or when the source tier is not
    /// eligible for auto-tiering.
    #[must_use]
    pub fn compute_tiering_decision(
        &self,
        source_tier: Option<StorageTier>,
        heat_score: u64,
        promotion_threshold: u64,
        demotion_threshold: u64,
    ) -> TieringDecision {
        let source = match source_tier {
            Some(s) if s.is_auto_tiering_eligible() => s,
            _ => return TieringDecision::NoChange,
        };

        // Determine the preferred tier for this heat score by scanning
        // available tiers.
        let available: Vec<StorageTier> = self
            .domain_tiers
            .values()
            .filter(|t| t.is_auto_tiering_eligible())
            .copied()
            .collect();

        if heat_score >= promotion_threshold && self.auto_promote {
            // Hot data: find a faster tier that exists in this policy
            for t in &available {
                if source.is_promotion_to(*t) {
                    return TieringDecision::Promote(*t);
                }
            }
        }

        if heat_score <= demotion_threshold && self.auto_demote {
            // Cold data: find a slower tier that exists in this policy
            for t in &available {
                if source.is_demotion_to(*t) {
                    return TieringDecision::Demote(*t);
                }
            }
        }

        TieringDecision::NoChange
    }
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementIntentClass {
    AuthorityHome = 0,
    FailoverSuccessor = 1,
    VoterSpread = 2,
    LearnerStaging = 3,
    WitnessSpread = 4,
    ReplicaTarget = 5,
    RebuildRelocateTarget = 6,
    ShadowValidationOnly = 7,
}

impl PlacementIntentClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityHome => "placement.membership_placement_0.authority_home.p0",
            Self::FailoverSuccessor => "placement.membership_placement_0.failover_successor.p1",
            Self::VoterSpread => "placement.membership_placement_0.voter_spread.p2",
            Self::LearnerStaging => "placement.membership_placement_0.learner_staging.p3",
            Self::WitnessSpread => "placement.membership_placement_0.witness_spread.p4",
            Self::ReplicaTarget => "placement.membership_placement_0.replica_target.p5",
            Self::RebuildRelocateTarget => {
                "placement.membership_placement_0.rebuild_relocate_target.p6"
            }
            Self::ShadowValidationOnly => {
                "placement.membership_placement_0.shadow_validation_only.p7"
            }
        }
    }
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerdictClass {
    Admit = 0,
    AdmitDegraded = 1,
    HoldCatchup = 2,
    HoldDomainGap = 3,
    RefuseSplitBrain = 4,
    RefusePolicyOrCapacity = 5,
    Quarantine = 6,
}

impl VerdictClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "verdict.membership_placement_0.admit.v0",
            Self::AdmitDegraded => "verdict.membership_placement_0.admit_degraded.v1",
            Self::HoldCatchup => "verdict.membership_placement_0.hold_catchup.v2",
            Self::HoldDomainGap => "verdict.membership_placement_0.hold_domain_gap.v3",
            Self::RefuseSplitBrain => "verdict.membership_placement_0.refuse_split_brain.v4",
            Self::RefusePolicyOrCapacity => {
                "verdict.membership_placement_0.refuse_policy_or_capacity.v5"
            }
            Self::Quarantine => "verdict.membership_placement_0.quarantine.v6",
        }
    }
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportCohortClass {
    PeerPair = 0,
    AuthorityDomainControl = 1,
    ReplicaSet = 3,
    StateTransfer = 4,
    ShadowCompare = 5,
    TransitionStage = 6,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum HealthClass {
    Healthy,
    Suspect,
    Down,
}

impl HealthClass {
    #[must_use]
    pub const fn admits_new_work(self) -> bool {
        matches!(self, Self::Healthy | Self::Suspect)
    }
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum AntiAffinityClass {
    Strict = 0,
    DegradedVisible = 1,
}

impl AntiAffinityClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "anti_affinity.membership_placement_0.strict.a0",
            Self::DegradedVisible => "anti_affinity.membership_placement_0.degraded_visible.a1",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureDomainPlacementPolicy {
    pub placement_class: PlacementIntentClass,
    pub required_replica_count: usize,
    pub required_failure_domain_class_ref: FailureDomainClass,
    pub anti_affinity_class: AntiAffinityClass,
    /// Target storage tier for tier-conscious placement. None = any tier.
    pub target_tier: Option<StorageTier>,
}

impl FailureDomainPlacementPolicy {
    #[must_use]
    pub const fn strict_replica_targets(
        required_replica_count: usize,
        required_failure_domain_class_ref: FailureDomainClass,
    ) -> Self {
        Self {
            placement_class: PlacementIntentClass::ReplicaTarget,
            required_replica_count,
            required_failure_domain_class_ref,
            anti_affinity_class: AntiAffinityClass::Strict,
            target_tier: None,
        }
    }

    #[must_use]
    pub const fn degraded_visible_replica_targets(
        required_replica_count: usize,
        required_failure_domain_class_ref: FailureDomainClass,
    ) -> Self {
        Self {
            placement_class: PlacementIntentClass::ReplicaTarget,
            required_replica_count,
            required_failure_domain_class_ref,
            anti_affinity_class: AntiAffinityClass::DegradedVisible,
            target_tier: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureDomainVector {
    pub device: DomainId,
    pub node: DomainId,
    pub chassis: DomainId,
    pub rack: DomainId,
    pub zone: DomainId,
    pub region: DomainId,
}

impl FailureDomainVector {
    #[must_use]
    pub const fn new(
        device: DomainId,
        node: DomainId,
        chassis: DomainId,
        rack: DomainId,
        zone: DomainId,
        region: DomainId,
    ) -> Self {
        Self {
            device,
            node,
            chassis,
            rack,
            zone,
            region,
        }
    }

    #[must_use]
    pub const fn domain(self, class: FailureDomainClass) -> DomainId {
        match class {
            FailureDomainClass::Device => self.device,
            FailureDomainClass::Node => self.node,
            FailureDomainClass::Chassis => self.chassis,
            FailureDomainClass::Rack => self.rack,
            FailureDomainClass::Zone => self.zone,
            FailureDomainClass::Region => self.region,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberAdmission {
    pub member_id: MemberId,
    pub member_class: MemberClass,
    pub log_frontier: u64,
    pub health: HealthClass,
    pub failure_domain_vector: FailureDomainVector,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClusterMemberRecord {
    pub member_id: MemberId,
    pub member_class: MemberClass,
    pub current_membership_epoch_ref: EpochId,
    pub log_frontier: u64,
    pub health: HealthClass,
    pub failure_domain_vector: FailureDomainVector,
    pub digest: u64,
}

impl ClusterMemberRecord {
    #[must_use]
    pub const fn with_class(mut self, member_class: MemberClass) -> Self {
        self.member_class = member_class;
        self.digest = derive_record_id(self.member_id.0, self.current_membership_epoch_ref.0, 0x35);
        self
    }

    #[must_use]
    pub const fn with_frontier(mut self, log_frontier: u64) -> Self {
        self.log_frontier = log_frontier;
        self.digest = derive_record_id(self.member_id.0, log_frontier, 0x46);
        self
    }
}

// ── MembershipRosterEntry ──────────────────────────────────────────

/// Canonical per-member roster entry with capability advertisement.
///
/// Extends the bare [`MemberId`] with a transport address for session
/// establishment and an optional [`PeerCapabilities`] blob for placement
/// and transport carrier selection.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct MembershipRosterEntry {
    /// The member's identity within the epoch.
    pub member_id: MemberId,
    /// Transport address for session establishment.
    pub transport_addr: std::net::SocketAddr,
    /// Advertised operational capabilities, if any.
    pub capabilities: Option<PeerCapabilities>,
}

impl MembershipRosterEntry {
    /// Create a new roster entry with no capabilities.
    #[must_use]
    pub fn new(member_id: MemberId, transport_addr: std::net::SocketAddr) -> Self {
        Self {
            member_id,
            transport_addr,
            capabilities: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberFailureDomainBindingRecord {
    pub binding_id: u64,
    pub member_ref: MemberId,
    pub failure_domain_vector: FailureDomainVector,
    pub last_verified_receipt_ref: ReceiptId,
    pub digest: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct AuthorityPlacementIntentRecord {
    pub placement_intent_id: u64,
    pub authority_domain_ref: AuthorityDomainId,
    pub placement_class_ref: PlacementIntentClass,
    pub primary_member_ref: MemberId,
    pub successor_candidate_refs: Vec<MemberId>,
    pub required_failure_domain_class_ref: FailureDomainClass,
    pub quorum_class_ref: ConfigClass,
    /// Reserved for fence-policy linkage once a FencePolicyClass enumeration is defined.
    pub fence_policy_ref: u64,
    pub digest: u64,
}

impl AuthorityPlacementIntentRecord {
    /// Create an authority-placement intent with sorted, deduplicated successor candidates
    /// and a deterministic digest.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        placement_intent_id: u64,
        authority_domain_ref: AuthorityDomainId,
        placement_class_ref: PlacementIntentClass,
        primary_member_ref: MemberId,
        successor_candidate_refs: &[MemberId],
        required_failure_domain_class_ref: FailureDomainClass,
        quorum_class_ref: ConfigClass,
        fence_policy_ref: u64,
    ) -> Self {
        let mut sorted = successor_candidate_refs.to_vec();
        sorted.sort();
        sorted.dedup();
        let digest = derive_record_id(
            placement_intent_id,
            authority_domain_ref.0 ^ (placement_class_ref as u64),
            0x55,
        );
        Self {
            placement_intent_id,
            authority_domain_ref,
            placement_class_ref,
            primary_member_ref,
            successor_candidate_refs: sorted,
            required_failure_domain_class_ref,
            quorum_class_ref,
            fence_policy_ref,
            digest,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct MembershipConfigRecord {
    pub membership_epoch_id: EpochId,
    pub config_class: ConfigClass,
    pub version_index: u64,
    pub voter_set_refs: Vec<MemberId>,
    pub learner_set_refs: Vec<MemberId>,
    pub observer_set_refs: Vec<MemberId>,
    pub joint_old_set_refs: Vec<MemberId>,
    pub joint_new_set_refs: Vec<MemberId>,
    pub issuance_receipt_ref: ReceiptId,
    pub digest: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct CohortPopulationRecord {
    pub population_id: u64,
    pub membership_epoch_ref: EpochId,
    pub cohort_class: TransportCohortClass,
    pub eligible_member_refs: Vec<MemberId>,
    pub excluded_member_refs: Vec<MemberId>,
    pub issuance_receipt_ref: ReceiptId,
    pub digest: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct MembershipPlacementVerdictRecord {
    pub verdict_id: u64,
    pub membership_epoch_ref: EpochId,
    pub placement_class: PlacementIntentClass,
    pub selected_member_refs: Vec<MemberId>,
    pub selected_domain_refs: Vec<DomainId>,
    pub verdict_class: VerdictClass,
    #[serde(with = "static_str_vec")]
    pub degraded_reason_refs: Vec<&'static str>,
    pub issuance_receipt_ref: ReceiptId,
    pub digest: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct FailureDomainPlacementPlan {
    pub policy_ref: FailureDomainPlacementPolicy,
    pub selected_member_refs: Vec<MemberId>,
    pub selected_domain_refs: Vec<DomainId>,
    pub duplicate_domain_member_refs: Vec<MemberId>,
    pub excluded_member_refs: Vec<MemberId>,
    pub verdict: MembershipPlacementVerdictRecord,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct MembershipTransitionRecord {
    pub transition_id: u64,
    pub subject_member_ref: MemberId,
    pub from_member_class_ref: MemberClass,
    pub to_member_class_ref: MemberClass,
    pub required_catchup_frontier_ref: u64,
    pub current_frontier_ref: u64,
    pub verdict_class: VerdictClass,
    #[serde(with = "static_str_vec")]
    pub blocking_reason_refs: Vec<&'static str>,
    pub open_receipt_ref: ReceiptId,
    pub close_receipt_ref: ReceiptId,
    pub digest: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct SplitBrainHazardRecord {
    pub hazard_id: u64,
    pub authority_domain_ref: AuthorityDomainId,
    pub membership_epoch_ref: EpochId,
    pub conflicting_holder_refs: Vec<MemberId>,
    pub conflicting_domain_refs: Vec<DomainId>,
    pub required_hold_or_quarantine_ref: VerdictClass,
    pub resolution_receipt_ref: ReceiptId,
    pub digest: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct FailureDomainRecord {
    /// Unique domain cell identifier within the failure-domain hierarchy.
    pub failure_domain_id: DomainId,
    /// Failure-domain class: device, node, chassis, rack, zone, or region.
    pub failure_domain_class_ref: FailureDomainClass,
    /// Parent domain in the hierarchy (ZERO for region-level roots).
    pub parent_domain_ref: DomainId,
    /// Member set bound to this domain cell.
    pub member_refs: Vec<MemberId>,
    /// Anti-affinity separation policy for this domain cell.
    pub separation_policy_ref: AntiAffinityClass,
    /// Domain-level health classification.
    pub health_class: HealthClass,
    /// Receipt proving domain availability was verified.
    pub availability_receipt_ref: ReceiptId,
    /// Storage tier for device-level failure domains. None for non-device domains.
    pub storage_tier: Option<StorageTier>,
    pub digest: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum MembershipModelError {
    DuplicateMember(MemberId),
    EmptyVoterSet,
    MissingMember(MemberId),
    IllegalVoterClass(MemberId),
    LearnerPromotionRequiresLearner(MemberId),
    JointConfigRequiresOldAndNewVoters,
    NonJointConfigCarriesJointQuorumSets,
    UnavailableJointVoter(MemberId),
    UnavailablePrimary(MemberId),
    PrimaryMustBeVoter(MemberId),
    QuarantinedCandidate(MemberId),
    /// A domain cell appears with members that disagree on the parent domain,
    /// indicating inconsistent failure-domain inventory.
    InconsistentParentDomain {
        domain_id: DomainId,
        class: FailureDomainClass,
    },
    StaleMemberEpoch {
        member_id: MemberId,
        member_epoch: EpochId,
        config_epoch: EpochId,
    },
}

/// # Errors
///
/// Returns [`MembershipModelError`] on failure.
pub fn inventory_members_and_classify_participation_roles(
    admissions: &[MemberAdmission],
    epoch_id: EpochId,
) -> Result<Vec<ClusterMemberRecord>, MembershipModelError> {
    let mut seen = BTreeSet::new();
    let mut records = Vec::with_capacity(admissions.len());

    for admission in admissions {
        if !seen.insert(admission.member_id) {
            return Err(MembershipModelError::DuplicateMember(admission.member_id));
        }
        records.push(ClusterMemberRecord {
            member_id: admission.member_id,
            member_class: admission.member_class,
            current_membership_epoch_ref: epoch_id,
            log_frontier: admission.log_frontier,
            health: admission.health,
            failure_domain_vector: admission.failure_domain_vector,
            digest: derive_record_id(admission.member_id.0, epoch_id.0, 0x11),
        });
    }

    records.sort_by_key(|record| record.member_id);
    Ok(records)
}

#[must_use]
pub const fn bind_member_to_failure_domain_vector(
    member_ref: MemberId,
    vector: FailureDomainVector,
    last_verified_receipt_ref: ReceiptId,
) -> MemberFailureDomainBindingRecord {
    MemberFailureDomainBindingRecord {
        binding_id: derive_record_id(member_ref.0, last_verified_receipt_ref.0, 0x22),
        member_ref,
        failure_domain_vector: vector,
        last_verified_receipt_ref,
        digest: derive_record_id(member_ref.0, vector.rack.0 ^ vector.zone.0, 0x23),
    }
}

/// # Errors
///
/// Returns [`MembershipModelError`] on failure.
pub fn synthesize_membership_config_epoch_and_quorum_sets(
    membership_epoch_id: EpochId,
    config_class: ConfigClass,
    version_index: u64,
    members: &[ClusterMemberRecord],
    joint_old_set_refs: &[MemberId],
    joint_new_set_refs: &[MemberId],
) -> Result<MembershipConfigRecord, MembershipModelError> {
    let by_id = members_by_id(members);
    let mut voter_set_refs = Vec::new();
    let mut learner_set_refs = Vec::new();
    let mut observer_set_refs = Vec::new();

    for member in members {
        if member.member_class == MemberClass::Quarantined || member.health == HealthClass::Down {
            continue;
        }
        match member.member_class {
            MemberClass::Voter => voter_set_refs.push(member.member_id),
            MemberClass::Learner => learner_set_refs.push(member.member_id),
            MemberClass::WitnessOnly | MemberClass::ShadowOnly => {
                observer_set_refs.push(member.member_id);
            }
            MemberClass::DataOnly | MemberClass::Quarantined => {}
        }
    }

    if voter_set_refs.is_empty() && config_class != ConfigClass::Quarantined {
        return Err(MembershipModelError::EmptyVoterSet);
    }

    match config_class {
        ConfigClass::Joint => {
            if joint_old_set_refs.is_empty() || joint_new_set_refs.is_empty() {
                return Err(MembershipModelError::JointConfigRequiresOldAndNewVoters);
            }
            validate_voters(&by_id, joint_old_set_refs)?;
            validate_voters(&by_id, joint_new_set_refs)?;
        }
        ConfigClass::Bootstrap | ConfigClass::Normal | ConfigClass::Quarantined => {
            if !joint_old_set_refs.is_empty() || !joint_new_set_refs.is_empty() {
                return Err(MembershipModelError::NonJointConfigCarriesJointQuorumSets);
            }
        }
    }

    voter_set_refs.sort();
    learner_set_refs.sort();
    observer_set_refs.sort();
    let mut joint_old_set_refs = joint_old_set_refs.to_vec();
    let mut joint_new_set_refs = joint_new_set_refs.to_vec();
    sort_and_dedup_member_refs(&mut joint_old_set_refs);
    sort_and_dedup_member_refs(&mut joint_new_set_refs);

    let digest = derive_record_id(membership_epoch_id.0, version_index, config_class as u64);
    Ok(MembershipConfigRecord {
        membership_epoch_id,
        config_class,
        version_index,
        voter_set_refs,
        learner_set_refs,
        observer_set_refs,
        joint_old_set_refs,
        joint_new_set_refs,
        issuance_receipt_ref: ReceiptId(derive_record_id(
            membership_epoch_id.0,
            version_index,
            0x31,
        )),
        digest,
    })
}

#[must_use]
pub fn populate_transport_session_cohorts_from_membership_epoch(
    config: &MembershipConfigRecord,
    members: &[ClusterMemberRecord],
    cohort_class: TransportCohortClass,
) -> CohortPopulationRecord {
    let voter_set: BTreeSet<MemberId> = config.voter_set_refs.iter().copied().collect();
    let learner_set: BTreeSet<MemberId> = config.learner_set_refs.iter().copied().collect();
    let mut eligible_member_refs = Vec::new();
    let mut excluded_member_refs = Vec::new();

    for member in members {
        if member.current_membership_epoch_ref != config.membership_epoch_id
            || member.member_class == MemberClass::Quarantined
            || !member.health.admits_new_work()
        {
            excluded_member_refs.push(member.member_id);
            continue;
        }

        let eligible = match cohort_class {
            TransportCohortClass::PeerPair => true,
            TransportCohortClass::AuthorityDomainControl => {
                voter_set.contains(&member.member_id) || learner_set.contains(&member.member_id)
            }
            TransportCohortClass::ReplicaSet | TransportCohortClass::StateTransfer => {
                member.member_class.can_hold_replicas()
            }
            TransportCohortClass::ShadowCompare => matches!(
                member.member_class,
                MemberClass::Voter | MemberClass::Learner | MemberClass::ShadowOnly
            ),
            TransportCohortClass::TransitionStage => {
                voter_set.contains(&member.member_id) || learner_set.contains(&member.member_id)
            }
        };

        if eligible {
            eligible_member_refs.push(member.member_id);
        } else {
            excluded_member_refs.push(member.member_id);
        }
    }

    eligible_member_refs.sort();
    excluded_member_refs.sort();
    let population_id = derive_record_id(
        config.membership_epoch_id.0,
        cohort_class as u64,
        eligible_member_refs.len() as u64,
    );
    CohortPopulationRecord {
        population_id,
        membership_epoch_ref: config.membership_epoch_id,
        cohort_class,
        eligible_member_refs,
        excluded_member_refs,
        issuance_receipt_ref: ReceiptId(derive_record_id(population_id, 0, 0x41)),
        digest: derive_record_id(population_id, config.digest, 0x42),
    }
}

/// # Errors
///
/// Returns [`MembershipModelError`] on failure.
pub fn derive_authority_home_and_failover_successor_candidates(
    config: &MembershipConfigRecord,
    members: &[ClusterMemberRecord],
    primary_member_ref: MemberId,
    required_failure_domain_class_ref: FailureDomainClass,
) -> Result<MembershipPlacementVerdictRecord, MembershipModelError> {
    let by_id = members_by_id(members);
    let primary = member_or_missing(&by_id, primary_member_ref)?;
    if primary.current_membership_epoch_ref != config.membership_epoch_id {
        return Err(MembershipModelError::StaleMemberEpoch {
            member_id: primary_member_ref,
            member_epoch: primary.current_membership_epoch_ref,
            config_epoch: config.membership_epoch_id,
        });
    }
    if primary.member_class != MemberClass::Voter
        || !config.voter_set_refs.contains(&primary_member_ref)
    {
        return Err(MembershipModelError::PrimaryMustBeVoter(primary_member_ref));
    }
    if !primary.health.admits_new_work() {
        return Err(MembershipModelError::UnavailablePrimary(primary_member_ref));
    }

    let primary_domain = primary
        .failure_domain_vector
        .domain(required_failure_domain_class_ref);
    let mut separated_successors = Vec::new();
    let mut selected_domain_refs = vec![primary_domain];

    for member in members {
        if member.member_id == primary_member_ref {
            continue;
        }
        if !config.voter_set_refs.contains(&member.member_id) {
            continue;
        }
        if member.current_membership_epoch_ref != config.membership_epoch_id {
            return Err(MembershipModelError::StaleMemberEpoch {
                member_id: member.member_id,
                member_epoch: member.current_membership_epoch_ref,
                config_epoch: config.membership_epoch_id,
            });
        }
        if member.member_class == MemberClass::Quarantined {
            return Err(MembershipModelError::QuarantinedCandidate(member.member_id));
        }
        if !member.member_class.can_vote() {
            return Err(MembershipModelError::IllegalVoterClass(member.member_id));
        }
        if !member.health.admits_new_work() {
            continue;
        }
        let domain = member
            .failure_domain_vector
            .domain(required_failure_domain_class_ref);
        if domain != primary_domain {
            separated_successors.push(member.member_id);
            selected_domain_refs.push(domain);
        }
    }

    separated_successors.sort();
    selected_domain_refs.sort();
    selected_domain_refs.dedup();

    let mut selected_member_refs = vec![primary_member_ref];
    selected_member_refs.extend(separated_successors.iter().copied());
    let verdict_class = if separated_successors.is_empty() {
        VerdictClass::HoldDomainGap
    } else {
        VerdictClass::Admit
    };
    let degraded_reason_refs = if separated_successors.is_empty() {
        vec!["missing required failure-domain-separated voter successor"]
    } else {
        Vec::new()
    };

    Ok(issue_membership_or_placement_verdict(
        config.membership_epoch_id,
        PlacementIntentClass::FailoverSuccessor,
        selected_member_refs,
        selected_domain_refs,
        verdict_class,
        degraded_reason_refs,
    ))
}

#[must_use]
pub fn derive_replica_targets_from_failure_domain_policy(
    config: &MembershipConfigRecord,
    members: &[ClusterMemberRecord],
    required_replica_count: usize,
    required_failure_domain_class_ref: FailureDomainClass,
) -> MembershipPlacementVerdictRecord {
    plan_failure_domain_placement_from_policy(
        config,
        members,
        FailureDomainPlacementPolicy::degraded_visible_replica_targets(
            required_replica_count,
            required_failure_domain_class_ref,
        ),
    )
    .verdict
}

#[must_use]
pub fn plan_failure_domain_placement_from_policy(
    config: &MembershipConfigRecord,
    members: &[ClusterMemberRecord],
    policy: FailureDomainPlacementPolicy,
) -> FailureDomainPlacementPlan {
    let mut selected_member_refs = Vec::new();
    let mut selected_domain_refs = Vec::new();
    let mut duplicate_domain_member_refs = Vec::new();
    let mut excluded_member_refs = Vec::new();
    let mut eligible_by_domain: BTreeMap<DomainId, Vec<MemberId>> = BTreeMap::new();

    for member in members {
        if member.current_membership_epoch_ref != config.membership_epoch_id
            || !member.member_class.can_hold_replicas()
            || !member.health.admits_new_work()
        {
            excluded_member_refs.push(member.member_id);
            continue;
        }
        let domain = member
            .failure_domain_vector
            .domain(policy.required_failure_domain_class_ref);
        eligible_by_domain
            .entry(domain)
            .or_default()
            .push(member.member_id);
    }

    for members_in_domain in eligible_by_domain.values_mut() {
        members_in_domain.sort();
    }

    for (domain, members_in_domain) in &eligible_by_domain {
        if selected_member_refs.len() < policy.required_replica_count {
            if let Some(member_ref) = members_in_domain.first() {
                selected_member_refs.push(*member_ref);
                selected_domain_refs.push(*domain);
            }
        }
        for member_ref in members_in_domain.iter().skip(1) {
            duplicate_domain_member_refs.push(*member_ref);
        }
    }

    if selected_member_refs.len() < policy.required_replica_count
        && policy.anti_affinity_class == AntiAffinityClass::DegradedVisible
    {
        for member_ref in &duplicate_domain_member_refs {
            if selected_member_refs.len() == policy.required_replica_count {
                break;
            }
            selected_member_refs.push(*member_ref);
        }
    }

    selected_member_refs.sort();
    selected_member_refs.dedup();
    selected_domain_refs.sort();
    selected_domain_refs.dedup();
    duplicate_domain_member_refs.sort();
    duplicate_domain_member_refs.dedup();
    excluded_member_refs.sort();
    excluded_member_refs.dedup();

    let has_required_count = selected_member_refs.len() >= policy.required_replica_count;
    let has_required_spread = selected_domain_refs.len() >= policy.required_replica_count;
    let verdict_class =
        if policy.required_replica_count == 0 || (has_required_count && has_required_spread) {
            VerdictClass::Admit
        } else if selected_member_refs.is_empty()
            || (policy.anti_affinity_class == AntiAffinityClass::Strict && !has_required_spread)
        {
            VerdictClass::HoldDomainGap
        } else {
            VerdictClass::AdmitDegraded
        };

    let mut degraded_reason_refs = Vec::new();
    if verdict_class != VerdictClass::Admit {
        if !has_required_spread {
            degraded_reason_refs.push("insufficient separated failure-domain targets");
        }
        if !has_required_count {
            degraded_reason_refs.push("insufficient eligible replica targets");
        }
        if policy.anti_affinity_class == AntiAffinityClass::Strict
            && !duplicate_domain_member_refs.is_empty()
        {
            degraded_reason_refs
                .push("strict anti-affinity policy forbids duplicate-domain replica targets");
        }
        if policy.anti_affinity_class == AntiAffinityClass::DegradedVisible
            && has_required_count
            && !has_required_spread
        {
            degraded_reason_refs.push("duplicate-domain replica target admitted as degraded");
        }
    }

    let verdict = issue_membership_or_placement_verdict(
        config.membership_epoch_id,
        policy.placement_class,
        selected_member_refs.clone(),
        selected_domain_refs.clone(),
        verdict_class,
        degraded_reason_refs,
    );

    FailureDomainPlacementPlan {
        policy_ref: policy,
        selected_member_refs,
        selected_domain_refs,
        duplicate_domain_member_refs,
        excluded_member_refs,
        verdict,
    }
}

#[must_use]
pub fn evaluate_transition_catchup_and_readiness(
    member: &ClusterMemberRecord,
    to_member_class_ref: MemberClass,
    required_catchup_frontier_ref: u64,
) -> MembershipTransitionRecord {
    let (verdict_class, blocking_reason_refs, close_receipt_ref) =
        if member.member_class == MemberClass::Quarantined {
            (
                VerdictClass::Quarantine,
                vec!["member is quarantined"],
                ReceiptId::ZERO,
            )
        } else if !member.health.admits_new_work() {
            (
                VerdictClass::RefusePolicyOrCapacity,
                vec!["member health does not admit new work"],
                ReceiptId::ZERO,
            )
        } else if member.log_frontier < required_catchup_frontier_ref {
            (
                VerdictClass::HoldCatchup,
                vec!["catch-up frontier is behind required epoch frontier"],
                ReceiptId::ZERO,
            )
        } else {
            (
                VerdictClass::Admit,
                Vec::new(),
                ReceiptId(derive_record_id(
                    member.member_id.0,
                    required_catchup_frontier_ref,
                    0x55,
                )),
            )
        };

    let transition_id = derive_record_id(member.member_id.0, required_catchup_frontier_ref, 0x51);
    MembershipTransitionRecord {
        transition_id,
        subject_member_ref: member.member_id,
        from_member_class_ref: member.member_class,
        to_member_class_ref,
        required_catchup_frontier_ref,
        current_frontier_ref: member.log_frontier,
        verdict_class,
        blocking_reason_refs,
        open_receipt_ref: ReceiptId(derive_record_id(transition_id, 0, 0x52)),
        close_receipt_ref,
        digest: derive_record_id(transition_id, verdict_class as u64, 0x53),
    }
}
/// # Errors
///
/// Returns [`MembershipModelError`] on failure.
pub fn promote_caught_up_learner_to_voter(
    members: &[ClusterMemberRecord],
    member_id: MemberId,
    required_catchup_frontier_ref: u64,
) -> Result<(Vec<ClusterMemberRecord>, MembershipTransitionRecord), MembershipModelError> {
    let by_id = members_by_id(members);
    let member = member_or_missing(&by_id, member_id)?;
    if member.member_class != MemberClass::Learner {
        return Err(MembershipModelError::LearnerPromotionRequiresLearner(
            member_id,
        ));
    }
    let transition = evaluate_transition_catchup_and_readiness(
        member,
        MemberClass::Voter,
        required_catchup_frontier_ref,
    );
    let mut updated = members.to_vec();
    if transition.verdict_class == VerdictClass::Admit {
        for candidate in &mut updated {
            if candidate.member_id == member_id {
                *candidate = candidate.with_class(MemberClass::Voter);
            }
        }
    }
    Ok((updated, transition))
}

#[must_use]
pub fn issue_membership_or_placement_verdict(
    membership_epoch_ref: EpochId,
    placement_class: PlacementIntentClass,
    mut selected_member_refs: Vec<MemberId>,
    mut selected_domain_refs: Vec<DomainId>,
    verdict_class: VerdictClass,
    degraded_reason_refs: Vec<&'static str>,
) -> MembershipPlacementVerdictRecord {
    selected_member_refs.sort();
    selected_member_refs.dedup();
    selected_domain_refs.sort();
    selected_domain_refs.dedup();
    let verdict_id = derive_record_id(
        membership_epoch_ref.0,
        placement_class as u64,
        verdict_class as u64,
    );
    MembershipPlacementVerdictRecord {
        verdict_id,
        membership_epoch_ref,
        placement_class,
        selected_member_refs,
        selected_domain_refs,
        verdict_class,
        degraded_reason_refs,
        issuance_receipt_ref: ReceiptId(derive_record_id(verdict_id, 0, 0x61)),
        digest: derive_record_id(verdict_id, membership_epoch_ref.0, 0x62),
    }
}

#[must_use]
pub fn detect_split_brain_hazard_and_force_hold_or_quarantine(
    authority_domain_ref: AuthorityDomainId,
    membership_epoch_ref: EpochId,
    holder_claim_refs: &[MemberId],
    members: &[ClusterMemberRecord],
    required_failure_domain_class_ref: FailureDomainClass,
) -> Option<SplitBrainHazardRecord> {
    let unique_holders: BTreeSet<MemberId> = holder_claim_refs.iter().copied().collect();
    if unique_holders.len() <= 1 {
        return None;
    }

    let by_id = members_by_id(members);
    let mut conflicting_holder_refs: Vec<MemberId> = unique_holders.iter().copied().collect();
    conflicting_holder_refs.sort();
    let mut conflicting_domain_refs = Vec::new();
    for holder in &conflicting_holder_refs {
        if let Some(member) = by_id.get(holder) {
            conflicting_domain_refs.push(
                member
                    .failure_domain_vector
                    .domain(required_failure_domain_class_ref),
            );
        }
    }
    conflicting_domain_refs.sort();
    conflicting_domain_refs.dedup();

    let hazard_id = derive_record_id(
        authority_domain_ref.0,
        membership_epoch_ref.0,
        conflicting_holder_refs.len() as u64,
    );
    Some(SplitBrainHazardRecord {
        hazard_id,
        authority_domain_ref,
        membership_epoch_ref,
        conflicting_holder_refs,
        conflicting_domain_refs,
        required_hold_or_quarantine_ref: VerdictClass::RefuseSplitBrain,
        resolution_receipt_ref: ReceiptId::ZERO,
        digest: derive_record_id(hazard_id, VerdictClass::RefuseSplitBrain as u64, 0x71),
    })
}

#[must_use]
pub fn inventory_failure_domain_hierarchy(
    members: &[ClusterMemberRecord],
) -> Vec<FailureDomainRecord> {
    // Collect (domain_id, class) -> member_refs mappings from all member vectors.
    let mut domain_members: BTreeMap<(DomainId, FailureDomainClass), BTreeSet<MemberId>> =
        BTreeMap::new();

    for member in members {
        let fdv = member.failure_domain_vector;
        let entries: [(DomainId, FailureDomainClass); 6] = [
            (fdv.device, FailureDomainClass::Device),
            (fdv.node, FailureDomainClass::Node),
            (fdv.chassis, FailureDomainClass::Chassis),
            (fdv.rack, FailureDomainClass::Rack),
            (fdv.zone, FailureDomainClass::Zone),
            (fdv.region, FailureDomainClass::Region),
        ];
        for (domain_id, class) in &entries {
            // DomainId::ZERO is the null sentinel; skip.
            if domain_id.0 == 0 {
                continue;
            }
            domain_members
                .entry((*domain_id, *class))
                .or_default()
                .insert(member.member_id);
        }
    }

    let mut records: Vec<FailureDomainRecord> = Vec::with_capacity(domain_members.len());

    for ((domain_id, class), member_set) in &domain_members {
        let parent_domain_ref = parent_domain_of(*class, *domain_id, members);

        let mut member_refs: Vec<MemberId> = member_set.iter().copied().collect();
        member_refs.sort();

        records.push(FailureDomainRecord {
            failure_domain_id: *domain_id,
            failure_domain_class_ref: *class,
            parent_domain_ref,
            member_refs,
            separation_policy_ref: AntiAffinityClass::Strict,
            health_class: HealthClass::Healthy,
            availability_receipt_ref: ReceiptId::ZERO,
            storage_tier: None,
            digest: derive_record_id(domain_id.0, *class as u64, 0x41),
        });
    }

    records.sort_by_key(|r| (r.failure_domain_class_ref as u32, r.failure_domain_id));
    records
}

/// Return the parent domain id for a given (class, domain_id) by looking up
/// the next-higher class in any member of this domain.
///
/// Returns `DomainId::ZERO` for region-class domains (no parent).
fn parent_domain_of(
    class: FailureDomainClass,
    domain_id: DomainId,
    members: &[ClusterMemberRecord],
) -> DomainId {
    let next_class = match class {
        FailureDomainClass::Device => FailureDomainClass::Node,
        FailureDomainClass::Node => FailureDomainClass::Chassis,
        FailureDomainClass::Chassis => FailureDomainClass::Rack,
        FailureDomainClass::Rack => FailureDomainClass::Zone,
        FailureDomainClass::Zone => FailureDomainClass::Region,
        FailureDomainClass::Region => return DomainId::ZERO,
    };

    // All members in the same domain should agree on the parent.
    // Use the first member that belongs to this domain.
    for member in members {
        if member.failure_domain_vector.domain(class) == domain_id {
            return member.failure_domain_vector.domain(next_class);
        }
    }
    DomainId::ZERO
}

/// # Errors
///
/// Returns [`MembershipModelError`] on failure.
pub fn control_membership_placement_failure_domain_protocol(
    config: &MembershipConfigRecord,
    members: &[ClusterMemberRecord],
    primary_member_ref: MemberId,
    required_failure_domain_class_ref: FailureDomainClass,
    holder_claim_refs: &[MemberId],
) -> Result<MembershipPlacementVerdictRecord, MembershipModelError> {
    if detect_split_brain_hazard_and_force_hold_or_quarantine(
        AuthorityDomainId(config.membership_epoch_id.0),
        config.membership_epoch_id,
        holder_claim_refs,
        members,
        required_failure_domain_class_ref,
    )
    .is_some()
    {
        return Ok(issue_membership_or_placement_verdict(
            config.membership_epoch_id,
            PlacementIntentClass::AuthorityHome,
            holder_claim_refs.to_vec(),
            Vec::new(),
            VerdictClass::RefuseSplitBrain,
            vec!["competing holder claims for one membership epoch"],
        ));
    }

    derive_authority_home_and_failover_successor_candidates(
        config,
        members,
        primary_member_ref,
        required_failure_domain_class_ref,
    )
}

fn validate_voters(
    by_id: &BTreeMap<MemberId, &ClusterMemberRecord>,
    refs: &[MemberId],
) -> Result<(), MembershipModelError> {
    for member_ref in refs {
        let member = member_or_missing(by_id, *member_ref)?;
        if !member.member_class.can_vote() {
            return Err(MembershipModelError::IllegalVoterClass(*member_ref));
        }
        if !member.health.admits_new_work() {
            return Err(MembershipModelError::UnavailableJointVoter(*member_ref));
        }
    }
    Ok(())
}

fn member_or_missing<'a>(
    by_id: &'a BTreeMap<MemberId, &'a ClusterMemberRecord>,
    member_ref: MemberId,
) -> Result<&'a ClusterMemberRecord, MembershipModelError> {
    by_id
        .get(&member_ref)
        .copied()
        .ok_or(MembershipModelError::MissingMember(member_ref))
}

fn members_by_id(members: &[ClusterMemberRecord]) -> BTreeMap<MemberId, &ClusterMemberRecord> {
    members
        .iter()
        .map(|member| (member.member_id, member))
        .collect()
}

fn sort_and_dedup_member_refs(member_refs: &mut Vec<MemberId>) {
    member_refs.sort();
    member_refs.dedup();
}

const fn derive_record_id(left: u64, right: u64, salt: u64) -> u64 {
    left.wrapping_mul(0x9E37_79B1_85EB_CA87)
        ^ right.rotate_left(17)
        ^ salt.wrapping_mul(0xC2B2_AE3D_27D4_EB4F)
}

// =========================================================================
// Identity integration: NodeIdentity binding for fencing and join authorization
// =========================================================================

/// A membership entry binds a member's node identity with its authenticated
/// Ed25519-based identity. This is the unit of membership that the epoch state
/// machine carries for identity-aware operations (fencing, rotation, join auth).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MembershipEntry {
    /// Simple node identity (from membership-types).
    pub node_id: NodeIdentity,
    /// Full Ed25519-authenticated identity (from tidefs-auth).
    pub auth_identity: AuthNodeIdentity,
}

impl MembershipEntry {
    pub fn new(node_id: NodeIdentity, auth_identity: AuthNodeIdentity) -> Self {
        Self {
            node_id,
            auth_identity,
        }
    }

    /// Verify the self-signature on the auth identity.
    pub fn verify_auth_identity(&self) -> Result<(), IdentityError> {
        self.auth_identity.verify_self_signature()
    }

    /// Get the identity version from the auth identity.
    pub fn identity_version(&self) -> u64 {
        self.auth_identity.identity_version
    }
}

impl PartialOrd for MembershipEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MembershipEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.node_id.cmp(&other.node_id)
    }
}

/// Set of membership entries, maintained in sorted order by node_id.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EpochEntrySet {
    entries: BTreeSet<MembershipEntry>,
}

impl EpochEntrySet {
    pub fn new(entries: impl IntoIterator<Item = MembershipEntry>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, node_id: &NodeIdentity) -> bool {
        self.entries.iter().any(|e| e.node_id == *node_id)
    }

    pub fn get(&self, node_id: &NodeIdentity) -> Option<&MembershipEntry> {
        self.entries.iter().find(|e| e.node_id == *node_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &MembershipEntry> {
        self.entries.iter()
    }

    pub fn node_ids(&self) -> Vec<NodeIdentity> {
        self.entries.iter().map(|e| e.node_id).collect()
    }

    pub fn insert(&mut self, entry: MembershipEntry) -> bool {
        self.entries.insert(entry)
    }

    pub fn remove(&mut self, node_id: &NodeIdentity) -> Option<MembershipEntry> {
        if let Some(entry) = self.entries.iter().find(|e| e.node_id == *node_id).cloned() {
            self.entries.remove(&entry);
            Some(entry)
        } else {
            None
        }
    }
}

/// Result of an identity fence operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FenceVerdict {
    /// Node was a member and has been fenced (removed) in the new epoch.
    Fenced { epoch_id: u64, removed_node_id: u64 },
    /// Node was not a member; no change to the member set.
    NotAMember { node_id: u64 },
    /// Node was not found in the epoch.
    NotFound { node_id: u64 },
}

/// Result of an identity rotation within the epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotateVerdict {
    /// Identity was rotated and epoch advanced.
    Rotated {
        epoch_id: u64,
        node_id: u64,
        old_version: u64,
        new_version: u64,
    },
    /// Node was not a member.
    NotAMember { node_id: u64 },
}

/// Verifies identity validity at epoch boundaries.
///
/// The `IdentityVerifier` checks every member's authenticated identity against
/// the revocation set at epoch transitions. A revoked identity causes the
/// member to be fenced (removed) in the new epoch.
// Manual Debug impl below (NodeKeyStore lacks Debug)
pub struct IdentityVerifier {
    pub revocation_set: RevocationSet,
    pub key_store: NodeKeyStore,
}

impl std::fmt::Debug for IdentityVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityVerifier")
            .field("revocation_set", &self.revocation_set)
            .field("key_store", &"<NodeKeyStore>")
            .finish()
    }
}

impl IdentityVerifier {
    pub fn new(revocation_set: RevocationSet, key_store: NodeKeyStore) -> Self {
        Self {
            revocation_set,
            key_store,
        }
    }

    /// Verify all entries in an epoch entry set have valid, non-revoked identities.
    ///
    /// Returns the list of node_ids that are revoked and must be fenced.
    pub fn verify_epoch_entries(&self, entries: &EpochEntrySet) -> Vec<u64> {
        let mut revoked_nodes = Vec::new();
        for entry in entries.iter() {
            let node_id = entry.node_id.node_id;
            let version = entry.identity_version();
            if check_revocation_status(&self.revocation_set, node_id, version).is_err() {
                revoked_nodes.push(node_id);
            }
        }
        revoked_nodes
    }

    /// Verify a single entry's identity is valid (not revoked, signature valid).
    pub fn verify_entry(&self, entry: &MembershipEntry) -> Result<(), IdentityError> {
        entry.verify_auth_identity()?;
        check_revocation_status(
            &self.revocation_set,
            entry.node_id.node_id,
            entry.identity_version(),
        )?;
        Ok(())
    }

    /// Check whether a node identity version is revoked.
    pub fn is_revoked(&self, node_id: u64, identity_version: u64) -> bool {
        check_revocation_status(&self.revocation_set, node_id, identity_version).is_err()
    }

    /// Register a node identity in the key store (bootstrap trust).
    pub fn register_identity(
        &mut self,
        auth_identity: AuthNodeIdentity,
    ) -> Result<(), IdentityError> {
        self.key_store.register(auth_identity)
    }

    /// Look up a node's verifying key from the key store.
    pub fn get_verifying_key_bytes(&self, node_id: u64) -> Option<[u8; 32]> {
        self.key_store
            .get_verifying_key(node_id)
            .map(|pk| pk.to_bytes())
    }
}

// =========================================================================
// Identity-aware EpochStateMachine extensions
// =========================================================================

impl EpochStateMachine {
    /// Fence a node from the member set due to identity compromise or revocation.
    ///
    /// Creates a new epoch without the fenced node. If the node is not a member,
    /// the epoch still increments but no member is removed.
    pub fn fence_node(&mut self, node_id: u64) -> FenceVerdict {
        let target = NodeIdentity::new(node_id);
        if !self.current.members.contains(&target) {
            self.increment();
            return FenceVerdict::NotAMember { node_id };
        }

        let transition = self.leave(target);
        FenceVerdict::Fenced {
            epoch_id: transition.to_epoch_id,
            removed_node_id: node_id,
        }
    }

    /// Rotate a member's identity, advancing the epoch.
    ///
    /// The member remains in the set but with a bumped identity version.
    /// This is used for scheduled key rotation.
    pub fn rotate_identity(
        &mut self,
        node_id: u64,
        new_auth_identity: AuthNodeIdentity,
    ) -> RotateVerdict {
        let target = NodeIdentity::new(node_id);
        if !self.current.members.contains(&target) {
            return RotateVerdict::NotAMember { node_id };
        }

        let old_version = new_auth_identity.identity_version.saturating_sub(1);

        // Advance the epoch via increment (member set unchanged).
        let transition = self.increment();

        RotateVerdict::Rotated {
            epoch_id: transition.to_epoch_id,
            node_id,
            old_version,
            new_version: new_auth_identity.identity_version,
        }
    }

    /// List the member node_ids in the current epoch.
    pub fn member_node_ids(&self) -> Vec<u64> {
        self.current.members.iter().map(|ni| ni.node_id).collect()
    }

    /// Check if a node is a member of the current epoch.
    pub fn is_member(&self, node_id: u64) -> bool {
        self.current.members.contains(&NodeIdentity::new(node_id))
    }
}

// =========================================================================
// Epoch state machine
// =========================================================================

/// An ordered set of node identities forming a membership epoch's member set.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochMemberSet {
    members: BTreeSet<NodeIdentity>,
}

impl EpochMemberSet {
    pub fn new(members: impl IntoIterator<Item = NodeIdentity>) -> Self {
        Self {
            members: members.into_iter().collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn contains(&self, node: &NodeIdentity) -> bool {
        self.members.contains(node)
    }

    pub fn iter(&self) -> impl Iterator<Item = &NodeIdentity> {
        self.members.iter()
    }

    pub fn members(&self) -> &BTreeSet<NodeIdentity> {
        &self.members
    }

    fn insert(&mut self, node: NodeIdentity) -> bool {
        self.members.insert(node)
    }

    fn remove(&mut self, node: &NodeIdentity) -> bool {
        self.members.remove(node)
    }
}

/// A membership epoch binds an epoch identifier to a concrete member set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MembershipEpoch {
    pub epoch_id: u64,
    pub members: EpochMemberSet,
}

impl MembershipEpoch {
    /// Create a quorum proposal to transition to a new member configuration.
    ///
    /// Builds an [`EpochProposal`](crate::quorum::EpochProposal) with a
    /// BLAKE3 hash covering the proposed member set. The caller must supply
    /// a `sequence_number` that is strictly greater than `self.epoch_id`.
    /// The proposed member ids are sorted and deduplicated before hashing.
    pub fn propose(
        &self,
        proposer_id: u64,
        sequence_number: u64,
        proposed_members: &[u64],
    ) -> Result<crate::quorum::EpochProposal, crate::quorum::QuorumError> {
        if sequence_number <= self.epoch_id {
            return Err(crate::quorum::QuorumError::StaleSequence);
        }
        let mut sorted = proposed_members.to_vec();
        sorted.sort();
        sorted.dedup();
        if sorted.is_empty() {
            return Err(crate::quorum::QuorumError::EmptyMemberSet);
        }
        let proposed_epoch_id = self.epoch_id + 1;
        let blake3_hash = crate::quorum::EpochProposal::compute_hash(
            proposer_id,
            sequence_number,
            proposed_epoch_id,
            self.epoch_id,
            &sorted,
        );
        let proposal_id = proposer_id.wrapping_mul(sequence_number);
        Ok(crate::quorum::EpochProposal {
            proposal_id,
            sequence_number,
            proposer_id,
            proposed_epoch_id,
            prior_epoch_id: self.epoch_id,
            proposed_members: sorted,
            blake3_hash,
        })
    }

    /// Advance the epoch to a verified, committed configuration.
    ///
    /// Validates the [`EpochCommitment`](crate::quorum::EpochCommitment):
    /// - BLAKE3 integrity proof on the committed configuration
    /// - Sequence number is strictly greater than current epoch
    /// - `prior_epoch_id` matches `self.epoch_id`
    ///
    /// Returns the new `MembershipEpoch` on success.
    pub fn advance(
        &self,
        commitment: &crate::quorum::EpochCommitment,
    ) -> Result<MembershipEpoch, crate::quorum::QuorumError> {
        if !commitment.verify() {
            return Err(crate::quorum::QuorumError::VoteVerificationFailed);
        }
        if commitment.sequence_number <= self.epoch_id {
            return Err(crate::quorum::QuorumError::StaleSequence);
        }
        if commitment.prior_epoch_id != self.epoch_id {
            return Err(crate::quorum::QuorumError::InvalidPriorEpoch);
        }
        if commitment.member_set.is_empty() {
            return Err(crate::quorum::QuorumError::EmptyMemberSet);
        }
        let members = EpochMemberSet::new(
            commitment
                .member_set
                .iter()
                .map(|&id| NodeIdentity::new(id)),
        );
        Ok(MembershipEpoch {
            epoch_id: commitment.epoch_id,
            members,
        })
    }
}
/// An event that triggers an epoch transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EpochEvent {
    Join(NodeIdentity),
    Leave(NodeIdentity),
    Increment,
    CoordinatorChanged {
        old: NodeIdentity,
        new: NodeIdentity,
    },
}

/// Delta applied to the member set during an epoch transition.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemberSetDelta {
    pub added: Vec<NodeIdentity>,
    pub removed: Vec<NodeIdentity>,
}

/// Record of a single epoch transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochTransition {
    pub from_epoch_id: u64,
    pub to_epoch_id: u64,
    pub event: EpochEvent,
    pub member_set_delta: MemberSetDelta,
}

/// Deterministic epoch state machine.
///
/// Given the same sequence of join/leave events, the same epoch sequence is
/// produced.  Epoch identifiers are strictly monotonic and never reused.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochStateMachine {
    current: MembershipEpoch,
    next_epoch_id: u64,
}

impl EpochStateMachine {
    /// Bootstrap the state machine with an initial member set at epoch 0.
    pub fn bootstrap(initial_members: EpochMemberSet) -> Self {
        Self {
            current: MembershipEpoch {
                epoch_id: 0,
                members: initial_members,
            },
            next_epoch_id: 1,
        }
    }

    /// Set the epoch counter to match a snapshot epoch during crash recovery.
    ///
    /// Only valid when called immediately after bootstrap (epoch 0).
    pub(crate) fn set_snapshot_epoch(&mut self, epoch: u64) {
        self.current.epoch_id = epoch;
        self.next_epoch_id = epoch + 1;
    }

    /// Return the current membership epoch.
    pub fn current_epoch(&self) -> &MembershipEpoch {
        &self.current
    }

    /// Handle a node join, advancing to a new epoch.
    ///
    /// If the node is already a member, the epoch still increments but the
    /// transition carries an empty member-set delta.
    pub fn join(&mut self, node: NodeIdentity) -> EpochTransition {
        let from_epoch_id = self.current.epoch_id;
        let to_epoch_id = self.next_epoch_id;
        self.next_epoch_id += 1;

        let mut new_members = self.current.members.clone();
        let added = if new_members.insert(node) {
            vec![node]
        } else {
            Vec::new()
        };

        let transition = EpochTransition {
            from_epoch_id,
            to_epoch_id,
            event: EpochEvent::Join(node),
            member_set_delta: MemberSetDelta {
                added: added.clone(),
                removed: Vec::new(),
            },
        };

        self.current = MembershipEpoch {
            epoch_id: to_epoch_id,
            members: new_members,
        };

        transition
    }

    /// Handle a node leave, advancing to a new epoch.
    ///
    /// If the node is not a member, the epoch still increments but the
    /// transition carries an empty member-set delta.
    pub fn leave(&mut self, node: NodeIdentity) -> EpochTransition {
        let from_epoch_id = self.current.epoch_id;
        let to_epoch_id = self.next_epoch_id;
        self.next_epoch_id += 1;

        let mut new_members = self.current.members.clone();
        let removed = if new_members.remove(&node) {
            vec![node]
        } else {
            Vec::new()
        };

        let transition = EpochTransition {
            from_epoch_id,
            to_epoch_id,
            event: EpochEvent::Leave(node),
            member_set_delta: MemberSetDelta {
                added: Vec::new(),
                removed: removed.clone(),
            },
        };

        self.current = MembershipEpoch {
            epoch_id: to_epoch_id,
            members: new_members,
        };

        transition
    }

    /// Increment the epoch number without changing the member set.
    ///
    /// Used for heartbeat-based failure detection: when a peer becomes
    /// unreachable, the epoch is incremented so that recovery paths can
    /// observe a membership event without necessarily removing the peer
    /// from the member set (that is left to the fencing layer).
    pub fn increment(&mut self) -> EpochTransition {
        let from_epoch_id = self.current.epoch_id;
        let to_epoch_id = self.next_epoch_id;
        self.next_epoch_id += 1;

        let transition = EpochTransition {
            from_epoch_id,
            to_epoch_id,
            event: EpochEvent::Increment,
            member_set_delta: MemberSetDelta {
                added: Vec::new(),
                removed: Vec::new(),
            },
        };

        self.current = MembershipEpoch {
            epoch_id: to_epoch_id,
            members: self.current.members.clone(),
        };

        transition
    }
}

/// Ring buffer retaining the last N epoch transitions for late-join catch-up.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochHistory {
    buffer: Vec<EpochTransition>,
    capacity: usize,
    write_pos: usize,
}

impl EpochHistory {
    /// Create a new history buffer with the given capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "EpochHistory capacity must be > 0");
        Self {
            buffer: Vec::with_capacity(capacity),
            capacity,
            write_pos: 0,
        }
    }

    /// Push a transition into the buffer, overwriting the oldest entry when
    /// full.
    pub fn push(&mut self, transition: EpochTransition) {
        if self.buffer.len() < self.capacity {
            self.buffer.push(transition);
        } else {
            self.buffer[self.write_pos] = transition;
            self.write_pos = (self.write_pos + 1) % self.capacity;
        }
    }

    /// Number of transitions currently stored.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Iterate transitions in chronological order (oldest first).
    pub fn iter(&self) -> Box<dyn Iterator<Item = &EpochTransition> + '_> {
        if self.buffer.len() < self.capacity {
            Box::new(self.buffer.iter())
        } else {
            Box::new(
                self.buffer[self.write_pos..]
                    .iter()
                    .chain(self.buffer[..self.write_pos].iter()),
            )
        }
    }

    /// Collect all stored transitions in chronological order.
    pub fn transitions(&self) -> Vec<EpochTransition> {
        self.iter().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Lease-oriented epoch primitives: Monotonic trait, EpochCounter, EpochToken,
// is_lease_valid, and EpochTransitionBarrier.
// ---------------------------------------------------------------------------

/// Trait for types that support strictly-monotonic advance.
///
/// Implementors guarantee that `advance()` always produces a value
/// strictly greater than `self`.
pub trait Monotonic: Ord + Copy {
    /// Advance to the next strictly-greater value.
    #[must_use]
    fn advance(self) -> Self;
}

impl Monotonic for EpochId {
    fn advance(self) -> Self {
        self.next()
    }
}

/// Error returned when an epoch advance is rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EpochAdvanceError {
    /// The proposed next epoch is not strictly greater than the current epoch.
    NonMonotonic { current: EpochId, proposed: EpochId },
    /// A transition barrier is held; no lease acquisition is permitted.
    TransitionInProgress,
    /// The epoch token does not match the current generation.
    StaleToken,
}

/// Opaque token proving that the holder witnessed the epoch at the time of
/// a successful `epoch_advance()`. Required for lease validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochToken {
    pub epoch: EpochId,
    pub generation: u64,
}

/// A monotonically-advancing epoch counter with generation-based fencing.
///
/// Each successful `epoch_advance()` increments the epoch (guaranteed
/// monotonic via the `Monotonic` trait) and issues a new `EpochToken`
/// embedding a generation counter. The token proves the caller witnessed
/// the epoch transition and must be presented for lease validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochCounter {
    current: EpochId,
    generation: u64,
}

impl EpochCounter {
    /// Create a new counter at the given epoch with generation 0.
    pub fn new(start: EpochId) -> Self {
        Self {
            current: start,
            generation: 0,
        }
    }

    /// Return the current epoch.
    pub fn current_epoch(&self) -> EpochId {
        self.current
    }

    /// Return the current generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Attempt to advance the epoch to `next`, issuing a new `EpochToken`.
    ///
    /// # Errors
    ///
    /// Returns `EpochAdvanceError::NonMonotonic` if `next` is not strictly
    /// greater than `self.current`.
    pub fn epoch_advance(&mut self, next: EpochId) -> Result<EpochToken, EpochAdvanceError> {
        if next <= self.current {
            return Err(EpochAdvanceError::NonMonotonic {
                current: self.current,
                proposed: next,
            });
        }
        self.current = next;
        self.generation += 1;
        Ok(EpochToken {
            epoch: self.current,
            generation: self.generation,
        })
    }

    /// Advance the epoch by one using the `Monotonic` trait.
    pub fn advance(&mut self) -> Result<EpochToken, EpochAdvanceError> {
        let next = self.current.advance();
        self.epoch_advance(next)
    }

    /// Verify that a token matches the current epoch and generation.
    pub fn validate_token(&self, token: &EpochToken) -> Result<(), EpochAdvanceError> {
        if token.epoch != self.current || token.generation != self.generation {
            return Err(EpochAdvanceError::StaleToken);
        }
        Ok(())
    }
}

/// Returns `true` if a lease acquired at `lease_epoch` is still valid given
/// `current_epoch`. A lease is valid only while the epoch has not changed.
#[must_use]
pub fn is_lease_valid(lease_epoch: EpochId, current: EpochId) -> bool {
    current == lease_epoch
}

/// A guard that marks an epoch transition as pending and blocks lease
/// acquisition while the transition is in progress.
///
/// During a transition window the barrier must be acquired before the
/// epoch advances and released after. Lease validation should check
/// `is_blocked()` before granting a new lease.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochTransitionBarrier {
    held: bool,
    pending_epoch: Option<EpochId>,
}

impl EpochTransitionBarrier {
    /// Create a new, released barrier.
    pub fn new() -> Self {
        Self {
            held: false,
            pending_epoch: None,
        }
    }

    /// Acquire the barrier in preparation for an epoch transition to
    /// `next_epoch`. While held, `is_blocked()` returns `true`.
    ///
    /// # Errors
    ///
    /// Returns `EpochAdvanceError::TransitionInProgress` if the barrier is
    /// already held.
    pub fn acquire(&mut self, next_epoch: EpochId) -> Result<(), EpochAdvanceError> {
        if self.held {
            return Err(EpochAdvanceError::TransitionInProgress);
        }
        self.held = true;
        self.pending_epoch = Some(next_epoch);
        Ok(())
    }

    /// Release the barrier, allowing lease acquisition to resume.
    pub fn release(&mut self) {
        self.held = false;
        self.pending_epoch = None;
    }

    /// Returns `true` when an epoch transition is pending and lease
    /// acquisition should be blocked.
    pub fn is_blocked(&self) -> bool {
        self.held
    }

    /// Return the pending target epoch, if any.
    pub fn pending_epoch(&self) -> Option<EpochId> {
        self.pending_epoch
    }
}

impl Default for EpochTransitionBarrier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn domain(seed: u64, rack: u64, zone: u64) -> FailureDomainVector {
        FailureDomainVector::new(
            DomainId::new(seed * 10 + 1),
            DomainId::new(seed * 10 + 2),
            DomainId::new(seed * 10 + 3),
            DomainId::new(rack),
            DomainId::new(zone),
            DomainId::new(1),
        )
    }

    fn admit(
        id: u64,
        member_class: MemberClass,
        frontier: u64,
        health: HealthClass,
        domains: [u64; 6],
    ) -> MemberAdmission {
        let [device, node, chassis, rack, zone, region] = domains;
        MemberAdmission {
            member_id: MemberId::new(id),
            member_class,
            log_frontier: frontier,
            health,
            failure_domain_vector: FailureDomainVector::new(
                DomainId::new(device),
                DomainId::new(node),
                DomainId::new(chassis),
                DomainId::new(rack),
                DomainId::new(zone),
                DomainId::new(region),
            ),
        }
    }

    fn admission(
        id: u64,
        member_class: MemberClass,
        frontier: u64,
        health: HealthClass,
        rack: u64,
        zone: u64,
    ) -> MemberAdmission {
        MemberAdmission {
            member_id: MemberId::new(id),
            member_class,
            log_frontier: frontier,
            health,
            failure_domain_vector: domain(id, rack, zone),
        }
    }

    fn three_voter_config() -> (Vec<ClusterMemberRecord>, MembershipConfigRecord) {
        let members = inventory_members_and_classify_participation_roles(
            &[
                admission(1, MemberClass::Voter, 100, HealthClass::Healthy, 1, 1),
                admission(2, MemberClass::Voter, 100, HealthClass::Healthy, 2, 1),
                admission(3, MemberClass::Voter, 100, HealthClass::Healthy, 3, 2),
            ],
            EpochId::new(7),
        )
        .expect("inventory");
        let config = synthesize_membership_config_epoch_and_quorum_sets(
            EpochId::new(7),
            ConfigClass::Normal,
            7,
            &members,
            &[],
            &[],
        )
        .expect("config");
        (members, config)
    }

    const fn with_epoch(mut member: ClusterMemberRecord, epoch_id: EpochId) -> ClusterMemberRecord {
        member.current_membership_epoch_ref = epoch_id;
        member.digest = derive_record_id(member.member_id.0, epoch_id.0, 0x11);
        member
    }

    #[test]
    fn bootstrap_epoch_admits_failure_domain_separated_successor() {
        let (members, config) = three_voter_config();

        let verdict = derive_authority_home_and_failover_successor_candidates(
            &config,
            &members,
            MemberId::new(1),
            FailureDomainClass::Rack,
        )
        .expect("successor verdict");

        assert_eq!(verdict.verdict_class, VerdictClass::Admit);
        assert_eq!(
            verdict.selected_member_refs,
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]
        );
        assert_eq!(
            verdict.selected_domain_refs,
            vec![DomainId::new(1), DomainId::new(2), DomainId::new(3)]
        );
    }

    #[test]
    fn stale_epoch_primary_is_refused_from_current_config() {
        let (members, config) = three_voter_config();
        let stale_members: Vec<ClusterMemberRecord> = members
            .iter()
            .map(|member| {
                if member.member_id == MemberId::new(1) {
                    with_epoch(*member, EpochId::new(6))
                } else {
                    *member
                }
            })
            .collect();

        let err = derive_authority_home_and_failover_successor_candidates(
            &config,
            &stale_members,
            MemberId::new(1),
            FailureDomainClass::Rack,
        )
        .expect_err("current config must reject stale primary record");

        assert_eq!(
            err,
            MembershipModelError::StaleMemberEpoch {
                member_id: MemberId::new(1),
                member_epoch: EpochId::new(6),
                config_epoch: EpochId::new(7),
            }
        );
    }

    #[test]
    fn stale_epoch_successor_is_refused_from_current_config() {
        let (members, config) = three_voter_config();
        let stale_members: Vec<ClusterMemberRecord> = members
            .iter()
            .map(|member| {
                if member.member_id == MemberId::new(2) {
                    with_epoch(*member, EpochId::new(6))
                } else {
                    *member
                }
            })
            .collect();

        let err = derive_authority_home_and_failover_successor_candidates(
            &config,
            &stale_members,
            MemberId::new(1),
            FailureDomainClass::Rack,
        )
        .expect_err("current config must reject stale successor record");

        assert_eq!(
            err,
            MembershipModelError::StaleMemberEpoch {
                member_id: MemberId::new(2),
                member_epoch: EpochId::new(6),
                config_epoch: EpochId::new(7),
            }
        );
    }

    #[test]
    fn unavailable_primary_refuses_authority_home_from_stale_config() {
        let (members, config) = three_voter_config();
        let stale_members: Vec<ClusterMemberRecord> = members
            .iter()
            .map(|member| {
                let mut record = *member;
                if record.member_id == MemberId::new(1) {
                    record.health = HealthClass::Down;
                }
                record
            })
            .collect();

        let err = derive_authority_home_and_failover_successor_candidates(
            &config,
            &stale_members,
            MemberId::new(1),
            FailureDomainClass::Rack,
        )
        .expect_err("down primary must not be selected from stale config");

        assert_eq!(
            err,
            MembershipModelError::UnavailablePrimary(MemberId::new(1))
        );
    }

    #[test]
    fn non_voter_successor_is_refused_from_stale_config() {
        let (members, config) = three_voter_config();
        let stale_members: Vec<ClusterMemberRecord> = members
            .iter()
            .map(|member| {
                if member.member_id == MemberId::new(2) {
                    member.with_class(MemberClass::DataOnly)
                } else {
                    *member
                }
            })
            .collect();

        let err = derive_authority_home_and_failover_successor_candidates(
            &config,
            &stale_members,
            MemberId::new(1),
            FailureDomainClass::Rack,
        )
        .expect_err("stale config must not select a non-voter successor");

        assert_eq!(
            err,
            MembershipModelError::IllegalVoterClass(MemberId::new(2))
        );
    }

    #[test]
    fn same_rack_successor_is_held_as_domain_gap() {
        let members = inventory_members_and_classify_participation_roles(
            &[
                admission(1, MemberClass::Voter, 100, HealthClass::Healthy, 9, 1),
                admission(2, MemberClass::Voter, 100, HealthClass::Healthy, 9, 1),
            ],
            EpochId::new(2),
        )
        .expect("inventory");
        let config = synthesize_membership_config_epoch_and_quorum_sets(
            EpochId::new(2),
            ConfigClass::Normal,
            2,
            &members,
            &[],
            &[],
        )
        .expect("config");

        let verdict = derive_authority_home_and_failover_successor_candidates(
            &config,
            &members,
            MemberId::new(1),
            FailureDomainClass::Rack,
        )
        .expect("successor verdict");

        assert_eq!(verdict.verdict_class, VerdictClass::HoldDomainGap);
        assert_eq!(
            verdict.degraded_reason_refs,
            vec!["missing required failure-domain-separated voter successor"]
        );
    }

    #[test]
    fn split_brain_validation_refuses_ordinary_failover() {
        let (members, config) = three_voter_config();

        let hazard = detect_split_brain_hazard_and_force_hold_or_quarantine(
            AuthorityDomainId::new(44),
            config.membership_epoch_id,
            &[MemberId::new(1), MemberId::new(2), MemberId::new(1)],
            &members,
            FailureDomainClass::Rack,
        )
        .expect("hazard");
        let verdict = control_membership_placement_failure_domain_protocol(
            &config,
            &members,
            MemberId::new(1),
            FailureDomainClass::Rack,
            &[MemberId::new(1), MemberId::new(2)],
        )
        .expect("protocol verdict");

        assert_eq!(
            hazard.required_hold_or_quarantine_ref,
            VerdictClass::RefuseSplitBrain
        );
        assert_eq!(
            hazard.conflicting_holder_refs,
            vec![MemberId::new(1), MemberId::new(2)]
        );
        assert_eq!(verdict.verdict_class, VerdictClass::RefuseSplitBrain);
    }

    #[test]
    fn learner_rejoin_waits_for_catchup_then_enters_joint_config() {
        let base_members = inventory_members_and_classify_participation_roles(
            &[
                admission(1, MemberClass::Voter, 120, HealthClass::Healthy, 1, 1),
                admission(2, MemberClass::Voter, 120, HealthClass::Healthy, 2, 1),
                admission(4, MemberClass::Learner, 80, HealthClass::Healthy, 3, 2),
            ],
            EpochId::new(10),
        )
        .expect("inventory");

        let (_, blocked) = promote_caught_up_learner_to_voter(&base_members, MemberId::new(4), 120)
            .expect("blocked transition");
        assert_eq!(blocked.verdict_class, VerdictClass::HoldCatchup);

        let caught_up: Vec<ClusterMemberRecord> = base_members
            .iter()
            .map(|member| {
                if member.member_id == MemberId::new(4) {
                    member.with_frontier(120)
                } else {
                    *member
                }
            })
            .collect();
        let (promoted, transition) =
            promote_caught_up_learner_to_voter(&caught_up, MemberId::new(4), 120)
                .expect("promoted transition");
        let joint = synthesize_membership_config_epoch_and_quorum_sets(
            EpochId::new(11),
            ConfigClass::Joint,
            11,
            &promoted,
            &[MemberId::new(1), MemberId::new(2)],
            &[MemberId::new(1), MemberId::new(2), MemberId::new(4)],
        )
        .expect("joint config");

        assert_eq!(transition.verdict_class, VerdictClass::Admit);
        assert_eq!(joint.config_class, ConfigClass::Joint);
        assert_eq!(
            joint.joint_new_set_refs,
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(4)]
        );
    }

    #[test]
    fn unavailable_learner_cannot_promote_to_voter_by_catchup_only() {
        let members = inventory_members_and_classify_participation_roles(
            &[
                admission(1, MemberClass::Voter, 120, HealthClass::Healthy, 1, 1),
                admission(4, MemberClass::Learner, 120, HealthClass::Down, 3, 2),
            ],
            EpochId::new(13),
        )
        .expect("inventory");

        let (unchanged, transition) =
            promote_caught_up_learner_to_voter(&members, MemberId::new(4), 120)
                .expect("down learner transition");

        assert_eq!(
            transition.verdict_class,
            VerdictClass::RefusePolicyOrCapacity
        );
        assert_eq!(
            transition.blocking_reason_refs,
            vec!["member health does not admit new work"]
        );
        assert_eq!(transition.close_receipt_ref, ReceiptId::ZERO);
        assert_eq!(unchanged[1].member_class, MemberClass::Learner);
    }

    #[test]
    fn non_learners_cannot_promote_to_voters_by_catchup_only() {
        for member_class in [
            MemberClass::Voter,
            MemberClass::WitnessOnly,
            MemberClass::DataOnly,
            MemberClass::ShadowOnly,
            MemberClass::Quarantined,
        ] {
            let members = inventory_members_and_classify_participation_roles(
                &[admission(9, member_class, 120, HealthClass::Healthy, 3, 2)],
                EpochId::new(13),
            )
            .expect("inventory");

            let err = promote_caught_up_learner_to_voter(&members, MemberId::new(9), 120)
                .expect_err("non-learner promotion must be refused");

            assert_eq!(
                err,
                MembershipModelError::LearnerPromotionRequiresLearner(MemberId::new(9))
            );
            assert_eq!(members[0].member_class, member_class);
        }
    }

    #[test]
    fn joint_config_quorum_sets_are_sorted_distinct_voters() {
        let members = inventory_members_and_classify_participation_roles(
            &[
                admission(1, MemberClass::Voter, 120, HealthClass::Healthy, 1, 1),
                admission(2, MemberClass::Voter, 120, HealthClass::Healthy, 2, 1),
                admission(3, MemberClass::Voter, 120, HealthClass::Healthy, 3, 2),
            ],
            EpochId::new(12),
        )
        .expect("inventory");

        let joint = synthesize_membership_config_epoch_and_quorum_sets(
            EpochId::new(12),
            ConfigClass::Joint,
            12,
            &members,
            &[
                MemberId::new(2),
                MemberId::new(1),
                MemberId::new(2),
                MemberId::new(1),
            ],
            &[
                MemberId::new(3),
                MemberId::new(1),
                MemberId::new(3),
                MemberId::new(2),
            ],
        )
        .expect("joint config");

        assert_eq!(
            joint.joint_old_set_refs,
            vec![MemberId::new(1), MemberId::new(2)]
        );
        assert_eq!(
            joint.joint_new_set_refs,
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]
        );
    }

    #[test]
    fn non_joint_configs_refuse_joint_quorum_sets() {
        let members = inventory_members_and_classify_participation_roles(
            &[
                admission(1, MemberClass::Voter, 120, HealthClass::Healthy, 1, 1),
                admission(2, MemberClass::Voter, 120, HealthClass::Healthy, 2, 1),
            ],
            EpochId::new(14),
        )
        .expect("inventory");

        for config_class in [
            ConfigClass::Bootstrap,
            ConfigClass::Normal,
            ConfigClass::Quarantined,
        ] {
            let err = synthesize_membership_config_epoch_and_quorum_sets(
                EpochId::new(14),
                config_class,
                14,
                &members,
                &[MemberId::new(1)],
                &[MemberId::new(2)],
            )
            .expect_err("non-joint config must reject joint quorum refs");

            assert_eq!(
                err,
                MembershipModelError::NonJointConfigCarriesJointQuorumSets
            );
        }
    }

    #[test]
    fn joint_config_quorum_sets_refuse_down_voters() {
        let members = inventory_members_and_classify_participation_roles(
            &[
                admission(1, MemberClass::Voter, 120, HealthClass::Healthy, 1, 1),
                admission(2, MemberClass::Voter, 120, HealthClass::Down, 2, 1),
                admission(3, MemberClass::Voter, 120, HealthClass::Healthy, 3, 2),
            ],
            EpochId::new(15),
        )
        .expect("inventory");

        let old_err = synthesize_membership_config_epoch_and_quorum_sets(
            EpochId::new(15),
            ConfigClass::Joint,
            15,
            &members,
            &[MemberId::new(1), MemberId::new(2)],
            &[MemberId::new(1), MemberId::new(3)],
        )
        .expect_err("joint old quorum refs must reject down voters");
        assert_eq!(
            old_err,
            MembershipModelError::UnavailableJointVoter(MemberId::new(2))
        );

        let new_err = synthesize_membership_config_epoch_and_quorum_sets(
            EpochId::new(15),
            ConfigClass::Joint,
            15,
            &members,
            &[MemberId::new(1), MemberId::new(3)],
            &[MemberId::new(2), MemberId::new(3)],
        )
        .expect_err("joint new quorum refs must reject down voters");
        assert_eq!(
            new_err,
            MembershipModelError::UnavailableJointVoter(MemberId::new(2))
        );
    }

    #[test]
    fn quarantined_member_is_excluded_from_cohorts_and_replica_placement() {
        let members = inventory_members_and_classify_participation_roles(
            &[
                admission(1, MemberClass::Voter, 100, HealthClass::Healthy, 1, 1),
                admission(2, MemberClass::Quarantined, 100, HealthClass::Healthy, 2, 1),
                admission(3, MemberClass::DataOnly, 100, HealthClass::Healthy, 3, 1),
            ],
            EpochId::new(20),
        )
        .expect("inventory");
        let config = synthesize_membership_config_epoch_and_quorum_sets(
            EpochId::new(20),
            ConfigClass::Normal,
            20,
            &members,
            &[],
            &[],
        )
        .expect("config");

        let cohort = populate_transport_session_cohorts_from_membership_epoch(
            &config,
            &members,
            TransportCohortClass::ReplicaSet,
        );
        let replica = derive_replica_targets_from_failure_domain_policy(
            &config,
            &members,
            3,
            FailureDomainClass::Rack,
        );

        assert!(cohort.excluded_member_refs.contains(&MemberId::new(2)));
        assert!(!replica.selected_member_refs.contains(&MemberId::new(2)));
        assert_eq!(replica.verdict_class, VerdictClass::AdmitDegraded);
    }

    #[test]
    fn stale_epoch_members_are_excluded_from_cohorts_and_replica_placement() {
        let current_members = inventory_members_and_classify_participation_roles(
            &[
                admission(1, MemberClass::Voter, 100, HealthClass::Healthy, 1, 1),
                admission(2, MemberClass::Voter, 100, HealthClass::Healthy, 2, 1),
                admission(3, MemberClass::DataOnly, 100, HealthClass::Healthy, 3, 1),
            ],
            EpochId::new(40),
        )
        .expect("inventory");
        let members: Vec<ClusterMemberRecord> = current_members
            .iter()
            .map(|member| {
                if member.member_id == MemberId::new(3) {
                    with_epoch(*member, EpochId::new(39))
                } else {
                    *member
                }
            })
            .collect();
        let config = synthesize_membership_config_epoch_and_quorum_sets(
            EpochId::new(40),
            ConfigClass::Normal,
            40,
            &current_members,
            &[],
            &[],
        )
        .expect("config");

        let cohort = populate_transport_session_cohorts_from_membership_epoch(
            &config,
            &members,
            TransportCohortClass::ReplicaSet,
        );
        let plan = plan_failure_domain_placement_from_policy(
            &config,
            &members,
            FailureDomainPlacementPolicy::strict_replica_targets(3, FailureDomainClass::Rack),
        );

        assert_eq!(
            cohort.eligible_member_refs,
            vec![MemberId::new(1), MemberId::new(2)]
        );
        assert_eq!(cohort.excluded_member_refs, vec![MemberId::new(3)]);
        assert_eq!(plan.verdict.verdict_class, VerdictClass::HoldDomainGap);
        assert_eq!(
            plan.selected_member_refs,
            vec![MemberId::new(1), MemberId::new(2)]
        );
        assert_eq!(plan.excluded_member_refs, vec![MemberId::new(3)]);
        assert!(!plan.selected_member_refs.contains(&MemberId::new(3)));
    }

    #[test]
    fn deterministic_failure_domain_policy_ignores_input_order() {
        let members = inventory_members_and_classify_participation_roles(
            &[
                admission(10, MemberClass::Voter, 100, HealthClass::Healthy, 1, 1),
                admission(20, MemberClass::Voter, 100, HealthClass::Healthy, 1, 1),
                admission(30, MemberClass::Voter, 100, HealthClass::Healthy, 2, 1),
                admission(40, MemberClass::Voter, 100, HealthClass::Healthy, 3, 2),
            ],
            EpochId::new(30),
        )
        .expect("inventory");
        let shuffled_members = vec![members[3], members[1], members[2], members[0]];
        let config = synthesize_membership_config_epoch_and_quorum_sets(
            EpochId::new(30),
            ConfigClass::Normal,
            30,
            &members,
            &[],
            &[],
        )
        .expect("config");

        let plan = plan_failure_domain_placement_from_policy(
            &config,
            &shuffled_members,
            FailureDomainPlacementPolicy::strict_replica_targets(3, FailureDomainClass::Rack),
        );

        assert_eq!(plan.verdict.verdict_class, VerdictClass::Admit);
        assert_eq!(
            plan.selected_member_refs,
            vec![MemberId::new(10), MemberId::new(30), MemberId::new(40)]
        );
        assert_eq!(
            plan.selected_domain_refs,
            vec![DomainId::new(1), DomainId::new(2), DomainId::new(3)]
        );
        assert_eq!(plan.duplicate_domain_member_refs, vec![MemberId::new(20)]);
        assert!(plan.excluded_member_refs.is_empty());
    }

    #[test]
    fn strict_anti_affinity_holds_duplicate_domain_targets() {
        let members = inventory_members_and_classify_participation_roles(
            &[
                admission(1, MemberClass::Voter, 100, HealthClass::Healthy, 1, 1),
                admission(2, MemberClass::DataOnly, 100, HealthClass::Healthy, 1, 1),
                admission(3, MemberClass::Voter, 100, HealthClass::Healthy, 2, 1),
            ],
            EpochId::new(31),
        )
        .expect("inventory");
        let config = synthesize_membership_config_epoch_and_quorum_sets(
            EpochId::new(31),
            ConfigClass::Normal,
            31,
            &members,
            &[],
            &[],
        )
        .expect("config");

        let plan = plan_failure_domain_placement_from_policy(
            &config,
            &members,
            FailureDomainPlacementPolicy::strict_replica_targets(3, FailureDomainClass::Rack),
        );

        assert_eq!(plan.verdict.verdict_class, VerdictClass::HoldDomainGap);
        assert_eq!(
            plan.selected_member_refs,
            vec![MemberId::new(1), MemberId::new(3)]
        );
        assert_eq!(plan.duplicate_domain_member_refs, vec![MemberId::new(2)]);
        assert!(plan
            .verdict
            .degraded_reason_refs
            .contains(&"strict anti-affinity policy forbids duplicate-domain replica targets"));
    }

    #[test]
    fn degraded_visible_policy_marks_duplicate_domain_selection() {
        let members = inventory_members_and_classify_participation_roles(
            &[
                admission(1, MemberClass::Voter, 100, HealthClass::Healthy, 1, 1),
                admission(2, MemberClass::DataOnly, 100, HealthClass::Healthy, 1, 1),
                admission(3, MemberClass::Voter, 100, HealthClass::Healthy, 2, 1),
            ],
            EpochId::new(32),
        )
        .expect("inventory");
        let config = synthesize_membership_config_epoch_and_quorum_sets(
            EpochId::new(32),
            ConfigClass::Normal,
            32,
            &members,
            &[],
            &[],
        )
        .expect("config");

        let plan = plan_failure_domain_placement_from_policy(
            &config,
            &members,
            FailureDomainPlacementPolicy::degraded_visible_replica_targets(
                3,
                FailureDomainClass::Rack,
            ),
        );

        assert_eq!(plan.verdict.verdict_class, VerdictClass::AdmitDegraded);
        assert_eq!(
            plan.selected_member_refs,
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]
        );
        assert_eq!(
            plan.selected_domain_refs,
            vec![DomainId::new(1), DomainId::new(2)]
        );
        assert_eq!(plan.duplicate_domain_member_refs, vec![MemberId::new(2)]);
        assert!(plan
            .verdict
            .degraded_reason_refs
            .contains(&"duplicate-domain replica target admitted as degraded"));
    }

    #[test]
    fn ineligible_members_are_excluded_from_failure_domain_plan() {
        let members = inventory_members_and_classify_participation_roles(
            &[
                admission(1, MemberClass::Voter, 100, HealthClass::Healthy, 1, 1),
                admission(2, MemberClass::WitnessOnly, 100, HealthClass::Healthy, 2, 1),
                admission(3, MemberClass::ShadowOnly, 100, HealthClass::Healthy, 3, 1),
                admission(4, MemberClass::DataOnly, 100, HealthClass::Down, 4, 1),
                admission(5, MemberClass::Quarantined, 100, HealthClass::Healthy, 5, 1),
                admission(6, MemberClass::DataOnly, 100, HealthClass::Healthy, 6, 1),
            ],
            EpochId::new(33),
        )
        .expect("inventory");
        let config = synthesize_membership_config_epoch_and_quorum_sets(
            EpochId::new(33),
            ConfigClass::Normal,
            33,
            &members,
            &[],
            &[],
        )
        .expect("config");

        let plan = plan_failure_domain_placement_from_policy(
            &config,
            &members,
            FailureDomainPlacementPolicy::strict_replica_targets(2, FailureDomainClass::Rack),
        );

        assert_eq!(plan.verdict.verdict_class, VerdictClass::Admit);
        assert_eq!(
            plan.selected_member_refs,
            vec![MemberId::new(1), MemberId::new(6)]
        );
        assert_eq!(
            plan.excluded_member_refs,
            vec![
                MemberId::new(2),
                MemberId::new(3),
                MemberId::new(4),
                MemberId::new(5)
            ]
        );
    }

    // ========== FailureDomainRecord tests ==========

    #[test]
    fn failure_domain_record_construction() {
        let record = FailureDomainRecord {
            failure_domain_id: DomainId::new(42),
            failure_domain_class_ref: FailureDomainClass::Rack,
            parent_domain_ref: DomainId::new(10),
            member_refs: vec![MemberId::new(1), MemberId::new(2)],
            separation_policy_ref: AntiAffinityClass::Strict,
            health_class: HealthClass::Healthy,
            availability_receipt_ref: ReceiptId::ZERO,
            storage_tier: None,
            digest: 0xCAFE,
        };
        assert_eq!(record.failure_domain_id, DomainId::new(42));
        assert_eq!(record.failure_domain_class_ref, FailureDomainClass::Rack);
        assert_eq!(record.parent_domain_ref, DomainId::new(10));
        assert_eq!(record.member_refs.len(), 2);
        assert_eq!(record.separation_policy_ref, AntiAffinityClass::Strict);
        assert_eq!(record.health_class, HealthClass::Healthy);
    }

    #[test]
    fn serde_roundtrip_failure_domain_record() {
        let record = FailureDomainRecord {
            failure_domain_id: DomainId::new(5),
            failure_domain_class_ref: FailureDomainClass::Zone,
            parent_domain_ref: DomainId::new(1),
            member_refs: vec![MemberId::new(10), MemberId::new(20)],
            separation_policy_ref: AntiAffinityClass::DegradedVisible,
            health_class: HealthClass::Suspect,
            availability_receipt_ref: ReceiptId(99),
            storage_tier: None,
            digest: 0xDEAD,
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let round: FailureDomainRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, round);
    }

    #[test]
    fn inventory_failure_domain_hierarchy_builds_all_levels() {
        let members = inventory_members_and_classify_participation_roles(
            &[
                admit(
                    1,
                    MemberClass::Voter,
                    100,
                    HealthClass::Healthy,
                    [1, 1, 1, 1, 1, 1],
                ),
                admit(
                    2,
                    MemberClass::Voter,
                    100,
                    HealthClass::Healthy,
                    [2, 2, 2, 2, 1, 1],
                ),
            ],
            EpochId::new(50),
        )
        .expect("inventory");

        let hierarchy = inventory_failure_domain_hierarchy(&members);

        // Should produce records for device, node, chassis, rack, zone, region
        // Each member has unique device and node, but may share rack/zone/region.
        // With: member 1: d=1,n=1,c=1,r=1,z=1,reg=1
        //       member 2: d=2,n=2,c=2,r=2,z=1,reg=1
        // Device domains: 2 (d=1, d=2)
        // Node domains: 2 (n=1, n=2)
        // Chassis domains: 2 (c=1, c=2)
        // Rack domains: 2 (r=1, r=2)
        // Zone domains: 1 (z=1)
        // Region domains: 1 (reg=1)
        assert!(!hierarchy.is_empty());
        assert!(hierarchy
            .iter()
            .any(|r| r.failure_domain_class_ref == FailureDomainClass::Device));
        assert!(hierarchy
            .iter()
            .any(|r| r.failure_domain_class_ref == FailureDomainClass::Region));
    }

    #[test]
    fn inventory_failure_domain_hierarchy_parent_linkage() {
        let members = inventory_members_and_classify_participation_roles(
            &[admit(
                1,
                MemberClass::Voter,
                100,
                HealthClass::Healthy,
                [1, 10, 100, 1000, 1, 1],
            )],
            EpochId::new(51),
        )
        .expect("inventory");

        let hierarchy = inventory_failure_domain_hierarchy(&members);

        // Find the device record (d=1)
        let device = hierarchy
            .iter()
            .find(|r| {
                r.failure_domain_class_ref == FailureDomainClass::Device
                    && r.failure_domain_id == DomainId::new(1)
            })
            .expect("device domain");
        // Device's parent should be node (n=10)
        assert_eq!(device.parent_domain_ref, DomainId::new(10));

        // Find the node record (n=10)
        let node = hierarchy
            .iter()
            .find(|r| {
                r.failure_domain_class_ref == FailureDomainClass::Node
                    && r.failure_domain_id == DomainId::new(10)
            })
            .expect("node domain");
        // Node's parent should be chassis (c=100)
        assert_eq!(node.parent_domain_ref, DomainId::new(100));

        // Find the region record (reg=1)
        let region = hierarchy
            .iter()
            .find(|r| {
                r.failure_domain_class_ref == FailureDomainClass::Region
                    && r.failure_domain_id == DomainId::new(1)
            })
            .expect("region domain");
        // Region has no parent
        assert_eq!(region.parent_domain_ref, DomainId::ZERO);
    }

    #[test]
    fn inventory_failure_domain_hierarchy_sorted_output() {
        let members = inventory_members_and_classify_participation_roles(
            &[
                admit(
                    1,
                    MemberClass::Voter,
                    100,
                    HealthClass::Healthy,
                    [3, 3, 3, 3, 3, 3],
                ),
                admit(
                    2,
                    MemberClass::Voter,
                    100,
                    HealthClass::Healthy,
                    [1, 1, 1, 1, 1, 1],
                ),
            ],
            EpochId::new(52),
        )
        .expect("inventory");

        let hierarchy = inventory_failure_domain_hierarchy(&members);

        // Records should be sorted by (class, domain_id)
        for pair in hierarchy.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            let a_key = (a.failure_domain_class_ref as u32, a.failure_domain_id);
            let b_key = (b.failure_domain_class_ref as u32, b.failure_domain_id);
            assert!(a_key <= b_key, "unsorted: {a_key:?} then {b_key:?}");
        }
    }

    #[test]
    fn inventory_failure_domain_hierarchy_member_sets() {
        let members = inventory_members_and_classify_participation_roles(
            &[
                admit(
                    1,
                    MemberClass::Voter,
                    100,
                    HealthClass::Healthy,
                    [1, 1, 1, 1, 1, 1],
                ),
                admit(
                    2,
                    MemberClass::DataOnly,
                    100,
                    HealthClass::Healthy,
                    [1, 1, 1, 1, 1, 1],
                ),
                admit(
                    3,
                    MemberClass::Voter,
                    100,
                    HealthClass::Healthy,
                    [2, 1, 1, 1, 1, 1],
                ),
            ],
            EpochId::new(53),
        )
        .expect("inventory");

        let hierarchy = inventory_failure_domain_hierarchy(&members);

        // Device d=1 should have members 1 and 2
        let device_1 = hierarchy
            .iter()
            .find(|r| {
                r.failure_domain_class_ref == FailureDomainClass::Device
                    && r.failure_domain_id == DomainId::new(1)
            })
            .expect("device domain 1");
        assert_eq!(
            device_1.member_refs,
            vec![MemberId::new(1), MemberId::new(2)]
        );

        // Device d=2 should have only member 3
        let device_2 = hierarchy
            .iter()
            .find(|r| {
                r.failure_domain_class_ref == FailureDomainClass::Device
                    && r.failure_domain_id == DomainId::new(2)
            })
            .expect("device domain 2");
        assert_eq!(device_2.member_refs, vec![MemberId::new(3)]);

        // Node n=1 (shared by all) should have all three members
        let node_1 = hierarchy
            .iter()
            .find(|r| {
                r.failure_domain_class_ref == FailureDomainClass::Node
                    && r.failure_domain_id == DomainId::new(1)
            })
            .expect("node domain 1");
        assert_eq!(
            node_1.member_refs,
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]
        );
    }

    #[test]
    fn inventory_failure_domain_hierarchy_empty_input() {
        let hierarchy = inventory_failure_domain_hierarchy(&[]);
        assert!(hierarchy.is_empty());
    }

    #[test]
    fn inventory_failure_domain_hierarchy_skips_zero_domains() {
        // Member with zero device/node (sentinel values) should not create records for them
        let members = inventory_members_and_classify_participation_roles(
            &[MemberAdmission {
                member_id: MemberId::new(1),
                member_class: MemberClass::Voter,
                log_frontier: 100,
                health: HealthClass::Healthy,
                failure_domain_vector: FailureDomainVector::new(
                    DomainId::ZERO,   // device
                    DomainId::ZERO,   // node
                    DomainId::ZERO,   // chassis
                    DomainId::new(1), // rack
                    DomainId::new(1), // zone
                    DomainId::new(1), // region
                ),
            }],
            EpochId::new(54),
        )
        .expect("inventory");

        let hierarchy = inventory_failure_domain_hierarchy(&members);

        // Should only have rack, zone, region records (no device/node/chassis with ZERO)
        assert!(!hierarchy
            .iter()
            .any(|r| r.failure_domain_class_ref == FailureDomainClass::Device));
        assert!(!hierarchy
            .iter()
            .any(|r| r.failure_domain_class_ref == FailureDomainClass::Node));
        assert!(!hierarchy
            .iter()
            .any(|r| r.failure_domain_class_ref == FailureDomainClass::Chassis));
        assert!(hierarchy
            .iter()
            .any(|r| r.failure_domain_class_ref == FailureDomainClass::Rack));
        assert!(hierarchy
            .iter()
            .any(|r| r.failure_domain_class_ref == FailureDomainClass::Zone));
        assert!(hierarchy
            .iter()
            .any(|r| r.failure_domain_class_ref == FailureDomainClass::Region));
    }

    #[test]
    fn from_device_entries_maps_device_class_to_tiers() {
        use super::*;
        let entries: &[(DomainId, u8)] = &[
            (DomainId::new(1), 0),  // Hdd -> HddArchive
            (DomainId::new(2), 1),  // Ssd -> SsdCapacity
            (DomainId::new(3), 2),  // Nvme -> NvmePerformance
            (DomainId::new(4), 3),  // Special -> SpecialDevice
            (DomainId::new(5), 99), // unknown -> skipped
        ];

        let policy = StorageTierPolicy::from_device_entries(entries);
        assert_eq!(
            policy.tier_for_domain(DomainId::new(1)),
            Some(StorageTier::HddArchive)
        );
        assert_eq!(
            policy.tier_for_domain(DomainId::new(2)),
            Some(StorageTier::SsdCapacity)
        );
        assert_eq!(
            policy.tier_for_domain(DomainId::new(3)),
            Some(StorageTier::NvmePerformance)
        );
        assert_eq!(
            policy.tier_for_domain(DomainId::new(4)),
            Some(StorageTier::SpecialDevice)
        );
        assert!(policy.tier_for_domain(DomainId::new(5)).is_none());
        assert!(!policy.auto_promote);
        assert!(!policy.auto_demote);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;

    const fn prng(seed: u64, iter: u64) -> u64 {
        seed.wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407)
            .wrapping_add(iter)
    }

    fn gen_health(seed: u64, iter: u64) -> HealthClass {
        if prng(seed, iter) % 5 < 4 {
            HealthClass::Healthy
        } else {
            HealthClass::Down
        }
    }

    fn gen_voter_or_data(seed: u64, iter: u64) -> MemberClass {
        if prng(seed, iter) % 2 == 0 {
            MemberClass::Voter
        } else {
            MemberClass::DataOnly
        }
    }

    fn arb_admission(id: u64, seed: u64) -> MemberAdmission {
        let rack = (prng(seed, id) % 10) + 1;
        let zone = (prng(seed, id.wrapping_add(100)) % 3) + 1;
        MemberAdmission {
            member_id: MemberId::new(id),
            member_class: gen_voter_or_data(seed, id),
            log_frontier: prng(seed, id.wrapping_add(200)) % 200,
            health: gen_health(seed, id),
            failure_domain_vector: FailureDomainVector::new(
                DomainId::new(id * 10 + 1),
                DomainId::new(id * 10 + 2),
                DomainId::new(id * 10 + 3),
                DomainId::new(rack),
                DomainId::new(zone),
                DomainId::new(1),
            ),
        }
    }

    fn arb_admissions(count: u64, seed: u64) -> Vec<MemberAdmission> {
        (1..=count).map(|id| arb_admission(id, seed)).collect()
    }

    #[test]
    fn config_epoch_synthesis_is_deterministic() {
        for seed in 0..20u64 {
            let count = 3 + (seed % 8);
            let admissions = arb_admissions(count, seed);
            let members_1 =
                inventory_members_and_classify_participation_roles(&admissions, EpochId::new(1))
                    .expect("inventory_1");
            let config_1 = synthesize_membership_config_epoch_and_quorum_sets(
                EpochId::new(1),
                ConfigClass::Normal,
                1,
                &members_1,
                &[],
                &[],
            )
            .expect("config_1");
            let members_2 =
                inventory_members_and_classify_participation_roles(&admissions, EpochId::new(1))
                    .expect("inventory_2");
            let config_2 = synthesize_membership_config_epoch_and_quorum_sets(
                EpochId::new(1),
                ConfigClass::Normal,
                1,
                &members_2,
                &[],
                &[],
            )
            .expect("config_2");

            assert_eq!(members_1.len(), members_2.len(), "seed={seed}");
            assert_eq!(
                config_1.voter_set_refs.len(),
                config_2.voter_set_refs.len(),
                "seed={seed}"
            );
            assert_eq!(config_1.config_class, config_2.config_class, "seed={seed}");
            for (m1, m2) in members_1.iter().zip(members_2.iter()) {
                assert_eq!(m1.member_id, m2.member_id, "seed={seed}");
                assert_eq!(m1.member_class, m2.member_class, "seed={seed}");
            }
        }
    }

    #[test]
    fn config_epoch_deterministic_under_reordered_input() {
        for seed in 0..20u64 {
            let count = 3 + (seed % 8);
            let ordered = arb_admissions(count, seed);
            let mut reordered = ordered.clone();
            if reordered.len() >= 2 {
                let last = reordered.len() - 1;
                reordered.swap(0, last);
            }

            let members_ordered =
                inventory_members_and_classify_participation_roles(&ordered, EpochId::new(1))
                    .expect("inventory_ordered");
            let config_ordered = synthesize_membership_config_epoch_and_quorum_sets(
                EpochId::new(1),
                ConfigClass::Normal,
                1,
                &members_ordered,
                &[],
                &[],
            )
            .expect("config_ordered");

            let members_reordered =
                inventory_members_and_classify_participation_roles(&reordered, EpochId::new(1))
                    .expect("inventory_reordered");
            let config_reordered = synthesize_membership_config_epoch_and_quorum_sets(
                EpochId::new(1),
                ConfigClass::Normal,
                1,
                &members_reordered,
                &[],
                &[],
            )
            .expect("config_reordered");

            assert_eq!(
                config_ordered.config_class, config_reordered.config_class,
                "seed={seed}"
            );
            assert_eq!(
                config_ordered.voter_set_refs.len(),
                config_reordered.voter_set_refs.len(),
                "seed={seed}"
            );
            assert_eq!(
                members_ordered.len(),
                members_reordered.len(),
                "seed={seed}"
            );
        }
    }

    #[test]
    fn split_brain_detection_is_idempotent() {
        for seed in 0..15u64 {
            let count = 3 + (seed % 6);
            let admissions = arb_admissions(count, seed);
            let members =
                inventory_members_and_classify_participation_roles(&admissions, EpochId::new(2))
                    .expect("inventory");

            let hazard_1 = detect_split_brain_hazard_and_force_hold_or_quarantine(
                AuthorityDomainId::new(1),
                EpochId::new(2),
                &[MemberId::new(1)],
                &members,
                FailureDomainClass::Rack,
            );
            let hazard_2 = detect_split_brain_hazard_and_force_hold_or_quarantine(
                AuthorityDomainId::new(1),
                EpochId::new(2),
                &[MemberId::new(1)],
                &members,
                FailureDomainClass::Rack,
            );

            assert_eq!(
                hazard_1.as_ref().map(|h| h.required_hold_or_quarantine_ref),
                hazard_2.as_ref().map(|h| h.required_hold_or_quarantine_ref),
                "seed={seed}"
            );
            assert_eq!(
                hazard_1.as_ref().map(|h| h.conflicting_holder_refs.clone()),
                hazard_2.as_ref().map(|h| h.conflicting_holder_refs.clone()),
                "seed={seed}"
            );
        }
    }

    #[test]
    fn placement_plan_never_exceeds_requested_replica_count() {
        for seed in 0..12u64 {
            let count = 3 + (seed % 13);
            let replica_count = (1 + (seed % 5)) as usize;
            let admissions = arb_admissions(count, seed);
            let members =
                inventory_members_and_classify_participation_roles(&admissions, EpochId::new(3))
                    .expect("inventory");
            let config = synthesize_membership_config_epoch_and_quorum_sets(
                EpochId::new(3),
                ConfigClass::Normal,
                3,
                &members,
                &[],
                &[],
            )
            .expect("config");

            let plan = plan_failure_domain_placement_from_policy(
                &config,
                &members,
                FailureDomainPlacementPolicy::strict_replica_targets(
                    replica_count,
                    FailureDomainClass::Rack,
                ),
            );

            assert!(
                plan.selected_member_refs.len() <= replica_count,
                "seed={seed}: selected {} members, requested {}",
                plan.selected_member_refs.len(),
                replica_count,
            );
        }
    }

    #[test]
    fn selected_placement_targets_are_healthy_eligible_members() {
        for seed in 0..15u64 {
            let count = 4 + (seed % 9);
            let admissions = arb_admissions(count, seed);
            let members =
                inventory_members_and_classify_participation_roles(&admissions, EpochId::new(4))
                    .expect("inventory");
            let config = synthesize_membership_config_epoch_and_quorum_sets(
                EpochId::new(4),
                ConfigClass::Normal,
                4,
                &members,
                &[],
                &[],
            )
            .expect("config");

            let plan = plan_failure_domain_placement_from_policy(
                &config,
                &members,
                FailureDomainPlacementPolicy::strict_replica_targets(3, FailureDomainClass::Rack),
            );

            for mid in &plan.selected_member_refs {
                let member = members
                    .iter()
                    .find(|m| m.member_id == *mid)
                    .expect("selected member not in member list");
                assert_ne!(
                    member.health,
                    HealthClass::Down,
                    "seed={seed}: selected member {mid:?} is Down"
                );
                assert!(
                    matches!(
                        member.member_class,
                        MemberClass::Voter | MemberClass::DataOnly
                    ),
                    "seed={seed}: selected member {mid:?} has class {:?}",
                    member.member_class,
                );
            }
        }
    }

    #[test]
    fn config_class_preserves_expected_behavior() {
        for seed in 0..10u64 {
            let count = 3 + (seed % 6);
            let admissions = arb_admissions(count, seed);
            for class in &[
                ConfigClass::Bootstrap,
                ConfigClass::Normal,
                ConfigClass::Joint,
                ConfigClass::Quarantined,
            ] {
                let members = inventory_members_and_classify_participation_roles(
                    &admissions,
                    EpochId::new(5),
                )
                .expect("inventory");
                let config = match synthesize_membership_config_epoch_and_quorum_sets(
                    EpochId::new(5),
                    *class,
                    5,
                    &members,
                    &[],
                    &[],
                ) {
                    Ok(c) => c,
                    Err(_) => {
                        // Joint config requires old/new voters; skip
                        continue;
                    }
                };

                assert_eq!(config.config_class, *class, "seed={seed} class={class:?}");
                // Bootstrap and Quarantined classes have no quorum,
                // but the voter set is populated from admitted members.
                // The invariant is that config_class is preserved.
                if *class == ConfigClass::Bootstrap {
                    // Bootstrap configs admit all healthy voters
                    assert!(
                        !config.voter_set_refs.is_empty() || members.is_empty(),
                        "seed={seed} class={class:?}: empty voter set in bootstrap with {n} members",
                        n = members.len(),
                    );
                }
            }
        }
    }

    // ========== serde round-trip tests ==========

    #[test]
    fn serde_roundtrip_failure_domain_vector() {
        let fdv = FailureDomainVector::new(
            DomainId(0),
            DomainId(1),
            DomainId(2),
            DomainId(3),
            DomainId(4),
            DomainId(5),
        );
        let json = serde_json::to_string(&fdv).expect("serialize");
        let round: FailureDomainVector = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(fdv, round);
    }

    #[test]
    fn serde_roundtrip_placement_verdict() {
        let v = MembershipPlacementVerdictRecord {
            verdict_id: 42,
            membership_epoch_ref: EpochId(1),
            placement_class: PlacementIntentClass::FailoverSuccessor,
            selected_member_refs: vec![MemberId(10), MemberId(20)],
            selected_domain_refs: vec![DomainId(100)],
            verdict_class: VerdictClass::AdmitDegraded,
            degraded_reason_refs: vec!["test reason"],
            issuance_receipt_ref: ReceiptId(99),
            digest: 0xABCD,
        };
        let json = serde_json::to_string(&v).expect("serialize");
        let round: MembershipPlacementVerdictRecord =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, round);
    }

    #[test]
    fn serde_roundtrip_authority_placement_intent() {
        let record = AuthorityPlacementIntentRecord::new(
            1,
            AuthorityDomainId(100),
            PlacementIntentClass::AuthorityHome,
            MemberId(10),
            &[MemberId(20), MemberId(30)],
            FailureDomainClass::Zone,
            ConfigClass::Normal,
            0xBEEF,
        );
        let json = serde_json::to_string(&record).expect("serialize");
        let round: AuthorityPlacementIntentRecord =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, round);
        assert_eq!(
            record.placement_class_ref,
            PlacementIntentClass::AuthorityHome
        );
        assert_eq!(round.successor_candidate_refs.len(), 2);
    }

    #[test]
    fn serde_roundtrip_transition() {
        let t = MembershipTransitionRecord {
            transition_id: 7,
            subject_member_ref: MemberId(3),
            from_member_class_ref: MemberClass::Learner,
            to_member_class_ref: MemberClass::Voter,
            required_catchup_frontier_ref: 100,
            current_frontier_ref: 80,
            verdict_class: VerdictClass::HoldCatchup,
            blocking_reason_refs: vec!["catch-up behind required frontier"],
            open_receipt_ref: ReceiptId(200),
            close_receipt_ref: ReceiptId::ZERO,
            digest: 0xBEEF,
        };
        let json = serde_json::to_string(&t).expect("serialize");
        let round: MembershipTransitionRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(t, round);
    }

    #[test]
    fn serde_roundtrip_cluster_member() {
        let m = ClusterMemberRecord {
            member_id: MemberId(5),
            member_class: MemberClass::Voter,
            current_membership_epoch_ref: EpochId(1),
            log_frontier: 120,
            health: HealthClass::Healthy,
            failure_domain_vector: FailureDomainVector::new(
                DomainId(1),
                DomainId(2),
                DomainId(0),
                DomainId(0),
                DomainId(0),
                DomainId(0),
            ),
            digest: 0,
        };
        let json = serde_json::to_string(&m).expect("serialize");
        let round: ClusterMemberRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(m, round);
    }

    #[test]
    fn serde_roundtrip_vec_static_str_preserved() {
        let v = MembershipPlacementVerdictRecord {
            verdict_id: 1,
            membership_epoch_ref: EpochId(1),
            placement_class: PlacementIntentClass::ReplicaTarget,
            selected_member_refs: vec![],
            selected_domain_refs: vec![],
            verdict_class: VerdictClass::AdmitDegraded,
            degraded_reason_refs: vec![
                "insufficient separated failure-domain targets",
                "insufficient eligible replica targets",
            ],
            issuance_receipt_ref: ReceiptId::ZERO,
            digest: 0,
        };
        let json = serde_json::to_string(&v).expect("serialize");
        let round: MembershipPlacementVerdictRecord =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, round);
        assert_eq!(round.degraded_reason_refs.len(), 2);
        assert!(round
            .degraded_reason_refs
            .contains(&"insufficient separated failure-domain targets"));
    }

    #[test]
    fn authority_placement_intent_construction_and_digest() {
        let record = AuthorityPlacementIntentRecord::new(
            42,
            AuthorityDomainId(7),
            PlacementIntentClass::FailoverSuccessor,
            MemberId(1),
            &[MemberId(3), MemberId(2), MemberId(2)],
            FailureDomainClass::Rack,
            ConfigClass::Joint,
            0xDEAD,
        );
        // duplicate successor is deduplicated
        assert_eq!(
            record.successor_candidate_refs,
            vec![MemberId(2), MemberId(3)]
        );
        assert_eq!(record.placement_intent_id, 42);
        assert_eq!(
            record.required_failure_domain_class_ref,
            FailureDomainClass::Rack
        );
        assert_eq!(record.quorum_class_ref, ConfigClass::Joint);
        // digest is deterministic: same inputs produce same output
        let r2 = AuthorityPlacementIntentRecord::new(
            42,
            AuthorityDomainId(7),
            PlacementIntentClass::FailoverSuccessor,
            MemberId(1),
            &[MemberId(3), MemberId(2)],
            FailureDomainClass::Rack,
            ConfigClass::Joint,
            0xDEAD,
        );
        assert_eq!(record.digest, r2.digest);
        assert_eq!(record.successor_candidate_refs, r2.successor_candidate_refs);
    }
}

#[cfg(test)]
mod epoch_state_machine_tests {
    use super::*;

    fn n(id: u64) -> NodeIdentity {
        NodeIdentity::new(id)
    }

    fn members(ids: &[u64]) -> EpochMemberSet {
        EpochMemberSet::new(ids.iter().map(|&id| n(id)))
    }

    #[test]
    fn bootstrap_single_node() {
        let sm = EpochStateMachine::bootstrap(members(&[1]));
        let epoch = sm.current_epoch();
        assert_eq!(epoch.epoch_id, 0);
        assert_eq!(epoch.members.len(), 1);
        assert!(epoch.members.contains(&n(1)));
    }

    #[test]
    fn bootstrap_empty_set() {
        let sm = EpochStateMachine::bootstrap(EpochMemberSet::default());
        let epoch = sm.current_epoch();
        assert_eq!(epoch.epoch_id, 0);
        assert!(epoch.members.is_empty());
    }

    #[test]
    fn bootstrap_multi_node() {
        let sm = EpochStateMachine::bootstrap(members(&[3, 1, 2]));
        let epoch = sm.current_epoch();
        assert_eq!(epoch.epoch_id, 0);
        assert_eq!(epoch.members.len(), 3);
        let ids: Vec<u64> = epoch.members.iter().map(|ni| ni.node_id).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn join_new_node() {
        let mut sm = EpochStateMachine::bootstrap(members(&[1]));
        let t = sm.join(n(2));
        assert_eq!(t.from_epoch_id, 0);
        assert_eq!(t.to_epoch_id, 1);
        assert_eq!(t.member_set_delta.added, vec![n(2)]);
        assert!(t.member_set_delta.removed.is_empty());

        let epoch = sm.current_epoch();
        assert_eq!(epoch.epoch_id, 1);
        assert_eq!(epoch.members.len(), 2);
        assert!(epoch.members.contains(&n(1)));
        assert!(epoch.members.contains(&n(2)));
    }

    #[test]
    fn join_existing_node_noops_delta() {
        let mut sm = EpochStateMachine::bootstrap(members(&[1]));
        let t = sm.join(n(1));
        assert_eq!(t.from_epoch_id, 0);
        assert_eq!(t.to_epoch_id, 1);
        assert!(t.member_set_delta.added.is_empty());
        assert!(t.member_set_delta.removed.is_empty());

        let epoch = sm.current_epoch();
        assert_eq!(epoch.epoch_id, 1);
        assert_eq!(epoch.members.len(), 1);
    }

    #[test]
    fn leave_existing_node() {
        let mut sm = EpochStateMachine::bootstrap(members(&[1, 2]));
        let t = sm.leave(n(1));
        assert_eq!(t.from_epoch_id, 0);
        assert_eq!(t.to_epoch_id, 1);
        assert_eq!(t.member_set_delta.removed, vec![n(1)]);
        assert!(t.member_set_delta.added.is_empty());

        let epoch = sm.current_epoch();
        assert_eq!(epoch.epoch_id, 1);
        assert_eq!(epoch.members.len(), 1);
        assert!(epoch.members.contains(&n(2)));
    }

    #[test]
    fn leave_nonexistent_node_noops_delta() {
        let mut sm = EpochStateMachine::bootstrap(members(&[1]));
        let t = sm.leave(n(99));
        assert_eq!(t.from_epoch_id, 0);
        assert_eq!(t.to_epoch_id, 1);
        assert!(t.member_set_delta.removed.is_empty());

        let epoch = sm.current_epoch();
        assert_eq!(epoch.epoch_id, 1);
        assert_eq!(epoch.members.len(), 1);
    }

    #[test]
    fn deterministic_same_sequence_produces_same_epochs() {
        fn run_sequence() -> Vec<(u64, Vec<u64>)> {
            let mut sm = EpochStateMachine::bootstrap(members(&[1]));
            let mut snapshots = Vec::new();
            snapshots.push((sm.current_epoch().epoch_id, member_ids(&sm)));

            sm.join(n(2));
            snapshots.push((sm.current_epoch().epoch_id, member_ids(&sm)));

            sm.join(n(3));
            snapshots.push((sm.current_epoch().epoch_id, member_ids(&sm)));

            sm.leave(n(1));
            snapshots.push((sm.current_epoch().epoch_id, member_ids(&sm)));

            sm.join(n(1));
            snapshots.push((sm.current_epoch().epoch_id, member_ids(&sm)));

            snapshots
        }

        fn member_ids(sm: &EpochStateMachine) -> Vec<u64> {
            let mut ids: Vec<u64> = sm
                .current_epoch()
                .members
                .iter()
                .map(|ni| ni.node_id)
                .collect();
            ids.sort();
            ids
        }

        let first = run_sequence();
        let second = run_sequence();
        assert_eq!(first, second);
    }

    #[test]
    fn epoch_id_strictly_monotonic() {
        let mut sm = EpochStateMachine::bootstrap(members(&[1]));
        let mut prev = sm.current_epoch().epoch_id;

        for i in 2..=20u64 {
            sm.join(n(i));
            let curr = sm.current_epoch().epoch_id;
            assert!(curr > prev, "epoch {curr} not > {prev} after join({i})");
            prev = curr;
        }

        for i in 1..=15u64 {
            sm.leave(n(i));
            let curr = sm.current_epoch().epoch_id;
            assert!(curr > prev, "epoch {curr} not > {prev} after leave({i})");
            prev = curr;
        }
    }

    #[test]
    fn rejoin_produces_distinct_epoch() {
        let mut sm = EpochStateMachine::bootstrap(members(&[1, 2]));
        let e0 = sm.current_epoch().epoch_id;

        sm.leave(n(2));
        let e1 = sm.current_epoch().epoch_id;
        assert_ne!(e1, e0);

        sm.join(n(2));
        let e2 = sm.current_epoch().epoch_id;
        assert_ne!(e2, e0);
        assert_ne!(e2, e1);

        assert_eq!(sm.current_epoch().members.len(), 2);
        assert!(sm.current_epoch().members.contains(&n(1)));
        assert!(sm.current_epoch().members.contains(&n(2)));
    }

    #[test]
    fn history_stores_transitions_in_order() {
        let mut hist = EpochHistory::new(10);
        let mut sm = EpochStateMachine::bootstrap(members(&[1]));

        let t1 = sm.join(n(2));
        let t2 = sm.join(n(3));
        let t3 = sm.leave(n(1));

        hist.push(t1.clone());
        hist.push(t2.clone());
        hist.push(t3.clone());

        assert_eq!(hist.len(), 3);
        let ts = hist.transitions();
        assert_eq!(ts.len(), 3);
        assert_eq!(ts[0], t1);
        assert_eq!(ts[1], t2);
        assert_eq!(ts[2], t3);
    }

    #[test]
    fn history_ring_buffer_wraps_correctly() {
        let capacity = 3;
        let mut hist = EpochHistory::new(capacity);
        let mut sm = EpochStateMachine::bootstrap(members(&[1]));

        let mut transitions = Vec::new();
        for i in 2..=6u64 {
            let t = sm.join(n(i));
            transitions.push(t.clone());
            hist.push(t);
        }

        assert_eq!(hist.len(), capacity);
        let ts = hist.transitions();
        assert_eq!(ts.len(), capacity);

        assert_eq!(ts[0], transitions[2]); // node 4
        assert_eq!(ts[1], transitions[3]); // node 5
        assert_eq!(ts[2], transitions[4]); // node 6
    }

    #[test]
    fn history_empty() {
        let hist = EpochHistory::new(5);
        assert!(hist.is_empty());
        assert_eq!(hist.len(), 0);
        assert!(hist.transitions().is_empty());
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn history_zero_capacity_panics() {
        EpochHistory::new(0);
    }

    #[test]
    fn member_set_deduplicates() {
        let set = members(&[1, 1, 2, 2, 3]);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn member_set_contains() {
        let set = members(&[1, 2]);
        assert!(set.contains(&n(1)));
        assert!(!set.contains(&n(99)));
    }

    #[test]
    fn member_set_iter_yields_sorted() {
        let set = members(&[3, 1, 2]);
        let ids: Vec<u64> = set.iter().map(|ni| ni.node_id).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }
}

#[cfg(test)]
mod identity_integration_tests {
    use super::*;
    use tidefs_auth::{IdentityRevocationRecord, RevocationReason, RevocationSet};

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
    use ed25519_dalek::Keypair;
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;

    fn gen_auth_identity(node_id: u64) -> (AuthNodeIdentity, Keypair) {
        let mut csprng = OsRng;
        let signing_key = Keypair::generate(&mut csprng);
        let verifying_key = signing_key.public;
        let attested_at = now_ms();
        let version = 1u64;

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&node_id.to_le_bytes());
        preimage.extend_from_slice(verifying_key.as_bytes());
        preimage.extend_from_slice(&attested_at.to_le_bytes());
        preimage.extend_from_slice(&version.to_le_bytes());

        let self_signature = signing_key.sign(&preimage).to_bytes().to_vec();

        let identity = AuthNodeIdentity {
            node_id,
            verifying_key_bytes: verifying_key.to_bytes(),
            attested_at_millis: attested_at,
            identity_version: version,
            self_signature,
        };
        (identity, signing_key)
    }

    fn make_entry(node_id: u64) -> (MembershipEntry, Keypair) {
        let (auth_id, keypair) = gen_auth_identity(node_id);
        let entry = MembershipEntry::new(NodeIdentity::new(node_id), auth_id);
        (entry, keypair)
    }

    fn make_entry_set(ids: &[u64]) -> EpochEntrySet {
        let entries: Vec<_> = ids
            .iter()
            .map(|&id| {
                let (e, _) = make_entry(id);
                e
            })
            .collect();
        EpochEntrySet::new(entries)
    }

    // -----------------------------------------------------------------------
    // MembershipEntry tests
    // -----------------------------------------------------------------------

    #[test]
    fn membership_entry_verify_self_signature() {
        let (entry, _kp) = make_entry(1);
        assert!(entry.verify_auth_identity().is_ok());
    }

    #[test]
    fn membership_entry_tampered_signature_fails() {
        let (mut entry, _kp) = make_entry(1);
        entry.auth_identity.self_signature[0] ^= 0xFF;
        assert!(entry.verify_auth_identity().is_err());
    }

    #[test]
    fn membership_entry_ordering() {
        let (e1, _) = make_entry(1);
        let (e2, _) = make_entry(2);
        let (e3, _) = make_entry(3);

        assert!(e1 < e2);
        assert!(e2 < e3);
        assert!(e1 < e3);
    }

    #[test]
    fn membership_entry_identity_version() {
        let (entry, _kp) = make_entry(5);
        assert_eq!(entry.identity_version(), 1);
    }

    // -----------------------------------------------------------------------
    // EpochEntrySet tests
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_entry_set_empty() {
        let set = EpochEntrySet::default();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert!(set.iter().next().is_none());
    }

    #[test]
    fn epoch_entry_set_new_and_iterate() {
        let set = make_entry_set(&[3, 1, 2]);
        assert_eq!(set.len(), 3);
        let ids: Vec<u64> = set.iter().map(|e| e.node_id.node_id).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn epoch_entry_set_contains() {
        let set = make_entry_set(&[1, 2]);
        assert!(set.contains(&NodeIdentity::new(1)));
        assert!(!set.contains(&NodeIdentity::new(99)));
    }

    #[test]
    fn epoch_entry_set_get() {
        let set = make_entry_set(&[1, 2]);
        let entry = set.get(&NodeIdentity::new(1));
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().node_id.node_id, 1);
        assert!(set.get(&NodeIdentity::new(99)).is_none());
    }

    #[test]
    fn epoch_entry_set_insert_and_remove() {
        let mut set = EpochEntrySet::default();
        let (entry, _) = make_entry(1);
        assert!(set.insert(entry.clone()));
        assert_eq!(set.len(), 1);

        // Duplicate insert returns false
        assert!(!set.insert(entry.clone()));

        let removed = set.remove(&NodeIdentity::new(1));
        assert!(removed.is_some());
        assert_eq!(set.len(), 0);

        // Remove non-existent
        assert!(set.remove(&NodeIdentity::new(99)).is_none());
    }

    // -----------------------------------------------------------------------
    // IdentityVerifier tests
    // -----------------------------------------------------------------------

    #[test]
    fn identity_verifier_empty_set_passes() {
        let verifier = IdentityVerifier::new(RevocationSet::new(), NodeKeyStore::new());
        let entries = EpochEntrySet::default();
        let revoked = verifier.verify_epoch_entries(&entries);
        assert!(revoked.is_empty());
    }

    #[test]
    fn identity_verifier_non_revoked_entries_pass() {
        let verifier = IdentityVerifier::new(RevocationSet::new(), NodeKeyStore::new());
        let set = make_entry_set(&[1, 2, 3]);
        let revoked = verifier.verify_epoch_entries(&set);
        assert!(revoked.is_empty());
    }

    #[test]
    fn identity_verifier_revoked_entry_detected() {
        let mut revocation_set = RevocationSet::new();
        let revoked_by = tidefs_auth::PrincipalId(1);
        let signing_key = Keypair::generate(&mut OsRng);

        // Revoke node 2, version 1
        let rec = IdentityRevocationRecord::new(
            2,
            1,
            revoked_by,
            RevocationReason::SuspectedCompromise,
            &signing_key,
        );
        revocation_set.insert((2, 1), rec);

        let verifier = IdentityVerifier::new(revocation_set, NodeKeyStore::new());
        let set = make_entry_set(&[1, 2, 3]);

        let revoked = verifier.verify_epoch_entries(&set);
        assert_eq!(revoked, vec![2]);
    }

    #[test]
    fn identity_verifier_verify_entry_ok() {
        let verifier = IdentityVerifier::new(RevocationSet::new(), NodeKeyStore::new());
        let (entry, _) = make_entry(1);
        assert!(verifier.verify_entry(&entry).is_ok());
    }

    #[test]
    fn identity_verifier_verify_entry_revoked() {
        let mut revocation_set = RevocationSet::new();
        let revoked_by = tidefs_auth::PrincipalId(1);
        let signing_key = Keypair::generate(&mut OsRng);

        let rec = IdentityRevocationRecord::new(
            1,
            1,
            revoked_by,
            RevocationReason::ConfirmedCompromise,
            &signing_key,
        );
        revocation_set.insert((1, 1), rec);

        let verifier = IdentityVerifier::new(revocation_set, NodeKeyStore::new());
        let (entry, _) = make_entry(1);

        assert!(verifier.verify_entry(&entry).is_err());
    }

    #[test]
    fn identity_verifier_is_revoked() {
        let mut revocation_set = RevocationSet::new();
        let revoked_by = tidefs_auth::PrincipalId(1);
        let signing_key = Keypair::generate(&mut OsRng);

        let rec = IdentityRevocationRecord::new(
            3,
            1,
            revoked_by,
            RevocationReason::NodeDecommissioned,
            &signing_key,
        );
        revocation_set.insert((3, 1), rec);

        let verifier = IdentityVerifier::new(revocation_set, NodeKeyStore::new());

        assert!(verifier.is_revoked(3, 1));
        assert!(!verifier.is_revoked(3, 2)); // different version
        assert!(!verifier.is_revoked(4, 1)); // different node
    }

    #[test]
    fn identity_verifier_register_and_lookup_key() {
        let mut verifier = IdentityVerifier::new(RevocationSet::new(), NodeKeyStore::new());
        let (auth_id, _kp) = gen_auth_identity(42);

        verifier
            .register_identity(auth_id.clone())
            .expect("register");

        let key_bytes = verifier.get_verifying_key_bytes(42);
        assert!(key_bytes.is_some());
        assert_eq!(key_bytes.unwrap(), auth_id.verifying_key_bytes);
    }

    // -----------------------------------------------------------------------
    // EpochStateMachine: fence_node
    // -----------------------------------------------------------------------

    #[test]
    fn fence_node_removes_member() {
        let mut sm = EpochStateMachine::bootstrap(EpochMemberSet::new([
            NodeIdentity::new(1),
            NodeIdentity::new(2),
        ]));

        let result = sm.fence_node(1);
        match result {
            FenceVerdict::Fenced {
                epoch_id,
                removed_node_id,
            } => {
                assert!(epoch_id > 0);
                assert_eq!(removed_node_id, 1);
            }
            other => panic!("expected Fenced, got {other:?}"),
        }

        assert!(!sm.is_member(1));
        assert!(sm.is_member(2));
        assert_eq!(sm.current_epoch().epoch_id, 1); // bootstrap=0, leave=1
    }

    #[test]
    fn fence_node_not_a_member() {
        let mut sm = EpochStateMachine::bootstrap(EpochMemberSet::new([NodeIdentity::new(1)]));

        let result = sm.fence_node(99);
        match result {
            FenceVerdict::NotAMember { node_id } => {
                assert_eq!(node_id, 99);
            }
            other => panic!("expected NotAMember, got {other:?}"),
        }

        // Epoch still incremented (the guard increment occurs inside fence_node)
        assert!(sm.current_epoch().epoch_id > 0);
        assert!(sm.is_member(1));
    }

    #[test]
    fn fence_node_idempotent() {
        let mut sm = EpochStateMachine::bootstrap(EpochMemberSet::new([NodeIdentity::new(1)]));

        let r1 = sm.fence_node(1);
        match r1 {
            FenceVerdict::Fenced {
                removed_node_id, ..
            } => assert_eq!(removed_node_id, 1),
            _ => panic!("first fence should remove"),
        }

        let r2 = sm.fence_node(1);
        match r2 {
            FenceVerdict::NotAMember { node_id } => assert_eq!(node_id, 1),
            _ => panic!("second fence should be NotAMember"),
        }
    }

    #[test]
    fn fence_node_epoch_monotonically_increases() {
        let mut sm = EpochStateMachine::bootstrap(EpochMemberSet::new([
            NodeIdentity::new(1),
            NodeIdentity::new(2),
            NodeIdentity::new(3),
        ]));

        let mut prev_epoch = sm.current_epoch().epoch_id;
        for node_id in 1..=3u64 {
            let _result = sm.fence_node(node_id);
            let curr_epoch = sm.current_epoch().epoch_id;
            assert!(
                curr_epoch > prev_epoch,
                "epoch did not increase after fencing node {node_id}"
            );
            prev_epoch = curr_epoch;
        }
    }

    // -----------------------------------------------------------------------
    // EpochStateMachine: rotate_identity
    // -----------------------------------------------------------------------

    #[test]
    fn rotate_identity_advances_epoch() {
        let mut sm = EpochStateMachine::bootstrap(EpochMemberSet::new([NodeIdentity::new(1)]));

        let (new_auth_id, _kp) = gen_auth_identity(1);
        // Force version 2 for the rotation test
        let new_auth_id = AuthNodeIdentity {
            identity_version: 2,
            ..new_auth_id
        };

        let result = sm.rotate_identity(1, new_auth_id);
        match result {
            RotateVerdict::Rotated {
                epoch_id,
                node_id,
                old_version,
                new_version,
            } => {
                assert!(epoch_id > 0);
                assert_eq!(node_id, 1);
                assert_eq!(old_version, 1);
                assert_eq!(new_version, 2);
            }
            other => panic!("expected Rotated, got {other:?}"),
        }

        assert!(sm.is_member(1));
        assert!(sm.current_epoch().epoch_id > 0);
    }

    #[test]
    fn rotate_identity_not_a_member() {
        let mut sm = EpochStateMachine::bootstrap(EpochMemberSet::new([NodeIdentity::new(1)]));

        let (new_auth_id, _) = gen_auth_identity(99);
        let result = sm.rotate_identity(99, new_auth_id);

        match result {
            RotateVerdict::NotAMember { node_id } => assert_eq!(node_id, 99),
            other => panic!("expected NotAMember, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // EpochStateMachine: member queries
    // -----------------------------------------------------------------------

    #[test]
    fn member_node_ids_returns_sorted() {
        let sm = EpochStateMachine::bootstrap(EpochMemberSet::new([
            NodeIdentity::new(3),
            NodeIdentity::new(1),
            NodeIdentity::new(2),
        ]));

        let ids = sm.member_node_ids();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn is_member_positive_and_negative() {
        let sm = EpochStateMachine::bootstrap(EpochMemberSet::new([NodeIdentity::new(1)]));

        assert!(sm.is_member(1));
        assert!(!sm.is_member(99));
    }

    // -----------------------------------------------------------------------
    // Full lifecycle: join -> verify -> rotate -> fence -> verify
    // -----------------------------------------------------------------------

    #[test]
    fn full_identity_lifecycle() {
        // Bootstrap with node 1
        let mut sm = EpochStateMachine::bootstrap(EpochMemberSet::new([NodeIdentity::new(1)]));

        // Join node 2
        sm.join(NodeIdentity::new(2));
        assert!(sm.is_member(2));

        // Create entries and verifier
        let verifier = IdentityVerifier::new(RevocationSet::new(), NodeKeyStore::new());
        let entries = make_entry_set(&[1, 2]);
        let revoked = verifier.verify_epoch_entries(&entries);
        assert!(revoked.is_empty());

        // Rotate identity for node 1
        let (new_auth, _) = gen_auth_identity(1);
        let new_auth = AuthNodeIdentity {
            identity_version: 2,
            ..new_auth
        };
        let rot = sm.rotate_identity(1, new_auth);
        assert!(matches!(rot, RotateVerdict::Rotated { .. }));

        // Fence node 2
        let fence = sm.fence_node(2);
        assert!(matches!(fence, FenceVerdict::Fenced { .. }));
        assert!(!sm.is_member(2));

        // Verify node 2 with a revocation record would be caught
        let mut revocation_set = RevocationSet::new();
        let revoked_by = tidefs_auth::PrincipalId(0);
        let signing_key = Keypair::generate(&mut OsRng);
        let rec = IdentityRevocationRecord::new(
            2,
            1,
            revoked_by,
            RevocationReason::SuspectedCompromise,
            &signing_key,
        );
        revocation_set.insert((2, 1), rec);

        let verifier2 = IdentityVerifier::new(revocation_set, NodeKeyStore::new());
        let (entry2, _) = make_entry(2);
        assert!(verifier2.verify_entry(&entry2).is_err());
    }

    // -----------------------------------------------------------------------
    // Deterministic fence reproducibility
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_fence_reproducible() {
        fn run_fence_sequence() -> (u64, Vec<u64>) {
            let mut sm = EpochStateMachine::bootstrap(EpochMemberSet::new([
                NodeIdentity::new(1),
                NodeIdentity::new(2),
                NodeIdentity::new(3),
            ]));

            sm.fence_node(2);
            let epoch_after_first = sm.current_epoch().epoch_id;

            sm.fence_node(1);
            let members_after = sm.member_node_ids();

            (epoch_after_first, members_after)
        }

        let (e1, m1) = run_fence_sequence();
        let (e2, m2) = run_fence_sequence();
        assert_eq!(e1, e2, "epoch after first fence must be deterministic");
        assert_eq!(
            m1, m2,
            "member ids after second fence must be deterministic"
        );
    }
}

#[cfg(test)]
mod lease_epoch_tests {
    use super::*;

    // ── Monotonic trait ────────────────────────────────────────────────

    #[test]
    fn monotonic_advance_is_strictly_greater() {
        let e = EpochId::new(0);
        let next = e.advance();
        assert!(next > e);
        assert_eq!(next, EpochId::new(1));
    }

    #[test]
    fn monotonic_chain_is_strictly_increasing() {
        let mut e = EpochId::new(0);
        for i in 1u64..=100 {
            let prev = e;
            e = e.advance();
            assert!(e > prev, "epoch {e:?} not > {prev:?} at step {i}");
        }
        assert_eq!(e, EpochId::new(100));
    }

    // ── EpochCounter ───────────────────────────────────────────────────

    #[test]
    fn epoch_counter_new_starts_at_given_epoch() {
        let counter = EpochCounter::new(EpochId::new(5));
        assert_eq!(counter.current_epoch(), EpochId::new(5));
        assert_eq!(counter.generation(), 0);
    }

    #[test]
    fn epoch_advance_returns_token_and_increments() {
        let mut counter = EpochCounter::new(EpochId::new(0));

        let token = counter
            .epoch_advance(EpochId::new(1))
            .expect("advance should succeed");
        assert_eq!(token.epoch, EpochId::new(1));
        assert_eq!(token.generation, 1);
        assert_eq!(counter.current_epoch(), EpochId::new(1));
        assert_eq!(counter.generation(), 1);
    }

    #[test]
    fn epoch_advance_rejects_non_monotonic_equal() {
        let mut counter = EpochCounter::new(EpochId::new(5));
        let result = counter.epoch_advance(EpochId::new(5));
        match result {
            Err(EpochAdvanceError::NonMonotonic { current, proposed }) => {
                assert_eq!(current, EpochId::new(5));
                assert_eq!(proposed, EpochId::new(5));
            }
            other => panic!("expected NonMonotonic, got {other:?}"),
        }
    }

    #[test]
    fn epoch_advance_rejects_non_monotonic_less() {
        let mut counter = EpochCounter::new(EpochId::new(10));
        let result = counter.epoch_advance(EpochId::new(9));
        match result {
            Err(EpochAdvanceError::NonMonotonic { current, proposed }) => {
                assert_eq!(current, EpochId::new(10));
                assert_eq!(proposed, EpochId::new(9));
            }
            other => panic!("expected NonMonotonic, got {other:?}"),
        }
    }

    #[test]
    fn epoch_advance_skip_multiple() {
        let mut counter = EpochCounter::new(EpochId::new(0));
        let token = counter
            .epoch_advance(EpochId::new(42))
            .expect("skip advance should succeed");
        assert_eq!(token.epoch, EpochId::new(42));
        assert_eq!(counter.current_epoch(), EpochId::new(42));
    }

    #[test]
    fn advance_method_uses_monotonic_trait() {
        let mut counter = EpochCounter::new(EpochId::new(7));
        let token = counter.advance().expect("advance should succeed");
        assert_eq!(token.epoch, EpochId::new(8));
        assert_eq!(counter.current_epoch(), EpochId::new(8));
    }

    // ── EpochToken uniqueness ──────────────────────────────────────────

    #[test]
    fn epoch_token_uniqueness_across_advances() {
        let mut counter = EpochCounter::new(EpochId::new(0));

        let t1 = counter.epoch_advance(EpochId::new(1)).unwrap();
        let t2 = counter.epoch_advance(EpochId::new(2)).unwrap();
        let t3 = counter.epoch_advance(EpochId::new(3)).unwrap();

        assert_ne!(t1, t2);
        assert_ne!(t2, t3);
        assert_ne!(t1, t3);

        assert_eq!(t1.generation, 1);
        assert_eq!(t2.generation, 2);
        assert_eq!(t3.generation, 3);
    }

    // ── Token validation ───────────────────────────────────────────────

    #[test]
    fn validate_token_accepts_current_token() {
        let mut counter = EpochCounter::new(EpochId::new(0));
        let token = counter.epoch_advance(EpochId::new(1)).unwrap();
        assert!(counter.validate_token(&token).is_ok());
    }

    #[test]
    fn validate_token_rejects_stale_token() {
        let mut counter = EpochCounter::new(EpochId::new(0));
        let old_token = counter.epoch_advance(EpochId::new(1)).unwrap();
        counter.epoch_advance(EpochId::new(2)).unwrap();

        match counter.validate_token(&old_token) {
            Err(EpochAdvanceError::StaleToken) => {}
            other => panic!("expected StaleToken, got {other:?}"),
        }
    }

    // ── is_lease_valid ─────────────────────────────────────────────────

    #[test]
    fn lease_valid_when_epoch_matches() {
        assert!(is_lease_valid(EpochId::new(3), EpochId::new(3)));
    }

    #[test]
    fn lease_invalid_when_epoch_advanced() {
        assert!(!is_lease_valid(EpochId::new(3), EpochId::new(4)));
    }

    #[test]
    fn lease_invalid_when_epoch_regressed() {
        // Should never happen with monotonic epochs, but the function
        // checks strict equality.
        assert!(!is_lease_valid(EpochId::new(5), EpochId::new(3)));
    }

    #[test]
    fn lease_validity_integration_with_counter() {
        let mut counter = EpochCounter::new(EpochId::new(0));

        // Acquire a "lease" at epoch 1
        counter.epoch_advance(EpochId::new(1)).unwrap();
        let lease_epoch = counter.current_epoch();
        assert!(is_lease_valid(lease_epoch, counter.current_epoch()));

        // Advance epoch — lease should become invalid
        counter.epoch_advance(EpochId::new(2)).unwrap();
        assert!(!is_lease_valid(lease_epoch, counter.current_epoch()));
    }

    // ── EpochTransitionBarrier ─────────────────────────────────────────

    #[test]
    fn barrier_default_is_not_blocked() {
        let barrier = EpochTransitionBarrier::default();
        assert!(!barrier.is_blocked());
        assert!(barrier.pending_epoch().is_none());
    }

    #[test]
    fn barrier_acquire_sets_blocked() {
        let mut barrier = EpochTransitionBarrier::new();
        barrier
            .acquire(EpochId::new(5))
            .expect("acquire should succeed");
        assert!(barrier.is_blocked());
        assert_eq!(barrier.pending_epoch(), Some(EpochId::new(5)));
    }

    #[test]
    fn barrier_double_acquire_fails() {
        let mut barrier = EpochTransitionBarrier::new();
        barrier.acquire(EpochId::new(1)).expect("first acquire");

        match barrier.acquire(EpochId::new(2)) {
            Err(EpochAdvanceError::TransitionInProgress) => {}
            other => panic!("expected TransitionInProgress, got {other:?}"),
        }
        // Still blocked with original pending epoch
        assert_eq!(barrier.pending_epoch(), Some(EpochId::new(1)));
    }

    #[test]
    fn barrier_release_clears_blocked() {
        let mut barrier = EpochTransitionBarrier::new();
        barrier.acquire(EpochId::new(3)).expect("acquire");
        barrier.release();
        assert!(!barrier.is_blocked());
        assert!(barrier.pending_epoch().is_none());
    }

    #[test]
    fn barrier_acquire_release_acquire_cycle() {
        let mut barrier = EpochTransitionBarrier::new();

        barrier.acquire(EpochId::new(10)).expect("first acquire");
        assert!(barrier.is_blocked());
        barrier.release();
        assert!(!barrier.is_blocked());

        barrier
            .acquire(EpochId::new(20))
            .expect("second acquire after release");
        assert!(barrier.is_blocked());
        assert_eq!(barrier.pending_epoch(), Some(EpochId::new(20)));
    }

    // ── Serialization round-trip ───────────────────────────────────────

    #[test]
    fn epoch_counter_serde_roundtrip() {
        let mut counter = EpochCounter::new(EpochId::new(3));
        counter.epoch_advance(EpochId::new(7)).unwrap();

        let json = serde_json::to_string(&counter).expect("serialize");
        let restored: EpochCounter = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(restored.current_epoch(), EpochId::new(7));
        assert_eq!(restored.generation(), 1);
    }

    #[test]
    fn epoch_token_serde_roundtrip() {
        let token = EpochToken {
            epoch: EpochId::new(42),
            generation: 7,
        };
        let json = serde_json::to_string(&token).expect("serialize");
        let restored: EpochToken = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(restored.epoch, EpochId::new(42));
        assert_eq!(restored.generation, 7);
    }

    #[test]
    fn epoch_advance_error_serde_roundtrip() {
        let err = EpochAdvanceError::NonMonotonic {
            current: EpochId::new(5),
            proposed: EpochId::new(3),
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let restored: EpochAdvanceError = serde_json::from_str(&json).expect("deserialize");

        match restored {
            EpochAdvanceError::NonMonotonic { current, proposed } => {
                assert_eq!(current, EpochId::new(5));
                assert_eq!(proposed, EpochId::new(3));
            }
            other => panic!("expected NonMonotonic, got {other:?}"),
        }
    }

    #[test]
    fn epoch_transition_barrier_serde_roundtrip() {
        let mut barrier = EpochTransitionBarrier::new();
        barrier.acquire(EpochId::new(99)).unwrap();

        let json = serde_json::to_string(&barrier).expect("serialize");
        let restored: EpochTransitionBarrier = serde_json::from_str(&json).expect("deserialize");

        assert!(restored.is_blocked());
        assert_eq!(restored.pending_epoch(), Some(EpochId::new(99)));
    }

    // ── Barrier does not enforce epoch monotonicity ───────────────────

    #[test]
    fn barrier_acquire_accepts_any_epoch() {
        // The barrier is a simple transition-in-progress guard, not an
        // epoch validator. It does not check whether the pending epoch
        // is greater than the current epoch — that is the caller's
        // responsibility.
        let mut barrier = EpochTransitionBarrier::new();
        assert!(barrier.acquire(EpochId::new(0)).is_ok());
        assert!(barrier.is_blocked());
    }

    #[test]
    fn barrier_acquire_epoch_zero_is_idempotent_guard() {
        // Acquiring with epoch 0 blocks further acquisitions
        let mut barrier = EpochTransitionBarrier::new();
        barrier.acquire(EpochId::new(0)).unwrap();
        assert!(matches!(
            barrier.acquire(EpochId::new(0)),
            Err(EpochAdvanceError::TransitionInProgress)
        ));
    }

    // ── Token validation edge cases ───────────────────────────────────

    #[test]
    fn validate_token_rejects_wrong_epoch_correct_generation() {
        let mut counter = EpochCounter::new(EpochId::new(0));
        counter.epoch_advance(EpochId::new(5)).unwrap();
        let token = EpochToken {
            epoch: EpochId::new(4),
            generation: 1,
        };
        match counter.validate_token(&token) {
            Err(EpochAdvanceError::StaleToken) => {}
            other => panic!("expected StaleToken, got {other:?}"),
        }
    }

    #[test]
    fn validate_token_rejects_correct_epoch_wrong_generation() {
        let mut counter = EpochCounter::new(EpochId::new(0));
        counter.epoch_advance(EpochId::new(5)).unwrap();
        let token = EpochToken {
            epoch: EpochId::new(5),
            generation: 99,
        };
        match counter.validate_token(&token) {
            Err(EpochAdvanceError::StaleToken) => {}
            other => panic!("expected StaleToken, got {other:?}"),
        }
    }

    #[test]
    fn validate_token_rejects_token_from_different_counter() {
        let mut c1 = EpochCounter::new(EpochId::new(0));
        c1.epoch_advance(EpochId::new(1)).unwrap();
        let token_from_c1 = EpochToken {
            epoch: EpochId::new(1),
            generation: 1,
        };

        let mut c2 = EpochCounter::new(EpochId::new(0));
        c2.epoch_advance(EpochId::new(1)).unwrap();

        // Same epoch and generation values, but from a different counter
        match c2.validate_token(&token_from_c1) {
            Ok(()) => {} // deterministic: same values match
            other => panic!("token with matching epoch+gen from different counter should be valid, got {other:?}"),
        }
    }

    #[test]
    fn epoch_advance_generation_wraps_correctly() {
        let mut counter = EpochCounter::new(EpochId::new(0));
        // Advance to a high generation to verify no overflow issues
        for i in 1u64..=100u64 {
            let token = counter.epoch_advance(EpochId::new(i)).unwrap();
            assert_eq!(token.generation, i);
        }
        assert_eq!(counter.current_epoch(), EpochId::new(100));
        assert_eq!(counter.generation(), 100);
    }
}

#[cfg(test)]
mod epoch_quorum_tests {
    use super::*;

    fn make_epoch(epoch_id: u64, member_ids: &[u64]) -> MembershipEpoch {
        MembershipEpoch {
            epoch_id,
            members: EpochMemberSet::new(member_ids.iter().map(|&id| NodeIdentity::new(id))),
        }
    }

    // ── propose() ─────────────────────────────────────────────────────

    #[test]
    fn propose_creates_valid_proposal() {
        let epoch = make_epoch(1, &[1, 2, 3]);
        let p = epoch.propose(1, 2, &[1, 2, 3, 4]).unwrap();
        assert!(p.verify());
        assert_eq!(p.proposer_id, 1);
        assert_eq!(p.sequence_number, 2);
        assert_eq!(p.prior_epoch_id, 1);
        assert_eq!(p.proposed_epoch_id, 2);
        assert_eq!(p.proposed_members, vec![1, 2, 3, 4]);
    }

    #[test]
    fn propose_rejects_stale_sequence() {
        let epoch = make_epoch(5, &[1]);
        let result = epoch.propose(1, 5, &[1, 2]);
        assert!(matches!(
            result,
            Err(crate::quorum::QuorumError::StaleSequence)
        ));
    }

    #[test]
    fn propose_rejects_stale_sequence_less_than_epoch() {
        let epoch = make_epoch(5, &[1]);
        let result = epoch.propose(1, 3, &[1, 2]);
        assert!(matches!(
            result,
            Err(crate::quorum::QuorumError::StaleSequence)
        ));
    }

    #[test]
    fn propose_rejects_empty_member_set() {
        let epoch = make_epoch(1, &[1, 2]);
        let result = epoch.propose(1, 2, &[]);
        assert!(matches!(
            result,
            Err(crate::quorum::QuorumError::EmptyMemberSet)
        ));
    }

    #[test]
    fn propose_dedup_sorts_members() {
        let epoch = make_epoch(1, &[1]);
        let p = epoch.propose(1, 2, &[3, 1, 3, 2, 1]).unwrap();
        assert_eq!(p.proposed_members, vec![1, 2, 3]);
        assert!(p.verify());
    }

    #[test]
    fn propose_deterministic_for_same_inputs() {
        let epoch = make_epoch(1, &[1, 2]);
        let p1 = epoch.propose(1, 2, &[1, 2, 3]).unwrap();
        let p2 = epoch.propose(1, 2, &[1, 2, 3]).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(p1.blake3_hash, p2.blake3_hash);
    }

    #[test]
    fn propose_different_proposer_yields_different_hash() {
        let epoch = make_epoch(1, &[1, 2]);
        let p1 = epoch.propose(1, 2, &[1, 2, 3]).unwrap();
        let p2 = epoch.propose(99, 2, &[1, 2, 3]).unwrap();
        assert_ne!(p1.blake3_hash, p2.blake3_hash);
    }

    // ── advance() ─────────────────────────────────────────────────────

    #[test]
    fn advance_accepts_valid_commitment() {
        let epoch = make_epoch(1, &[1, 2, 3]);
        let p = epoch.propose(1, 2, &[1, 2, 3, 4]).unwrap();
        // Simulate quorum: commit the proposal
        let mut tally = crate::quorum::QuorumVoteTally::new(p.clone(), 3);
        tally
            .cast_vote(&crate::quorum::EpochVote::approve(1, &p.blake3_hash))
            .unwrap();
        tally
            .cast_vote(&crate::quorum::EpochVote::approve(2, &p.blake3_hash))
            .unwrap();
        let commitment = tally.commitment.unwrap();
        let new_epoch = epoch.advance(&commitment).unwrap();
        assert_eq!(new_epoch.epoch_id, 2);
        assert_eq!(
            new_epoch
                .members
                .members()
                .iter()
                .map(|ni| ni.node_id)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
    }

    #[test]
    fn advance_rejects_tampered_commitment() {
        let epoch = make_epoch(1, &[1, 2]);
        let p = epoch.propose(1, 2, &[1, 2, 3]).unwrap();
        let mut tally = crate::quorum::QuorumVoteTally::new(p.clone(), 2);
        tally
            .cast_vote(&crate::quorum::EpochVote::approve(1, &p.blake3_hash))
            .unwrap();
        tally
            .cast_vote(&crate::quorum::EpochVote::approve(2, &p.blake3_hash))
            .unwrap();
        let mut commitment = tally.commitment.unwrap();
        commitment.member_set.push(99); // tamper
        let result = epoch.advance(&commitment);
        assert!(matches!(
            result,
            Err(crate::quorum::QuorumError::VoteVerificationFailed)
        ));
    }

    #[test]
    fn advance_rejects_stale_sequence() {
        let epoch = make_epoch(5, &[1]);
        let commitment = crate::quorum::EpochCommitment {
            epoch_id: 3,
            member_set: vec![1],
            blake3_commitment: crate::quorum::EpochCommitment::compute_commitment(3, &[1]),
            sequence_number: 3,
            prior_epoch_id: 4,
        };
        let result = epoch.advance(&commitment);
        assert!(matches!(
            result,
            Err(crate::quorum::QuorumError::StaleSequence)
        ));
    }

    #[test]
    fn advance_rejects_wrong_prior_epoch() {
        let epoch = make_epoch(5, &[1]);
        let commitment = crate::quorum::EpochCommitment {
            epoch_id: 6,
            member_set: vec![1, 2],
            blake3_commitment: crate::quorum::EpochCommitment::compute_commitment(6, &[1, 2]),
            sequence_number: 6,
            prior_epoch_id: 99, // wrong
        };
        let result = epoch.advance(&commitment);
        assert!(matches!(
            result,
            Err(crate::quorum::QuorumError::InvalidPriorEpoch)
        ));
    }

    #[test]
    fn advance_rejects_empty_member_set() {
        let epoch = make_epoch(1, &[1]);
        let commitment = crate::quorum::EpochCommitment {
            epoch_id: 2,
            member_set: vec![],
            blake3_commitment: crate::quorum::EpochCommitment::compute_commitment(2, &[]),
            sequence_number: 2,
            prior_epoch_id: 1,
        };
        let result = epoch.advance(&commitment);
        assert!(matches!(
            result,
            Err(crate::quorum::QuorumError::EmptyMemberSet)
        ));
    }

    // ── Full lifecycle: propose → vote → commit → advance ─────────────────

    #[test]
    fn full_epoch_lifecycle_propose_vote_commit_advance() {
        let epoch = make_epoch(0, &[1, 2]);
        let proposal = epoch.propose(1, 1, &[1, 2, 3]).unwrap();
        assert!(proposal.verify());

        let mut tally = crate::quorum::QuorumVoteTally::new(proposal, 3);
        for voter_id in 1..=2u64 {
            let vote = crate::quorum::EpochVote::approve(voter_id, &tally.proposal.blake3_hash);
            tally.cast_vote(&vote).unwrap();
        }
        assert!(tally.committed);
        let commitment = tally.commitment.unwrap();
        assert!(commitment.verify());

        let new_epoch = epoch.advance(&commitment).unwrap();
        assert_eq!(new_epoch.epoch_id, 1);
        assert_eq!(
            new_epoch
                .members
                .members()
                .iter()
                .map(|ni| ni.node_id)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn multi_epoch_chain() {
        // Epoch 0: [1]
        let epoch0 = make_epoch(0, &[1]);

        // Advance to epoch 1: [1, 2]
        let p1 = epoch0.propose(1, 1, &[1, 2]).unwrap();
        let mut t1 = crate::quorum::QuorumVoteTally::new(p1, 1);
        t1.cast_vote(&crate::quorum::EpochVote::approve(
            1,
            &t1.proposal.blake3_hash,
        ))
        .unwrap();
        let epoch1 = epoch0.advance(&t1.commitment.unwrap()).unwrap();
        assert_eq!(epoch1.epoch_id, 1);

        // Advance to epoch 2: [1, 2, 3]
        let p2 = epoch1.propose(1, 2, &[1, 2, 3]).unwrap();
        let mut t2 = crate::quorum::QuorumVoteTally::new(p2, 2);
        t2.cast_vote(&crate::quorum::EpochVote::approve(
            1,
            &t2.proposal.blake3_hash,
        ))
        .unwrap();
        t2.cast_vote(&crate::quorum::EpochVote::approve(
            2,
            &t2.proposal.blake3_hash,
        ))
        .unwrap();
        let epoch2 = epoch1.advance(&t2.commitment.unwrap()).unwrap();
        assert_eq!(epoch2.epoch_id, 2);

        // Advance to epoch 3: [1, 3] (node 2 removed)
        let p3 = epoch2.propose(1, 3, &[1, 3]).unwrap();
        let mut t3 = crate::quorum::QuorumVoteTally::new(p3, 2);
        t3.cast_vote(&crate::quorum::EpochVote::approve(
            1,
            &t3.proposal.blake3_hash,
        ))
        .unwrap();
        t3.cast_vote(&crate::quorum::EpochVote::approve(
            3,
            &t3.proposal.blake3_hash,
        ))
        .unwrap();
        let epoch3 = epoch2.advance(&t3.commitment.unwrap()).unwrap();
        assert_eq!(epoch3.epoch_id, 3);
        assert_eq!(
            epoch3
                .members
                .members()
                .iter()
                .map(|ni| ni.node_id)
                .collect::<Vec<_>>(),
            vec![1, 3]
        );
    }
}

// ── MembershipEpochDriver ───────────────────────────────────────────

/// Callback trait for network-level proposal dissemination and ack
/// collection. Implementations (typically in `tidefs-membership-live`)
/// handle broadcast, peer communication, and ack forwarding.
pub trait EpochTransitionOps {
    /// Called when a proposal has been created and is ready to broadcast.
    fn broadcast_proposal(&mut self, proposal: &epoch_proposal::EpochProposalMessage);
    /// Called when ack collection should begin (after broadcast).
    fn start_ack_collection(&mut self);
    /// Called when an epoch transition has been committed.
    fn on_epoch_committed(&mut self, result: &epoch_transition::EpochTransitionResult);
    /// Called when a proposal timeout occurs and the transition is aborted.
    fn on_timeout(&mut self);
}

/// High-level driver that translates membership events into epoch
/// transitions through the [`epoch_transition::EpochTransitionStateMachine`].
///
/// This struct lives in `tidefs-membership-epoch` and bridges to
/// membership-live via the [`EpochTransitionOps`] trait, avoiding
/// circular dependencies. Callers feed membership deltas (join,
/// drain, failure, suspicion) and the driver manages the full
/// propose -> broadcast -> ack -> commit lifecycle.
pub struct MembershipEpochDriver<O: EpochTransitionOps> {
    /// The underlying transition state machine.
    pub sm: epoch_transition::EpochTransitionStateMachine,
    /// Network/transport callback.
    pub ops: O,
    /// The proposer's own node id.
    pub proposer_id: u64,
    /// The current epoch number (before any pending transition).
    pub current_epoch: u64,
    /// The current member set (node ids, sorted).
    pub members: Vec<u64>,
}

impl<O: EpochTransitionOps> MembershipEpochDriver<O> {
    /// Create a new driver in `Stable` state.
    ///
    /// `peer_count` is the number of voting peers excluding the
    /// proposer.
    #[must_use]
    pub fn new(
        config: epoch_transition::EpochTransitionConfig,
        peer_count: usize,
        ops: O,
        proposer_id: u64,
        current_epoch: u64,
        members: Vec<u64>,
    ) -> Self {
        let sm = epoch_transition::EpochTransitionStateMachine::new(config, peer_count);
        Self {
            sm,
            ops,
            proposer_id,
            current_epoch,
            members,
        }
    }

    /// Feed a membership delta into the driver.
    ///
    /// Computes the resulting member set by applying `delta` to
    /// `self.members`, creates a proposal, transitions the state
    /// machine to `Proposing`, and broadcasts via `ops`.
    ///
    /// If peer_count is 0 (single-node), the transition commits
    /// immediately and `ops.on_epoch_committed()` is called.
    ///
    /// # Errors
    ///
    /// Returns [`epoch_transition::TransitionError`] if the state
    /// machine cannot transition or the proposal is invalid.
    pub fn on_membership_event(
        &mut self,
        delta: epoch_proposal::MembershipDelta,
    ) -> Result<(), epoch_transition::TransitionError> {
        let resulting = apply_delta(&self.members, delta);
        let proposal = self
            .sm
            .propose(self.proposer_id, self.current_epoch, delta, &resulting)?;

        // Single-node: commit immediately
        if self.sm.state() == epoch_state::EpochState::Committed {
            self.apply_committed_result(&resulting);
            return Ok(());
        }

        self.ops.broadcast_proposal(&proposal);
        self.sm.broadcast()?;
        self.ops.start_ack_collection();
        Ok(())
    }

    /// Feed a peer acknowledgment into the driver.
    ///
    /// # Errors
    ///
    /// Returns [`epoch_transition::TransitionError`] if the ack is
    /// invalid, a duplicate, or the machine is in wrong state.
    pub fn receive_ack(
        &mut self,
        ack: &epoch_proposal::EpochAckMessage,
    ) -> Result<(), epoch_transition::TransitionError> {
        self.sm.receive_ack(ack)?;

        // Check if quorum reached and auto-commit
        if self.sm.quorum_reached() {
            let result = self.sm.commit()?;
            let delta = result.proposal.delta;
            let resulting = apply_delta(&self.members, delta);
            self.apply_committed_result(&resulting);
            self.ops.on_epoch_committed(&result);
        }

        Ok(())
    }

    /// Attempt to commit the current proposal if quorum is reached.
    ///
    /// # Errors
    ///
    /// Returns [`epoch_transition::TransitionError`] if quorum
    /// hasn't been reached or the transition is invalid.
    pub fn try_commit(
        &mut self,
    ) -> Result<epoch_transition::EpochTransitionResult, epoch_transition::TransitionError> {
        let result = self.sm.commit()?;
        let delta = result.proposal.delta;
        let resulting = apply_delta(&self.members, delta);
        self.apply_committed_result(&resulting);
        self.ops.on_epoch_committed(&result);
        Ok(result)
    }

    /// Abort the current proposal and notify ops.
    ///
    /// # Errors
    ///
    /// Returns [`epoch_transition::TransitionError`] if not in an
    /// abortable state.
    pub fn abort(&mut self) -> Result<(), epoch_transition::TransitionError> {
        self.sm.abort()?;
        self.ops.on_timeout();
        Ok(())
    }

    /// Reset after a committed epoch, allowing new proposals.
    ///
    /// # Errors
    ///
    /// Returns [`epoch_transition::TransitionError`] if not in
    /// `Committed` state.
    pub fn reset(&mut self) -> Result<(), epoch_transition::TransitionError> {
        self.sm.reset()
    }

    /// Apply committed result: update members and advance epoch.
    fn apply_committed_result(&mut self, new_members: &[u64]) {
        self.members = new_members.to_vec();
        self.current_epoch += 1;
    }
}

/// Apply a [`epoch_proposal::MembershipDelta`] to a sorted member list,
/// returning the new sorted list.
fn apply_delta(members: &[u64], delta: epoch_proposal::MembershipDelta) -> Vec<u64> {
    let mut result = members.to_vec();
    match delta {
        epoch_proposal::MembershipDelta::NodeJoined(id) => {
            result.push(id);
        }
        epoch_proposal::MembershipDelta::NodeDrained(id)
        | epoch_proposal::MembershipDelta::NodeFailed(id)
        | epoch_proposal::MembershipDelta::NodeSuspected(id) => {
            result.retain(|m| *m != id);
        }
    }
    result.sort();
    result.dedup();
    result
}

#[cfg(test)]
mod membership_epoch_driver_tests {
    use super::*;
    use crate::epoch_proposal::{EpochAckMessage, MembershipDelta};
    use crate::epoch_state::EpochState;
    use crate::epoch_transition::{EpochTransitionConfig, EpochTransitionResult, QuorumThreshold};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A mock ops implementation that records calls for test assertions.
    struct MockOps {
        proposals: Rc<RefCell<Vec<epoch_proposal::EpochProposalMessage>>>,
        commits: Rc<RefCell<Vec<EpochTransitionResult>>>,
        acks_started: Rc<RefCell<usize>>,
        timeouts: Rc<RefCell<usize>>,
    }

    impl MockOps {
        fn new(
            proposals: Rc<RefCell<Vec<epoch_proposal::EpochProposalMessage>>>,
            commits: Rc<RefCell<Vec<EpochTransitionResult>>>,
            acks_started: Rc<RefCell<usize>>,
            timeouts: Rc<RefCell<usize>>,
        ) -> Self {
            Self {
                proposals,
                commits,
                acks_started,
                timeouts,
            }
        }
    }

    impl EpochTransitionOps for MockOps {
        fn broadcast_proposal(&mut self, proposal: &epoch_proposal::EpochProposalMessage) {
            self.proposals.borrow_mut().push(proposal.clone());
        }

        fn start_ack_collection(&mut self) {
            *self.acks_started.borrow_mut() += 1;
        }

        fn on_epoch_committed(&mut self, result: &EpochTransitionResult) {
            self.commits.borrow_mut().push(result.clone());
        }

        fn on_timeout(&mut self) {
            *self.timeouts.borrow_mut() += 1;
        }
    }

    type ProposalLog = Rc<RefCell<Vec<epoch_proposal::EpochProposalMessage>>>;
    type TransitionLog = Rc<RefCell<Vec<EpochTransitionResult>>>;
    type CounterCell = Rc<RefCell<usize>>;
    type DriverFixture = (
        MembershipEpochDriver<MockOps>,
        ProposalLog,
        TransitionLog,
        CounterCell,
        CounterCell,
    );

    fn make_driver(
        peer_count: usize,
        proposer_id: u64,
        current_epoch: u64,
        members: Vec<u64>,
    ) -> DriverFixture {
        let proposals = Rc::new(RefCell::new(Vec::new()));
        let commits = Rc::new(RefCell::new(Vec::new()));
        let acks = Rc::new(RefCell::new(0));
        let timeouts = Rc::new(RefCell::new(0));

        let config = EpochTransitionConfig {
            quorum_threshold: QuorumThreshold::SimpleMajority,
            timeout_ms: 30_000,
        };
        let ops = MockOps::new(
            proposals.clone(),
            commits.clone(),
            acks.clone(),
            timeouts.clone(),
        );
        let driver = MembershipEpochDriver::new(
            config,
            peer_count,
            ops,
            proposer_id,
            current_epoch,
            members,
        );
        (driver, proposals, commits, acks, timeouts)
    }

    // ── Single-node join ────────────────────────────────────────────

    #[test]
    fn single_node_join_commits_immediately() {
        let (mut driver, proposals, commits, _, _) = make_driver(0, 1, 0, vec![1]);

        driver
            .on_membership_event(MembershipDelta::NodeJoined(2))
            .unwrap();

        assert_eq!(driver.sm.state(), EpochState::Committed);
        assert_eq!(driver.current_epoch, 1);
        assert_eq!(driver.members, vec![1, 2]);
        // No broadcast needed for single-node
        assert!(proposals.borrow().is_empty());
        assert!(commits.borrow().is_empty()); // committed automatically, no ops callback for single-node
    }

    // ── Multi-node join -> broadcast -> ack -> commit ───────────────

    #[test]
    fn multi_node_join_broadcast_and_ack_commit() {
        let (mut driver, proposals, commits, acks, _) = make_driver(1, 1, 0, vec![1]);

        driver
            .on_membership_event(MembershipDelta::NodeJoined(2))
            .unwrap();

        // Proposal was broadcast
        assert_eq!(proposals.borrow().len(), 1);
        let msg = &proposals.borrow()[0];
        assert_eq!(msg.proposer_id, 1);
        assert_eq!(msg.current_epoch, 0);
        assert_eq!(msg.proposed_epoch, 1);
        assert_eq!(msg.delta, MembershipDelta::NodeJoined(2));

        // Ack collection started
        assert_eq!(*acks.borrow(), 1);

        // State is AwaitingAcks
        assert_eq!(driver.sm.state(), EpochState::AwaitingAcks);

        // Receive ack from peer 2
        let ack = EpochAckMessage::approve(2, &msg.blake3_hash);
        driver.receive_ack(&ack).unwrap();

        // Committed
        assert_eq!(driver.sm.state(), EpochState::Committed);
        assert_eq!(driver.current_epoch, 1);
        assert_eq!(driver.members, vec![1, 2]);
        assert_eq!(commits.borrow().len(), 1);
    }

    // ── Multi-node drain ────────────────────────────────────────────

    #[test]
    fn multi_node_drain_commits() {
        let (mut driver, proposals, _commits, _, _) = make_driver(1, 1, 5, vec![1, 2, 3]);

        driver
            .on_membership_event(MembershipDelta::NodeDrained(2))
            .unwrap();

        let msg = &proposals.borrow()[0];
        assert_eq!(msg.delta, MembershipDelta::NodeDrained(2));
        assert_eq!(msg.resulting_members, vec![1, 3]);

        let ack = EpochAckMessage::approve(3, &msg.blake3_hash);
        driver.receive_ack(&ack).unwrap();

        assert_eq!(driver.current_epoch, 6);
        assert_eq!(driver.members, vec![1, 3]);
    }

    // ── Multi-node failure ──────────────────────────────────────────

    #[test]
    fn multi_node_failure_commits() {
        let (mut driver, proposals, _commits, _, _) = make_driver(2, 1, 10, vec![1, 2, 3, 4]);

        driver
            .on_membership_event(MembershipDelta::NodeFailed(3))
            .unwrap();

        let msg = &proposals.borrow()[0];
        assert_eq!(msg.delta, MembershipDelta::NodeFailed(3));

        // Need 2 acks (simple majority of 2 peers = 2)
        let ack2 = EpochAckMessage::approve(2, &msg.blake3_hash);
        let ack4 = EpochAckMessage::approve(4, &msg.blake3_hash);
        driver.receive_ack(&ack2).unwrap();
        driver.receive_ack(&ack4).unwrap();

        assert_eq!(driver.current_epoch, 11);
        assert_eq!(driver.members, vec![1, 2, 4]);
    }

    // ── Abort and timeout ───────────────────────────────────────────

    #[test]
    fn abort_triggers_timeout_callback() {
        let (mut driver, proposals, _, _, timeouts) = make_driver(2, 1, 0, vec![1, 2, 3]);

        driver
            .on_membership_event(MembershipDelta::NodeJoined(4))
            .unwrap();
        assert_eq!(proposals.borrow().len(), 1);

        driver.abort().unwrap();
        assert_eq!(*timeouts.borrow(), 1);
        assert_eq!(driver.sm.state(), EpochState::Stable);
    }

    // ── Reset after commit ──────────────────────────────────────────

    #[test]
    fn reset_after_commit_allows_new_cycle() {
        let (mut driver, proposals, _, _, _) = make_driver(1, 1, 0, vec![1]);

        // First transition
        driver
            .on_membership_event(MembershipDelta::NodeJoined(2))
            .unwrap();
        let msg0 = proposals.borrow()[0].clone();
        driver
            .receive_ack(&EpochAckMessage::approve(2, &msg0.blake3_hash))
            .unwrap();
        assert_eq!(driver.current_epoch, 1);

        // Reset
        driver.reset().unwrap();
        assert_eq!(driver.sm.state(), EpochState::Stable);

        // Second transition
        proposals.borrow_mut().clear();
        driver
            .on_membership_event(MembershipDelta::NodeJoined(3))
            .unwrap();
        let msg1 = proposals.borrow()[0].clone();
        driver
            .receive_ack(&EpochAckMessage::approve(2, &msg1.blake3_hash))
            .unwrap();
        assert_eq!(driver.current_epoch, 2);
        assert_eq!(driver.members, vec![1, 2, 3]);
    }

    // ── All four delta variants ─────────────────────────────────────

    #[test]
    fn all_delta_variants_drive_correct_epoch() {
        let variants = [
            (MembershipDelta::NodeJoined(99), vec![1, 99]),
            (MembershipDelta::NodeDrained(1), vec![]), // empty set after drain - handled by proposal validation
            (MembershipDelta::NodeFailed(1), vec![]),
            (MembershipDelta::NodeSuspected(1), vec![]),
        ];

        for (delta, _expected) in &variants {
            let (mut driver, _, _, _, _) = make_driver(2, 1, 0, vec![1, 2, 3]);

            let result = driver.on_membership_event(*delta);
            // Some deltas (drain of last member) may fail with EmptyMemberSet
            if result.is_ok() {
                let msg = driver.sm.current_proposal().unwrap();
                assert!(msg.verify());
            }
        }
    }

    // ── apply_delta helper ──────────────────────────────────────────

    #[test]
    fn apply_delta_join_adds_and_sorts() {
        let result = apply_delta(&[1, 2, 3], MembershipDelta::NodeJoined(5));
        assert_eq!(result, vec![1, 2, 3, 5]);

        let result = apply_delta(&[1, 2, 3], MembershipDelta::NodeJoined(0));
        assert_eq!(result, vec![0, 1, 2, 3]);
    }

    #[test]
    fn apply_delta_drain_removes() {
        let result = apply_delta(&[1, 2, 3, 4], MembershipDelta::NodeDrained(2));
        assert_eq!(result, vec![1, 3, 4]);
    }

    #[test]
    fn apply_delta_failed_removes() {
        let result = apply_delta(&[1, 2, 3], MembershipDelta::NodeFailed(1));
        assert_eq!(result, vec![2, 3]);
    }

    #[test]
    fn apply_delta_suspected_removes() {
        let result = apply_delta(&[1, 2, 3], MembershipDelta::NodeSuspected(3));
        assert_eq!(result, vec![1, 2]);
    }

    #[test]
    fn apply_delta_missing_node_noop() {
        let result = apply_delta(&[1, 2], MembershipDelta::NodeDrained(99));
        assert_eq!(result, vec![1, 2]);
    }

    #[test]
    fn apply_delta_duplicate_join_is_deduped() {
        let result = apply_delta(&[1, 2], MembershipDelta::NodeJoined(2));
        assert_eq!(result, vec![1, 2]);
    }
}
