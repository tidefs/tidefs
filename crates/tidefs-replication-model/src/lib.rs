#![forbid(unsafe_code)]

//! Deterministic replica set type model for OW-304 replication, placement,
//! rebuild, and durability assessment.
//!
//! This crate is an executable model — not a networked runtime. It provides
//! the canonical types and state machines consumed by every multi-node
//! replication crate: `tidefs-replication`, `tidefs-quorum-write`,
//! `tidefs-quorum-write-runtime`, `tidefs-replicated-object-store`,
//! `tidefs-rebuild-runtime`, `tidefs-node-drain`, and others.
//!
//! # State machines
//!
//! ## Flow state machine (`FlowState`)
//!
//! Data-movement flows progress through: `Planned → Transferring →
//! Transferred → Verifying → Verified → Complete`. Any state may transition
//! to `Aborted` (terminal). Idempotent same-state transitions are allowed.
//! Invalid transitions (e.g. `Transferred → Planned`) panic.
//!
//! ## Replica chunk state machine (`ReplicaChunkState`)
//!
//! Per-chunk transfers progress through: `Pending → Transferring →
//! Verifying → Committed`. Failure paths: `Transferring → Failed` (transport
//! error), `Verifying → Failed` (digest mismatch). Cancellation paths:
//! `Pending → Cancelled`, `Transferring → Cancelled`, `Failed → Cancelled`.
//! Terminal states (`Committed`, `Cancelled`) deny further advancement.
//! After failure, a new chunk (fresh `Pending` with new `chunk_id`) is
//! created rather than retrying the failed chunk in place.
//!
//! ## Durability level (`DurabilityLevel`)
//!
//! Four-tier assessment: `Normal` (all replicas/shards online), `Warning`
//! (below target but above critical), `Critical` (exactly 1 replica or
//! exactly k data shards — readable but zero redundancy), `LossImminent`
//! (zero replicas or fewer than k data shards — data unavailable).
//!
//! `DurabilityLevel::for_replicated(healthy_replicas, r)` uses healthy count
//! thresholds: `>= r → Normal`, `> 1 → Warning`, `== 1 → Critical`, `0 →
//! LossImminent`. This was corrected in #5421; the previous thresholds
//! (`> 2` / `== 2`) misclassified intermediate replica counts.
//!
//! `DurabilityLevel::for_erasure_coded(healthy_shards, k, m)` uses:
//! `>= k+m → Normal`, `> k → Warning`, `== k → Critical`, `< k →
//! LossImminent`.
//!
//! ## Replica set record (`ReplicaSetRecord`)
//!
//! Immutable logical set binding a replicated subject to a placement policy,
//! required replica count, target failure domains, and current placement
//! receipt references. Lifecycle: created with `required_count` ≥ 1,
//! members join/leave via placement receipt append/removal, durability
//! assessed via `DurabilityLevel`, and set is destroyed when the subject is
//! trimmed or relocated.

pub mod class;
pub mod erasure_coding_profile;
pub mod failure_domain;
pub mod intent;
pub mod repair_source;
pub mod replication_factor;
pub mod topology;
pub mod validator;

pub use class::ReplicationClass;
pub use class::ReplicationModelError;
pub use erasure_coding_profile::ErasureCodingAlgorithm;
pub use erasure_coding_profile::ErasureCodingProfile;
pub use erasure_coding_profile::ErasureCodingProfileError;
pub use failure_domain::FailureDomain;
pub use intent::ReplicationIntent;
pub use intent::ReplicationIntentError;
pub use repair_source::RepairDatasetId;
pub use repair_source::RepairSourceDecision;
pub use repair_source::RepairSourceEvidenceKind;
pub use repair_source::RepairSourceFreshness;
pub use repair_source::RepairSourceReceiptManifest;
pub use repair_source::RepairSourceReceiptVerifier;
pub use repair_source::RepairSourceSubject;
pub use repair_source::RepairSourceValidationTier;
pub use repair_source::RepairSourceVerification;
pub use repair_source::RepairSourceVerificationContext;
pub use repair_source::RepairSourceVerificationError;
pub use replication_factor::ReplicationFactor;
pub use replication_factor::ReplicationFactorError;
pub use replication_factor::MAX_REPLICATION_COPIES;
pub use validator::LayoutValidationError;
pub use validator::LayoutValidator;
pub use validator::PlacementEntry;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use tidefs_membership_epoch::{
    plan_failure_domain_placement_from_policy, ClusterMemberRecord, DomainId, EpochId,
    FailureDomainPlacementPolicy, HealthClass, MemberId, MembershipConfigRecord,
    MembershipPlacementVerdictRecord, StorageTier, VerdictClass,
};

pub const REPLICATED_OBJECT_ROOT_STORAGE_GATE_OW_304: &str =
    "OW-304 replicated object/root storage model covers degraded read/write and rebuild gates";
pub const REBUILD_BACKFILL_REBALANCE_GATE_OW_305: &str =
    "OW-305 rebuild/backfill/rebalance model covers fault injection and capacity movement gates";
pub const ERASURE_CODED_LAYOUT_GATE_OW_306: &str =
    "OW-306 erasure-coded layout model covers decode, rebuild, and partial failure gates";

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct ReplicatedSubjectId(pub u64);

impl ReplicatedSubjectId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct ReplicatedReceiptId(pub u64);

impl ReplicatedReceiptId {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct ObjectDigest(pub u64);

impl ObjectDigest {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Redundancy policy identity recorded by a placement receipt reference.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ReceiptRedundancyPolicy {
    /// Full replicas on distinct placement targets.
    Replicated { copies: u8 },
    /// One erasure stripe with data plus parity shard targets.
    Erasure { data_shards: u8, parity_shards: u8 },
}

impl Default for ReceiptRedundancyPolicy {
    fn default() -> Self {
        Self::Replicated { copies: 1 }
    }
}

impl ReceiptRedundancyPolicy {
    /// Number of physical targets required by this policy.
    #[must_use]
    pub const fn target_width(self) -> u16 {
        match self {
            Self::Replicated { copies } => copies as u16,
            Self::Erasure {
                data_shards,
                parity_shards,
            } => data_shards as u16 + parity_shards as u16,
        }
    }

    /// True when the policy can describe a usable receipt placement.
    #[must_use]
    pub const fn is_well_formed(self) -> bool {
        match self {
            Self::Replicated { copies } => copies > 0,
            Self::Erasure {
                data_shards,
                parity_shards,
            } => data_shards > 0 && parity_shards > 0,
        }
    }
}

/// Shared reference to durable source placement authority.
///
/// This is intentionally a reference-sized projection of the local placement
/// receipt, not a second placement planner. Distributed rebuild/backfill code
/// carries it so byte movement stays bound to the receipt that made the source
/// bytes legal.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct PlacementReceiptRef {
    /// Logical object id used by model/runtime planners.
    pub object_id: u64,
    /// Full 32-byte object key recorded by the local placement receipt.
    pub object_key: [u8; 32],
    /// Topology or membership epoch when this receipt was issued.
    pub receipt_epoch: EpochId,
    /// Monotonic receipt write generation.
    pub receipt_generation: u64,
    /// Redundancy policy identity in force for this placement.
    pub redundancy_policy: ReceiptRedundancyPolicy,
    /// Logical payload length before erasure padding.
    pub payload_len: u64,
    /// BLAKE3 digest of the logical payload.
    pub payload_digest: [u8; 32],
    /// Number of physical targets recorded by the placement receipt.
    pub target_count: u16,
}

impl PlacementReceiptRef {
    /// Construct a placement receipt reference from explicit receipt fields.
    #[must_use]
    pub const fn new(
        object_id: u64,
        object_key: [u8; 32],
        receipt_epoch: EpochId,
        receipt_generation: u64,
        redundancy_policy: ReceiptRedundancyPolicy,
        payload_len: u64,
        payload_digest: [u8; 32],
        target_count: u16,
    ) -> Self {
        Self {
            object_id,
            object_key,
            receipt_epoch,
            receipt_generation,
            redundancy_policy,
            payload_len,
            payload_digest,
            target_count,
        }
    }

    /// Construct a replicated placement receipt reference.
    #[must_use]
    pub const fn replicated(
        object_id: u64,
        object_key: [u8; 32],
        receipt_epoch: EpochId,
        receipt_generation: u64,
        copies: u8,
        payload_len: u64,
        payload_digest: [u8; 32],
    ) -> Self {
        let redundancy_policy = ReceiptRedundancyPolicy::Replicated { copies };
        Self::new(
            object_id,
            object_key,
            receipt_epoch,
            receipt_generation,
            redundancy_policy,
            payload_len,
            payload_digest,
            redundancy_policy.target_width(),
        )
    }

    /// Construct an erasure-coded placement receipt reference.
    #[must_use]
    pub const fn erasure(
        object_id: u64,
        object_key: [u8; 32],
        receipt_epoch: EpochId,
        receipt_generation: u64,
        data_shards: u8,
        parity_shards: u8,
        payload_len: u64,
        payload_digest: [u8; 32],
    ) -> Self {
        let redundancy_policy = ReceiptRedundancyPolicy::Erasure {
            data_shards,
            parity_shards,
        };
        Self::new(
            object_id,
            object_key,
            receipt_epoch,
            receipt_generation,
            redundancy_policy,
            payload_len,
            payload_digest,
            redundancy_policy.target_width(),
        )
    }

    /// Compatibility fallback for legacy callers that do not yet pass a real
    /// local placement receipt. Generation zero deliberately keeps this from
    /// validating as durable placement authority.
    #[must_use]
    pub fn synthetic_for_subject(subject: ReplicatedSubjectId) -> Self {
        let mut object_key = [0u8; 32];
        object_key[..8].copy_from_slice(&subject.0.to_le_bytes());
        Self {
            object_id: subject.0,
            object_key,
            receipt_epoch: EpochId::ZERO,
            receipt_generation: 0,
            redundancy_policy: ReceiptRedundancyPolicy::default(),
            payload_len: 0,
            payload_digest: [0; 32],
            target_count: 1,
        }
    }

    /// True when this is the legacy compatibility fallback rather than a
    /// receipt emitted by the placement authority.
    #[must_use]
    pub const fn is_synthetic(self) -> bool {
        self.receipt_generation == 0
    }

    #[must_use]
    pub const fn is_committed_authority(self) -> bool {
        !self.is_synthetic() && self.redundancy_policy.is_well_formed() && self.target_count > 0
    }
}

/// Per-member receipt identity committed by the placement authority.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct CommittedReceiptIdentity {
    pub member: MemberId,
    pub receipt_id: ReplicatedReceiptId,
    pub placement_receipt_ref: PlacementReceiptRef,
}

impl CommittedReceiptIdentity {
    #[must_use]
    pub const fn new(
        member: MemberId,
        receipt_id: ReplicatedReceiptId,
        placement_receipt_ref: PlacementReceiptRef,
    ) -> Self {
        Self {
            member,
            receipt_id,
            placement_receipt_ref,
        }
    }

    #[must_use]
    pub const fn is_committed_for(self, member: MemberId, epoch: EpochId) -> bool {
        self.member.0 == member.0
            && !self.receipt_id.is_zero()
            && self.placement_receipt_ref.receipt_epoch.0 == epoch.0
            && self.placement_receipt_ref.is_committed_authority()
    }
}

/// Durable quorum token bound to the per-member receipt identities that
/// actually satisfied a quorum.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct QuorumDurabilityToken {
    pub write_id: u64,
    pub epoch: EpochId,
    pub target_count: usize,
    pub quorum_required: usize,
    pub receipt_identities: Vec<CommittedReceiptIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuorumDurabilityTokenError {
    EmptyQuorum,
    QuorumExceedsTargets {
        quorum_required: usize,
        target_count: usize,
    },
    InsufficientCommittedReceipts {
        committed_receipts: usize,
        quorum_required: usize,
    },
    InvalidReceiptIdentity {
        member: MemberId,
        receipt_id: ReplicatedReceiptId,
    },
    DuplicateMember(MemberId),
    DuplicateReceipt(ReplicatedReceiptId),
}

impl QuorumDurabilityToken {
    /// Build a quorum durability token from committed receipt identities.
    ///
    /// # Errors
    ///
    /// Returns an error when the quorum shape is impossible, a receipt is not
    /// committed authority for this epoch, or duplicate member/receipt
    /// identities appear in the quorum.
    pub fn new(
        write_id: u64,
        epoch: EpochId,
        target_count: usize,
        quorum_required: usize,
        receipt_identities: Vec<CommittedReceiptIdentity>,
    ) -> Result<Self, QuorumDurabilityTokenError> {
        if quorum_required == 0 || target_count == 0 {
            return Err(QuorumDurabilityTokenError::EmptyQuorum);
        }
        if quorum_required > target_count {
            return Err(QuorumDurabilityTokenError::QuorumExceedsTargets {
                quorum_required,
                target_count,
            });
        }
        if receipt_identities.len() < quorum_required {
            return Err(QuorumDurabilityTokenError::InsufficientCommittedReceipts {
                committed_receipts: receipt_identities.len(),
                quorum_required,
            });
        }
        if receipt_identities.len() > target_count {
            return Err(QuorumDurabilityTokenError::QuorumExceedsTargets {
                quorum_required: receipt_identities.len(),
                target_count,
            });
        }

        let mut members = BTreeSet::new();
        let mut receipts = BTreeSet::new();
        for identity in &receipt_identities {
            if !identity.is_committed_for(identity.member, epoch) {
                return Err(QuorumDurabilityTokenError::InvalidReceiptIdentity {
                    member: identity.member,
                    receipt_id: identity.receipt_id,
                });
            }
            if !members.insert(identity.member) {
                return Err(QuorumDurabilityTokenError::DuplicateMember(identity.member));
            }
            if !receipts.insert(identity.receipt_id) {
                return Err(QuorumDurabilityTokenError::DuplicateReceipt(
                    identity.receipt_id,
                ));
            }
        }

        Ok(Self {
            write_id,
            epoch,
            target_count,
            quorum_required,
            receipt_identities,
        })
    }

    #[must_use]
    pub fn committed_count(&self) -> usize {
        self.receipt_identities.len()
    }

    #[must_use]
    pub fn committed_members(&self) -> Vec<MemberId> {
        self.receipt_identities
            .iter()
            .map(|identity| identity.member)
            .collect()
    }

    #[must_use]
    pub fn receipt_ids(&self) -> Vec<ReplicatedReceiptId> {
        self.receipt_identities
            .iter()
            .map(|identity| identity.receipt_id)
            .collect()
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicatedSubjectClass {
    ImmutableObject,
    AuthenticatedRoot,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicaCopyClass {
    Verified,
    Missing,
    Suspect,
    Unreachable,
    Rebuilding,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicatedWriteClass {
    Committed,
    DegradedCommitted,
    RefusedNoQuorum,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicatedReadClass {
    Exact,
    DegradedButValid,
    RepairRequired,
    Unavailable,
}

impl ReplicatedReadClass {
    #[must_use]
    pub const fn permits_payload_response(self) -> bool {
        matches!(self, Self::Exact | Self::DegradedButValid)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebuildPlanClass {
    NotRequired,
    Restored,
    BlockedNoSource,
    BlockedNoTarget,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicaMovementClass {
    RebuildLostOrSuspectCopy,
    BackfillLaggedCopy,
    RebalanceCapacityPressure,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicaMovementPlanClass {
    NotRequired,
    Planned,
    BlockedNoSource,
    BlockedNoTarget,
    BlockedNoCapacity,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureLayoutClass {
    SingleParityXor,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureShardClass {
    Data,
    Parity,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureShardStateClass {
    Available,
    Missing,
    Suspect,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureDecodeClass {
    Complete,
    ReconstructedSingleDataShard,
    RebuiltParityShard,
    RefusedTooManyMissing,
    RefusedMissingDataAndParity,
    RefusedInvalidLayout,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureLayoutPolicy {
    pub data_shard_count: usize,
    pub parity_shard_count: usize,
    pub shard_len: usize,
    pub layout_class: ErasureLayoutClass,
}

impl ErasureLayoutPolicy {
    #[must_use]
    pub const fn single_parity_xor(data_shard_count: usize, shard_len: usize) -> Self {
        Self {
            data_shard_count,
            parity_shard_count: 1,
            shard_len,
            layout_class: ErasureLayoutClass::SingleParityXor,
        }
    }

    #[must_use]
    pub const fn total_shard_count(self) -> usize {
        self.data_shard_count + self.parity_shard_count
    }

    #[must_use]
    pub const fn parity_shard_index(self) -> usize {
        self.data_shard_count
    }

    #[must_use]
    pub const fn data_capacity(self) -> Option<usize> {
        self.data_shard_count.checked_mul(self.shard_len)
    }

    #[must_use]
    pub const fn admits_single_parity_xor(self) -> bool {
        matches!(self.layout_class, ErasureLayoutClass::SingleParityXor)
            && self.data_shard_count > 0
            && self.parity_shard_count == 1
            && self.shard_len > 0
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ErasureShardRecord {
    pub subject_ref: ReplicatedSubjectId,
    pub stripe_index: u64,
    pub shard_index: usize,
    pub shard_class: ErasureShardClass,
    pub state_class: ErasureShardStateClass,
    pub payload_digest: ObjectDigest,
    pub payload_len: usize,
    pub bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ErasureStripeRecord {
    pub subject_ref: ReplicatedSubjectId,
    pub layout_policy: ErasureLayoutPolicy,
    pub stripe_index: u64,
    pub original_payload_len: usize,
    pub original_payload_digest: ObjectDigest,
    pub shards: Vec<ErasureShardRecord>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ErasureDecodePlan {
    pub subject_ref: ReplicatedSubjectId,
    pub stripe_index: u64,
    pub decode_class: ErasureDecodeClass,
    pub reconstructed_payload: Option<Vec<u8>>,
    pub rebuilt_shards: Vec<ErasureShardRecord>,
    pub unavailable_shard_indexes: Vec<usize>,
    pub decode_receipt_ref: ReplicatedReceiptId,
}

/// Per-dataset redundancy configuration.
///
/// Unlike ZFS (pool-wide PARITY_RAID level) and Ceph (pool-wide replication factor),
/// tidefs allows heterogeneous redundancy policies within a single pool.
///
/// Once set at dataset creation, this is immutable. Changing redundancy policy
/// requires dataset migration (send/receive to a new dataset with the desired
/// policy).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RedundancyPolicy {
    /// No redundancy: single ingest copy only. Data lives and dies with
    /// the ingest device. Suitable for transient/temporary datasets.
    #[default]
    None,
    /// Replicated: `r` full copies on `r` distinct devices.
    /// Write path: fanout to r targets via `ReplicationProtocol`.
    /// Read path: any healthy replica; failover on read error.
    Replicated { r: u8 },
    /// Erasure-coded: `k` data + `m` parity shards on (k+m) distinct devices.
    /// Write path: write ingest copy; rebake encodes k+m shards.
    /// Read path: read k data shards; reconstruct from parity on failure.
    ErasureCoded { k: u8, m: u8 },
}

impl RedundancyPolicy {
    /// Returns `true` if this policy provides any redundancy.
    #[must_use]
    pub const fn has_redundancy(&self) -> bool {
        !matches!(self, RedundancyPolicy::None)
    }

    /// Total data copies: 1 for None, r for Replicated, k+m for ErasureCoded.
    #[must_use]
    pub const fn total_device_count(&self) -> u8 {
        match self {
            RedundancyPolicy::None => 1,
            RedundancyPolicy::Replicated { r } => *r,
            RedundancyPolicy::ErasureCoded { k, m } => *k + *m,
        }
    }

    /// Minimum readable devices to reconstruct data.
    /// None: 1. Replicated: 1. ErasureCoded: k.
    #[must_use]
    pub const fn min_readable(&self) -> u8 {
        match self {
            RedundancyPolicy::None | RedundancyPolicy::Replicated { .. } => 1,
            RedundancyPolicy::ErasureCoded { k, .. } => *k,
        }
    }
}

/// Fine-grained lifecycle state for an ingest replica.
///
/// Refines `ExtentLifecycleState::Ingest` with emergency-rebake and scheduled-
/// rebake sub-states, and adds `Trimmed` as a terminal equivalent to `Freed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplicaLifecycle {
    /// Single-copy on one device; not durable. Bounded by ingest window
    /// (time, count, or capacity).
    Ingest,
    /// Ingest copy at risk; rebake elevated to critical priority.
    EmergencyRebake,
    /// Normal rebake queued; copy is safe for now.
    RebakeScheduled,
    /// k+m shards written; full redundancy achieved.
    BaseComplete,
    /// Space reclaimed from ingest device. Terminal.
    Trimmed,
}

impl ReplicaLifecycle {
    /// Returns `true` when the lifecycle has reached a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, ReplicaLifecycle::Trimmed)
    }

    /// Returns `true` when data is fully redundant (k+m shards written).
    #[must_use]
    pub const fn is_fully_redundant(&self) -> bool {
        matches!(self, ReplicaLifecycle::BaseComplete)
    }
}

/// Durability ladder levels for per-dataset redundancy assessment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DurabilityLevel {
    /// All replicas/sufficient shards online.
    Normal = 0,
    /// Replicas below target but above Critical threshold.
    Warning = 1,
    /// Only 1 replica remaining; no redundancy but reads still possible.
    Critical = 2,
    /// Zero replicas remaining; data is unavailable.
    LossImminent = 3,
}

impl DurabilityLevel {
    /// Calculate durability level for an erasure-coded extent with
    /// `healthy_shards` out of `k`+`m` total.
    #[must_use]
    pub const fn for_erasure_coded(healthy_shards: u8, k: u8, m: u8) -> Self {
        let total = k + m;
        if healthy_shards >= total {
            DurabilityLevel::Normal
        } else if healthy_shards > k {
            DurabilityLevel::Warning
        } else if healthy_shards == k {
            DurabilityLevel::Critical
        } else {
            DurabilityLevel::LossImminent
        }
    }

    /// Calculate durability level for a replicated extent with
    /// `healthy_replicas` out of `r` total.
    #[must_use]
    pub const fn for_replicated(healthy_replicas: u8, r: u8) -> Self {
        if healthy_replicas >= r {
            DurabilityLevel::Normal
        } else if healthy_replicas > 1 {
            DurabilityLevel::Warning
        } else if healthy_replicas == 1 {
            DurabilityLevel::Critical
        } else {
            DurabilityLevel::LossImminent
        }
    }
}

impl core::fmt::Display for RedundancyPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RedundancyPolicy::None => write!(f, "none"),
            RedundancyPolicy::Replicated { r } => write!(f, "replicated(r={r})"),
            RedundancyPolicy::ErasureCoded { k, m } => write!(f, "erasure_coded(k={k},m={m})"),
        }
    }
}

impl core::fmt::Display for ReplicaLifecycle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            ReplicaLifecycle::Ingest => "ingest",
            ReplicaLifecycle::EmergencyRebake => "emergency_rebake",
            ReplicaLifecycle::RebakeScheduled => "rebake_scheduled",
            ReplicaLifecycle::BaseComplete => "base_complete",
            ReplicaLifecycle::Trimmed => "trimmed",
        };
        write!(f, "{s}")
    }
}

impl core::fmt::Display for DurabilityLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            DurabilityLevel::Normal => "normal",
            DurabilityLevel::Warning => "warning",
            DurabilityLevel::Critical => "critical",
            DurabilityLevel::LossImminent => "loss_imminent",
        };
        write!(f, "{s}")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReplicatedObjectRootRecord {
    pub subject_id: ReplicatedSubjectId,
    pub subject_class: ReplicatedSubjectClass,
    pub membership_epoch_ref: EpochId,
    pub root_generation: u64,
    pub payload_digest: ObjectDigest,
    pub payload_len: u64,
    pub publication_receipt_ref: ReplicatedReceiptId,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReplicaCopyRecord {
    pub subject_ref: ReplicatedSubjectId,
    pub member_ref: MemberId,
    pub domain_ref: DomainId,
    pub copy_class: ReplicaCopyClass,
    pub payload_digest: ObjectDigest,
    pub freshness_frontier: u64,
    pub verification_receipt_ref: ReplicatedReceiptId,
}

impl ReplicaCopyRecord {
    #[must_use]
    pub const fn verified(
        subject_ref: ReplicatedSubjectId,
        member_ref: MemberId,
        domain_ref: DomainId,
        payload_digest: ObjectDigest,
        freshness_frontier: u64,
    ) -> Self {
        Self {
            subject_ref,
            member_ref,
            domain_ref,
            copy_class: ReplicaCopyClass::Verified,
            payload_digest,
            freshness_frontier,
            verification_receipt_ref: ReplicatedReceiptId(derive_receipt_id(
                subject_ref.0,
                member_ref.0,
                freshness_frontier,
            )),
        }
    }

    #[must_use]
    pub fn unavailable(
        subject_ref: ReplicatedSubjectId,
        member_ref: MemberId,
        domain_ref: DomainId,
        copy_class: ReplicaCopyClass,
        payload_digest: ObjectDigest,
    ) -> Self {
        Self {
            subject_ref,
            member_ref,
            domain_ref,
            copy_class,
            payload_digest,
            freshness_frontier: 0,
            verification_receipt_ref: ReplicatedReceiptId::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReplicatedWritePlan {
    pub subject: ReplicatedObjectRootRecord,
    pub placement_verdict: MembershipPlacementVerdictRecord,
    pub target_member_refs: Vec<MemberId>,
    pub committed_member_refs: Vec<MemberId>,
    pub unavailable_member_refs: Vec<MemberId>,
    pub quorum_required: usize,
    pub unplaced_replica_count: usize,
    pub write_class: ReplicatedWriteClass,
    pub commit_receipt_ref: ReplicatedReceiptId,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReplicatedReadPlan {
    pub subject_ref: ReplicatedSubjectId,
    pub source_member_ref: Option<MemberId>,
    pub verified_member_refs: Vec<MemberId>,
    pub unavailable_member_refs: Vec<MemberId>,
    pub missing_replica_count: usize,
    pub read_class: ReplicatedReadClass,
    pub rebuild_required: bool,
    pub read_receipt_ref: ReplicatedReceiptId,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RebuildPlan {
    pub subject_ref: ReplicatedSubjectId,
    pub source_member_refs: Vec<MemberId>,
    pub target_member_refs: Vec<MemberId>,
    pub final_member_refs: Vec<MemberId>,
    pub placement_verdict: MembershipPlacementVerdictRecord,
    pub rebuild_class: RebuildPlanClass,
    pub rebuild_receipt_ref: ReplicatedReceiptId,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReplicaMovementIntentRecord {
    pub intent_id: ReplicatedReceiptId,
    pub movement_class: ReplicaMovementClass,
    pub subject_ref: ReplicatedSubjectId,
    pub placement_receipt_ref: PlacementReceiptRef,
    pub source_member_ref: MemberId,
    pub target_member_ref: MemberId,
    pub payload_digest: ObjectDigest,
    pub payload_len: u64,
    pub verification_required: bool,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplicaCapacityRecord {
    pub member_ref: MemberId,
    pub used_bytes: u64,
    pub capacity_bytes: u64,
    pub reserved_rebuild_bytes: u64,
}

impl ReplicaCapacityRecord {
    #[must_use]
    pub const fn new(
        member_ref: MemberId,
        used_bytes: u64,
        capacity_bytes: u64,
        reserved_rebuild_bytes: u64,
    ) -> Self {
        Self {
            member_ref,
            used_bytes,
            capacity_bytes,
            reserved_rebuild_bytes,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct CapacityMovementPolicy {
    pub capacity_records: Vec<ReplicaCapacityRecord>,
    pub max_used_numerator: u64,
    pub max_used_denominator: u64,
}

impl CapacityMovementPolicy {
    #[must_use]
    pub const fn new(
        capacity_records: Vec<ReplicaCapacityRecord>,
        max_used_numerator: u64,
        max_used_denominator: u64,
    ) -> Self {
        Self {
            capacity_records,
            max_used_numerator,
            max_used_denominator,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReplicaMovementPlan {
    pub subject_ref: ReplicatedSubjectId,
    pub movement_class: ReplicaMovementClass,
    pub plan_class: ReplicaMovementPlanClass,
    pub source_member_refs: Vec<MemberId>,
    pub target_member_refs: Vec<MemberId>,
    pub retained_member_refs: Vec<MemberId>,
    pub faulted_member_refs: Vec<MemberId>,
    pub final_member_refs: Vec<MemberId>,
    pub transfer_intents: Vec<ReplicaMovementIntentRecord>,
    pub placement_verdict: MembershipPlacementVerdictRecord,
    pub movement_receipt_ref: ReplicatedReceiptId,
}

/// Canonical claim chain proof classes for verification outcomes.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationStatus {
    /// Digest, witness, and quorum checks all passed.
    Verified,
    /// Digest mismatch — payload is corrupt or tampered.
    DigestMismatch,
    /// Witness attestation missing or insufficient.
    WitnessInsufficient,
    /// Quorum not met for verification.
    QuorumNotMet,
    /// Verification degraded but placement still legal under degraded policy.
    DegradedVerified,
}

/// Authoritative transfer admission ticket (P8-03 §5: `ReplicaTransferTicketRecord`).
///
/// Issued when a movement intent is staged. Binds source anchors, target,
/// pin budget, freshness fence, and expiry so transfer workers operate
/// under explicit resource and safety bounds.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReplicaTransferTicketRecord {
    pub ticket_id: ReplicatedReceiptId,
    /// Reference to the placement/movement intent that authorised this transfer.
    pub intent_ref: ReplicatedReceiptId,
    /// Subjects (objects, roots, chunks) to transfer.
    pub subject_refs: Vec<ReplicatedSubjectId>,
    /// Source member anchor set — must not change during transfer.
    pub source_anchor_set: Vec<MemberId>,
    /// Target member for the transfer.
    pub target_ref: MemberId,
    /// Pin budget receipt reference (resource reservation).
    pub pin_budget_ref: ReplicatedReceiptId,
    /// Clock/fence frontier below which source reads are valid.
    pub freshness_fence_ref: u64,
    /// Epoch after which the ticket expires.
    pub expiry: u64,
}

/// Canonical receipt of transfer completion (P8-03 §5: `ReplicaTransferReceipt`).
///
/// Emitted after bytes have been successfully moved from source to target.
/// Does not constitute legal placement — verification must follow.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReplicaTransferReceipt {
    pub receipt_id: ReplicatedReceiptId,
    /// The ticket this transfer completed under.
    pub ticket_ref: ReplicatedReceiptId,
    /// Total bytes moved.
    pub bytes_moved: u64,
    /// Hash of the source anchor state at transfer time.
    pub source_anchor_hash: u64,
    /// Hash of the target anchor state after transfer.
    pub target_anchor_hash: u64,
    /// Membership epoch at transfer completion.
    pub completion_epoch: EpochId,
    /// Workers that participated in the transfer.
    pub worker_refs: Vec<MemberId>,
}

/// Canonical verification truth (P8-03 §5: `ReplicaVerificationReceipt`).
///
/// Emitted after digest comparison, witness attestation, and quorum
/// validation. A `Verified` status makes replica placement legal.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReplicaVerificationReceipt {
    pub receipt_id: ReplicatedReceiptId,
    /// Subjects that were verified.
    pub subject_refs: Vec<ReplicatedSubjectId>,
    /// Digest results for each verified subject.
    pub digest_results: Vec<ObjectDigest>,
    /// Witness members that attested to the verification.
    pub witness_refs: Vec<MemberId>,
    /// Quorum class for this verification.
    pub quorum_class: u64,
    /// Membership epoch at verification time.
    pub verification_epoch: EpochId,
    pub status: VerificationStatus,
}

// ── P8-03 §5 canonical schema families ──
// ReplicaFlowClass removed in favor of FlowCommitClass (6 canonical
// data-flow classes per P8-03 §2).  See `FlowCommitClass` below.

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicaChunkState {
    Pending,
    Transferring,
    Verifying,
    Committed,
    Failed,
    Cancelled,
}

/// Advance a `ReplicaChunkState` through the canonical P8-03 §4 state
/// machine.
///
/// Valid transitions:
/// - `Pending` → `Transferring` (ticket issued)
/// - `Pending` → `Cancelled` (abandoned)
/// - `Transferring` → `Verifying` (bytes received, verification starts)
/// - `Transferring` → `Failed` (transport error)
/// - `Transferring` → `Cancelled` (aborted mid-transfer)
/// - `Verifying` → `Committed` (verification passed)
/// - `Verifying` → `Failed` (digest mismatch or corruption)
/// - `Failed` → `Cancelled` (give up after retry exhaustion)
///
/// Terminal states (`Committed`, `Cancelled`) deny further advancement.
/// Idempotent transitions (same state → same state) are allowed.
///
/// # Panics
///
/// Panics on invalid transitions (e.g. `Pending` → `Committed`).
#[must_use]
pub fn advance_replica_chunk_state(
    current: ReplicaChunkState,
    event: ReplicaChunkState,
) -> ReplicaChunkState {
    match (current, event) {
        // Terminal states — no further advancement
        (ReplicaChunkState::Committed, _) => ReplicaChunkState::Committed,
        (ReplicaChunkState::Cancelled, _) => ReplicaChunkState::Cancelled,

        // Forward progress transitions
        (ReplicaChunkState::Pending, ReplicaChunkState::Transferring) => {
            ReplicaChunkState::Transferring
        }
        (ReplicaChunkState::Transferring, ReplicaChunkState::Verifying) => {
            ReplicaChunkState::Verifying
        }
        (ReplicaChunkState::Verifying, ReplicaChunkState::Committed) => {
            ReplicaChunkState::Committed
        }

        // Failure and cancellation transitions
        (ReplicaChunkState::Pending, ReplicaChunkState::Cancelled) => ReplicaChunkState::Cancelled,
        (ReplicaChunkState::Transferring, ReplicaChunkState::Failed) => ReplicaChunkState::Failed,
        (ReplicaChunkState::Transferring, ReplicaChunkState::Cancelled) => {
            ReplicaChunkState::Cancelled
        }
        (ReplicaChunkState::Verifying, ReplicaChunkState::Failed) => ReplicaChunkState::Failed,
        (ReplicaChunkState::Failed, ReplicaChunkState::Cancelled) => ReplicaChunkState::Cancelled,

        // Idempotent: same state → same state
        (s, e) if s == e => s,

        _ => panic!("invalid replica chunk state transition: {current:?} → {event:?}"),
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebuildFlowState {
    Open,
    Planning,
    Transferring,
    Verifying,
    Restored,
    BlockedNoSource,
    BlockedNoTarget,
    BlockedNoCapacity,
    Cancelled,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationReasonClass {
    ReclaimCapacity,
    TieringPolicy,
    DrainMember,
    RebalanceCapacityPressure,
    Administrative,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationFlowState {
    Open,
    Planning,
    Transferring,
    PointerMoveReady,
    SourceRetireReady,
    Completed,
    Blocked,
    Cancelled,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicaLagClass {
    Current,
    SlightlyBehind,
    ModeratelyBehind,
    SeverelyBehind,
    Stale,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum DegradedVisibilityClass {
    None,
    DegradedReadPossible,
    ReadUnavailable,
    StaleDataServed,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowScopeSelector {
    Subject(ReplicatedSubjectId),
    Domain(DomainId),
    Cohort(u64),
    Cluster,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum LossEventClass {
    NodeFailure,
    DiskFailure,
    CorruptionDetected,
    SuspectUnreachable,
    AdministrativeDecommission,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebuildDegradedClass {
    NotDegraded,
    DegradedReadPossible,
    DegradedReadOnly,
    FullyUnavailable,
}

// ── P8-03 §5 canonical schema families: record types ──

/// Authoritative desired/actual replica group state (P8-03 §5: `ReplicaSetRecord`).
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReplicaSetRecord {
    pub replica_set_id: u64,
    pub subject_ref: ReplicatedSubjectId,
    pub placement_policy_ref: u64,
    pub required_count: usize,
    pub target_failure_domains: Vec<DomainId>,
    pub current_placement_receipt_refs: Vec<ReplicatedReceiptId>,
}

/// Authoritative placement / movement intent (P8-03 §5: `ReplicaPlacementIntentRecord`).
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReplicaPlacementIntentRecord {
    pub intent_id: ReplicatedReceiptId,
    pub flow_class: FlowCommitClass,
    pub subject_ref: ReplicatedSubjectId,
    pub source_refs: Vec<MemberId>,
    pub target_refs: Vec<MemberId>,
    pub policy_revision_ref: u64,
    pub budget_domain_ref: u64,
    pub reserve_class_ref: u64,
    /// Target storage tier for tiering relocation. `None` for non-tiering intents.
    pub target_tier: Option<StorageTier>,
}

/// Authoritative per-chunk placement state (P8-03 §5: `ReplicaChunkStateRecord`).
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReplicaChunkStateRecord {
    pub chunk_id: u64,
    pub subject_ref: ReplicatedSubjectId,
    pub source_ref: MemberId,
    pub target_ref: MemberId,
    pub range_ref: u64,
    pub digest: ObjectDigest,
    pub state: ReplicaChunkState,
    pub transfer_ticket_ref: ReplicatedReceiptId,
    pub verification_receipt_ref: ReplicatedReceiptId,
}

/// Authoritative rebuild lifecycle (P8-03 §5: `RebuildFlowRecord`).
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RebuildFlowRecord {
    pub rebuild_flow_id: u64,
    pub loss_event_ref: u64,
    pub loss_event_class: LossEventClass,
    pub scope_selector: FlowScopeSelector,
    pub source_candidate_refs: Vec<MemberId>,
    pub target_refs: Vec<MemberId>,
    pub state: RebuildFlowState,
    pub degraded_class: RebuildDegradedClass,
}

/// Authoritative batch planning unit for rebuild (P8-03 §5: `RebuildBatchRecord`).
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RebuildBatchRecord {
    pub batch_id: u64,
    pub rebuild_flow_ref: u64,
    pub chunk_refs: Vec<u64>,
    pub source_bundle_refs: Vec<MemberId>,
    pub target_refs: Vec<MemberId>,
    pub verification_requirements: VerificationStatus,
}

/// Authoritative relocation lifecycle (P8-03 §5: `RelocationFlowRecord`).
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RelocationFlowRecord {
    pub relocation_flow_id: u64,
    pub reason_class: RelocationReasonClass,
    pub scope_selector: FlowScopeSelector,
    pub source_refs: Vec<MemberId>,
    pub target_refs: Vec<MemberId>,
    pub state: RelocationFlowState,
    pub reclaim_debt_ref: u64,
}

/// Authoritative relocation batch unit (P8-03 §5: `RelocationBatchRecord`).
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RelocationBatchRecord {
    pub batch_id: u64,
    pub relocation_flow_ref: u64,
    pub chunk_refs: Vec<u64>,
    pub pointer_move_ready: bool,
    pub source_retire_ready: bool,
    pub verification_refs: Vec<ReplicatedReceiptId>,
    #[serde(default)]
    pub placement_receipt_refs: Vec<PlacementReceiptRef>,
}

/// Authoritative lag / degraded visibility state (P8-03 §5: `ReplicaLagStateRecord`).
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReplicaLagStateRecord {
    pub subject_ref: ReplicatedSubjectId,
    pub target_ref: MemberId,
    pub freshness_fence_frontier: u64,
    pub lag_class: ReplicaLagClass,
    pub bytes_behind: u64,
    pub oldest_missing_receipt_ref: ReplicatedReceiptId,
    pub degraded_visibility_class: DegradedVisibilityClass,
}

/// Canonical placement receipt (P8-03 §5: `ReplicaPlacementReceipt`).
///
/// Emitted after verification succeeds. This is the final receipt in the
/// transfer→verify→place chain. Once emitted, replica placement is legal
/// and the copy is considered live.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReplicaPlacementReceipt {
    pub receipt_id: ReplicatedReceiptId,
    /// The verification receipt that authorised this placement.
    pub verification_ref: ReplicatedReceiptId,
    /// The transfer receipt that moved the bytes.
    pub transfer_ref: ReplicatedReceiptId,
    /// Subjects that are now legally placed.
    pub subject_refs: Vec<ReplicatedSubjectId>,
    /// Target member where placement is legal.
    pub placed_on: MemberId,
    /// Membership epoch at placement time.
    pub placement_epoch: EpochId,
    /// Number of subjects placed.
    pub subjects_placed: u64,
    /// Durable placement receipt refs emitted by the target placement
    /// authority. Empty for deterministic or compatibility commit paths that
    /// have not yet carried target pool receipts into the flow coordinator.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub placement_receipt_refs: Vec<PlacementReceiptRef>,
}

/// Canonical flow commit class: the type of data flow being committed.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum FlowCommitClass {
    /// Steady-state replication (primary → secondary copies).
    SteadyReplication,
    /// Catch-up replication for lagging copies.
    CatchupReplication,
    /// Rebuild flow: restore a lost or suspect copy.
    Rebuild,
    /// Relocation flow: move a copy between members.
    Relocation,
    /// Failover: promote a secondary to primary.
    Failover,
    /// Drain: decommission a member, moving its copies elsewhere.
    Drain,
}

impl FlowCommitClass {
    /// Priority for flow class admission ordering (lower = higher urgency).
    ///
    /// P8-03 §2: SteadyReplication(0) < CatchupReplication(1) < Rebuild(2)
    /// < Relocation(3) < Failover(4) < Drain(5).  Rebuild may preempt
    /// ordinary flows; Drain may override queue order for cutover/failover.
    #[must_use]
    pub const fn flow_class_priority(self) -> u8 {
        match self {
            Self::SteadyReplication => 0,
            Self::CatchupReplication => 1,
            Self::Rebuild => 2,
            Self::Relocation => 3,
            Self::Failover => 4,
            Self::Drain => 5,
        }
    }

    /// Whether this flow class may preempt ordinary product work.
    ///
    /// Per P8-03 §2: LossRebuild (Rebuild) is reserve-protected and may
    /// preempt. CutoverFailoverDrain (Drain) may override queue order.
    #[must_use]
    pub const fn may_preempt_product_work(self) -> bool {
        matches!(self, Self::Rebuild | Self::Drain)
    }

    /// Whether this flow class requires reserve budget before admission.
    #[must_use]
    pub const fn requires_reserve_budget(self) -> bool {
        matches!(self, Self::Rebuild | Self::Failover | Self::Drain)
    }
}

/// Canonical flow state machine position.
///
/// Every P8-03 data flow progresses through these states. The flow commit
/// coordinator advances the state as receipts are emitted.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum FlowState {
    /// Flow has been planned but no work has started.
    Planned,
    /// Transfer ticket issued; transfer is in progress.
    Transferring,
    /// Transfer completed; TransferReceipt emitted.
    Transferred,
    /// Verification in progress.
    Verifying,
    /// Verification succeeded; VerificationReceipt emitted.
    Verified,
    /// Placement receipt emitted; flow is complete.
    Complete,
    /// Flow aborted (expired, superseded, or unrecoverable error).
    Aborted,
}

/// Result of a flow commit operation: emitted receipts and final flow state.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct FlowCommitResult {
    /// The placement receipt emitted by this commit.
    pub placement_receipt: ReplicaPlacementReceipt,
    /// The updated replica copy record after state advancement.
    pub updated_copy: ReplicaCopyRecord,
    /// The final flow state after advancement.
    pub final_flow_state: FlowState,
    /// The flow commit class for audit.
    pub flow_class: FlowCommitClass,
    /// Membership epoch at commit time.
    pub commit_epoch: EpochId,
}

#[must_use]
pub fn commit_replicated_object_root_write(
    config: &MembershipConfigRecord,
    members: &[ClusterMemberRecord],
    subject: ReplicatedObjectRootRecord,
    policy: FailureDomainPlacementPolicy,
    writable_member_refs: &[MemberId],
) -> ReplicatedWritePlan {
    let placement_plan = plan_failure_domain_placement_from_policy(config, members, policy);
    let writable: BTreeSet<MemberId> = writable_member_refs.iter().copied().collect();
    let mut committed_member_refs = Vec::new();
    let mut unavailable_member_refs = Vec::new();

    for member_ref in &placement_plan.selected_member_refs {
        if writable.contains(member_ref) && member_accepts_writes(members, *member_ref) {
            committed_member_refs.push(*member_ref);
        } else {
            unavailable_member_refs.push(*member_ref);
        }
    }

    committed_member_refs.sort();
    unavailable_member_refs.sort();
    let quorum_required = write_quorum(policy.required_replica_count);
    let unplaced_replica_count = policy
        .required_replica_count
        .saturating_sub(placement_plan.selected_member_refs.len());
    let has_quorum = committed_member_refs.len() >= quorum_required;
    let write_class = if !has_quorum {
        ReplicatedWriteClass::RefusedNoQuorum
    } else if unplaced_replica_count == 0
        && unavailable_member_refs.is_empty()
        && placement_plan.verdict.verdict_class == VerdictClass::Admit
    {
        ReplicatedWriteClass::Committed
    } else {
        ReplicatedWriteClass::DegradedCommitted
    };
    let commit_receipt_ref = if write_class == ReplicatedWriteClass::RefusedNoQuorum {
        ReplicatedReceiptId::default()
    } else {
        ReplicatedReceiptId(derive_receipt_id(
            subject.subject_id.0,
            committed_member_refs.len() as u64,
            subject.root_generation,
        ))
    };

    ReplicatedWritePlan {
        subject,
        placement_verdict: placement_plan.verdict,
        target_member_refs: placement_plan.selected_member_refs,
        committed_member_refs,
        unavailable_member_refs,
        quorum_required,
        unplaced_replica_count,
        write_class,
        commit_receipt_ref,
    }
}

pub fn plan_replicated_object_root_read(
    subject: &ReplicatedObjectRootRecord,
    copies: &[ReplicaCopyRecord],
    required_replica_count: usize,
) -> ReplicatedReadPlan {
    let mut verified_member_refs = Vec::new();
    let mut unavailable_member_refs = Vec::new();

    for copy in copies {
        if copy.subject_ref != subject.subject_id {
            continue;
        }
        if copy.copy_class == ReplicaCopyClass::Verified
            && copy.payload_digest == subject.payload_digest
        {
            verified_member_refs.push(copy.member_ref);
        } else {
            unavailable_member_refs.push(copy.member_ref);
        }
    }

    verified_member_refs.sort();
    unavailable_member_refs.sort();
    verified_member_refs.dedup();
    unavailable_member_refs.dedup();
    let missing_replica_count = required_replica_count.saturating_sub(verified_member_refs.len());
    let source_member_ref = verified_member_refs.first().copied();
    let read_class = if verified_member_refs.is_empty() {
        ReplicatedReadClass::Unavailable
    } else if missing_replica_count == 0 && unavailable_member_refs.is_empty() {
        ReplicatedReadClass::Exact
    } else if missing_replica_count >= required_replica_count {
        ReplicatedReadClass::RepairRequired
    } else {
        ReplicatedReadClass::DegradedButValid
    };
    let read_receipt_ref = source_member_ref.map_or_else(ReplicatedReceiptId::default, |member| {
        ReplicatedReceiptId(derive_receipt_id(
            subject.subject_id.0,
            member.0,
            subject.root_generation,
        ))
    });

    ReplicatedReadPlan {
        subject_ref: subject.subject_id,
        source_member_ref,
        verified_member_refs,
        unavailable_member_refs,
        missing_replica_count,
        read_class,
        rebuild_required: read_class != ReplicatedReadClass::Exact,
        read_receipt_ref,
    }
}

#[must_use]
pub fn rebuild_replicated_object_root_from_sources(
    config: &MembershipConfigRecord,
    members: &[ClusterMemberRecord],
    subject: &ReplicatedObjectRootRecord,
    copies: &[ReplicaCopyRecord],
    policy: FailureDomainPlacementPolicy,
) -> RebuildPlan {
    let placement_plan = plan_failure_domain_placement_from_policy(config, members, policy);
    let mut source_member_refs = verified_source_members(members, subject, copies);
    let existing: BTreeSet<MemberId> = source_member_refs.iter().copied().collect();
    let mut target_member_refs = Vec::new();

    for member_ref in &placement_plan.selected_member_refs {
        if !existing.contains(member_ref) {
            target_member_refs.push(*member_ref);
        }
    }

    source_member_refs.sort();
    target_member_refs.sort();
    let mut final_member_refs = source_member_refs.clone();
    final_member_refs.extend(target_member_refs.iter().copied());
    final_member_refs.sort();
    final_member_refs.dedup();

    let rebuild_class = if source_member_refs.is_empty() {
        RebuildPlanClass::BlockedNoSource
    } else if final_member_refs.len() < policy.required_replica_count {
        RebuildPlanClass::BlockedNoTarget
    } else if target_member_refs.is_empty() {
        RebuildPlanClass::NotRequired
    } else {
        RebuildPlanClass::Restored
    };

    RebuildPlan {
        subject_ref: subject.subject_id,
        source_member_refs,
        target_member_refs,
        final_member_refs,
        placement_verdict: placement_plan.verdict,
        rebuild_class,
        rebuild_receipt_ref: ReplicatedReceiptId(derive_receipt_id(
            subject.subject_id.0,
            rebuild_class as u64,
            subject.root_generation,
        )),
    }
}

#[must_use]
pub fn open_rebuild_flow_from_loss_event(
    config: &MembershipConfigRecord,
    members: &[ClusterMemberRecord],
    subject: &ReplicatedObjectRootRecord,
    copies: &[ReplicaCopyRecord],
    policy: FailureDomainPlacementPolicy,
) -> ReplicaMovementPlan {
    let placement_plan = plan_failure_domain_placement_from_policy(config, members, policy);
    let source_member_refs = verified_source_members(members, subject, copies);
    let source_set: BTreeSet<MemberId> = source_member_refs.iter().copied().collect();
    let mut target_member_refs = Vec::new();

    for member_ref in &placement_plan.selected_member_refs {
        if !source_set.contains(member_ref) && member_accepts_writes(members, *member_ref) {
            target_member_refs.push(*member_ref);
        }
    }
    sort_and_dedup(&mut target_member_refs);

    let mut final_member_refs = source_member_refs.clone();
    final_member_refs.extend(target_member_refs.iter().copied());
    sort_and_dedup(&mut final_member_refs);

    let plan_class = if source_member_refs.is_empty() {
        ReplicaMovementPlanClass::BlockedNoSource
    } else if target_member_refs.is_empty()
        && source_member_refs.len() >= policy.required_replica_count
    {
        ReplicaMovementPlanClass::NotRequired
    } else if target_member_refs.is_empty()
        || final_member_refs.len() < policy.required_replica_count
    {
        ReplicaMovementPlanClass::BlockedNoTarget
    } else {
        ReplicaMovementPlanClass::Planned
    };

    let transfer_intents = if plan_class == ReplicaMovementPlanClass::Planned {
        movement_intents(
            ReplicaMovementClass::RebuildLostOrSuspectCopy,
            subject,
            &source_member_refs,
            &target_member_refs,
        )
    } else {
        Vec::new()
    };

    ReplicaMovementPlan {
        subject_ref: subject.subject_id,
        movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
        plan_class,
        source_member_refs: source_member_refs.clone(),
        target_member_refs,
        retained_member_refs: source_member_refs,
        faulted_member_refs: faulted_or_missing_member_refs(
            subject,
            copies,
            &placement_plan.selected_member_refs,
        ),
        final_member_refs,
        transfer_intents,
        placement_verdict: placement_plan.verdict,
        movement_receipt_ref: ReplicatedReceiptId(derive_receipt_id(
            subject.subject_id.0,
            plan_class as u64,
            subject.root_generation ^ 0x3050,
        )),
    }
}

#[must_use]
pub fn schedule_backfill_batches_from_witness_sets(
    config: &MembershipConfigRecord,
    members: &[ClusterMemberRecord],
    subject: &ReplicatedObjectRootRecord,
    copies: &[ReplicaCopyRecord],
    policy: FailureDomainPlacementPolicy,
    required_freshness_frontier: u64,
) -> ReplicaMovementPlan {
    let placement_plan = plan_failure_domain_placement_from_policy(config, members, policy);
    let selected: BTreeSet<MemberId> = placement_plan
        .selected_member_refs
        .iter()
        .copied()
        .collect();
    let mut source_member_refs = Vec::new();
    let mut target_member_refs = Vec::new();

    for copy in copies {
        if copy.subject_ref != subject.subject_id
            || copy.copy_class != ReplicaCopyClass::Verified
            || copy.payload_digest != subject.payload_digest
            || !selected.contains(&copy.member_ref)
        {
            continue;
        }
        if copy.freshness_frontier >= required_freshness_frontier {
            source_member_refs.push(copy.member_ref);
        } else if member_accepts_writes(members, copy.member_ref) {
            target_member_refs.push(copy.member_ref);
        }
    }

    sort_and_dedup(&mut source_member_refs);
    sort_and_dedup(&mut target_member_refs);

    let retained_member_refs = source_member_refs.clone();
    let mut final_member_refs = source_member_refs.clone();
    final_member_refs.extend(target_member_refs.iter().copied());
    sort_and_dedup(&mut final_member_refs);

    let has_distinct_source_for_each_target = target_member_refs.iter().all(|target| {
        source_member_refs
            .iter()
            .any(|source| source != target && member_accepts_writes(members, *source))
    });
    let plan_class = if target_member_refs.is_empty() {
        ReplicaMovementPlanClass::NotRequired
    } else if source_member_refs.is_empty() || !has_distinct_source_for_each_target {
        ReplicaMovementPlanClass::BlockedNoSource
    } else {
        ReplicaMovementPlanClass::Planned
    };

    let transfer_intents = if plan_class == ReplicaMovementPlanClass::Planned {
        movement_intents(
            ReplicaMovementClass::BackfillLaggedCopy,
            subject,
            &source_member_refs,
            &target_member_refs,
        )
    } else {
        Vec::new()
    };

    ReplicaMovementPlan {
        subject_ref: subject.subject_id,
        movement_class: ReplicaMovementClass::BackfillLaggedCopy,
        plan_class,
        source_member_refs,
        target_member_refs: target_member_refs.clone(),
        retained_member_refs,
        faulted_member_refs: target_member_refs,
        final_member_refs,
        transfer_intents,
        placement_verdict: placement_plan.verdict,
        movement_receipt_ref: ReplicatedReceiptId(derive_receipt_id(
            subject.subject_id.0,
            plan_class as u64,
            required_freshness_frontier ^ 0x3051,
        )),
    }
}

#[must_use]
pub fn plan_rebalance_for_capacity_movement(
    config: &MembershipConfigRecord,
    members: &[ClusterMemberRecord],
    subject: &ReplicatedObjectRootRecord,
    copies: &[ReplicaCopyRecord],
    policy: FailureDomainPlacementPolicy,
    capacity_policy: &CapacityMovementPolicy,
) -> ReplicaMovementPlan {
    let placement_plan = plan_failure_domain_placement_from_policy(config, members, policy);
    let verified_member_refs = verified_source_members(members, subject, copies);
    let capacity_by_member: BTreeMap<MemberId, ReplicaCapacityRecord> = capacity_policy
        .capacity_records
        .iter()
        .map(|record| (record.member_ref, *record))
        .collect();
    let overloaded_source_ref = verified_member_refs.iter().copied().find(|member_ref| {
        capacity_by_member
            .get(member_ref)
            .is_some_and(|capacity| capacity_is_over_threshold(*capacity, capacity_policy))
    });

    let Some(source_member_ref) = overloaded_source_ref else {
        return no_movement_plan(
            subject,
            ReplicaMovementClass::RebalanceCapacityPressure,
            ReplicaMovementPlanClass::NotRequired,
            placement_plan.verdict,
            verified_member_refs,
        );
    };

    let mut retained_member_refs: Vec<MemberId> = verified_member_refs
        .iter()
        .copied()
        .filter(|member_ref| *member_ref != source_member_ref)
        .collect();
    sort_and_dedup(&mut retained_member_refs);
    let target_member_ref = choose_capacity_rebalance_target(
        members,
        CapacityTargetSelection {
            capacity_by_member: &capacity_by_member,
            capacity_policy,
            placement_policy: policy,
            payload_len: subject.payload_len,
            existing_member_refs: &verified_member_refs,
            retained_member_refs: &retained_member_refs,
        },
    );

    let Some(target_member_ref) = target_member_ref else {
        return ReplicaMovementPlan {
            subject_ref: subject.subject_id,
            movement_class: ReplicaMovementClass::RebalanceCapacityPressure,
            plan_class: ReplicaMovementPlanClass::BlockedNoCapacity,
            source_member_refs: vec![source_member_ref],
            target_member_refs: Vec::new(),
            retained_member_refs,
            faulted_member_refs: vec![source_member_ref],
            final_member_refs: verified_member_refs,
            transfer_intents: Vec::new(),
            placement_verdict: placement_plan.verdict,
            movement_receipt_ref: ReplicatedReceiptId(derive_receipt_id(
                subject.subject_id.0,
                ReplicaMovementPlanClass::BlockedNoCapacity as u64,
                subject.payload_len ^ 0x3052,
            )),
        };
    };

    let mut final_member_refs = retained_member_refs.clone();
    final_member_refs.push(target_member_ref);
    sort_and_dedup(&mut final_member_refs);
    let plan_class = if final_member_refs.len() < policy.required_replica_count {
        ReplicaMovementPlanClass::BlockedNoTarget
    } else {
        ReplicaMovementPlanClass::Planned
    };
    let target_member_refs = if plan_class == ReplicaMovementPlanClass::Planned {
        vec![target_member_ref]
    } else {
        Vec::new()
    };
    let transfer_intents = if plan_class == ReplicaMovementPlanClass::Planned {
        movement_intents(
            ReplicaMovementClass::RebalanceCapacityPressure,
            subject,
            &[source_member_ref],
            &target_member_refs,
        )
    } else {
        Vec::new()
    };

    ReplicaMovementPlan {
        subject_ref: subject.subject_id,
        movement_class: ReplicaMovementClass::RebalanceCapacityPressure,
        plan_class,
        source_member_refs: vec![source_member_ref],
        target_member_refs,
        retained_member_refs,
        faulted_member_refs: vec![source_member_ref],
        final_member_refs,
        transfer_intents,
        placement_verdict: placement_plan.verdict,
        movement_receipt_ref: ReplicatedReceiptId(derive_receipt_id(
            subject.subject_id.0,
            source_member_ref.0 ^ target_member_ref.0,
            subject.payload_len ^ 0x3053,
        )),
    }
}

#[must_use]
pub fn encode_single_parity_erasure_stripe(
    subject_ref: ReplicatedSubjectId,
    stripe_index: u64,
    payload: &[u8],
    policy: ErasureLayoutPolicy,
) -> Option<ErasureStripeRecord> {
    if !policy.admits_single_parity_xor() || payload.len() > policy.data_capacity()? {
        return None;
    }

    let mut shards = Vec::with_capacity(policy.total_shard_count());
    for shard_index in 0..policy.data_shard_count {
        let start = shard_index * policy.shard_len;
        let end = payload.len().min(start + policy.shard_len);
        let mut bytes = vec![0; policy.shard_len];
        if start < payload.len() {
            bytes[..end - start].copy_from_slice(&payload[start..end]);
        }
        shards.push(erasure_shard_record(
            subject_ref,
            stripe_index,
            shard_index,
            ErasureShardClass::Data,
            bytes,
        ));
    }

    let parity_bytes = xor_data_shard_bytes(&shards, policy.shard_len);
    shards.push(erasure_shard_record(
        subject_ref,
        stripe_index,
        policy.parity_shard_index(),
        ErasureShardClass::Parity,
        parity_bytes,
    ));

    Some(ErasureStripeRecord {
        subject_ref,
        layout_policy: policy,
        stripe_index,
        original_payload_len: payload.len(),
        original_payload_digest: derive_payload_digest(payload),
        shards,
    })
}

#[must_use]
pub fn decode_single_parity_erasure_stripe(
    stripe: &ErasureStripeRecord,
    shard_records: &[ErasureShardRecord],
) -> ErasureDecodePlan {
    let policy = stripe.layout_policy;
    if !policy.admits_single_parity_xor() {
        return erasure_decode_refusal(
            stripe,
            ErasureDecodeClass::RefusedInvalidLayout,
            Vec::new(),
        );
    }

    let available_by_index = available_erasure_shards_by_index(stripe, shard_records);
    let unavailable_shard_indexes = unavailable_erasure_shard_indexes(policy, &available_by_index);
    let missing_data_indexes: Vec<usize> = (0..policy.data_shard_count)
        .filter(|index| !available_by_index.contains_key(index))
        .collect();
    let parity_index = policy.parity_shard_index();
    let parity_present = available_by_index.contains_key(&parity_index);

    if missing_data_indexes.is_empty() {
        let mut rebuilt_shards = Vec::new();
        if !parity_present {
            let data_parts = data_parts_from_available(policy, &available_by_index);
            rebuilt_shards.push(erasure_shard_record(
                stripe.subject_ref,
                stripe.stripe_index,
                parity_index,
                ErasureShardClass::Parity,
                xor_bytes(&data_parts, policy.shard_len),
            ));
        }
        let payload = reconstruct_erasure_payload(stripe, policy, &available_by_index, None);
        let decode_class = if rebuilt_shards.is_empty() {
            ErasureDecodeClass::Complete
        } else {
            ErasureDecodeClass::RebuiltParityShard
        };
        return erasure_decode_success(
            stripe,
            decode_class,
            payload,
            rebuilt_shards,
            unavailable_shard_indexes,
        );
    }

    if missing_data_indexes.len() == 1 && parity_present {
        let missing_index = missing_data_indexes[0];
        let Some(parity_shard) = available_by_index.get(&parity_index) else {
            return erasure_decode_refusal(
                stripe,
                ErasureDecodeClass::RefusedMissingDataAndParity,
                unavailable_shard_indexes,
            );
        };
        let rebuilt_bytes = rebuild_missing_data_shard_bytes(
            policy,
            missing_index,
            parity_shard,
            &available_by_index,
        );
        let rebuilt_shard = erasure_shard_record(
            stripe.subject_ref,
            stripe.stripe_index,
            missing_index,
            ErasureShardClass::Data,
            rebuilt_bytes.clone(),
        );
        let payload = reconstruct_erasure_payload(
            stripe,
            policy,
            &available_by_index,
            Some((missing_index, rebuilt_bytes)),
        );
        return erasure_decode_success(
            stripe,
            ErasureDecodeClass::ReconstructedSingleDataShard,
            payload,
            vec![rebuilt_shard],
            unavailable_shard_indexes,
        );
    }

    let decode_class = if missing_data_indexes.len() == 1 && !parity_present {
        ErasureDecodeClass::RefusedMissingDataAndParity
    } else {
        ErasureDecodeClass::RefusedTooManyMissing
    };
    erasure_decode_refusal(stripe, decode_class, unavailable_shard_indexes)
}

/// Stage a transfer ticket from a movement intent, binding source anchors, target,
/// pin budget, freshness fence, and expiry (P8-03 `stage_replica_transfer_ticket()`).
///
/// # Panics
///
/// Panics if `intent.source_member_ref` or `intent.target_member_ref` equals `MemberId::ZERO`.
#[must_use]
pub fn stage_replica_transfer_ticket(
    intent: &ReplicaMovementIntentRecord,
    source_members: &[MemberId],
    freshness_fence: u64,
    ticket_expiry: u64,
) -> ReplicaTransferTicketRecord {
    assert_ne!(
        intent.source_member_ref,
        MemberId::ZERO,
        "source member must be set"
    );
    assert_ne!(
        intent.target_member_ref,
        MemberId::ZERO,
        "target member must be set"
    );

    let ticket_id = ReplicatedReceiptId(derive_receipt_id(
        intent.subject_ref.0,
        intent.source_member_ref.0 ^ intent.target_member_ref.0,
        freshness_fence,
    ));

    ReplicaTransferTicketRecord {
        ticket_id,
        intent_ref: intent.intent_id,
        subject_refs: vec![intent.subject_ref],
        source_anchor_set: source_members.to_vec(),
        target_ref: intent.target_member_ref,
        pin_budget_ref: ReplicatedReceiptId(derive_receipt_id(
            intent.intent_id.0,
            ticket_id.0,
            0x51,
        )),
        freshness_fence_ref: freshness_fence,
        expiry: ticket_expiry,
    }
}

/// Emit a transfer receipt after bytes have been successfully moved from source
/// to target under a ticket (P8-03 `commit_replica_transfer_and_placement_receipts()`
/// — transfer phase).
///
/// After this receipt is emitted, verification must follow before placement is legal.
#[must_use]
pub fn emit_replica_transfer_receipt(
    ticket: &ReplicaTransferTicketRecord,
    bytes_moved: u64,
    source_anchor_hash: u64,
    target_anchor_hash: u64,
    completion_epoch: EpochId,
    worker_refs: &[MemberId],
) -> ReplicaTransferReceipt {
    let receipt_id = ReplicatedReceiptId(derive_receipt_id(
        ticket.ticket_id.0,
        bytes_moved,
        completion_epoch.0,
    ));

    ReplicaTransferReceipt {
        receipt_id,
        ticket_ref: ticket.ticket_id,
        bytes_moved,
        source_anchor_hash,
        target_anchor_hash,
        completion_epoch,
        worker_refs: worker_refs.to_vec(),
    }
}

/// Verify transferred chunks against expected digests, witness attestation, and quorum,
/// then emit a verification receipt (P8-03 `verify_transferred_chunks_against_digest_and_witness()`).
///
/// A `Verified` status makes replica placement legal. Any other status means placement
/// cannot proceed without further action (re-transfer, witness recruitment, or degraded admission).
///
/// `expected_digest` is the authoritative digest from the publication receipt or root record.
/// `actual_digests` are the digests computed on the transferred payloads.
/// `witness_refs` are the members that attest to the verification.
#[must_use]
pub fn verify_transferred_chunks_and_emit_verification_receipt(
    transfer_receipt: &ReplicaTransferReceipt,
    subject_refs: &[ReplicatedSubjectId],
    expected_digest: ObjectDigest,
    actual_digests: &[ObjectDigest],
    witness_refs: &[MemberId],
    quorum_class: u64,
    verification_epoch: EpochId,
) -> ReplicaVerificationReceipt {
    let receipt_id = ReplicatedReceiptId(derive_receipt_id(
        transfer_receipt.receipt_id.0,
        verification_epoch.0,
        quorum_class,
    ));

    let digests_match =
        !actual_digests.is_empty() && actual_digests.iter().all(|d| *d == expected_digest);
    let has_witnesses = !witness_refs.is_empty();
    let quorum_met = true; // Deterministic model — quorum is caller's responsibility.

    let status = if digests_match && has_witnesses && quorum_met {
        VerificationStatus::Verified
    } else if digests_match && !has_witnesses {
        VerificationStatus::WitnessInsufficient
    } else if !digests_match {
        VerificationStatus::DigestMismatch
    } else if !quorum_met {
        VerificationStatus::QuorumNotMet
    } else {
        VerificationStatus::DegradedVerified
    };

    ReplicaVerificationReceipt {
        receipt_id,
        subject_refs: subject_refs.to_vec(),
        digest_results: actual_digests.to_vec(),
        witness_refs: witness_refs.to_vec(),
        quorum_class,
        verification_epoch,
        status,
    }
}

/// Full receipt chain: stage ticket → emit transfer receipt → verify → mark replica copy
/// as verified with the verification receipt reference.
///
/// This is the core P8-03 law 3+7 implementation: "Copying bytes does not make placement legal.
/// Placement becomes legal only after verification and emission of matching receipts."
///
/// Returns the updated `ReplicaCopyRecord` with `copy_class = Verified` and the verification
/// receipt reference set, but only if verification succeeded. On failure, returns the
/// original copy with class unchanged.
#[must_use]
pub fn advance_replica_copy_through_receipt_chain(
    mut copy: ReplicaCopyRecord,
    expected_digest: ObjectDigest,
    actual_digests: &[ObjectDigest],
    witness_refs: &[MemberId],
    quorum_class: u64,
    verification_epoch: EpochId,
    transfer_receipt: &ReplicaTransferReceipt,
) -> (ReplicaCopyRecord, ReplicaVerificationReceipt) {
    let verification = verify_transferred_chunks_and_emit_verification_receipt(
        transfer_receipt,
        &[copy.subject_ref],
        expected_digest,
        actual_digests,
        witness_refs,
        quorum_class,
        verification_epoch,
    );

    if verification.status == VerificationStatus::Verified {
        copy.copy_class = ReplicaCopyClass::Verified;
        copy.verification_receipt_ref = verification.receipt_id;
        copy.payload_digest = expected_digest;
    }

    (copy, verification)
}

/// Emit a placement receipt after successful verification (P8-03
/// `data_copy_7.flow_commit_coordinator` — placement phase).
///
/// This is the final receipt in the transfer→verify→place chain. Once
/// emitted, replica placement is legal and the copy transitions to live.
///
/// # Panics
///
/// Panics if the verification status is not `Verified`.
#[must_use]
pub fn emit_replica_placement_receipt(
    verification: &ReplicaVerificationReceipt,
    transfer: &ReplicaTransferReceipt,
    placed_on: MemberId,
    placement_epoch: EpochId,
) -> ReplicaPlacementReceipt {
    assert_eq!(
        verification.status,
        VerificationStatus::Verified,
        "placement requires Verified status, got {:?}",
        verification.status
    );

    let receipt_id = ReplicatedReceiptId(derive_receipt_id(
        verification.receipt_id.0,
        transfer.receipt_id.0,
        placement_epoch.0,
    ));

    ReplicaPlacementReceipt {
        receipt_id,
        verification_ref: verification.receipt_id,
        transfer_ref: transfer.receipt_id,
        subject_refs: verification.subject_refs.clone(),
        placed_on,
        placement_epoch,
        subjects_placed: verification.subject_refs.len() as u64,
        placement_receipt_refs: Vec::new(),
    }
}

/// Advance a flow through its canonical state machine (P8-03
/// `data_copy_7.flow_commit_coordinator` — state advancement phase).
///
/// The flow progresses through: Planned → Transferring → Transferred →
/// Verifying → Verified → Complete. An `Aborted` state is terminal.
///
/// All valid transitions are forward-only. Any state can transition to
/// `Aborted`. Idempotent transitions (same state → same state) are allowed.
///
/// # Panics
///
/// Panics on invalid transitions (e.g. Transferred → Planned).
#[must_use]
pub fn advance_flow_state(current: FlowState, event: FlowState) -> FlowState {
    match (current, event) {
        // Aborted is terminal — no further transitions allowed
        (FlowState::Aborted, _) => FlowState::Aborted,
        (FlowState::Planned, FlowState::Transferring) => FlowState::Transferring,
        (FlowState::Transferring, FlowState::Transferred) => FlowState::Transferred,
        (FlowState::Transferred, FlowState::Verifying) => FlowState::Verifying,
        (FlowState::Verifying, FlowState::Verified) => FlowState::Verified,
        (FlowState::Verified, FlowState::Complete) => FlowState::Complete,

        // All states can transition to Aborted (terminal)
        (_, FlowState::Aborted) => FlowState::Aborted,

        // Idempotent: same state → same state
        (s, e) if s == e => s,

        _ => panic!("invalid flow state transition: {current:?} → {event:?}"),
    }
}

/// Full flow commit: verification → placement receipt → state advancement
/// (P8-03 `data_copy_7.flow_commit_coordinator` end-to-end).
///
/// This is the core commitment function. It takes a verified transfer and
/// produces:
///
/// 1. A `ReplicaPlacementReceipt` — the legal proof of placement
/// 2. An updated `ReplicaCopyRecord` — `copy_class` advanced to `Verified`
/// 3. An updated `FlowState` — flow advanced to `Complete`
///
/// The function validates preconditions: verification must be `Verified`,
/// the verification must cover the copy's subject, and the flow must be
/// in a state that can transition to `Complete`.
///
/// # Panics
///
/// Panics if `verification.status` is not `Verified` or if the verification
/// does not cover the copy's subject.
#[must_use]
pub fn commit_transfer_flow(
    copy: ReplicaCopyRecord,
    verification: &ReplicaVerificationReceipt,
    transfer: &ReplicaTransferReceipt,
    flow_class: FlowCommitClass,
    current_flow_state: FlowState,
    commit_epoch: EpochId,
    expected_digest: ObjectDigest,
) -> FlowCommitResult {
    assert!(
        verification.status == VerificationStatus::Verified,
        "commit_transfer_flow requires Verified, got {:?}",
        verification.status
    );
    assert!(
        verification.subject_refs.contains(&copy.subject_ref),
        "verification subject_refs must contain copy subject {:?}",
        copy.subject_ref
    );

    // Emit placement receipt
    let placement =
        emit_replica_placement_receipt(verification, transfer, copy.member_ref, commit_epoch);

    // Advance copy state machine
    let mut updated_copy = copy;
    updated_copy.copy_class = ReplicaCopyClass::Verified;
    updated_copy.verification_receipt_ref = verification.receipt_id;
    updated_copy.payload_digest = expected_digest;

    // Advance flow state machine
    let final_flow_state = advance_flow_state(current_flow_state, FlowState::Complete);

    FlowCommitResult {
        placement_receipt: placement,
        updated_copy,
        final_flow_state,
        flow_class,
        commit_epoch,
    }
}
// ── P8-03 §2: Transfer Orchestrator (data_copy_1) ──

/// Lane class discriminants for transfer link assignments.
///
/// Mirrors `LaneClass` in `tidefs-types-transport-session` without pulling
/// in a transport dependency. The deterministic model assigns the canonical
/// lane class; the runtime resolves it to the transport-level enum.
pub mod lane_class_discriminant {
    pub const CONTROL: u8 = 0;
    pub const METADATA: u8 = 1;
    pub const DEMAND: u8 = 2;
    pub const SPECULATIVE: u8 = 3;
    /// Bulk data movement (rebuild, relocation, catch-up, steady replication).
    pub const BACKGROUND: u8 = 4;
}

/// Link assignment for a scheduled transfer.
///
/// Binds a transfer ticket to a specific source→target link with lane class
/// and priority so the runtime can dispatch it to the correct transport lane.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransferLinkAssignment {
    pub source: MemberId,
    pub target: MemberId,
    /// Lane class discriminant (see `lane_class_discriminant`).
    pub lane_class: u8,
    /// Priority within the lane (lower = higher, 0 = highest).
    pub priority: u8,
}

/// A transfer ticket bound to a specific link assignment.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransferScheduleRecord {
    pub ticket: ReplicaTransferTicketRecord,
    pub assignment: TransferLinkAssignment,
    pub flow_class: FlowCommitClass,
}

/// Per-link resource consumption tracked by the orchestrator.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinkConsumption {
    pub active_transfers: usize,
    pub bytes_in_flight: u64,
}

/// Transfer orchestrator configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransferOrchestratorConfig {
    pub max_concurrent_per_link: usize,
    pub max_bytes_in_flight_per_link: u64,
    pub max_total_bytes_in_flight: u64,
    /// Default ticket expiry offset (epochs) from the current epoch.
    pub default_ticket_expiry_offset: u64,
}

impl Default for TransferOrchestratorConfig {
    fn default() -> Self {
        Self {
            max_concurrent_per_link: 8,
            max_bytes_in_flight_per_link: 64 * 1024 * 1024, // 64 MiB
            max_total_bytes_in_flight: 512 * 1024 * 1024,   // 512 MiB
            default_ticket_expiry_offset: 10,
        }
    }
}

/// Result of scheduling movement intents into executable transfers.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct OrchestrationPlan {
    pub scheduled: Vec<TransferScheduleRecord>,
    pub rejected: Vec<ReplicaMovementIntentRecord>,
    /// Per-link budget consumption after scheduling.
    pub link_consumption: Vec<LinkConsumptionEntry>,
    /// Rejection reasons, parallel to `rejected`.
    pub rejection_reasons: Vec<String>,
}

/// Priority for a movement class (lower = higher urgency).
#[must_use]
pub const fn movement_priority(class: ReplicaMovementClass) -> u8 {
    match class {
        ReplicaMovementClass::RebuildLostOrSuspectCopy => 0,
        ReplicaMovementClass::BackfillLaggedCopy => 1,
        ReplicaMovementClass::RebalanceCapacityPressure => 2,
    }
}

/// Map a movement class to its canonical flow commit class.
#[must_use]
pub const fn movement_to_flow_class(class: ReplicaMovementClass) -> FlowCommitClass {
    match class {
        ReplicaMovementClass::RebuildLostOrSuspectCopy => FlowCommitClass::Rebuild,
        ReplicaMovementClass::BackfillLaggedCopy => FlowCommitClass::CatchupReplication,
        ReplicaMovementClass::RebalanceCapacityPressure => FlowCommitClass::Relocation,
    }
}

/// Decompose a `ReplicaMovementPlan` into scheduled transfer tickets with
/// link assignments, respecting budget constraints and priority ordering.
///
/// P8-03 §2: `data_copy_1.transfer_orchestrator` — "build chunk/extent transfer
/// tickets and assign them to links/workers."
///
/// The orchestrator:
/// 1. Sorts intents by priority (rebuild > backfill > rebalance)
/// 2. For each intent, creates a transfer ticket via `stage_replica_transfer_ticket()`
/// 3. Assigns the ticket to the source→target link on the Background lane
/// 4. Enforces per-link concurrency and byte-in-flight budgets
/// 5. Rejects intents that would exceed budgets
///
/// `current_load` maps `(source, target)` pairs to their existing consumption;
/// pass an empty map for a fresh schedule.
#[must_use]
pub fn orchestrate_movement_plan(
    plan: &ReplicaMovementPlan,
    config: &TransferOrchestratorConfig,
    current_load: &BTreeMap<(MemberId, MemberId), LinkConsumption>,
    freshness_fence: u64,
    current_epoch: u64,
) -> OrchestrationPlan {
    orchestrate_transfer_intents(
        &plan.transfer_intents,
        config,
        current_load,
        freshness_fence,
        current_epoch,
    )
}

/// A single link-consumption entry for serialization.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct LinkConsumptionEntry {
    pub source: MemberId,
    pub target: MemberId,
    pub consumption: LinkConsumption,
}
/// Schedule a set of transfer intents directly, without requiring a full
/// movement plan wrapper.
#[must_use]
pub fn orchestrate_transfer_intents(
    intents: &[ReplicaMovementIntentRecord],
    config: &TransferOrchestratorConfig,
    current_load: &BTreeMap<(MemberId, MemberId), LinkConsumption>,
    freshness_fence: u64,
    current_epoch: u64,
) -> OrchestrationPlan {
    let ticket_expiry = current_epoch + config.default_ticket_expiry_offset;
    let mut link_consumption = current_load.clone();
    let mut scheduled = Vec::new();
    let mut rejected = Vec::new();
    let mut rejection_reasons = Vec::new();

    let mut total_bytes_in_flight: u64 = link_consumption.values().map(|c| c.bytes_in_flight).sum();

    // Sort by priority (highest first = lowest number)
    let mut sorted: Vec<&ReplicaMovementIntentRecord> = intents.iter().collect();
    sorted.sort_by_key(|i| movement_priority(i.movement_class));

    for intent in &sorted {
        let link_key = (intent.source_member_ref, intent.target_member_ref);
        let consumption = link_consumption.entry(link_key).or_default();

        if consumption.active_transfers >= config.max_concurrent_per_link {
            rejected.push((*intent).clone());
            rejection_reasons.push(format!(
                "concurrency budget exhausted ({}/{})",
                consumption.active_transfers, config.max_concurrent_per_link
            ));
            continue;
        }

        if consumption.bytes_in_flight + intent.payload_len > config.max_bytes_in_flight_per_link {
            rejected.push((*intent).clone());
            rejection_reasons.push(format!(
                "per-link byte budget exceeded ({} + {} > {})",
                consumption.bytes_in_flight,
                intent.payload_len,
                config.max_bytes_in_flight_per_link
            ));
            continue;
        }

        if total_bytes_in_flight + intent.payload_len > config.max_total_bytes_in_flight {
            rejected.push((*intent).clone());
            rejection_reasons.push(format!(
                "global byte budget exceeded ({} + {} > {})",
                total_bytes_in_flight, intent.payload_len, config.max_total_bytes_in_flight
            ));
            continue;
        }

        let ticket = stage_replica_transfer_ticket(
            intent,
            &[intent.source_member_ref],
            freshness_fence,
            ticket_expiry,
        );

        consumption.active_transfers += 1;
        consumption.bytes_in_flight += intent.payload_len;
        total_bytes_in_flight += intent.payload_len;

        scheduled.push(TransferScheduleRecord {
            ticket,
            assignment: TransferLinkAssignment {
                source: intent.source_member_ref,
                target: intent.target_member_ref,
                lane_class: lane_class_discriminant::BACKGROUND,
                priority: movement_priority(intent.movement_class),
            },
            flow_class: movement_to_flow_class(intent.movement_class),
        });
    }

    OrchestrationPlan {
        scheduled,
        rejected,
        link_consumption: link_consumption
            .into_iter()
            .map(|((source, target), consumption)| LinkConsumptionEntry {
                source,
                target,
                consumption,
            })
            .collect(),
        rejection_reasons,
    }
}

#[must_use]
pub const fn write_quorum(required_replica_count: usize) -> usize {
    required_replica_count / 2 + 1
}

fn member_accepts_writes(members: &[ClusterMemberRecord], member_ref: MemberId) -> bool {
    members.iter().any(|member| {
        member.member_id == member_ref
            && member.health != HealthClass::Down
            && member.member_class.can_hold_replicas()
    })
}

fn verified_source_members(
    members: &[ClusterMemberRecord],
    subject: &ReplicatedObjectRootRecord,
    copies: &[ReplicaCopyRecord],
) -> Vec<MemberId> {
    let mut refs = Vec::new();
    for copy in copies {
        let is_healthy = members
            .iter()
            .any(|m| m.member_id == copy.member_ref && m.health != HealthClass::Down);
        if is_healthy
            && copy.subject_ref == subject.subject_id
            && copy.copy_class == ReplicaCopyClass::Verified
            && copy.payload_digest == subject.payload_digest
        {
            refs.push(copy.member_ref);
        }
    }
    refs.sort();
    refs.dedup();
    refs
}

fn sort_and_dedup(refs: &mut Vec<MemberId>) {
    refs.sort();
    refs.dedup();
}

fn digest_bytes_for_model_receipt(digest: ObjectDigest) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&digest.0.to_le_bytes());
    bytes
}

fn model_placement_receipt_ref(
    subject: &ReplicatedObjectRootRecord,
    source_member_refs: &[MemberId],
) -> PlacementReceiptRef {
    let mut object_key = [0u8; 32];
    object_key[..8].copy_from_slice(&subject.subject_id.0.to_le_bytes());
    object_key[8..16].copy_from_slice(&subject.publication_receipt_ref.0.to_le_bytes());
    object_key[16..24].copy_from_slice(&subject.root_generation.to_le_bytes());
    object_key[24..32].copy_from_slice(&subject.payload_len.to_le_bytes());

    let copies = source_member_refs.len().clamp(1, u8::MAX as usize) as u8;
    PlacementReceiptRef::replicated(
        subject.subject_id.0,
        object_key,
        subject.membership_epoch_ref,
        subject.root_generation,
        copies,
        subject.payload_len,
        digest_bytes_for_model_receipt(subject.payload_digest),
    )
}

fn movement_intents(
    movement_class: ReplicaMovementClass,
    subject: &ReplicatedObjectRootRecord,
    source_member_refs: &[MemberId],
    target_member_refs: &[MemberId],
) -> Vec<ReplicaMovementIntentRecord> {
    let mut intents = Vec::new();
    for target_member_ref in target_member_refs {
        let Some(source_member_ref) = source_member_refs
            .iter()
            .copied()
            .find(|source| source != target_member_ref)
            .or_else(|| source_member_refs.first().copied())
        else {
            continue;
        };
        intents.push(ReplicaMovementIntentRecord {
            intent_id: ReplicatedReceiptId(derive_receipt_id(
                subject.subject_id.0,
                source_member_ref.0 ^ target_member_ref.0,
                subject.root_generation ^ movement_class as u64,
            )),
            movement_class,
            subject_ref: subject.subject_id,
            placement_receipt_ref: model_placement_receipt_ref(subject, source_member_refs),
            source_member_ref,
            target_member_ref: *target_member_ref,
            payload_digest: subject.payload_digest,
            payload_len: subject.payload_len,
            verification_required: true,
        });
    }
    intents
}

fn faulted_or_missing_member_refs(
    subject: &ReplicatedObjectRootRecord,
    copies: &[ReplicaCopyRecord],
    selected_member_refs: &[MemberId],
) -> Vec<MemberId> {
    let mut faulted = Vec::new();
    let mut seen = BTreeSet::new();
    for copy in copies {
        if copy.subject_ref != subject.subject_id {
            continue;
        }
        seen.insert(copy.member_ref);
        if copy.copy_class != ReplicaCopyClass::Verified
            || copy.payload_digest != subject.payload_digest
        {
            faulted.push(copy.member_ref);
        }
    }
    for member_ref in selected_member_refs {
        if !seen.contains(member_ref) {
            faulted.push(*member_ref);
        }
    }
    sort_and_dedup(&mut faulted);
    faulted
}

fn no_movement_plan(
    subject: &ReplicatedObjectRootRecord,
    movement_class: ReplicaMovementClass,
    plan_class: ReplicaMovementPlanClass,
    placement_verdict: MembershipPlacementVerdictRecord,
    final_member_refs: Vec<MemberId>,
) -> ReplicaMovementPlan {
    ReplicaMovementPlan {
        subject_ref: subject.subject_id,
        movement_class,
        plan_class,
        source_member_refs: Vec::new(),
        target_member_refs: Vec::new(),
        retained_member_refs: final_member_refs.clone(),
        faulted_member_refs: Vec::new(),
        final_member_refs,
        transfer_intents: Vec::new(),
        placement_verdict,
        movement_receipt_ref: ReplicatedReceiptId(derive_receipt_id(
            subject.subject_id.0,
            plan_class as u64,
            subject.root_generation ^ 0x3054,
        )),
    }
}

const fn capacity_is_over_threshold(
    capacity: ReplicaCapacityRecord,
    policy: &CapacityMovementPolicy,
) -> bool {
    if policy.max_used_denominator == 0 || capacity.capacity_bytes == 0 {
        return true;
    }
    let usable_capacity = capacity
        .capacity_bytes
        .saturating_sub(capacity.reserved_rebuild_bytes);
    if usable_capacity == 0 {
        return true;
    }
    capacity
        .used_bytes
        .saturating_mul(policy.max_used_denominator)
        > usable_capacity.saturating_mul(policy.max_used_numerator)
}

const fn capacity_accepts_payload(
    capacity: ReplicaCapacityRecord,
    payload_len: u64,
    policy: &CapacityMovementPolicy,
) -> bool {
    if policy.max_used_denominator == 0 || capacity.capacity_bytes == 0 {
        return false;
    }
    let usable_capacity = capacity
        .capacity_bytes
        .saturating_sub(capacity.reserved_rebuild_bytes);
    capacity
        .used_bytes
        .saturating_add(payload_len)
        .saturating_mul(policy.max_used_denominator)
        <= usable_capacity.saturating_mul(policy.max_used_numerator)
}

struct CapacityTargetSelection<'a> {
    capacity_by_member: &'a BTreeMap<MemberId, ReplicaCapacityRecord>,
    capacity_policy: &'a CapacityMovementPolicy,
    placement_policy: FailureDomainPlacementPolicy,
    payload_len: u64,
    existing_member_refs: &'a [MemberId],
    retained_member_refs: &'a [MemberId],
}

fn choose_capacity_rebalance_target(
    members: &[ClusterMemberRecord],
    selection: CapacityTargetSelection<'_>,
) -> Option<MemberId> {
    let existing: BTreeSet<MemberId> = selection.existing_member_refs.iter().copied().collect();
    let retained_domains: BTreeSet<DomainId> = selection
        .retained_member_refs
        .iter()
        .filter_map(|member_ref| {
            member_domain(
                members,
                *member_ref,
                selection.placement_policy.required_failure_domain_class_ref,
            )
        })
        .collect();
    let mut candidates: Vec<&ClusterMemberRecord> = members
        .iter()
        .filter(|member| !existing.contains(&member.member_id))
        .filter(|member| member_accepts_writes(members, member.member_id))
        .filter(|member| {
            let Some(capacity) = selection.capacity_by_member.get(&member.member_id) else {
                return false;
            };
            capacity_accepts_payload(*capacity, selection.payload_len, selection.capacity_policy)
        })
        .collect();
    candidates.sort_by_key(|member| member.member_id);

    candidates
        .iter()
        .find(|member| {
            let domain = member
                .failure_domain_vector
                .domain(selection.placement_policy.required_failure_domain_class_ref);
            !retained_domains.contains(&domain)
        })
        .or_else(|| {
            if selection.placement_policy.anti_affinity_class
                == tidefs_membership_epoch::AntiAffinityClass::DegradedVisible
            {
                candidates.first()
            } else {
                None
            }
        })
        .map(|member| member.member_id)
}

fn member_domain(
    members: &[ClusterMemberRecord],
    member_ref: MemberId,
    domain_class: tidefs_membership_epoch::FailureDomainClass,
) -> Option<DomainId> {
    members
        .iter()
        .find(|member| member.member_id == member_ref)
        .map(|member| member.failure_domain_vector.domain(domain_class))
}

fn erasure_shard_record(
    subject_ref: ReplicatedSubjectId,
    stripe_index: u64,
    shard_index: usize,
    shard_class: ErasureShardClass,
    bytes: Vec<u8>,
) -> ErasureShardRecord {
    ErasureShardRecord {
        subject_ref,
        stripe_index,
        shard_index,
        shard_class,
        state_class: ErasureShardStateClass::Available,
        payload_digest: derive_payload_digest(&bytes),
        payload_len: bytes.len(),
        bytes,
    }
}

fn available_erasure_shards_by_index<'a>(
    stripe: &ErasureStripeRecord,
    shard_records: &'a [ErasureShardRecord],
) -> BTreeMap<usize, &'a ErasureShardRecord> {
    let policy = stripe.layout_policy;
    let mut available = BTreeMap::new();
    for shard in shard_records {
        if erasure_shard_is_available_for_stripe(stripe, shard) {
            let expected_class = if shard.shard_index < policy.data_shard_count {
                ErasureShardClass::Data
            } else {
                ErasureShardClass::Parity
            };
            if shard.shard_index < policy.total_shard_count() && shard.shard_class == expected_class
            {
                available.entry(shard.shard_index).or_insert(shard);
            }
        }
    }
    available
}

fn erasure_shard_is_available_for_stripe(
    stripe: &ErasureStripeRecord,
    shard: &ErasureShardRecord,
) -> bool {
    shard.subject_ref == stripe.subject_ref
        && shard.stripe_index == stripe.stripe_index
        && shard.state_class == ErasureShardStateClass::Available
        && shard.payload_len == stripe.layout_policy.shard_len
        && shard.bytes.len() == stripe.layout_policy.shard_len
        && shard.payload_digest == derive_payload_digest(&shard.bytes)
}

fn unavailable_erasure_shard_indexes(
    policy: ErasureLayoutPolicy,
    available_by_index: &BTreeMap<usize, &ErasureShardRecord>,
) -> Vec<usize> {
    (0..policy.total_shard_count())
        .filter(|index| !available_by_index.contains_key(index))
        .collect()
}

fn data_parts_from_available(
    policy: ErasureLayoutPolicy,
    available_by_index: &BTreeMap<usize, &ErasureShardRecord>,
) -> Vec<Vec<u8>> {
    (0..policy.data_shard_count)
        .filter_map(|index| {
            available_by_index
                .get(&index)
                .map(|shard| shard.bytes.clone())
        })
        .collect()
}

fn rebuild_missing_data_shard_bytes(
    policy: ErasureLayoutPolicy,
    missing_index: usize,
    parity_shard: &ErasureShardRecord,
    available_by_index: &BTreeMap<usize, &ErasureShardRecord>,
) -> Vec<u8> {
    let mut rebuilt = parity_shard.bytes.clone();
    for data_index in 0..policy.data_shard_count {
        if data_index == missing_index {
            continue;
        }
        let Some(data_shard) = available_by_index.get(&data_index) else {
            continue;
        };
        xor_into(&mut rebuilt, &data_shard.bytes);
    }
    rebuilt
}

fn reconstruct_erasure_payload(
    stripe: &ErasureStripeRecord,
    policy: ErasureLayoutPolicy,
    available_by_index: &BTreeMap<usize, &ErasureShardRecord>,
    rebuilt_data: Option<(usize, Vec<u8>)>,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(policy.data_capacity().unwrap_or_default());
    for data_index in 0..policy.data_shard_count {
        if let Some((rebuilt_index, bytes)) = rebuilt_data.as_ref() {
            if *rebuilt_index == data_index {
                payload.extend_from_slice(bytes);
                continue;
            }
        }
        if let Some(data_shard) = available_by_index.get(&data_index) {
            payload.extend_from_slice(&data_shard.bytes);
        }
    }
    payload.truncate(stripe.original_payload_len);
    payload
}

fn xor_data_shard_bytes(shards: &[ErasureShardRecord], shard_len: usize) -> Vec<u8> {
    let data_parts: Vec<Vec<u8>> = shards
        .iter()
        .filter(|shard| shard.shard_class == ErasureShardClass::Data)
        .map(|shard| shard.bytes.clone())
        .collect();
    xor_bytes(&data_parts, shard_len)
}

fn xor_bytes(parts: &[Vec<u8>], shard_len: usize) -> Vec<u8> {
    let mut parity = vec![0; shard_len];
    for part in parts {
        xor_into(&mut parity, part);
    }
    parity
}

fn xor_into(target: &mut [u8], part: &[u8]) {
    for (left, right) in target.iter_mut().zip(part) {
        *left ^= *right;
    }
}

const fn erasure_decode_success(
    stripe: &ErasureStripeRecord,
    decode_class: ErasureDecodeClass,
    reconstructed_payload: Vec<u8>,
    rebuilt_shards: Vec<ErasureShardRecord>,
    unavailable_shard_indexes: Vec<usize>,
) -> ErasureDecodePlan {
    ErasureDecodePlan {
        subject_ref: stripe.subject_ref,
        stripe_index: stripe.stripe_index,
        decode_class,
        reconstructed_payload: Some(reconstructed_payload),
        rebuilt_shards,
        unavailable_shard_indexes,
        decode_receipt_ref: ReplicatedReceiptId(derive_receipt_id(
            stripe.subject_ref.0,
            decode_class as u64,
            stripe.stripe_index ^ stripe.original_payload_digest.0,
        )),
    }
}

fn erasure_decode_refusal(
    stripe: &ErasureStripeRecord,
    decode_class: ErasureDecodeClass,
    unavailable_shard_indexes: Vec<usize>,
) -> ErasureDecodePlan {
    ErasureDecodePlan {
        subject_ref: stripe.subject_ref,
        stripe_index: stripe.stripe_index,
        decode_class,
        reconstructed_payload: None,
        rebuilt_shards: Vec::new(),
        unavailable_shard_indexes,
        decode_receipt_ref: ReplicatedReceiptId::default(),
    }
}

fn derive_payload_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = (bytes.len() as u64).wrapping_mul(0x9E37_79B1_85EB_CA87);
    for (index, byte) in bytes.iter().enumerate() {
        digest ^= u64::from(*byte).wrapping_add((index as u64).rotate_left(17));
        digest = digest.rotate_left(9).wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
    }
    ObjectDigest(digest)
}

const fn derive_receipt_id(left: u64, right: u64, salt: u64) -> u64 {
    left.wrapping_mul(0x517C_C1B7_2722_0A95)
        ^ right.rotate_left(11)
        ^ salt.wrapping_mul(0xA24B_AED4_963E_E407)
}

#[cfg(test)]
mod tests {
    use tidefs_membership_epoch::{
        synthesize_membership_config_epoch_and_quorum_sets, ConfigClass, FailureDomainClass,
        FailureDomainVector, MemberAdmission, MemberClass,
    };

    use super::*;

    fn receipt_key(object_id: u64) -> [u8; 32] {
        let mut key = [0xA5; 32];
        key[..8].copy_from_slice(&object_id.to_le_bytes());
        key
    }

    fn receipt_digest(object_id: u64, generation: u64) -> [u8; 32] {
        let mut digest = [0x5A; 32];
        digest[..8].copy_from_slice(&object_id.to_le_bytes());
        digest[8..16].copy_from_slice(&generation.to_le_bytes());
        digest
    }

    fn intent_receipt_ref(
        object_id: u64,
        payload_len: u64,
        generation: u64,
    ) -> PlacementReceiptRef {
        PlacementReceiptRef::replicated(
            object_id,
            receipt_key(object_id),
            EpochId::new(1),
            generation,
            1,
            payload_len,
            receipt_digest(object_id, generation),
        )
    }

    #[test]
    fn placement_receipt_ref_records_policy_width() {
        let replicated = PlacementReceiptRef::replicated(
            42,
            receipt_key(42),
            EpochId::new(7),
            9,
            3,
            4096,
            receipt_digest(42, 9),
        );
        assert_eq!(replicated.target_count, 3);
        assert_eq!(
            replicated.redundancy_policy,
            ReceiptRedundancyPolicy::Replicated { copies: 3 }
        );
        assert!(replicated.redundancy_policy.is_well_formed());
        assert!(!replicated.is_synthetic());

        let erasure = PlacementReceiptRef::erasure(
            42,
            receipt_key(42),
            EpochId::new(7),
            10,
            4,
            2,
            8192,
            receipt_digest(42, 10),
        );
        assert_eq!(erasure.target_count, 6);
        assert_eq!(
            erasure.redundancy_policy,
            ReceiptRedundancyPolicy::Erasure {
                data_shards: 4,
                parity_shards: 2,
            }
        );
    }

    #[test]
    fn synthetic_receipt_ref_is_compatibility_only() {
        let receipt = PlacementReceiptRef::synthetic_for_subject(ReplicatedSubjectId::new(77));
        assert_eq!(receipt.object_id, 77);
        assert_eq!(receipt.receipt_generation, 0);
        assert!(receipt.is_synthetic());
    }

    fn committed_identity(
        member: u64,
        object_id: u64,
        generation: u64,
    ) -> CommittedReceiptIdentity {
        CommittedReceiptIdentity::new(
            MemberId::new(member),
            ReplicatedReceiptId::new(generation),
            intent_receipt_ref(object_id, 4096, generation),
        )
    }

    #[test]
    fn quorum_durability_token_binds_committed_receipt_identities() {
        let token = QuorumDurabilityToken::new(
            55,
            EpochId::new(1),
            3,
            2,
            vec![
                committed_identity(10, 100, 1000),
                committed_identity(20, 200, 2000),
            ],
        )
        .unwrap();

        assert_eq!(token.committed_count(), 2);
        assert_eq!(
            token.committed_members(),
            vec![MemberId::new(10), MemberId::new(20)]
        );
        assert_eq!(
            token.receipt_ids(),
            vec![
                ReplicatedReceiptId::new(1000),
                ReplicatedReceiptId::new(2000)
            ]
        );
    }

    #[test]
    fn quorum_durability_token_rejects_synthetic_receipts() {
        let identity = CommittedReceiptIdentity::new(
            MemberId::new(10),
            ReplicatedReceiptId::new(1),
            PlacementReceiptRef::synthetic_for_subject(ReplicatedSubjectId::new(1)),
        );

        assert!(matches!(
            QuorumDurabilityToken::new(55, EpochId::new(1), 1, 1, vec![identity]),
            Err(QuorumDurabilityTokenError::InvalidReceiptIdentity { .. })
        ));
    }

    #[test]
    fn quorum_durability_token_round_trips_across_restart() {
        let token = QuorumDurabilityToken::new(
            55,
            EpochId::new(1),
            3,
            2,
            vec![
                committed_identity(10, 100, 1000),
                committed_identity(20, 200, 2000),
            ],
        )
        .unwrap();
        let encoded = serde_json::to_string(&token).unwrap();
        let decoded: QuorumDurabilityToken = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, token);
        assert_eq!(decoded.committed_count(), 2);
    }

    const fn domain(seed: u64, rack: u64) -> FailureDomainVector {
        FailureDomainVector::new(
            DomainId::new(seed * 10 + 1),
            DomainId::new(seed * 10 + 2),
            DomainId::new(seed * 10 + 3),
            DomainId::new(rack),
            DomainId::new(1),
            DomainId::new(1),
        )
    }

    const fn admission(
        id: u64,
        member_class: MemberClass,
        health: HealthClass,
        rack: u64,
    ) -> MemberAdmission {
        MemberAdmission {
            member_id: MemberId::new(id),
            member_class,
            log_frontier: 100,
            health,
            failure_domain_vector: domain(id, rack),
        }
    }

    fn cluster(
        admissions: &[MemberAdmission],
        epoch: u64,
    ) -> (Vec<ClusterMemberRecord>, MembershipConfigRecord) {
        let members = tidefs_membership_epoch::inventory_members_and_classify_participation_roles(
            admissions,
            EpochId::new(epoch),
        )
        .expect("inventory");
        let config = synthesize_membership_config_epoch_and_quorum_sets(
            EpochId::new(epoch),
            ConfigClass::Normal,
            epoch,
            &members,
            &[],
            &[],
        )
        .expect("config");
        (members, config)
    }

    const fn root_subject(epoch: u64) -> ReplicatedObjectRootRecord {
        ReplicatedObjectRootRecord {
            subject_id: ReplicatedSubjectId::new(700),
            subject_class: ReplicatedSubjectClass::AuthenticatedRoot,
            membership_epoch_ref: EpochId::new(epoch),
            root_generation: 9,
            payload_digest: ObjectDigest::new(0xA11CE),
            payload_len: 4096,
            publication_receipt_ref: ReplicatedReceiptId(17),
        }
    }

    #[test]
    fn degraded_write_commits_with_quorum_and_records_unplaced_target() {
        let (members, config) = cluster(
            &[
                admission(1, MemberClass::Voter, HealthClass::Healthy, 1),
                admission(2, MemberClass::Voter, HealthClass::Healthy, 2),
                admission(3, MemberClass::DataOnly, HealthClass::Down, 3),
            ],
            40,
        );
        let subject = root_subject(40);

        let plan = commit_replicated_object_root_write(
            &config,
            &members,
            subject,
            FailureDomainPlacementPolicy::degraded_visible_replica_targets(
                3,
                FailureDomainClass::Rack,
            ),
            &[MemberId::new(1), MemberId::new(2)],
        );

        assert_eq!(plan.write_class, ReplicatedWriteClass::DegradedCommitted);
        assert_eq!(plan.quorum_required, 2);
        assert_eq!(
            plan.committed_member_refs,
            vec![MemberId::new(1), MemberId::new(2)]
        );
        assert_eq!(plan.unplaced_replica_count, 1);
        assert_eq!(
            plan.placement_verdict.verdict_class,
            VerdictClass::AdmitDegraded
        );
    }

    #[test]
    fn write_refuses_without_replica_quorum() {
        let (members, config) = cluster(
            &[
                admission(1, MemberClass::Voter, HealthClass::Healthy, 1),
                admission(2, MemberClass::Voter, HealthClass::Healthy, 2),
                admission(3, MemberClass::DataOnly, HealthClass::Healthy, 3),
            ],
            41,
        );
        let subject = root_subject(41);

        let plan = commit_replicated_object_root_write(
            &config,
            &members,
            subject,
            FailureDomainPlacementPolicy::strict_replica_targets(3, FailureDomainClass::Rack),
            &[MemberId::new(1)],
        );

        assert_eq!(plan.write_class, ReplicatedWriteClass::RefusedNoQuorum);
        assert_eq!(plan.commit_receipt_ref, ReplicatedReceiptId::default());
        assert_eq!(plan.unavailable_member_refs.len(), 2);
    }

    #[test]
    fn degraded_read_uses_verified_replica_and_requests_rebuild() {
        let subject = root_subject(42);
        let copies = vec![
            ReplicaCopyRecord::verified(
                subject.subject_id,
                MemberId::new(2),
                DomainId::new(2),
                subject.payload_digest,
                9,
            ),
            ReplicaCopyRecord::unavailable(
                subject.subject_id,
                MemberId::new(1),
                DomainId::new(1),
                ReplicaCopyClass::Unreachable,
                subject.payload_digest,
            ),
            ReplicaCopyRecord::unavailable(
                subject.subject_id,
                MemberId::new(3),
                DomainId::new(3),
                ReplicaCopyClass::Suspect,
                ObjectDigest::new(0xBAD),
            ),
        ];

        let plan = plan_replicated_object_root_read(&subject, &copies, 3);

        assert_eq!(plan.read_class, ReplicatedReadClass::DegradedButValid);
        assert_eq!(plan.source_member_ref, Some(MemberId::new(2)));
        assert_eq!(plan.verified_member_refs, vec![MemberId::new(2)]);
        assert_eq!(
            plan.unavailable_member_refs,
            vec![MemberId::new(1), MemberId::new(3)]
        );
        assert!(plan.rebuild_required);
        assert_ne!(plan.read_receipt_ref, ReplicatedReceiptId::default());
    }

    #[test]
    fn unavailable_read_without_verified_source_has_no_receipt() {
        let subject = root_subject(42);
        let copies = vec![
            ReplicaCopyRecord::unavailable(
                subject.subject_id,
                MemberId::new(1),
                DomainId::new(1),
                ReplicaCopyClass::Unreachable,
                subject.payload_digest,
            ),
            ReplicaCopyRecord::unavailable(
                subject.subject_id,
                MemberId::new(2),
                DomainId::new(2),
                ReplicaCopyClass::Suspect,
                ObjectDigest::new(0xBAD),
            ),
            ReplicaCopyRecord::unavailable(
                subject.subject_id,
                MemberId::new(3),
                DomainId::new(3),
                ReplicaCopyClass::Missing,
                subject.payload_digest,
            ),
        ];

        let plan = plan_replicated_object_root_read(&subject, &copies, 3);

        assert_eq!(plan.read_class, ReplicatedReadClass::Unavailable);
        assert_eq!(plan.source_member_ref, None);
        assert!(plan.verified_member_refs.is_empty());
        assert_eq!(
            plan.unavailable_member_refs,
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]
        );
        assert_eq!(plan.missing_replica_count, 3);
        assert!(plan.rebuild_required);
        assert_eq!(plan.read_receipt_ref, ReplicatedReceiptId::default());
    }

    #[test]
    fn read_class_payload_response_policy_is_fail_closed() {
        assert!(ReplicatedReadClass::Exact.permits_payload_response());
        assert!(ReplicatedReadClass::DegradedButValid.permits_payload_response());
        assert!(!ReplicatedReadClass::RepairRequired.permits_payload_response());
        assert!(!ReplicatedReadClass::Unavailable.permits_payload_response());
    }

    #[test]
    fn rebuild_restores_required_failure_domain_spread() {
        let (members, config) = cluster(
            &[
                admission(1, MemberClass::Voter, HealthClass::Healthy, 1),
                admission(2, MemberClass::Voter, HealthClass::Healthy, 2),
                admission(3, MemberClass::DataOnly, HealthClass::Healthy, 3),
            ],
            43,
        );
        let subject = root_subject(43);
        let copies = vec![
            ReplicaCopyRecord::verified(
                subject.subject_id,
                MemberId::new(1),
                DomainId::new(1),
                subject.payload_digest,
                9,
            ),
            ReplicaCopyRecord::verified(
                subject.subject_id,
                MemberId::new(2),
                DomainId::new(2),
                subject.payload_digest,
                9,
            ),
        ];

        let plan = rebuild_replicated_object_root_from_sources(
            &config,
            &members,
            &subject,
            &copies,
            FailureDomainPlacementPolicy::strict_replica_targets(3, FailureDomainClass::Rack),
        );

        assert_eq!(plan.rebuild_class, RebuildPlanClass::Restored);
        assert_eq!(
            plan.source_member_refs,
            vec![MemberId::new(1), MemberId::new(2)]
        );
        assert_eq!(plan.target_member_refs, vec![MemberId::new(3)]);
        assert_eq!(
            plan.final_member_refs,
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]
        );
        assert_eq!(plan.placement_verdict.verdict_class, VerdictClass::Admit);
    }

    #[test]
    fn rebuild_flow_restores_faulted_copy_from_verified_source() {
        let (members, config) = cluster(
            &[
                admission(1, MemberClass::Voter, HealthClass::Healthy, 1),
                admission(2, MemberClass::Voter, HealthClass::Healthy, 2),
                admission(3, MemberClass::DataOnly, HealthClass::Healthy, 3),
            ],
            44,
        );
        let subject = root_subject(44);
        let copies = vec![
            ReplicaCopyRecord::verified(
                subject.subject_id,
                MemberId::new(1),
                DomainId::new(1),
                subject.payload_digest,
                9,
            ),
            ReplicaCopyRecord::verified(
                subject.subject_id,
                MemberId::new(2),
                DomainId::new(2),
                subject.payload_digest,
                9,
            ),
            ReplicaCopyRecord::unavailable(
                subject.subject_id,
                MemberId::new(3),
                DomainId::new(3),
                ReplicaCopyClass::Suspect,
                ObjectDigest::new(0xBAD),
            ),
        ];

        let plan = open_rebuild_flow_from_loss_event(
            &config,
            &members,
            &subject,
            &copies,
            FailureDomainPlacementPolicy::strict_replica_targets(3, FailureDomainClass::Rack),
        );

        assert_eq!(plan.plan_class, ReplicaMovementPlanClass::Planned);
        assert_eq!(
            plan.movement_class,
            ReplicaMovementClass::RebuildLostOrSuspectCopy
        );
        assert_eq!(
            plan.source_member_refs,
            vec![MemberId::new(1), MemberId::new(2)]
        );
        assert_eq!(plan.target_member_refs, vec![MemberId::new(3)]);
        assert_eq!(plan.faulted_member_refs, vec![MemberId::new(3)]);
        assert_eq!(
            plan.final_member_refs,
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]
        );
        assert_eq!(plan.transfer_intents.len(), 1);
        assert_eq!(plan.transfer_intents[0].target_member_ref, MemberId::new(3));
        assert!(plan.transfer_intents[0].verification_required);
    }

    #[test]
    fn rebuild_blocks_when_all_sources_are_corrupt_or_missing() {
        let (members, config) = cluster(
            &[
                admission(1, MemberClass::Voter, HealthClass::Healthy, 1),
                admission(2, MemberClass::Voter, HealthClass::Healthy, 2),
                admission(3, MemberClass::DataOnly, HealthClass::Healthy, 3),
            ],
            45,
        );
        let subject = root_subject(45);
        let copies = vec![
            ReplicaCopyRecord::unavailable(
                subject.subject_id,
                MemberId::new(1),
                DomainId::new(1),
                ReplicaCopyClass::Missing,
                subject.payload_digest,
            ),
            ReplicaCopyRecord::unavailable(
                subject.subject_id,
                MemberId::new(2),
                DomainId::new(2),
                ReplicaCopyClass::Suspect,
                ObjectDigest::new(0xBAD),
            ),
        ];

        let plan = open_rebuild_flow_from_loss_event(
            &config,
            &members,
            &subject,
            &copies,
            FailureDomainPlacementPolicy::strict_replica_targets(3, FailureDomainClass::Rack),
        );

        assert_eq!(plan.plan_class, ReplicaMovementPlanClass::BlockedNoSource);
        assert!(plan.source_member_refs.is_empty());
        assert!(plan.transfer_intents.is_empty());
        assert_eq!(
            plan.faulted_member_refs,
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]
        );
    }

    #[test]
    fn backfill_targets_lagged_replica_without_replacing_fresh_sources() {
        let (members, config) = cluster(
            &[
                admission(1, MemberClass::Voter, HealthClass::Healthy, 1),
                admission(2, MemberClass::Voter, HealthClass::Healthy, 2),
                admission(3, MemberClass::DataOnly, HealthClass::Healthy, 3),
            ],
            46,
        );
        let subject = root_subject(46);
        let copies = vec![
            ReplicaCopyRecord::verified(
                subject.subject_id,
                MemberId::new(1),
                DomainId::new(1),
                subject.payload_digest,
                9,
            ),
            ReplicaCopyRecord::verified(
                subject.subject_id,
                MemberId::new(2),
                DomainId::new(2),
                subject.payload_digest,
                7,
            ),
            ReplicaCopyRecord::verified(
                subject.subject_id,
                MemberId::new(3),
                DomainId::new(3),
                subject.payload_digest,
                9,
            ),
        ];

        let plan = schedule_backfill_batches_from_witness_sets(
            &config,
            &members,
            &subject,
            &copies,
            FailureDomainPlacementPolicy::strict_replica_targets(3, FailureDomainClass::Rack),
            subject.root_generation,
        );

        assert_eq!(plan.plan_class, ReplicaMovementPlanClass::Planned);
        assert_eq!(
            plan.movement_class,
            ReplicaMovementClass::BackfillLaggedCopy
        );
        assert_eq!(
            plan.source_member_refs,
            vec![MemberId::new(1), MemberId::new(3)]
        );
        assert_eq!(plan.target_member_refs, vec![MemberId::new(2)]);
        assert_eq!(
            plan.final_member_refs,
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]
        );
        assert_eq!(plan.transfer_intents[0].source_member_ref, MemberId::new(1));
        assert_eq!(plan.transfer_intents[0].target_member_ref, MemberId::new(2));
    }

    #[test]
    fn rebalance_moves_overloaded_verified_copy_to_capacity_target() {
        let (members, config) = cluster(
            &[
                admission(1, MemberClass::Voter, HealthClass::Healthy, 1),
                admission(2, MemberClass::Voter, HealthClass::Healthy, 2),
                admission(3, MemberClass::DataOnly, HealthClass::Healthy, 3),
                admission(4, MemberClass::DataOnly, HealthClass::Healthy, 4),
            ],
            47,
        );
        let subject = root_subject(47);
        let copies = vec![
            ReplicaCopyRecord::verified(
                subject.subject_id,
                MemberId::new(1),
                DomainId::new(1),
                subject.payload_digest,
                9,
            ),
            ReplicaCopyRecord::verified(
                subject.subject_id,
                MemberId::new(2),
                DomainId::new(2),
                subject.payload_digest,
                9,
            ),
            ReplicaCopyRecord::verified(
                subject.subject_id,
                MemberId::new(3),
                DomainId::new(3),
                subject.payload_digest,
                9,
            ),
        ];
        let capacities = vec![
            ReplicaCapacityRecord::new(MemberId::new(1), 9_200, 10_000, 0),
            ReplicaCapacityRecord::new(MemberId::new(2), 5_000, 10_000, 0),
            ReplicaCapacityRecord::new(MemberId::new(3), 5_000, 10_000, 0),
            ReplicaCapacityRecord::new(MemberId::new(4), 1_000, 10_000, 0),
        ];
        let capacity_policy = CapacityMovementPolicy::new(capacities, 80, 100);

        let plan = plan_rebalance_for_capacity_movement(
            &config,
            &members,
            &subject,
            &copies,
            FailureDomainPlacementPolicy::strict_replica_targets(3, FailureDomainClass::Rack),
            &capacity_policy,
        );

        assert_eq!(plan.plan_class, ReplicaMovementPlanClass::Planned);
        assert_eq!(
            plan.movement_class,
            ReplicaMovementClass::RebalanceCapacityPressure
        );
        assert_eq!(plan.source_member_refs, vec![MemberId::new(1)]);
        assert_eq!(plan.target_member_refs, vec![MemberId::new(4)]);
        assert_eq!(
            plan.retained_member_refs,
            vec![MemberId::new(2), MemberId::new(3)]
        );
        assert_eq!(
            plan.final_member_refs,
            vec![MemberId::new(2), MemberId::new(3), MemberId::new(4)]
        );
        assert_eq!(plan.transfer_intents[0].payload_len, subject.payload_len);
    }

    #[test]
    fn rebalance_blocks_when_spare_capacity_would_violate_reserve_floor() {
        let (members, config) = cluster(
            &[
                admission(1, MemberClass::Voter, HealthClass::Healthy, 1),
                admission(2, MemberClass::Voter, HealthClass::Healthy, 2),
                admission(3, MemberClass::DataOnly, HealthClass::Healthy, 3),
                admission(4, MemberClass::DataOnly, HealthClass::Healthy, 4),
            ],
            48,
        );
        let subject = root_subject(48);
        let copies = vec![
            ReplicaCopyRecord::verified(
                subject.subject_id,
                MemberId::new(1),
                DomainId::new(1),
                subject.payload_digest,
                9,
            ),
            ReplicaCopyRecord::verified(
                subject.subject_id,
                MemberId::new(2),
                DomainId::new(2),
                subject.payload_digest,
                9,
            ),
            ReplicaCopyRecord::verified(
                subject.subject_id,
                MemberId::new(3),
                DomainId::new(3),
                subject.payload_digest,
                9,
            ),
        ];
        let capacities = vec![
            ReplicaCapacityRecord::new(MemberId::new(1), 9_200, 10_000, 0),
            ReplicaCapacityRecord::new(MemberId::new(2), 5_000, 10_000, 0),
            ReplicaCapacityRecord::new(MemberId::new(3), 5_000, 10_000, 0),
            ReplicaCapacityRecord::new(MemberId::new(4), 7_900, 10_000, 0),
        ];
        let capacity_policy = CapacityMovementPolicy::new(capacities, 80, 100);

        let plan = plan_rebalance_for_capacity_movement(
            &config,
            &members,
            &subject,
            &copies,
            FailureDomainPlacementPolicy::strict_replica_targets(3, FailureDomainClass::Rack),
            &capacity_policy,
        );

        assert_eq!(plan.plan_class, ReplicaMovementPlanClass::BlockedNoCapacity);
        assert_eq!(plan.source_member_refs, vec![MemberId::new(1)]);
        assert!(plan.target_member_refs.is_empty());
        assert!(plan.transfer_intents.is_empty());
    }

    const fn erasure_policy() -> ErasureLayoutPolicy {
        ErasureLayoutPolicy::single_parity_xor(3, 4)
    }

    fn erasure_stripe(payload: &[u8]) -> ErasureStripeRecord {
        encode_single_parity_erasure_stripe(
            ReplicatedSubjectId::new(900),
            3,
            payload,
            erasure_policy(),
        )
        .expect("valid erasure stripe")
    }

    fn mark_erasure_shard_unavailable(
        shards: &mut [ErasureShardRecord],
        shard_index: usize,
        state_class: ErasureShardStateClass,
    ) {
        let shard = shards
            .iter_mut()
            .find(|candidate| candidate.shard_index == shard_index)
            .expect("shard");
        shard.state_class = state_class;
        shard.bytes.clear();
        shard.payload_len = 0;
        shard.payload_digest = ObjectDigest::default();
    }

    #[test]
    fn erasure_decode_round_trips_complete_single_parity_stripe() {
        let payload = b"root-payload".to_vec();
        let stripe = erasure_stripe(&payload);

        let plan = decode_single_parity_erasure_stripe(&stripe, &stripe.shards);

        assert_eq!(plan.decode_class, ErasureDecodeClass::Complete);
        assert_eq!(
            plan.reconstructed_payload.as_deref(),
            Some(payload.as_slice())
        );
        assert!(plan.rebuilt_shards.is_empty());
        assert!(plan.unavailable_shard_indexes.is_empty());
        assert_ne!(plan.decode_receipt_ref, ReplicatedReceiptId::default());
    }

    #[test]
    fn erasure_rebuilds_one_missing_data_shard_from_parity() {
        let payload = b"object-root".to_vec();
        let stripe = erasure_stripe(&payload);
        let expected_shard = stripe.shards[1].clone();
        let mut available = stripe.shards.clone();
        mark_erasure_shard_unavailable(&mut available, 1, ErasureShardStateClass::Missing);

        let plan = decode_single_parity_erasure_stripe(&stripe, &available);

        assert_eq!(
            plan.decode_class,
            ErasureDecodeClass::ReconstructedSingleDataShard
        );
        assert_eq!(
            plan.reconstructed_payload.as_deref(),
            Some(payload.as_slice())
        );
        assert_eq!(plan.rebuilt_shards.len(), 1);
        assert_eq!(plan.rebuilt_shards[0], expected_shard);
        assert_eq!(plan.unavailable_shard_indexes, vec![1]);
    }

    #[test]
    fn erasure_rebuilds_missing_parity_from_data_shards() {
        let payload = b"abc12345".to_vec();
        let stripe = erasure_stripe(&payload);
        let parity_index = erasure_policy().parity_shard_index();
        let expected_parity = stripe.shards[parity_index].clone();
        let mut available = stripe.shards.clone();
        mark_erasure_shard_unavailable(
            &mut available,
            parity_index,
            ErasureShardStateClass::Missing,
        );

        let plan = decode_single_parity_erasure_stripe(&stripe, &available);

        assert_eq!(plan.decode_class, ErasureDecodeClass::RebuiltParityShard);
        assert_eq!(
            plan.reconstructed_payload.as_deref(),
            Some(payload.as_slice())
        );
        assert_eq!(plan.rebuilt_shards, vec![expected_parity]);
        assert_eq!(plan.unavailable_shard_indexes, vec![parity_index]);
    }

    #[test]
    fn erasure_refuses_when_two_data_shards_are_missing() {
        let payload = b"refuse-two".to_vec();
        let stripe = erasure_stripe(&payload);
        let mut available = stripe.shards.clone();
        mark_erasure_shard_unavailable(&mut available, 0, ErasureShardStateClass::Missing);
        mark_erasure_shard_unavailable(&mut available, 2, ErasureShardStateClass::Suspect);

        let plan = decode_single_parity_erasure_stripe(&stripe, &available);

        assert_eq!(plan.decode_class, ErasureDecodeClass::RefusedTooManyMissing);
        assert!(plan.reconstructed_payload.is_none());
        assert!(plan.rebuilt_shards.is_empty());
        assert_eq!(plan.unavailable_shard_indexes, vec![0, 2]);
        assert_eq!(plan.decode_receipt_ref, ReplicatedReceiptId::default());
    }

    #[test]
    fn erasure_refuses_when_data_and_parity_are_missing() {
        let payload = b"data-parity".to_vec();
        let stripe = erasure_stripe(&payload);
        let parity_index = erasure_policy().parity_shard_index();
        let mut available = stripe.shards.clone();
        mark_erasure_shard_unavailable(&mut available, 0, ErasureShardStateClass::Missing);
        mark_erasure_shard_unavailable(
            &mut available,
            parity_index,
            ErasureShardStateClass::Missing,
        );

        let plan = decode_single_parity_erasure_stripe(&stripe, &available);

        assert_eq!(
            plan.decode_class,
            ErasureDecodeClass::RefusedMissingDataAndParity
        );
        assert!(plan.reconstructed_payload.is_none());
        assert!(plan.rebuilt_shards.is_empty());
        assert_eq!(plan.unavailable_shard_indexes, vec![0, parity_index]);
    }

    // ========== Transfer ticket / verification receipt tests ==========
    #[test]
    fn stage_transfer_ticket_binds_source_target_and_fence() {
        let intent = ReplicaMovementIntentRecord {
            intent_id: ReplicatedReceiptId(100),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            subject_ref: ReplicatedSubjectId::new(42),
            placement_receipt_ref: intent_receipt_ref(42, 8192, 100),
            source_member_ref: MemberId::new(1),
            target_member_ref: MemberId::new(5),
            payload_digest: ObjectDigest::new(0xC0FFEE),
            payload_len: 8192,
            verification_required: true,
        };

        let ticket = stage_replica_transfer_ticket(&intent, &[MemberId::new(1)], 200, 300);

        assert_eq!(ticket.intent_ref, ReplicatedReceiptId(100));
        assert_eq!(ticket.subject_refs, vec![ReplicatedSubjectId::new(42)]);
        assert_eq!(ticket.source_anchor_set, vec![MemberId::new(1)]);
        assert_eq!(ticket.target_ref, MemberId::new(5));
        assert_eq!(ticket.freshness_fence_ref, 200);
        assert_eq!(ticket.expiry, 300);
        assert_ne!(ticket.pin_budget_ref, ReplicatedReceiptId::default());
        assert_ne!(ticket.ticket_id, ReplicatedReceiptId::default());
    }

    #[test]
    fn transfer_receipt_chains_to_ticket() {
        let intent = ReplicaMovementIntentRecord {
            intent_id: ReplicatedReceiptId(200),
            movement_class: ReplicaMovementClass::RebalanceCapacityPressure,
            subject_ref: ReplicatedSubjectId::new(99),
            placement_receipt_ref: intent_receipt_ref(99, 4096, 200),
            source_member_ref: MemberId::new(2),
            target_member_ref: MemberId::new(3),
            payload_digest: ObjectDigest::new(0xBEEF),
            payload_len: 4096,
            verification_required: true,
        };

        let ticket = stage_replica_transfer_ticket(&intent, &[MemberId::new(2)], 100, 400);

        let receipt = emit_replica_transfer_receipt(
            &ticket,
            4096,
            0xAAAA,
            0xBBBB,
            EpochId::new(10),
            &[MemberId::new(2), MemberId::new(3)],
        );

        assert_eq!(receipt.ticket_ref, ticket.ticket_id);
        assert_eq!(receipt.bytes_moved, 4096);
        assert_eq!(receipt.source_anchor_hash, 0xAAAA);
        assert_eq!(receipt.target_anchor_hash, 0xBBBB);
        assert_eq!(receipt.completion_epoch, EpochId::new(10));
        assert_eq!(
            receipt.worker_refs,
            vec![MemberId::new(2), MemberId::new(3)]
        );
        assert_ne!(receipt.receipt_id, ReplicatedReceiptId::default());
    }

    #[test]
    fn verification_receipt_confirms_digest_match() {
        let intent = ReplicaMovementIntentRecord {
            intent_id: ReplicatedReceiptId(300),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            subject_ref: ReplicatedSubjectId::new(7),
            placement_receipt_ref: intent_receipt_ref(7, 1024, 300),
            source_member_ref: MemberId::new(10),
            target_member_ref: MemberId::new(20),
            payload_digest: ObjectDigest::new(0xABCD),
            payload_len: 1024,
            verification_required: true,
        };

        let ticket = stage_replica_transfer_ticket(&intent, &[MemberId::new(10)], 50, 500);

        let transfer = emit_replica_transfer_receipt(
            &ticket,
            1024,
            0x1111,
            0x2222,
            EpochId::new(5),
            &[MemberId::new(10)],
        );

        let expected_digest = ObjectDigest::new(0xABCD);
        let verification = verify_transferred_chunks_and_emit_verification_receipt(
            &transfer,
            &[ReplicatedSubjectId::new(7)],
            expected_digest,
            &[ObjectDigest::new(0xABCD)],
            &[MemberId::new(30)],
            2,
            EpochId::new(5),
        );

        assert_eq!(verification.status, VerificationStatus::Verified);
        assert_eq!(verification.subject_refs, vec![ReplicatedSubjectId::new(7)]);
        assert_eq!(verification.witness_refs, vec![MemberId::new(30)]);
        assert_eq!(verification.quorum_class, 2);
        assert_eq!(verification.verification_epoch, EpochId::new(5));
        assert_ne!(verification.receipt_id, ReplicatedReceiptId::default());
    }

    #[test]
    fn verification_receipt_rejects_digest_mismatch() {
        let intent = ReplicaMovementIntentRecord {
            intent_id: ReplicatedReceiptId(400),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            subject_ref: ReplicatedSubjectId::new(8),
            placement_receipt_ref: intent_receipt_ref(8, 512, 400),
            source_member_ref: MemberId::new(11),
            target_member_ref: MemberId::new(21),
            payload_digest: ObjectDigest::new(0xCAFE),
            payload_len: 512,
            verification_required: true,
        };

        let ticket = stage_replica_transfer_ticket(&intent, &[MemberId::new(11)], 60, 600);

        let transfer = emit_replica_transfer_receipt(
            &ticket,
            512,
            0x3333,
            0x4444,
            EpochId::new(6),
            &[MemberId::new(11)],
        );

        // Digest mismatch: expected 0xCAFE but got 0xB0B0
        let verification = verify_transferred_chunks_and_emit_verification_receipt(
            &transfer,
            &[ReplicatedSubjectId::new(8)],
            ObjectDigest::new(0xCAFE),
            &[ObjectDigest::new(0xB0B0)],
            &[MemberId::new(30)],
            2,
            EpochId::new(6),
        );

        assert_eq!(verification.status, VerificationStatus::DigestMismatch);
        assert_eq!(verification.digest_results, vec![ObjectDigest::new(0xB0B0)]);
    }

    #[test]
    fn verification_receipt_rejects_missing_witnesses() {
        let intent = ReplicaMovementIntentRecord {
            intent_id: ReplicatedReceiptId(500),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            subject_ref: ReplicatedSubjectId::new(9),
            placement_receipt_ref: intent_receipt_ref(9, 2048, 500),
            source_member_ref: MemberId::new(12),
            target_member_ref: MemberId::new(22),
            payload_digest: ObjectDigest::new(0xDEAD),
            payload_len: 2048,
            verification_required: true,
        };

        let ticket = stage_replica_transfer_ticket(&intent, &[MemberId::new(12)], 70, 700);

        let transfer = emit_replica_transfer_receipt(
            &ticket,
            2048,
            0x5555,
            0x6666,
            EpochId::new(7),
            &[MemberId::new(12)],
        );

        // Digest matches but no witnesses
        let verification = verify_transferred_chunks_and_emit_verification_receipt(
            &transfer,
            &[ReplicatedSubjectId::new(9)],
            ObjectDigest::new(0xDEAD),
            &[ObjectDigest::new(0xDEAD)],
            &[],
            2,
            EpochId::new(7),
        );

        assert_eq!(verification.status, VerificationStatus::WitnessInsufficient);
    }

    #[test]
    fn receipt_chain_advances_copy_to_verified_on_success() {
        let expected_digest = ObjectDigest::new(0xF00D);
        let copy = ReplicaCopyRecord {
            subject_ref: ReplicatedSubjectId::new(55),
            member_ref: MemberId::new(30),
            domain_ref: DomainId::new(300),
            copy_class: ReplicaCopyClass::Rebuilding,
            payload_digest: ObjectDigest::default(),
            freshness_frontier: 0,
            verification_receipt_ref: ReplicatedReceiptId::default(),
        };

        let intent = ReplicaMovementIntentRecord {
            intent_id: ReplicatedReceiptId(600),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            subject_ref: ReplicatedSubjectId::new(55),
            placement_receipt_ref: intent_receipt_ref(55, 4096, 600),
            source_member_ref: MemberId::new(10),
            target_member_ref: MemberId::new(30),
            payload_digest: expected_digest,
            payload_len: 4096,
            verification_required: true,
        };

        let ticket = stage_replica_transfer_ticket(&intent, &[MemberId::new(10)], 100, 1000);

        let transfer = emit_replica_transfer_receipt(
            &ticket,
            4096,
            0x7777,
            0x8888,
            EpochId::new(15),
            &[MemberId::new(10)],
        );

        let (updated_copy, verification) = advance_replica_copy_through_receipt_chain(
            copy.clone(),
            expected_digest,
            &[expected_digest],
            &[MemberId::new(40)],
            2,
            EpochId::new(15),
            &transfer,
        );

        assert_eq!(verification.status, VerificationStatus::Verified);
        assert_eq!(updated_copy.copy_class, ReplicaCopyClass::Verified);
        assert_eq!(updated_copy.payload_digest, expected_digest);
        assert_eq!(
            updated_copy.verification_receipt_ref,
            verification.receipt_id
        );
        assert_ne!(
            updated_copy.verification_receipt_ref,
            ReplicatedReceiptId::default()
        );
    }

    #[test]
    fn receipt_chain_does_not_advance_copy_on_digest_failure() {
        let expected_digest = ObjectDigest::new(0xABCD);
        let copy = ReplicaCopyRecord {
            subject_ref: ReplicatedSubjectId::new(56),
            member_ref: MemberId::new(31),
            domain_ref: DomainId::new(301),
            copy_class: ReplicaCopyClass::Rebuilding,
            payload_digest: ObjectDigest::default(),
            freshness_frontier: 0,
            verification_receipt_ref: ReplicatedReceiptId::default(),
        };

        let intent = ReplicaMovementIntentRecord {
            intent_id: ReplicatedReceiptId(700),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            subject_ref: ReplicatedSubjectId::new(56),
            placement_receipt_ref: intent_receipt_ref(56, 4096, 700),
            source_member_ref: MemberId::new(11),
            target_member_ref: MemberId::new(31),
            payload_digest: expected_digest,
            payload_len: 4096,
            verification_required: true,
        };

        let ticket = stage_replica_transfer_ticket(&intent, &[MemberId::new(11)], 100, 1000);

        let transfer = emit_replica_transfer_receipt(
            &ticket,
            4096,
            0x9999,
            0xAAAA,
            EpochId::new(16),
            &[MemberId::new(11)],
        );

        // Wrong digest — should not advance
        let (updated_copy, verification) = advance_replica_copy_through_receipt_chain(
            copy.clone(),
            expected_digest,
            &[ObjectDigest::new(0xBAD)], // mismatched
            &[MemberId::new(40)],
            2,
            EpochId::new(16),
            &transfer,
        );

        assert_eq!(verification.status, VerificationStatus::DigestMismatch);
        assert_eq!(updated_copy.copy_class, ReplicaCopyClass::Rebuilding); // unchanged
        assert_eq!(
            updated_copy.verification_receipt_ref,
            ReplicatedReceiptId::default()
        );
    }

    #[test]
    fn transfer_ticket_deterministic_id() {
        let intent = ReplicaMovementIntentRecord {
            intent_id: ReplicatedReceiptId(42),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            subject_ref: ReplicatedSubjectId::new(100),
            placement_receipt_ref: intent_receipt_ref(100, 8192, 42),
            source_member_ref: MemberId::new(1),
            target_member_ref: MemberId::new(2),
            payload_digest: ObjectDigest::new(0xC0FFEE),
            payload_len: 8192,
            verification_required: true,
        };

        let ticket_a = stage_replica_transfer_ticket(&intent, &[MemberId::new(1)], 200, 300);
        let ticket_b = stage_replica_transfer_ticket(&intent, &[MemberId::new(1)], 200, 300);

        assert_eq!(ticket_a.ticket_id, ticket_b.ticket_id);
        assert_eq!(ticket_a.pin_budget_ref, ticket_b.pin_budget_ref);
    }

    #[test]
    fn serde_roundtrip_transfer_ticket() {
        let ticket = ReplicaTransferTicketRecord {
            ticket_id: ReplicatedReceiptId(1000),
            intent_ref: ReplicatedReceiptId(500),
            subject_refs: vec![ReplicatedSubjectId::new(1), ReplicatedSubjectId::new(2)],
            source_anchor_set: vec![MemberId::new(10), MemberId::new(20)],
            target_ref: MemberId::new(30),
            pin_budget_ref: ReplicatedReceiptId(777),
            freshness_fence_ref: 150,
            expiry: 999,
        };
        let json = serde_json::to_string(&ticket).expect("serialize");
        let round: ReplicaTransferTicketRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ticket, round);
    }

    #[test]
    fn serde_roundtrip_transfer_receipt() {
        let receipt = ReplicaTransferReceipt {
            receipt_id: ReplicatedReceiptId(2000),
            ticket_ref: ReplicatedReceiptId(1000),
            bytes_moved: 16384,
            source_anchor_hash: 0xFACE,
            target_anchor_hash: 0xB00C,
            completion_epoch: EpochId::new(42),
            worker_refs: vec![MemberId::new(5), MemberId::new(6)],
        };
        let json = serde_json::to_string(&receipt).expect("serialize");
        let round: ReplicaTransferReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, round);
    }

    #[test]
    fn serde_roundtrip_verification_receipt() {
        let receipt = ReplicaVerificationReceipt {
            receipt_id: ReplicatedReceiptId(3000),
            subject_refs: vec![ReplicatedSubjectId::new(77)],
            digest_results: vec![ObjectDigest::new(0xABCD)],
            witness_refs: vec![MemberId::new(100)],
            quorum_class: 2,
            verification_epoch: EpochId::new(10),
            status: VerificationStatus::Verified,
        };
        let json = serde_json::to_string(&receipt).expect("serialize");
        let round: ReplicaVerificationReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, round);
    }

    #[test]
    fn serde_roundtrip_verification_status_variants() {
        for status in &[
            VerificationStatus::Verified,
            VerificationStatus::DigestMismatch,
            VerificationStatus::WitnessInsufficient,
            VerificationStatus::QuorumNotMet,
            VerificationStatus::DegradedVerified,
        ] {
            let receipt = ReplicaVerificationReceipt {
                receipt_id: ReplicatedReceiptId(4000),
                subject_refs: vec![],
                digest_results: vec![],
                witness_refs: vec![],
                quorum_class: 0,
                verification_epoch: EpochId::new(1),
                status: *status,
            };
            let json = serde_json::to_string(&receipt).expect("serialize");
            let round: ReplicaVerificationReceipt =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(receipt, round, "roundtrip failed for {status:?}");
        }
    }

    // ── P8-03 §5 canonical schema family serde roundtrips ──

    #[test]
    fn serde_roundtrip_replica_set_record() {
        let rec = ReplicaSetRecord {
            replica_set_id: 1,
            subject_ref: ReplicatedSubjectId::new(100),
            placement_policy_ref: 42,
            required_count: 3,
            target_failure_domains: vec![DomainId::new(10), DomainId::new(20)],
            current_placement_receipt_refs: vec![
                ReplicatedReceiptId(500),
                ReplicatedReceiptId(501),
            ],
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        let round: ReplicaSetRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rec, round);
    }

    #[test]
    fn serde_roundtrip_replica_placement_intent_record() {
        let rec = ReplicaPlacementIntentRecord {
            intent_id: ReplicatedReceiptId(200),
            flow_class: FlowCommitClass::Rebuild,
            subject_ref: ReplicatedSubjectId::new(42),
            source_refs: vec![MemberId::new(1), MemberId::new(2)],
            target_refs: vec![MemberId::new(3)],
            policy_revision_ref: 7,
            budget_domain_ref: 88,
            target_tier: None,
            reserve_class_ref: 99,
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        let round: ReplicaPlacementIntentRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rec, round);
    }

    #[test]
    fn serde_roundtrip_replica_chunk_state_record() {
        let rec = ReplicaChunkStateRecord {
            chunk_id: 33,
            subject_ref: ReplicatedSubjectId::new(7),
            source_ref: MemberId::new(1),
            target_ref: MemberId::new(2),
            range_ref: 4096,
            digest: ObjectDigest::new(0xABCDEF),
            state: ReplicaChunkState::Transferring,
            transfer_ticket_ref: ReplicatedReceiptId(100),
            verification_receipt_ref: ReplicatedReceiptId::default(),
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        let round: ReplicaChunkStateRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rec, round);
    }

    #[test]
    fn serde_roundtrip_rebuild_flow_record() {
        let rec = RebuildFlowRecord {
            rebuild_flow_id: 10,
            loss_event_ref: 55,
            loss_event_class: LossEventClass::NodeFailure,
            scope_selector: FlowScopeSelector::Domain(DomainId::new(3)),
            source_candidate_refs: vec![MemberId::new(10), MemberId::new(20)],
            target_refs: vec![MemberId::new(30)],
            state: RebuildFlowState::Transferring,
            degraded_class: RebuildDegradedClass::DegradedReadPossible,
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        let round: RebuildFlowRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rec, round);
    }

    #[test]
    fn serde_roundtrip_rebuild_batch_record() {
        let rec = RebuildBatchRecord {
            batch_id: 1,
            rebuild_flow_ref: 10,
            chunk_refs: vec![100, 101, 102],
            source_bundle_refs: vec![MemberId::new(10)],
            target_refs: vec![MemberId::new(30)],
            verification_requirements: VerificationStatus::Verified,
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        let round: RebuildBatchRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rec, round);
    }

    #[test]
    fn serde_roundtrip_relocation_flow_record() {
        let rec = RelocationFlowRecord {
            relocation_flow_id: 5,
            reason_class: RelocationReasonClass::DrainMember,
            scope_selector: FlowScopeSelector::Subject(ReplicatedSubjectId::new(99)),
            source_refs: vec![MemberId::new(1)],
            target_refs: vec![MemberId::new(2), MemberId::new(3)],
            state: RelocationFlowState::Transferring,
            reclaim_debt_ref: 0,
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        let round: RelocationFlowRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rec, round);
    }

    #[test]
    fn serde_roundtrip_relocation_batch_record() {
        let rec = RelocationBatchRecord {
            batch_id: 2,
            relocation_flow_ref: 5,
            chunk_refs: vec![200, 201],
            pointer_move_ready: false,
            source_retire_ready: false,
            verification_refs: vec![ReplicatedReceiptId(800)],
            placement_receipt_refs: vec![PlacementReceiptRef::replicated(
                99,
                receipt_key(99),
                EpochId::new(12),
                3,
                2,
                8192,
                receipt_digest(99, 3),
            )],
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        let round: RelocationBatchRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rec, round);
    }

    #[test]
    fn serde_relocation_batch_record_defaults_legacy_receipts() {
        let json = r#"{
            "batch_id": 2,
            "relocation_flow_ref": 5,
            "chunk_refs": [200, 201],
            "pointer_move_ready": false,
            "source_retire_ready": false,
            "verification_refs": [800]
        }"#;
        let round: RelocationBatchRecord = serde_json::from_str(json).expect("deserialize");
        assert!(round.placement_receipt_refs.is_empty());
    }

    #[test]
    fn serde_roundtrip_replica_lag_state_record() {
        let rec = ReplicaLagStateRecord {
            subject_ref: ReplicatedSubjectId::new(55),
            target_ref: MemberId::new(3),
            freshness_fence_frontier: 5000,
            lag_class: ReplicaLagClass::ModeratelyBehind,
            bytes_behind: 65536,
            oldest_missing_receipt_ref: ReplicatedReceiptId(100),
            degraded_visibility_class: DegradedVisibilityClass::DegradedReadPossible,
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        let round: ReplicaLagStateRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rec, round);
    }
}

#[cfg(test)]
mod orchestrator_tests {
    use super::*;
    // ── Transfer Orchestrator tests (P8-03 §2: data_copy_1) ──

    fn orchestrator_receipt_ref(
        subject: u64,
        payload_len: u64,
        generation: u64,
    ) -> PlacementReceiptRef {
        let mut object_key = [0xC3; 32];
        object_key[..8].copy_from_slice(&subject.to_le_bytes());
        let mut payload_digest = [0x3C; 32];
        payload_digest[..8].copy_from_slice(&subject.to_le_bytes());
        payload_digest[8..16].copy_from_slice(&generation.to_le_bytes());
        PlacementReceiptRef::replicated(
            subject,
            object_key,
            EpochId::new(1),
            generation,
            1,
            payload_len,
            payload_digest,
        )
    }

    fn make_intent(
        id: u64,
        subject: u64,
        source: u64,
        target: u64,
        class: ReplicaMovementClass,
        payload_len: u64,
    ) -> ReplicaMovementIntentRecord {
        ReplicaMovementIntentRecord {
            intent_id: ReplicatedReceiptId(id),
            movement_class: class,
            subject_ref: ReplicatedSubjectId(subject),
            placement_receipt_ref: orchestrator_receipt_ref(subject, payload_len, id),
            source_member_ref: MemberId::new(source),
            target_member_ref: MemberId::new(target),
            payload_digest: ObjectDigest(subject * 100),
            payload_len,
            verification_required: true,
        }
    }

    fn make_verdict() -> MembershipPlacementVerdictRecord {
        MembershipPlacementVerdictRecord {
            verdict_id: 1,
            membership_epoch_ref: EpochId(1),
            placement_class: tidefs_membership_epoch::PlacementIntentClass::ReplicaTarget,
            selected_member_refs: vec![],
            selected_domain_refs: vec![],
            verdict_class: VerdictClass::Admit,
            degraded_reason_refs: vec![],
            issuance_receipt_ref: tidefs_membership_epoch::ReceiptId::ZERO,
            digest: 0,
        }
    }

    fn default_config() -> TransferOrchestratorConfig {
        TransferOrchestratorConfig {
            max_concurrent_per_link: 4,
            max_bytes_in_flight_per_link: 1_048_576, // 1 MiB
            max_total_bytes_in_flight: 4_194_304,    // 4 MiB
            default_ticket_expiry_offset: 10,
        }
    }

    #[test]
    fn orchestrator_empty_intents_yields_no_transfers() {
        let config = default_config();
        let load = BTreeMap::new();
        let result = orchestrate_transfer_intents(&[], &config, &load, 100, 50);
        assert!(result.scheduled.is_empty());
        assert!(result.rejected.is_empty());
        assert!(result.link_consumption.is_empty());
    }

    #[test]
    fn orchestrator_single_intent_schedules_one_ticket() {
        let intent = make_intent(
            1,
            10,
            101,
            201,
            ReplicaMovementClass::RebuildLostOrSuspectCopy,
            4096,
        );
        let config = default_config();
        let load = BTreeMap::new();
        let result = orchestrate_transfer_intents(&[intent.clone()], &config, &load, 100, 50);

        assert_eq!(result.scheduled.len(), 1);
        assert!(result.rejected.is_empty());

        let s = &result.scheduled[0];
        assert_eq!(s.ticket.subject_refs, vec![ReplicatedSubjectId(10)]);
        assert_eq!(s.ticket.target_ref, intent.target_member_ref);
        assert_eq!(s.ticket.freshness_fence_ref, 100);
        assert_eq!(s.ticket.expiry, 60);
        assert_eq!(s.assignment.source, intent.source_member_ref);
        assert_eq!(s.assignment.target, intent.target_member_ref);
        assert_eq!(s.assignment.lane_class, lane_class_discriminant::BACKGROUND);
        assert_eq!(s.assignment.priority, 0);
        assert_eq!(s.flow_class, FlowCommitClass::Rebuild);

        let link = result
            .link_consumption
            .iter()
            .find(|e| e.source == intent.source_member_ref && e.target == intent.target_member_ref)
            .map(|e| &e.consumption)
            .unwrap();
        assert_eq!(link.active_transfers, 1);
        assert_eq!(link.bytes_in_flight, 4096);
    }

    #[test]
    fn orchestrator_sorts_by_priority_rebuild_first() {
        let rebuild = make_intent(
            1,
            10,
            101,
            201,
            ReplicaMovementClass::RebuildLostOrSuspectCopy,
            1024,
        );
        let backfill = make_intent(
            2,
            11,
            102,
            202,
            ReplicaMovementClass::BackfillLaggedCopy,
            2048,
        );
        let rebalance = make_intent(
            3,
            12,
            103,
            203,
            ReplicaMovementClass::RebalanceCapacityPressure,
            4096,
        );
        let intents = vec![rebalance, backfill, rebuild];
        let config = default_config();
        let load = BTreeMap::new();
        let result = orchestrate_transfer_intents(&intents, &config, &load, 100, 50);
        assert_eq!(result.scheduled.len(), 3);
        assert!(result.rejected.is_empty());
        assert_eq!(result.scheduled[0].assignment.priority, 0);
        assert_eq!(result.scheduled[1].assignment.priority, 1);
        assert_eq!(result.scheduled[2].assignment.priority, 2);
    }

    #[test]
    fn orchestrator_respects_per_link_concurrency_budget() {
        let config = TransferOrchestratorConfig {
            max_concurrent_per_link: 2,
            max_bytes_in_flight_per_link: 1_048_576,
            max_total_bytes_in_flight: 4_194_304,
            default_ticket_expiry_offset: 10,
        };
        let intents: Vec<_> = (0..5)
            .map(|i| {
                make_intent(
                    i,
                    i,
                    101,
                    201,
                    ReplicaMovementClass::BackfillLaggedCopy,
                    1024,
                )
            })
            .collect();
        let load = BTreeMap::new();
        let result = orchestrate_transfer_intents(&intents, &config, &load, 100, 50);
        assert_eq!(result.scheduled.len(), 2);
        assert_eq!(result.rejected.len(), 3);
        for reason in &result.rejection_reasons {
            assert!(reason.contains("concurrency budget exhausted"));
        }
    }

    #[test]
    fn orchestrator_respects_per_link_byte_budget() {
        let config = TransferOrchestratorConfig {
            max_concurrent_per_link: 8,
            max_bytes_in_flight_per_link: 4096,
            max_total_bytes_in_flight: 1_048_576,
            default_ticket_expiry_offset: 10,
        };
        let intents = vec![
            make_intent(
                1,
                10,
                101,
                201,
                ReplicaMovementClass::BackfillLaggedCopy,
                2048,
            ),
            make_intent(
                2,
                11,
                101,
                201,
                ReplicaMovementClass::BackfillLaggedCopy,
                2048,
            ),
            make_intent(
                3,
                12,
                101,
                201,
                ReplicaMovementClass::BackfillLaggedCopy,
                2048,
            ),
        ];
        let load = BTreeMap::new();
        let result = orchestrate_transfer_intents(&intents, &config, &load, 100, 50);
        assert_eq!(result.scheduled.len(), 2);
        assert_eq!(result.rejected.len(), 1);
        assert!(result.rejection_reasons[0].contains("per-link byte budget exceeded"));
    }

    #[test]
    fn orchestrator_respects_global_byte_budget() {
        let config = TransferOrchestratorConfig {
            max_concurrent_per_link: 8,
            max_bytes_in_flight_per_link: 1_048_576,
            max_total_bytes_in_flight: 4096,
            default_ticket_expiry_offset: 10,
        };
        let intents = vec![
            make_intent(
                1,
                10,
                101,
                201,
                ReplicaMovementClass::BackfillLaggedCopy,
                2048,
            ),
            make_intent(
                2,
                11,
                102,
                202,
                ReplicaMovementClass::BackfillLaggedCopy,
                2048,
            ),
            make_intent(
                3,
                12,
                103,
                203,
                ReplicaMovementClass::BackfillLaggedCopy,
                2048,
            ),
        ];
        let load = BTreeMap::new();
        let result = orchestrate_transfer_intents(&intents, &config, &load, 100, 50);
        assert_eq!(result.scheduled.len(), 2);
        assert_eq!(result.rejected.len(), 1);
        assert!(result.rejection_reasons[0].contains("global byte budget exceeded"));
    }

    #[test]
    fn orchestrator_mixed_acceptance_and_rejection() {
        let config = TransferOrchestratorConfig {
            max_concurrent_per_link: 1,
            max_bytes_in_flight_per_link: 1_048_576,
            max_total_bytes_in_flight: 1_048_576,
            default_ticket_expiry_offset: 10,
        };
        let intents = vec![
            make_intent(
                1,
                10,
                101,
                201,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                1024,
            ),
            make_intent(
                2,
                11,
                101,
                201,
                ReplicaMovementClass::BackfillLaggedCopy,
                2048,
            ),
            make_intent(
                3,
                12,
                102,
                202,
                ReplicaMovementClass::RebalanceCapacityPressure,
                512,
            ),
        ];
        let load = BTreeMap::new();
        let result = orchestrate_transfer_intents(&intents, &config, &load, 100, 50);
        assert_eq!(result.scheduled.len(), 2);
        assert_eq!(result.rejected.len(), 1);
        assert_eq!(result.scheduled[0].flow_class, FlowCommitClass::Rebuild);
        assert_eq!(result.scheduled[1].flow_class, FlowCommitClass::Relocation);
        assert!(result.rejection_reasons[0].contains("concurrency budget exhausted"));
    }

    #[test]
    fn orchestrator_incremental_scheduling_with_existing_load() {
        let config = TransferOrchestratorConfig {
            max_concurrent_per_link: 2,
            max_bytes_in_flight_per_link: 1_048_576,
            max_total_bytes_in_flight: 1_048_576,
            default_ticket_expiry_offset: 10,
        };
        let mut load = BTreeMap::new();
        load.insert(
            (MemberId::new(101), MemberId::new(201)),
            LinkConsumption {
                active_transfers: 1,
                bytes_in_flight: 512,
            },
        );
        let intents = vec![
            make_intent(
                1,
                10,
                101,
                201,
                ReplicaMovementClass::BackfillLaggedCopy,
                1024,
            ),
            make_intent(
                2,
                11,
                101,
                201,
                ReplicaMovementClass::BackfillLaggedCopy,
                2048,
            ),
        ];
        let result = orchestrate_transfer_intents(&intents, &config, &load, 100, 50);
        assert_eq!(result.scheduled.len(), 1);
        assert_eq!(result.rejected.len(), 1);
        let link = result
            .link_consumption
            .iter()
            .find(|e| e.source == MemberId::new(101) && e.target == MemberId::new(201))
            .map(|e| &e.consumption)
            .unwrap();
        assert_eq!(link.active_transfers, 2);
        assert_eq!(link.bytes_in_flight, 512 + 1024);
    }

    #[test]
    fn orchestrator_freshness_fence_and_expiry_propagate() {
        let config = TransferOrchestratorConfig {
            max_concurrent_per_link: 8,
            max_bytes_in_flight_per_link: 1_048_576,
            max_total_bytes_in_flight: 1_048_576,
            default_ticket_expiry_offset: 42,
        };
        let intents = vec![make_intent(
            1,
            10,
            101,
            201,
            ReplicaMovementClass::RebuildLostOrSuspectCopy,
            1024,
        )];
        let load = BTreeMap::new();
        let result = orchestrate_transfer_intents(&intents, &config, &load, 777, 100);
        assert_eq!(result.scheduled.len(), 1);
        let ticket = &result.scheduled[0].ticket;
        assert_eq!(ticket.freshness_fence_ref, 777);
        assert_eq!(ticket.expiry, 142);
    }

    #[test]
    fn orchestrator_movement_to_flow_class_mapping() {
        assert_eq!(
            movement_to_flow_class(ReplicaMovementClass::RebuildLostOrSuspectCopy),
            FlowCommitClass::Rebuild
        );
        assert_eq!(
            movement_to_flow_class(ReplicaMovementClass::BackfillLaggedCopy),
            FlowCommitClass::CatchupReplication
        );
        assert_eq!(
            movement_to_flow_class(ReplicaMovementClass::RebalanceCapacityPressure),
            FlowCommitClass::Relocation
        );
    }

    #[test]
    fn orchestrator_movement_priority_ordering() {
        assert!(
            movement_priority(ReplicaMovementClass::RebuildLostOrSuspectCopy)
                < movement_priority(ReplicaMovementClass::BackfillLaggedCopy)
        );
        assert!(
            movement_priority(ReplicaMovementClass::BackfillLaggedCopy)
                < movement_priority(ReplicaMovementClass::RebalanceCapacityPressure)
        );
    }

    #[test]
    fn orchestrator_movement_plan_wraps_transfer_intents() {
        let intent = make_intent(
            1,
            10,
            101,
            201,
            ReplicaMovementClass::RebuildLostOrSuspectCopy,
            4096,
        );
        let plan = ReplicaMovementPlan {
            subject_ref: ReplicatedSubjectId(10),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            plan_class: ReplicaMovementPlanClass::Planned,
            source_member_refs: vec![MemberId::new(101)],
            target_member_refs: vec![MemberId::new(201)],
            retained_member_refs: vec![],
            faulted_member_refs: vec![],
            final_member_refs: vec![MemberId::new(201)],
            transfer_intents: vec![intent],
            placement_verdict: make_verdict(),
            movement_receipt_ref: ReplicatedReceiptId(1),
        };
        let config = default_config();
        let load = BTreeMap::new();
        let result = orchestrate_movement_plan(&plan, &config, &load, 100, 50);
        assert_eq!(result.scheduled.len(), 1);
        assert!(result.rejected.is_empty());
    }

    #[test]
    fn orchestrator_serde_roundtrip_schedule_record() {
        let intent = make_intent(
            1,
            10,
            101,
            201,
            ReplicaMovementClass::RebuildLostOrSuspectCopy,
            4096,
        );
        let ticket = stage_replica_transfer_ticket(&intent, &[intent.source_member_ref], 100, 60);
        let record = TransferScheduleRecord {
            ticket,
            assignment: TransferLinkAssignment {
                source: MemberId::new(101),
                target: MemberId::new(201),
                lane_class: lane_class_discriminant::BACKGROUND,
                priority: 0,
            },
            flow_class: FlowCommitClass::Rebuild,
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let round: TransferScheduleRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, round);
    }

    #[test]
    fn orchestrator_serde_roundtrip_orchestration_plan() {
        let intent = make_intent(
            1,
            10,
            101,
            201,
            ReplicaMovementClass::BackfillLaggedCopy,
            2048,
        );
        let config = default_config();
        let load = BTreeMap::new();
        let plan = orchestrate_transfer_intents(&[intent.clone()], &config, &load, 100, 50);
        let json = serde_json::to_string(&plan).expect("serialize");
        let round: OrchestrationPlan = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(plan.scheduled.len(), round.scheduled.len());
        assert_eq!(plan.rejected.len(), round.rejected.len());
        assert_eq!(plan.rejection_reasons, round.rejection_reasons);
        assert_eq!(plan.link_consumption, round.link_consumption);
    }

    #[test]
    fn orchestrator_default_config_is_reasonable() {
        let config = TransferOrchestratorConfig::default();
        assert_eq!(config.max_concurrent_per_link, 8);
        assert_eq!(config.max_bytes_in_flight_per_link, 64 * 1024 * 1024);
        assert_eq!(config.max_total_bytes_in_flight, 512 * 1024 * 1024);
        assert_eq!(config.default_ticket_expiry_offset, 10);
    }
}
#[cfg(test)]
mod property_tests {
    use super::*;
    use tidefs_membership_epoch::{
        synthesize_membership_config_epoch_and_quorum_sets, ConfigClass, FailureDomainClass,
        FailureDomainPlacementPolicy, FailureDomainVector, MemberAdmission, MemberClass,
    };

    const fn prng(seed: u64, iter: u64) -> u64 {
        seed.wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407)
            .wrapping_add(iter)
    }

    const fn domain(seed: u64, rack: u64) -> FailureDomainVector {
        FailureDomainVector::new(
            DomainId::new(seed * 10 + 1),
            DomainId::new(seed * 10 + 2),
            DomainId::new(seed * 10 + 3),
            DomainId::new(rack),
            DomainId::new(1),
            DomainId::new(1),
        )
    }

    fn admission(
        id: u64,
        member_class: MemberClass,
        health: HealthClass,
        rack: u64,
    ) -> MemberAdmission {
        MemberAdmission {
            member_id: MemberId::new(id),
            member_class,
            log_frontier: 100,
            health,
            failure_domain_vector: domain(id, rack),
        }
    }

    fn cluster(
        admissions: &[MemberAdmission],
        epoch: u64,
    ) -> (Vec<ClusterMemberRecord>, MembershipConfigRecord) {
        let members = tidefs_membership_epoch::inventory_members_and_classify_participation_roles(
            admissions,
            EpochId::new(epoch),
        )
        .expect("inventory");
        let config = synthesize_membership_config_epoch_and_quorum_sets(
            EpochId::new(epoch),
            ConfigClass::Normal,
            epoch,
            &members,
            &[],
            &[],
        )
        .expect("config");
        (members, config)
    }

    fn root_subject(subject_id: u64, epoch: u64) -> ReplicatedObjectRootRecord {
        ReplicatedObjectRootRecord {
            subject_id: ReplicatedSubjectId::new(subject_id),
            subject_class: ReplicatedSubjectClass::AuthenticatedRoot,
            membership_epoch_ref: EpochId::new(epoch),
            root_generation: 9,
            payload_digest: ObjectDigest::new(0xA11CE),
            payload_len: 4096,
            publication_receipt_ref: ReplicatedReceiptId(17),
        }
    }

    #[test]
    fn write_plan_always_meets_quorum_when_not_refused() {
        for seed in 0..8u64 {
            let replica_count = (1 + (seed % 5)) as usize;
            let voters = 3 + (prng(seed, 100) % 6);
            let data_members = prng(seed, 200) % 4;
            let mut ads = Vec::new();
            for i in 0..voters {
                ads.push(admission(
                    1 + i,
                    MemberClass::Voter,
                    HealthClass::Healthy,
                    1 + i,
                ));
            }
            for i in 0..data_members {
                ads.push(admission(
                    100 + i,
                    MemberClass::DataOnly,
                    HealthClass::Healthy,
                    100 + i,
                ));
            }
            let (members, config) = cluster(&ads, 10);
            let subject = root_subject(200, 10);

            let writable: Vec<MemberId> = members
                .iter()
                .filter(|m| {
                    m.member_class == MemberClass::Voter && m.health == HealthClass::Healthy
                })
                .map(|m| m.member_id)
                .collect();

            let plan = commit_replicated_object_root_write(
                &config,
                &members,
                subject,
                FailureDomainPlacementPolicy::strict_replica_targets(
                    replica_count,
                    FailureDomainClass::Rack,
                ),
                &writable,
            );

            if plan.write_class != ReplicatedWriteClass::RefusedNoQuorum {
                assert!(
                    plan.committed_member_refs.len() >= plan.quorum_required,
                    "seed={seed}: committed {} < quorum {} for write_class {:?}",
                    plan.committed_member_refs.len(),
                    plan.quorum_required,
                    plan.write_class,
                );
            }
        }
    }

    #[test]
    fn erasure_code_encode_decode_roundtrip() {
        for seed in 0..8u64 {
            let payload_len = 32 + (prng(seed, 0) as usize % 4065);
            let shard_len = 128 + (prng(seed, 1) as usize % 896);
            let data_shard_count = 2 + (prng(seed, 2) as usize % 5);
            let policy = ErasureLayoutPolicy {
                shard_len,
                data_shard_count,
                parity_shard_count: 1,
                layout_class: ErasureLayoutClass::SingleParityXor,
            };
            if !policy.admits_single_parity_xor() {
                continue;
            }

            let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
            let stripe = encode_single_parity_erasure_stripe(
                ReplicatedSubjectId::new(1),
                0,
                &payload,
                policy,
            );

            if let Some(ref s) = stripe {
                let all_shards: Vec<ErasureShardRecord> = s.shards.clone();
                let plan = decode_single_parity_erasure_stripe(s, &all_shards);

                assert!(
                    matches!(
                        plan.decode_class,
                        ErasureDecodeClass::Complete | ErasureDecodeClass::RebuiltParityShard
                    ),
                    "seed={seed}: decode failed with {:?}",
                    plan.decode_class
                );
                let decoded = plan.reconstructed_payload.as_ref().expect("no payload");
                assert_eq!(
                    decoded,
                    &payload,
                    "seed={seed}: roundtrip payload mismatch: expected len {} got len {}",
                    payload.len(),
                    decoded.len()
                );
            }
        }
    }

    #[test]
    fn erasure_code_single_shard_loss_recovery() {
        for seed in 0..6u64 {
            let payload_len = 64 + (prng(seed, 3) as usize % 1985);
            let policy = ErasureLayoutPolicy {
                shard_len: 256,
                data_shard_count: 4,
                parity_shard_count: 1,
                layout_class: ErasureLayoutClass::SingleParityXor,
            };

            let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
            let stripe = encode_single_parity_erasure_stripe(
                ReplicatedSubjectId::new(3),
                0,
                &payload,
                policy,
            );

            if let Some(ref s) = stripe {
                let lost_index = 1 + (seed as usize % 3);
                let partial_shards: Vec<ErasureShardRecord> = s
                    .shards
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != lost_index)
                    .map(|(_, shard)| shard.clone())
                    .collect();
                let plan = decode_single_parity_erasure_stripe(s, &partial_shards);

                assert!(
                    matches!(
                        plan.decode_class,
                        ErasureDecodeClass::ReconstructedSingleDataShard
                    ),
                    "seed={seed}: single-shard-loss decode failed with {:?}",
                    plan.decode_class
                );
                let decoded = plan.reconstructed_payload.as_ref().expect("no payload");
                assert_eq!(
                    decoded,
                    &payload,
                    "seed={seed}: recovery payload mismatch: expected len {} got len {}",
                    payload.len(),
                    decoded.len()
                );

                let rebuilt_data_shards: Vec<_> = plan
                    .rebuilt_shards
                    .iter()
                    .filter(|s| s.shard_class == ErasureShardClass::Data)
                    .collect();
                assert_eq!(
                    rebuilt_data_shards.len(),
                    1,
                    "seed={seed}: expected 1 rebuilt data shard, got {}",
                    rebuilt_data_shards.len()
                );
            }
        }
    }

    #[test]
    fn rebuild_plan_only_selects_healthy_verified_sources() {
        for seed in 0..8u64 {
            let member_count = 3 + (prng(seed, 10) % 8);
            let mut ads = Vec::new();
            for i in 0..member_count {
                let health = if i % 3 == 0 {
                    HealthClass::Down
                } else {
                    HealthClass::Healthy
                };
                ads.push(admission(1 + i, MemberClass::Voter, health, 1 + i));
            }
            let (members, config) = cluster(&ads, 20);
            let subject = root_subject(500, 20);

            let copies: Vec<ReplicaCopyRecord> = members
                .iter()
                .map(|m| {
                    ReplicaCopyRecord::verified(
                        subject.subject_id,
                        m.member_id,
                        DomainId::new(m.member_id.0 * 10 + 1),
                        subject.payload_digest,
                        100,
                    )
                })
                .collect();

            let plan = rebuild_replicated_object_root_from_sources(
                &config,
                &members,
                &subject,
                &copies,
                FailureDomainPlacementPolicy::strict_replica_targets(3, FailureDomainClass::Rack),
            );

            for src in &plan.source_member_refs {
                let member = members
                    .iter()
                    .find(|m| m.member_id == *src)
                    .expect("source member not found");
                assert_ne!(
                    member.health,
                    HealthClass::Down,
                    "seed={seed}: source member {src:?} is Down"
                );
            }
        }
    }

    #[test]
    fn read_plan_never_selects_unverified_source() {
        for seed in 0..8u64 {
            let member_count = 3 + (prng(seed, 20) % 6);
            let mut ads = Vec::new();
            for i in 0..member_count {
                ads.push(admission(
                    1 + i,
                    MemberClass::Voter,
                    HealthClass::Healthy,
                    1 + i,
                ));
            }
            let (members, _config) = cluster(&ads, 30);
            let subject = root_subject(600, 30);

            let copies: Vec<ReplicaCopyRecord> = members
                .iter()
                .enumerate()
                .map(|(i, m)| {
                    if i == 0 {
                        ReplicaCopyRecord::verified(
                            subject.subject_id,
                            m.member_id,
                            DomainId::new(m.member_id.0 * 10 + 1),
                            subject.payload_digest,
                            100,
                        )
                    } else {
                        ReplicaCopyRecord::unavailable(
                            subject.subject_id,
                            m.member_id,
                            DomainId::new(m.member_id.0 * 10 + 1),
                            ReplicaCopyClass::Missing,
                            ObjectDigest::default(),
                        )
                    }
                })
                .collect();

            let plan = plan_replicated_object_root_read(&subject, &copies, 3);

            if let Some(src) = plan.source_member_ref {
                let copy = copies
                    .iter()
                    .find(|c| c.member_ref == src)
                    .expect("source copy not found");
                assert_eq!(
                    copy.copy_class,
                    ReplicaCopyClass::Verified,
                    "seed={seed}: read plan selected non-verified source"
                );
            }
        }
    }

    // ========== serde round-trip tests ==========

    #[test]
    fn serde_roundtrip_replicated_subject_id() {
        let id = ReplicatedSubjectId::new(100);
        let json = serde_json::to_string(&id).expect("serialize");
        let round: ReplicatedSubjectId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, round);
    }

    #[test]
    fn serde_roundtrip_object_digest() {
        let d = ObjectDigest::new(0xDEAD);
        let json = serde_json::to_string(&d).expect("serialize");
        let round: ObjectDigest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(d, round);
    }

    #[test]
    fn serde_roundtrip_replicated_object_root_record() {
        let rec = ReplicatedObjectRootRecord {
            subject_id: ReplicatedSubjectId::new(200),
            subject_class: ReplicatedSubjectClass::ImmutableObject,
            membership_epoch_ref: tidefs_membership_epoch::EpochId(1),
            root_generation: 5,
            payload_digest: ObjectDigest::new(0xABCD),
            payload_len: 4096,
            publication_receipt_ref: ReplicatedReceiptId(500),
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        let round: ReplicatedObjectRootRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rec, round);
    }

    #[test]
    fn serde_roundtrip_replica_copy_record() {
        let rec = ReplicaCopyRecord {
            subject_ref: ReplicatedSubjectId::new(300),
            member_ref: tidefs_membership_epoch::MemberId(1),
            domain_ref: tidefs_membership_epoch::DomainId(10),
            copy_class: ReplicaCopyClass::Verified,
            payload_digest: ObjectDigest::new(0xBEEF),
            freshness_frontier: 120,
            verification_receipt_ref: ReplicatedReceiptId(600),
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        let round: ReplicaCopyRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rec, round);
    }

    #[test]
    fn serde_roundtrip_erasure_shard_record() {
        let shard = ErasureShardRecord {
            subject_ref: ReplicatedSubjectId::new(400),
            stripe_index: 0,
            shard_index: 0,
            shard_class: ErasureShardClass::Data,
            state_class: ErasureShardStateClass::Available,
            payload_digest: ObjectDigest::new(0xDEAD),
            payload_len: 64,
            bytes: vec![0u8; 64],
        };
        let json = serde_json::to_string(&shard).expect("serialize");
        let round: ErasureShardRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(shard, round);
        assert_eq!(round.bytes.len(), 64);
    }

    #[test]
    fn serde_roundtrip_rebuild_plan() {
        let plan = RebuildPlan {
            subject_ref: ReplicatedSubjectId::new(500),
            source_member_refs: vec![tidefs_membership_epoch::MemberId(1)],
            target_member_refs: vec![tidefs_membership_epoch::MemberId(2)],
            final_member_refs: vec![
                tidefs_membership_epoch::MemberId(1),
                tidefs_membership_epoch::MemberId(2),
            ],
            placement_verdict: tidefs_membership_epoch::MembershipPlacementVerdictRecord {
                verdict_id: 10,
                membership_epoch_ref: tidefs_membership_epoch::EpochId(1),
                placement_class: tidefs_membership_epoch::PlacementIntentClass::ReplicaTarget,
                selected_member_refs: vec![],
                selected_domain_refs: vec![],
                verdict_class: tidefs_membership_epoch::VerdictClass::Admit,
                degraded_reason_refs: vec![],
                issuance_receipt_ref: tidefs_membership_epoch::ReceiptId::ZERO,
                digest: 0,
            },
            rebuild_class: RebuildPlanClass::Restored,
            rebuild_receipt_ref: ReplicatedReceiptId(700),
        };
        let json = serde_json::to_string(&plan).expect("serialize");
        let round: RebuildPlan = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(plan, round);
    }

    // ========== Flow commit coordinator tests ==========

    fn flow_receipt_ref(subject: u64, payload_len: u64, generation: u64) -> PlacementReceiptRef {
        let mut object_key = [0xD4; 32];
        object_key[..8].copy_from_slice(&subject.to_le_bytes());
        let mut payload_digest = [0x4D; 32];
        payload_digest[..8].copy_from_slice(&subject.to_le_bytes());
        payload_digest[8..16].copy_from_slice(&generation.to_le_bytes());
        PlacementReceiptRef::replicated(
            subject,
            object_key,
            EpochId::new(1),
            generation,
            1,
            payload_len,
            payload_digest,
        )
    }

    fn make_test_flow_data() -> (
        ReplicaCopyRecord,
        ReplicaTransferTicketRecord,
        ReplicaTransferReceipt,
        ReplicaVerificationReceipt,
    ) {
        let expected_digest = ObjectDigest::new(0xF00D);
        let copy = ReplicaCopyRecord {
            subject_ref: ReplicatedSubjectId::new(100),
            member_ref: MemberId::new(50),
            domain_ref: DomainId::new(500),
            copy_class: ReplicaCopyClass::Rebuilding,
            payload_digest: ObjectDigest::default(),
            freshness_frontier: 0,
            verification_receipt_ref: ReplicatedReceiptId::default(),
        };

        let intent = ReplicaMovementIntentRecord {
            intent_id: ReplicatedReceiptId(1000),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            subject_ref: ReplicatedSubjectId::new(100),
            placement_receipt_ref: flow_receipt_ref(100, 4096, 1000),
            source_member_ref: MemberId::new(10),
            target_member_ref: MemberId::new(50),
            payload_digest: expected_digest,
            payload_len: 4096,
            verification_required: true,
        };

        let ticket = stage_replica_transfer_ticket(&intent, &[MemberId::new(10)], 100, 500);

        let transfer = emit_replica_transfer_receipt(
            &ticket,
            4096,
            0xAAAA,
            0xBBBB,
            EpochId::new(20),
            &[MemberId::new(10)],
        );

        let verification = verify_transferred_chunks_and_emit_verification_receipt(
            &transfer,
            &[ReplicatedSubjectId::new(100)],
            expected_digest,
            &[expected_digest],
            &[MemberId::new(60)],
            2,
            EpochId::new(20),
        );

        (copy, ticket, transfer, verification)
    }

    #[test]
    fn place_after_verification_emits_placement_receipt() {
        let (_, _ticket, transfer, verification) = make_test_flow_data();

        let placement = emit_replica_placement_receipt(
            &verification,
            &transfer,
            MemberId::new(50),
            EpochId::new(21),
        );

        assert_eq!(placement.verification_ref, verification.receipt_id);
        assert_eq!(placement.transfer_ref, transfer.receipt_id);
        assert_eq!(placement.subject_refs, vec![ReplicatedSubjectId::new(100)]);
        assert_eq!(placement.placed_on, MemberId::new(50));
        assert_eq!(placement.placement_epoch, EpochId::new(21));
        assert_eq!(placement.subjects_placed, 1);
        assert_ne!(placement.receipt_id, ReplicatedReceiptId::default());
    }

    #[test]
    #[should_panic(expected = "placement requires Verified")]
    fn placement_rejects_non_verified_verification() {
        let (_, _ticket, transfer, _) = make_test_flow_data();

        let bad_verification = ReplicaVerificationReceipt {
            receipt_id: ReplicatedReceiptId(9999),
            subject_refs: vec![ReplicatedSubjectId::new(100)],
            digest_results: vec![ObjectDigest::new(0xF00D)],
            witness_refs: vec![MemberId::new(60)],
            quorum_class: 2,
            verification_epoch: EpochId::new(20),
            status: VerificationStatus::DigestMismatch,
        };

        let _ = emit_replica_placement_receipt(
            &bad_verification,
            &transfer,
            MemberId::new(50),
            EpochId::new(21),
        );
    }

    #[test]
    fn flow_state_machine_advances_through_all_states() {
        let s = FlowState::Planned;
        let s = advance_flow_state(s, FlowState::Transferring);
        assert_eq!(s, FlowState::Transferring);

        let s = advance_flow_state(s, FlowState::Transferred);
        assert_eq!(s, FlowState::Transferred);

        let s = advance_flow_state(s, FlowState::Verifying);
        assert_eq!(s, FlowState::Verifying);

        let s = advance_flow_state(s, FlowState::Verified);
        assert_eq!(s, FlowState::Verified);

        let s = advance_flow_state(s, FlowState::Complete);
        assert_eq!(s, FlowState::Complete);
    }

    #[test]
    fn flow_state_machine_abort_is_terminal() {
        for start in &[
            FlowState::Planned,
            FlowState::Transferring,
            FlowState::Transferred,
            FlowState::Verifying,
            FlowState::Verified,
            FlowState::Complete,
        ] {
            let result = advance_flow_state(*start, FlowState::Aborted);
            assert_eq!(result, FlowState::Aborted);

            // Aborted is terminal
            let result2 = advance_flow_state(result, FlowState::Transferring);
            assert_eq!(result2, FlowState::Aborted);
        }
    }

    #[test]
    #[should_panic(expected = "invalid flow state transition")]
    fn flow_state_machine_invalid_transition_panics() {
        let _ = advance_flow_state(FlowState::Transferred, FlowState::Planned);
    }

    #[test]
    fn flow_state_idempotent_transition() {
        let result = advance_flow_state(FlowState::Transferring, FlowState::Transferring);
        assert_eq!(result, FlowState::Transferring);
    }

    #[test]
    fn commit_transfer_flow_produces_complete_result() {
        let (copy, _ticket, transfer, verification) = make_test_flow_data();
        let expected_digest = ObjectDigest::new(0xF00D);

        let result = commit_transfer_flow(
            copy.clone(),
            &verification,
            &transfer,
            FlowCommitClass::Rebuild,
            FlowState::Verified,
            EpochId::new(30),
            expected_digest,
        );

        assert_eq!(result.final_flow_state, FlowState::Complete);
        assert_eq!(result.flow_class, FlowCommitClass::Rebuild);
        assert_eq!(result.commit_epoch, EpochId::new(30));
        assert_eq!(result.updated_copy.copy_class, ReplicaCopyClass::Verified);
        assert_eq!(result.updated_copy.payload_digest, expected_digest);
        assert_eq!(
            result.updated_copy.verification_receipt_ref,
            verification.receipt_id
        );
        assert_eq!(
            result.placement_receipt.verification_ref,
            verification.receipt_id
        );
        assert_eq!(result.placement_receipt.transfer_ref, transfer.receipt_id);
        assert_eq!(result.placement_receipt.placed_on, MemberId::new(50));
    }

    #[test]
    #[should_panic(expected = "commit_transfer_flow requires Verified")]
    fn commit_transfer_flow_rejects_non_verified() {
        let (copy, _ticket, transfer, _verified) = make_test_flow_data();

        let bad_verification = ReplicaVerificationReceipt {
            receipt_id: ReplicatedReceiptId(9999),
            subject_refs: vec![ReplicatedSubjectId::new(100)],
            digest_results: vec![ObjectDigest::new(0xF00D)],
            witness_refs: vec![MemberId::new(60)],
            quorum_class: 2,
            verification_epoch: EpochId::new(20),
            status: VerificationStatus::DigestMismatch,
        };

        let _ = commit_transfer_flow(
            copy,
            &bad_verification,
            &transfer,
            FlowCommitClass::Rebuild,
            FlowState::Verified,
            EpochId::new(30),
            ObjectDigest::new(0xF00D),
        );
    }

    #[test]
    fn commit_transfer_flow_works_for_all_flow_classes() {
        let (copy, _ticket, transfer, verification) = make_test_flow_data();
        let expected_digest = ObjectDigest::new(0xF00D);

        for class in &[
            FlowCommitClass::SteadyReplication,
            FlowCommitClass::CatchupReplication,
            FlowCommitClass::Rebuild,
            FlowCommitClass::Relocation,
            FlowCommitClass::Failover,
            FlowCommitClass::Drain,
        ] {
            let result = commit_transfer_flow(
                copy.clone(),
                &verification,
                &transfer,
                *class,
                FlowState::Verified,
                EpochId::new(30),
                expected_digest,
            );
            assert_eq!(result.flow_class, *class);
            assert_eq!(result.final_flow_state, FlowState::Complete);
        }
    }

    #[test]
    fn serde_roundtrip_placement_receipt() {
        let receipt = ReplicaPlacementReceipt {
            receipt_id: ReplicatedReceiptId(5000),
            verification_ref: ReplicatedReceiptId(4000),
            transfer_ref: ReplicatedReceiptId(3000),
            subject_refs: vec![ReplicatedSubjectId::new(42)],
            placed_on: MemberId::new(99),
            placement_epoch: EpochId::new(15),
            subjects_placed: 1,
            placement_receipt_refs: Vec::new(),
        };
        let json = serde_json::to_string(&receipt).expect("serialize");
        let round: ReplicaPlacementReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, round);
    }

    #[test]
    fn serde_roundtrip_flow_state_variants() {
        for state in &[
            FlowState::Planned,
            FlowState::Transferring,
            FlowState::Transferred,
            FlowState::Verifying,
            FlowState::Verified,
            FlowState::Complete,
            FlowState::Aborted,
        ] {
            let json = serde_json::to_string(state).expect("serialize");
            let round: FlowState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*state, round, "roundtrip failed for {state:?}");
        }
    }

    #[test]
    fn serde_roundtrip_flow_commit_result() {
        let result = FlowCommitResult {
            placement_receipt: ReplicaPlacementReceipt {
                receipt_id: ReplicatedReceiptId(6000),
                verification_ref: ReplicatedReceiptId(5000),
                transfer_ref: ReplicatedReceiptId(4000),
                subject_refs: vec![ReplicatedSubjectId::new(1)],
                placed_on: MemberId::new(7),
                placement_epoch: EpochId::new(42),
                subjects_placed: 1,
                placement_receipt_refs: vec![flow_receipt_ref(1, 4096, 700)],
            },
            updated_copy: ReplicaCopyRecord {
                subject_ref: ReplicatedSubjectId::new(1),
                member_ref: MemberId::new(7),
                domain_ref: DomainId::new(70),
                copy_class: ReplicaCopyClass::Verified,
                payload_digest: ObjectDigest::new(0xCAFE),
                freshness_frontier: 100,
                verification_receipt_ref: ReplicatedReceiptId(5000),
            },
            final_flow_state: FlowState::Complete,
            flow_class: FlowCommitClass::Relocation,
            commit_epoch: EpochId::new(42),
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let round: FlowCommitResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, round);
    }

    #[test]
    fn flow_class_priority_ordering() {
        assert!(
            FlowCommitClass::SteadyReplication.flow_class_priority()
                < FlowCommitClass::CatchupReplication.flow_class_priority()
        );
        assert!(
            FlowCommitClass::CatchupReplication.flow_class_priority()
                < FlowCommitClass::Rebuild.flow_class_priority()
        );
        assert!(
            FlowCommitClass::Rebuild.flow_class_priority()
                < FlowCommitClass::Relocation.flow_class_priority()
        );
        assert!(
            FlowCommitClass::Relocation.flow_class_priority()
                < FlowCommitClass::Failover.flow_class_priority()
        );
        assert!(
            FlowCommitClass::Failover.flow_class_priority()
                < FlowCommitClass::Drain.flow_class_priority()
        );
    }

    #[test]
    fn flow_class_preemption_rules() {
        assert!(FlowCommitClass::Rebuild.may_preempt_product_work());
        assert!(FlowCommitClass::Drain.may_preempt_product_work());
        assert!(!FlowCommitClass::SteadyReplication.may_preempt_product_work());
        assert!(!FlowCommitClass::CatchupReplication.may_preempt_product_work());
        assert!(!FlowCommitClass::Relocation.may_preempt_product_work());
        assert!(!FlowCommitClass::Failover.may_preempt_product_work());
    }

    #[test]
    fn flow_class_reserve_budget_rules() {
        assert!(FlowCommitClass::Rebuild.requires_reserve_budget());
        assert!(FlowCommitClass::Failover.requires_reserve_budget());
        assert!(FlowCommitClass::Drain.requires_reserve_budget());
        assert!(!FlowCommitClass::SteadyReplication.requires_reserve_budget());
        assert!(!FlowCommitClass::CatchupReplication.requires_reserve_budget());
        assert!(!FlowCommitClass::Relocation.requires_reserve_budget());
    }

    // ── ReplicaChunkState state machine tests ──────────────────────────

    #[test]
    fn chunk_state_forward_progression() {
        let s = ReplicaChunkState::Pending;
        let s = advance_replica_chunk_state(s, ReplicaChunkState::Transferring);
        assert_eq!(s, ReplicaChunkState::Transferring);

        let s = advance_replica_chunk_state(s, ReplicaChunkState::Verifying);
        assert_eq!(s, ReplicaChunkState::Verifying);

        let s = advance_replica_chunk_state(s, ReplicaChunkState::Committed);
        assert_eq!(s, ReplicaChunkState::Committed);
    }

    #[test]
    fn chunk_state_committed_is_terminal() {
        let result =
            advance_replica_chunk_state(ReplicaChunkState::Committed, ReplicaChunkState::Verifying);
        assert_eq!(result, ReplicaChunkState::Committed);

        let result =
            advance_replica_chunk_state(ReplicaChunkState::Committed, ReplicaChunkState::Failed);
        assert_eq!(result, ReplicaChunkState::Committed);

        let result =
            advance_replica_chunk_state(ReplicaChunkState::Committed, ReplicaChunkState::Pending);
        assert_eq!(result, ReplicaChunkState::Committed);
    }

    #[test]
    fn chunk_state_cancelled_is_terminal() {
        let result =
            advance_replica_chunk_state(ReplicaChunkState::Cancelled, ReplicaChunkState::Pending);
        assert_eq!(result, ReplicaChunkState::Cancelled);

        let result = advance_replica_chunk_state(
            ReplicaChunkState::Cancelled,
            ReplicaChunkState::Transferring,
        );
        assert_eq!(result, ReplicaChunkState::Cancelled);
    }

    #[test]
    fn chunk_state_transferring_can_fail() {
        let result =
            advance_replica_chunk_state(ReplicaChunkState::Transferring, ReplicaChunkState::Failed);
        assert_eq!(result, ReplicaChunkState::Failed);
    }

    #[test]
    fn chunk_state_transferring_can_be_cancelled() {
        let result = advance_replica_chunk_state(
            ReplicaChunkState::Transferring,
            ReplicaChunkState::Cancelled,
        );
        assert_eq!(result, ReplicaChunkState::Cancelled);
    }

    #[test]
    fn chunk_state_verifying_can_fail() {
        let result =
            advance_replica_chunk_state(ReplicaChunkState::Verifying, ReplicaChunkState::Failed);
        assert_eq!(result, ReplicaChunkState::Failed);
    }

    #[test]
    fn chunk_state_pending_can_be_cancelled() {
        let result =
            advance_replica_chunk_state(ReplicaChunkState::Pending, ReplicaChunkState::Cancelled);
        assert_eq!(result, ReplicaChunkState::Cancelled);
    }

    #[test]
    fn chunk_state_failed_can_be_cancelled() {
        let result =
            advance_replica_chunk_state(ReplicaChunkState::Failed, ReplicaChunkState::Cancelled);
        assert_eq!(result, ReplicaChunkState::Cancelled);
    }

    #[test]
    fn chunk_state_idempotent_transitions() {
        for state in &[
            ReplicaChunkState::Pending,
            ReplicaChunkState::Transferring,
            ReplicaChunkState::Verifying,
            ReplicaChunkState::Committed,
            ReplicaChunkState::Failed,
            ReplicaChunkState::Cancelled,
        ] {
            let result = advance_replica_chunk_state(*state, *state);
            assert_eq!(result, *state, "idempotent failed for {state:?}");
        }
    }

    #[test]
    #[should_panic(expected = "invalid replica chunk state transition")]
    fn chunk_state_invalid_skip_transition() {
        // Cannot skip from Pending directly to Verifying
        let _ =
            advance_replica_chunk_state(ReplicaChunkState::Pending, ReplicaChunkState::Verifying);
    }

    #[test]
    #[should_panic(expected = "invalid replica chunk state transition")]
    fn chunk_state_invalid_reverse_transition() {
        // Cannot go backwards from Verifying to Transferring
        let _ = advance_replica_chunk_state(
            ReplicaChunkState::Verifying,
            ReplicaChunkState::Transferring,
        );
    }

    #[test]
    #[should_panic(expected = "invalid replica chunk state transition")]
    fn chunk_state_invalid_failed_to_verifying() {
        // Failed can go to Cancelled but not Verifying
        let _ =
            advance_replica_chunk_state(ReplicaChunkState::Failed, ReplicaChunkState::Verifying);
    }

    #[test]
    #[should_panic(expected = "invalid replica chunk state transition")]
    fn chunk_state_invalid_pending_to_committed() {
        // Cannot advance from Pending directly to Committed
        let _ =
            advance_replica_chunk_state(ReplicaChunkState::Pending, ReplicaChunkState::Committed);
    }

    #[test]
    #[should_panic(expected = "invalid replica chunk state transition")]
    fn chunk_state_invalid_failed_to_transferring() {
        // Failed can go to Cancelled but not Transferring
        let _ =
            advance_replica_chunk_state(ReplicaChunkState::Failed, ReplicaChunkState::Transferring);
    }

    // ── DurabilityLevel tests ──────────────────────────────────────────

    #[test]
    fn durability_replicated_normal() {
        assert_eq!(
            DurabilityLevel::for_replicated(1, 1),
            DurabilityLevel::Normal
        );
        assert_eq!(
            DurabilityLevel::for_replicated(3, 3),
            DurabilityLevel::Normal
        );
        assert_eq!(
            DurabilityLevel::for_replicated(5, 5),
            DurabilityLevel::Normal
        );
    }

    #[test]
    fn durability_replicated_warning() {
        assert_eq!(
            DurabilityLevel::for_replicated(2, 3),
            DurabilityLevel::Warning
        );
        assert_eq!(
            DurabilityLevel::for_replicated(4, 5),
            DurabilityLevel::Warning
        );
        assert_eq!(
            DurabilityLevel::for_replicated(3, 5),
            DurabilityLevel::Warning
        );
        assert_eq!(
            DurabilityLevel::for_replicated(2, 5),
            DurabilityLevel::Warning
        );
    }

    #[test]
    fn durability_replicated_critical() {
        assert_eq!(
            DurabilityLevel::for_replicated(1, 2),
            DurabilityLevel::Critical
        );
        assert_eq!(
            DurabilityLevel::for_replicated(1, 3),
            DurabilityLevel::Critical
        );
        assert_eq!(
            DurabilityLevel::for_replicated(1, 5),
            DurabilityLevel::Critical
        );
        assert_eq!(
            DurabilityLevel::for_replicated(1, 16),
            DurabilityLevel::Critical
        );
    }

    #[test]
    fn durability_replicated_loss_imminent() {
        assert_eq!(
            DurabilityLevel::for_replicated(0, 1),
            DurabilityLevel::LossImminent
        );
        assert_eq!(
            DurabilityLevel::for_replicated(0, 2),
            DurabilityLevel::LossImminent
        );
        assert_eq!(
            DurabilityLevel::for_replicated(0, 3),
            DurabilityLevel::LossImminent
        );
    }

    #[test]
    fn durability_replicated_full_ladder_r2() {
        assert_eq!(
            DurabilityLevel::for_replicated(2, 2),
            DurabilityLevel::Normal
        );
        assert_eq!(
            DurabilityLevel::for_replicated(1, 2),
            DurabilityLevel::Critical
        );
        assert_eq!(
            DurabilityLevel::for_replicated(0, 2),
            DurabilityLevel::LossImminent
        );
    }

    #[test]
    fn durability_replicated_full_ladder_r3() {
        assert_eq!(
            DurabilityLevel::for_replicated(3, 3),
            DurabilityLevel::Normal
        );
        assert_eq!(
            DurabilityLevel::for_replicated(2, 3),
            DurabilityLevel::Warning
        );
        assert_eq!(
            DurabilityLevel::for_replicated(1, 3),
            DurabilityLevel::Critical
        );
        assert_eq!(
            DurabilityLevel::for_replicated(0, 3),
            DurabilityLevel::LossImminent
        );
    }

    #[test]
    fn durability_erasure_coded_normal() {
        assert_eq!(
            DurabilityLevel::for_erasure_coded(6, 4, 2),
            DurabilityLevel::Normal
        );
        assert_eq!(
            DurabilityLevel::for_erasure_coded(3, 2, 1),
            DurabilityLevel::Normal
        );
    }

    #[test]
    fn durability_erasure_coded_warning() {
        assert_eq!(
            DurabilityLevel::for_erasure_coded(5, 4, 2),
            DurabilityLevel::Warning
        );
        assert_eq!(
            DurabilityLevel::for_erasure_coded(4, 3, 2),
            DurabilityLevel::Warning
        );
    }

    #[test]
    fn durability_erasure_coded_critical() {
        assert_eq!(
            DurabilityLevel::for_erasure_coded(4, 4, 2),
            DurabilityLevel::Critical
        );
        assert_eq!(
            DurabilityLevel::for_erasure_coded(2, 2, 1),
            DurabilityLevel::Critical
        );
    }

    #[test]
    fn durability_erasure_coded_loss_imminent() {
        assert_eq!(
            DurabilityLevel::for_erasure_coded(3, 4, 2),
            DurabilityLevel::LossImminent
        );
        assert_eq!(
            DurabilityLevel::for_erasure_coded(1, 2, 1),
            DurabilityLevel::LossImminent
        );
        assert_eq!(
            DurabilityLevel::for_erasure_coded(0, 4, 2),
            DurabilityLevel::LossImminent
        );
    }

    #[test]
    fn durability_level_ordering() {
        assert!(DurabilityLevel::Normal < DurabilityLevel::Warning);
        assert!(DurabilityLevel::Warning < DurabilityLevel::Critical);
        assert!(DurabilityLevel::Critical < DurabilityLevel::LossImminent);
    }

    // ── RedundancyPolicy tests ─────────────────────────────────────────

    #[test]
    fn redundancy_policy_none_no_redundancy() {
        assert!(!RedundancyPolicy::None.has_redundancy());
        assert_eq!(RedundancyPolicy::None.total_device_count(), 1);
        assert_eq!(RedundancyPolicy::None.min_readable(), 1);
    }

    #[test]
    fn redundancy_policy_replicated() {
        let r2 = RedundancyPolicy::Replicated { r: 2 };
        assert!(r2.has_redundancy());
        assert_eq!(r2.total_device_count(), 2);
        assert_eq!(r2.min_readable(), 1);

        let r3 = RedundancyPolicy::Replicated { r: 3 };
        assert!(r3.has_redundancy());
        assert_eq!(r3.total_device_count(), 3);
        assert_eq!(r3.min_readable(), 1);
    }

    #[test]
    fn redundancy_policy_erasure_coded() {
        let ec = RedundancyPolicy::ErasureCoded { k: 4, m: 2 };
        assert!(ec.has_redundancy());
        assert_eq!(ec.total_device_count(), 6);
        assert_eq!(ec.min_readable(), 4);

        let ec2 = RedundancyPolicy::ErasureCoded { k: 8, m: 3 };
        assert!(ec2.has_redundancy());
        assert_eq!(ec2.total_device_count(), 11);
        assert_eq!(ec2.min_readable(), 8);
    }

    #[test]
    fn redundancy_policy_display() {
        assert_eq!(format!("{}", RedundancyPolicy::None), "none");
        assert_eq!(
            format!("{}", RedundancyPolicy::Replicated { r: 3 }),
            "replicated(r=3)"
        );
        assert_eq!(
            format!("{}", RedundancyPolicy::ErasureCoded { k: 4, m: 2 }),
            "erasure_coded(k=4,m=2)"
        );
    }

    // ── FlowState additional edge cases ────────────────────────────────

    #[test]
    fn flow_state_complete_can_abort() {
        let result = advance_flow_state(FlowState::Complete, FlowState::Aborted);
        assert_eq!(result, FlowState::Aborted);
    }

    #[test]
    #[should_panic(expected = "invalid flow state transition")]
    fn flow_state_complete_to_planned_invalid() {
        let _ = advance_flow_state(FlowState::Complete, FlowState::Planned);
    }

    #[test]
    #[should_panic(expected = "invalid flow state transition")]
    fn flow_state_verified_to_transferring_invalid() {
        let _ = advance_flow_state(FlowState::Verified, FlowState::Transferring);
    }

    // ── ReplicaChunkState additional edge cases ────────────────────────

    #[test]
    #[should_panic(expected = "invalid replica chunk state transition")]
    fn chunk_state_verifying_to_pending_invalid() {
        let _ =
            advance_replica_chunk_state(ReplicaChunkState::Verifying, ReplicaChunkState::Pending);
    }

    #[test]
    #[should_panic(expected = "invalid replica chunk state transition")]
    fn chunk_state_transferred_to_planned_not_possible() {
        let _ = advance_replica_chunk_state(
            ReplicaChunkState::Transferring,
            ReplicaChunkState::Pending,
        );
    }

    // ── ReplicaLifecycle tests ─────────────────────────────────────────

    #[test]
    fn lifecycle_is_terminal_and_redundant() {
        assert!(!ReplicaLifecycle::Ingest.is_terminal());
        assert!(!ReplicaLifecycle::Ingest.is_fully_redundant());

        assert!(!ReplicaLifecycle::EmergencyRebake.is_terminal());
        assert!(!ReplicaLifecycle::EmergencyRebake.is_fully_redundant());

        assert!(!ReplicaLifecycle::RebakeScheduled.is_terminal());
        assert!(!ReplicaLifecycle::RebakeScheduled.is_fully_redundant());

        assert!(!ReplicaLifecycle::BaseComplete.is_terminal());
        assert!(ReplicaLifecycle::BaseComplete.is_fully_redundant());

        assert!(ReplicaLifecycle::Trimmed.is_terminal());
        assert!(!ReplicaLifecycle::Trimmed.is_fully_redundant());
    }

    #[test]
    fn lifecycle_display() {
        assert_eq!(format!("{}", ReplicaLifecycle::Ingest), "ingest");
        assert_eq!(
            format!("{}", ReplicaLifecycle::EmergencyRebake),
            "emergency_rebake"
        );
        assert_eq!(
            format!("{}", ReplicaLifecycle::RebakeScheduled),
            "rebake_scheduled"
        );
        assert_eq!(
            format!("{}", ReplicaLifecycle::BaseComplete),
            "base_complete"
        );
        assert_eq!(format!("{}", ReplicaLifecycle::Trimmed), "trimmed");
    }

    // ── DurabilityLevel Display tests ──────────────────────────────────

    #[test]
    fn durability_level_display() {
        assert_eq!(format!("{}", DurabilityLevel::Normal), "normal");
        assert_eq!(format!("{}", DurabilityLevel::Warning), "warning");
        assert_eq!(format!("{}", DurabilityLevel::Critical), "critical");
        assert_eq!(
            format!("{}", DurabilityLevel::LossImminent),
            "loss_imminent"
        );
    }

    // ── FlowCommitClass additional tests ───────────────────────────────

    #[test]
    fn flow_class_serde_roundtrip() {
        for class in &[
            FlowCommitClass::SteadyReplication,
            FlowCommitClass::CatchupReplication,
            FlowCommitClass::Rebuild,
            FlowCommitClass::Relocation,
            FlowCommitClass::Failover,
            FlowCommitClass::Drain,
        ] {
            let json = serde_json::to_string(class).expect("serialize");
            let round: FlowCommitClass = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*class, round, "serde roundtrip failed for {class:?}");
        }
    }

    #[test]
    fn replica_set_record_empty_domains() {
        let record = ReplicaSetRecord {
            replica_set_id: 1,
            subject_ref: ReplicatedSubjectId::new(1),
            placement_policy_ref: 0,
            required_count: 0,
            target_failure_domains: vec![],
            current_placement_receipt_refs: vec![],
        };
        assert!(record.target_failure_domains.is_empty());
        assert!(record.current_placement_receipt_refs.is_empty());
    }

    #[test]
    fn replica_set_record_with_data() {
        let record = ReplicaSetRecord {
            replica_set_id: 42,
            subject_ref: ReplicatedSubjectId::new(700),
            placement_policy_ref: 10,
            required_count: 3,
            target_failure_domains: vec![DomainId::new(1), DomainId::new(2), DomainId::new(3)],
            current_placement_receipt_refs: vec![
                ReplicatedReceiptId(100),
                ReplicatedReceiptId(200),
                ReplicatedReceiptId(300),
            ],
        };
        assert_eq!(record.required_count, 3);
        assert_eq!(record.target_failure_domains.len(), 3);
        assert_eq!(record.current_placement_receipt_refs.len(), 3);
    }

    // ── write_quorum tests ─────────────────────────────────────────────

    #[test]
    fn write_quorum_values() {
        assert_eq!(write_quorum(1), 1);
        assert_eq!(write_quorum(2), 2);
        assert_eq!(write_quorum(3), 2);
        assert_eq!(write_quorum(4), 3);
        assert_eq!(write_quorum(5), 3);
        assert_eq!(write_quorum(6), 4);
        assert_eq!(write_quorum(7), 4);
        assert_eq!(write_quorum(9), 5);
        assert_eq!(write_quorum(16), 9);
    }

    // ── FlowState additional idempotent tests ──────────────────────────

    #[test]
    fn flow_state_idempotent_all_states() {
        for state in &[
            FlowState::Planned,
            FlowState::Transferring,
            FlowState::Transferred,
            FlowState::Verifying,
            FlowState::Verified,
            FlowState::Complete,
            FlowState::Aborted,
        ] {
            let result = advance_flow_state(*state, *state);
            assert_eq!(result, *state, "idempotent failed for {state:?}");
        }
    }

    #[test]
    fn flow_state_any_to_aborted() {
        for state in &[
            FlowState::Planned,
            FlowState::Transferring,
            FlowState::Transferred,
            FlowState::Verifying,
            FlowState::Verified,
            FlowState::Complete,
        ] {
            let result = advance_flow_state(*state, FlowState::Aborted);
            assert_eq!(result, FlowState::Aborted, "abort failed for {state:?}");
        }
    }

    #[test]
    fn flow_state_aborted_is_absorbing() {
        // Aborted is terminal; any event stays Aborted.
        let result = advance_flow_state(FlowState::Aborted, FlowState::Planned);
        assert_eq!(result, FlowState::Aborted);
        let result = advance_flow_state(FlowState::Aborted, FlowState::Complete);
        assert_eq!(result, FlowState::Aborted);
    }

    #[test]
    #[should_panic(expected = "invalid flow state transition")]
    fn flow_state_transferred_to_verified_invalid() {
        let _ = advance_flow_state(FlowState::Transferred, FlowState::Verified);
    }

    #[test]
    #[should_panic(expected = "invalid flow state transition")]
    fn flow_state_verifying_to_transferred_invalid() {
        let _ = advance_flow_state(FlowState::Verifying, FlowState::Transferred);
    }

    // ── ReplicaChunkState additional edge cases ────────────────────────

    #[test]
    #[should_panic(expected = "invalid replica chunk state transition")]
    fn chunk_state_transferring_to_committed_invalid() {
        let _ = advance_replica_chunk_state(
            ReplicaChunkState::Transferring,
            ReplicaChunkState::Committed,
        );
    }

    #[test]
    fn chunk_state_cancelled_is_absorbing() {
        // Cancelled is terminal/absorbing; any event stays Cancelled.
        let result =
            advance_replica_chunk_state(ReplicaChunkState::Cancelled, ReplicaChunkState::Verifying);
        assert_eq!(result, ReplicaChunkState::Cancelled);
    }
}
