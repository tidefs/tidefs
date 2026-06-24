// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! P8-03 data_copy_0: replica placement target computation.
//!
//! This crate implements `compute_replica_target_set()`, the authoritative
//! placement engine that selects replica targets from a placement policy,
//! failure-domain inventory, and tier goal.  It produces a
//! `FailureDomainPlacementPlan` with a membership verdict.
//!
//! ## Design
//!
//! The algorithm respects anti-affinity:
//! - `Strict`: at most one member per failure-domain cell.
//! - `DegradedVisible`: may place multiple members in the same domain.
//!
//! Tier goals relax anti-affinity for non-primary tiers:
//! - `Primary`: full strictness.
//! - `Secondary`: moderate relaxation.
//! - `Archive`: most relaxed (always DegradedVisible).

use std::collections::{BTreeMap, BTreeSet};
pub mod constraint;
pub mod intent_planning;
pub mod node_placement;
pub mod placement_plan;
use tidefs_durability_layout::{
    DurabilityLayoutV1, DurabilityPolicy, FailureDomainLevel, FailureDomainV1,
};
use tidefs_membership_epoch::{
    AntiAffinityClass, DomainId, EpochId, FailureDomainClass, FailureDomainPlacementPlan,
    FailureDomainPlacementPolicy, FailureDomainRecord, HealthClass, MemberId,
    MembershipPlacementVerdictRecord, PlacementIntentClass, ReceiptId, VerdictClass,
};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Legacy storage-tier classification for replica-target computation.
///
/// `TierGoal` is preserved for existing callers and coarse tier selection,
/// but it is not a complete storage-intent model.  Callers that need
/// fine-grained placement roles, media constraints, trust/domain gates,
/// transport eligibility, data-shape compatibility, or movement-payback
/// evidence should use [`intent_planning::StorageIntentPlacementRole`]
/// instead.  When a `StorageIntentPlacementRequest` carries a `TierGoal`,
/// the planner emits a non-blocking `TierGoalIsNotStorageIntentModel` reason
/// to make the legacy intent visible to explanation and performance consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TierGoal {
    /// Primary replicas — full data set, strictest anti-affinity.  Prefer
    /// [`StorageIntentPlacementRole::DurableFullPlacement`] for new code.
    Primary = 0,
    /// Secondary replicas — may permit degraded placement.  Prefer
    /// [`StorageIntentPlacementRole::AuthoritativeHotServingReplica`] for
    /// authority-bearing secondary placement in new code.
    Secondary = 1,
    /// Archive or cold replicas — relaxed anti-affinity.  Prefer
    /// [`StorageIntentPlacementRole::ColdArchivePlacement`] for new code.
    Archive = 2,
}

/// A single selected replica placement target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaTarget {
    /// The member selected to host a replica.
    pub member_id: MemberId,
    /// The failure-domain cell the member belongs to.
    pub domain_id: DomainId,
    /// The failure-domain class (device, node, rack, etc.).
    pub domain_class: FailureDomainClass,
}

/// Errors returned by the placement planner.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlacementError {
    #[error("not enough healthy domains: need {required}, have {available}")]
    NotEnoughDomains { required: usize, available: usize },
    #[error("not enough healthy members: need {required}, have {available}")]
    NotEnoughMembers { required: usize, available: usize },
    #[error("no domains match the required failure-domain class")]
    NoMatchingDomainClass,
    #[error("not enough eligible devices: need {required}, have {available}")]
    NotEnoughDevices { required: usize, available: usize },
    #[error("no domains match the required storage tier")]
    NoMatchingTier,
    #[error("all candidate members are already excluded")]
    AllMembersExcluded,
}

/// Optional per-member placement weight.
///
/// A weight of `0` excludes the member from keyed placement. Missing members
/// default to weight `1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberPlacementWeight {
    /// Member whose draw weight is being overridden.
    pub member_id: MemberId,
    /// Relative draw weight. Higher values win more keyed placements.
    pub weight: u32,
}

// ---------------------------------------------------------------------------
// CommittedPlacementPlan — placement plan bound to a commit group
// ---------------------------------------------------------------------------

/// A placement plan whose evidence is committed at a specific commit group.
///
/// Wraps [`FailureDomainPlacementPlan`] with the commit group id at which
/// the placement receipts and failure-domain inventory were committed.
/// This binding enables downstream consumers (e.g. the rebalance planner)
/// to invalidate placement decisions when the underlying evidence is
/// superseded by a newer commit group.
///
/// The `committed_at` field uses a raw `u64` to avoid a dependency cycle
/// with `tidefs-commit_group`; callers in crates that already depend on
/// `tidefs-commit_group` can convert with `CommitGroupId(committed_at)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedPlacementPlan {
    /// The placement plan produced from committed evidence.
    pub plan: FailureDomainPlacementPlan,
    /// Commit group id at which the placement evidence was committed.
    pub committed_at: u64,
}

impl CommittedPlacementPlan {
    /// Returns `true` if the evidence backing this plan is stale relative
    /// to a newer commit group.
    #[must_use]
    pub fn is_stale(&self, current_commit_group_id: u64) -> bool {
        current_commit_group_id > self.committed_at
    }
}

// ---------------------------------------------------------------------------
// Core algorithm
// ---------------------------------------------------------------------------

/// Compute the set of replica targets for a given placement policy,
/// failure-domain inventory, and tier goal.
///
/// # Algorithm
///
/// 1. Filter domains to those matching the target failure-domain class
///    and with health at least enough for the tier goal.
/// 2. Order domains for fair distribution (least-loaded first).
/// 3. Select one member per domain (strict anti-affinity) or reuse
///    domains (degraded mode) until the required replica count is met.
/// 4. Produce a `FailureDomainPlacementPlan` with a verdict.
///
/// # Errors
///
/// Returns `PlacementError` if there are insufficient domains or members
/// to satisfy the policy.
pub fn compute_replica_target_set(
    policy: &FailureDomainPlacementPolicy,
    failure_domains: &[FailureDomainRecord],
    tier_goal: TierGoal,
    epoch: EpochId,
) -> Result<FailureDomainPlacementPlan, PlacementError> {
    let target_class = policy.required_failure_domain_class_ref;
    let required = policy.required_replica_count;

    // --- filter candidate domains -----------------------------------------
    let mut candidates: Vec<&FailureDomainRecord> = failure_domains
        .iter()
        .filter(|d| {
            d.failure_domain_class_ref == target_class
                && acceptable_health(d.health_class, tier_goal)
                && !d.member_refs.is_empty()
        })
        .collect();

    if candidates.is_empty() {
        return Err(PlacementError::NoMatchingDomainClass);
    }

    // Sort: prefer domains with fewer members (better distribution).
    candidates.sort_by_key(|d| (d.member_refs.len(), d.failure_domain_id.0));
    // --- filter by storage tier if specified -------------------------
    if let Some(target_tier) = policy.target_tier {
        candidates.retain(|d| d.storage_tier == Some(target_tier));
        if candidates.is_empty() {
            return Err(PlacementError::NoMatchingTier);
        }
    }

    // --- determine anti-affinity strictness --------------------------------
    let strict = match tier_goal {
        TierGoal::Primary => matches!(policy.anti_affinity_class, AntiAffinityClass::Strict),
        TierGoal::Archive => false,
        TierGoal::Secondary => match policy.anti_affinity_class {
            AntiAffinityClass::Strict => required <= candidates.len() / 2,
            AntiAffinityClass::DegradedVisible => false,
        },
    };

    // --- select members ----------------------------------------------------
    let mut selected_members: Vec<MemberId> = Vec::with_capacity(required);
    let mut selected_domains: Vec<DomainId> = Vec::with_capacity(required);
    let mut used_domain_ids: BTreeSet<DomainId> = BTreeSet::new();
    let mut used_member_ids: BTreeSet<MemberId> = BTreeSet::new();

    let mut round = 0;
    let mut degraded = false;

    // Total members across all candidate domains (for completion detection).
    let total_available: usize = candidates.iter().map(|d| d.member_refs.len()).sum();

    while selected_members.len() < required {
        if round >= candidates.len() {
            if strict && !degraded {
                // Fall back to degraded for remainder.
                degraded = true;
                round = 0;
                continue;
            }
            // Non-strict (degraded or archive): wrap around to reuse domains.
            round = 0;
        }

        // Safety: break if every member across all domains is already used.
        if used_member_ids.len() >= total_available {
            break;
        }

        let domain = &candidates[round];

        // Strict: skip domains we already placed a member in.
        if strict && !degraded && used_domain_ids.contains(&domain.failure_domain_id) {
            round += 1;
            continue;
        }

        // Pick the first unused member from this domain.
        let picked = domain
            .member_refs
            .iter()
            .find(|m| !used_member_ids.contains(m))
            .copied();

        match picked {
            Some(member) => {
                selected_members.push(member);
                used_member_ids.insert(member);
                used_domain_ids.insert(domain.failure_domain_id);
                selected_domains.push(domain.failure_domain_id);
                round += 1;
            }
            None => {
                round += 1;
            }
        }
    }

    if selected_members.len() < required {
        return Err(PlacementError::NotEnoughMembers {
            required,
            available: selected_members.len(),
        });
    }

    // --- collect excluded members ------------------------------------------
    let excluded_members: Vec<MemberId> = candidates
        .iter()
        .flat_map(|d| d.member_refs.iter().copied())
        .filter(|m| !used_member_ids.contains(m))
        .collect();

    let duplicate_members: Vec<MemberId> = Vec::new(); // not applicable with round-robin

    // --- build verdict -----------------------------------------------------
    let verdict_class = if degraded {
        VerdictClass::AdmitDegraded
    } else {
        VerdictClass::Admit
    };

    let degraded_reason_refs: Vec<&'static str> = if degraded {
        vec!["insufficient failure domains for strict anti-affinity"]
    } else {
        vec![]
    };

    let digest = derive_record_id(
        selected_members.first().map_or(0, |m| m.0),
        selected_members.len() as u64,
        policy.required_failure_domain_class_ref as u64,
    );

    let verdict = MembershipPlacementVerdictRecord {
        verdict_id: 0, // assigned by caller / epoch coordinator
        membership_epoch_ref: epoch,
        placement_class: PlacementIntentClass::ReplicaTarget,
        selected_member_refs: selected_members.clone(),
        selected_domain_refs: selected_domains.clone(),
        verdict_class,
        degraded_reason_refs,
        issuance_receipt_ref: ReceiptId::ZERO,
        digest,
    };

    Ok(FailureDomainPlacementPlan {
        policy_ref: *policy,
        selected_member_refs: selected_members,
        selected_domain_refs: selected_domains,
        duplicate_domain_member_refs: duplicate_members,
        excluded_member_refs: excluded_members,
        verdict,
    })
}

// ---------------------------------------------------------------------------
// Committed variants — consume committed placement receipts
// ---------------------------------------------------------------------------

/// Compute replica targets from committed placement receipts, bound to a
/// specific commit group.
///
/// Identical to [`compute_replica_target_set`] except the returned plan is
/// wrapped in a [`CommittedPlacementPlan`] that records `committed_at` and
/// supports staleness checks.
pub fn compute_committed_replica_target_set(
    policy: &FailureDomainPlacementPolicy,
    failure_domains: &[FailureDomainRecord],
    tier_goal: TierGoal,
    epoch: EpochId,
    committed_at: u64,
) -> Result<CommittedPlacementPlan, PlacementError> {
    let plan = compute_replica_target_set(policy, failure_domains, tier_goal, epoch)?;
    Ok(CommittedPlacementPlan { plan, committed_at })
}

/// Compute keyed replica targets from committed placement receipts, bound
/// to a specific commit group.
///
/// Identical to [`compute_keyed_replica_target_set`] except the returned plan
/// is wrapped in a [`CommittedPlacementPlan`] that records `committed_at` and
/// supports staleness checks.
pub fn compute_committed_keyed_replica_target_set(
    policy: &FailureDomainPlacementPolicy,
    failure_domains: &[FailureDomainRecord],
    tier_goal: TierGoal,
    epoch: EpochId,
    placement_key: u64,
    member_weights: &[MemberPlacementWeight],
    committed_at: u64,
) -> Result<CommittedPlacementPlan, PlacementError> {
    let plan = compute_keyed_replica_target_set(
        policy,
        failure_domains,
        tier_goal,
        epoch,
        placement_key,
        member_weights,
    )?;
    Ok(CommittedPlacementPlan { plan, committed_at })
}

/// Compute replica targets with placement-key-dependent weighted ordering.
///
/// This is the production-oriented selector for per-object or per-chunk
/// placement. It keeps the same failure-domain and health filtering as
/// [`compute_replica_target_set`], but ranks eligible members with a stable
/// keyed draw so different subjects naturally spread across the same healthy
/// topology.
///
/// `member_weights` is optional: absent members use weight `1`, and weight `0`
/// excludes a member from new placement.
pub fn compute_keyed_replica_target_set(
    policy: &FailureDomainPlacementPolicy,
    failure_domains: &[FailureDomainRecord],
    tier_goal: TierGoal,
    epoch: EpochId,
    placement_key: u64,
    member_weights: &[MemberPlacementWeight],
) -> Result<FailureDomainPlacementPlan, PlacementError> {
    let target_class = policy.required_failure_domain_class_ref;
    let required = policy.required_replica_count;
    let weights = member_weight_map(member_weights);

    let mut candidates: Vec<DomainCandidate> = failure_domains
        .iter()
        .filter(|d| {
            d.failure_domain_class_ref == target_class
                && acceptable_health(d.health_class, tier_goal)
                && !d.member_refs.is_empty()
        })
        .map(|d| {
            let mut members: Vec<(MemberId, u32)> = d
                .member_refs
                .iter()
                .copied()
                .filter_map(|member_id| {
                    let weight = member_weight(member_id, &weights);
                    (weight > 0).then_some((member_id, weight))
                })
                .collect();
            members.sort_by_key(|(member_id, _)| *member_id);
            DomainCandidate {
                domain_id: d.failure_domain_id,
                members,
            }
        })
        .collect();

    if candidates.is_empty() {
        return Err(PlacementError::NoMatchingDomainClass);
    }

    candidates.sort_by_key(|d| d.domain_id);

    let excluded_by_weight: Vec<MemberId> = failure_domains
        .iter()
        .filter(|d| {
            d.failure_domain_class_ref == target_class
                && acceptable_health(d.health_class, tier_goal)
        })
        .flat_map(|d| d.member_refs.iter().copied())
        .filter(|member_id| member_weight(*member_id, &weights) == 0)
        .collect();

    let total_available: usize = candidates.iter().map(|d| d.members.len()).sum();
    if total_available == 0 {
        return Err(PlacementError::AllMembersExcluded);
    }

    let strict = strict_for_tier(policy, tier_goal, candidates.len());
    let mut degraded = false;
    let mut selected_members: Vec<MemberId> = Vec::with_capacity(required);
    let mut selected_domains: Vec<DomainId> = Vec::with_capacity(required);
    let mut duplicate_domain_member_refs: Vec<MemberId> = Vec::new();
    let mut used_member_ids: BTreeSet<MemberId> = BTreeSet::new();
    let mut used_domain_ids: BTreeSet<DomainId> = BTreeSet::new();

    for replica_index in 0..required {
        let picked = pick_keyed_member(
            &candidates,
            &used_member_ids,
            &used_domain_ids,
            strict && !degraded,
            placement_key,
            replica_index as u64,
        );

        let picked = match picked {
            Some(picked) => Some(picked),
            None if strict && !degraded => {
                degraded = true;
                pick_keyed_member(
                    &candidates,
                    &used_member_ids,
                    &used_domain_ids,
                    false,
                    placement_key,
                    replica_index as u64,
                )
            }
            None => None,
        };

        let Some(picked) = picked else {
            break;
        };

        if used_domain_ids.contains(&picked.domain_id) {
            duplicate_domain_member_refs.push(picked.member_id);
            degraded = true;
        }
        used_member_ids.insert(picked.member_id);
        used_domain_ids.insert(picked.domain_id);
        selected_members.push(picked.member_id);
        selected_domains.push(picked.domain_id);
    }

    if selected_members.len() < required {
        return Err(PlacementError::NotEnoughMembers {
            required,
            available: selected_members.len(),
        });
    }

    let mut excluded_members: Vec<MemberId> = candidates
        .iter()
        .flat_map(|d| d.members.iter().map(|(member_id, _)| *member_id))
        .filter(|member_id| !used_member_ids.contains(member_id))
        .chain(excluded_by_weight)
        .collect();
    excluded_members.sort();
    excluded_members.dedup();
    duplicate_domain_member_refs.sort();
    duplicate_domain_member_refs.dedup();

    let verdict_class = if degraded {
        VerdictClass::AdmitDegraded
    } else {
        VerdictClass::Admit
    };
    let degraded_reason_refs: Vec<&'static str> = if degraded {
        vec!["keyed placement reused a failure domain after strict targets were exhausted"]
    } else {
        vec![]
    };
    let digest = derive_record_id(
        placement_key,
        selected_members.len() as u64,
        policy.required_failure_domain_class_ref as u64,
    );

    let verdict = MembershipPlacementVerdictRecord {
        verdict_id: 0,
        membership_epoch_ref: epoch,
        placement_class: policy.placement_class,
        selected_member_refs: selected_members.clone(),
        selected_domain_refs: selected_domains.clone(),
        verdict_class,
        degraded_reason_refs,
        issuance_receipt_ref: ReceiptId::ZERO,
        digest,
    };

    Ok(FailureDomainPlacementPlan {
        policy_ref: *policy,
        selected_member_refs: selected_members,
        selected_domain_refs: selected_domains,
        duplicate_domain_member_refs,
        excluded_member_refs: excluded_members,
        verdict,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Determine whether a domain's health class is acceptable for the given tier.
fn acceptable_health(health: HealthClass, tier: TierGoal) -> bool {
    match tier {
        TierGoal::Primary | TierGoal::Secondary => {
            matches!(health, HealthClass::Healthy | HealthClass::Suspect)
        }
        TierGoal::Archive => !matches!(health, HealthClass::Down),
    }
}

fn strict_for_tier(
    policy: &FailureDomainPlacementPolicy,
    tier_goal: TierGoal,
    candidate_domain_count: usize,
) -> bool {
    match tier_goal {
        TierGoal::Primary => matches!(policy.anti_affinity_class, AntiAffinityClass::Strict),
        TierGoal::Archive => false,
        TierGoal::Secondary => match policy.anti_affinity_class {
            AntiAffinityClass::Strict => {
                policy.required_replica_count <= candidate_domain_count / 2
            }
            AntiAffinityClass::DegradedVisible => false,
        },
    }
}

/// Deterministic record-id derivation (mirrors `tidefs-membership-epoch`).
const fn derive_record_id(left: u64, right: u64, salt: u64) -> u64 {
    left.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(right)
        .wrapping_add(salt)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DomainCandidate {
    domain_id: DomainId,
    members: Vec<(MemberId, u32)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PickedMember {
    member_id: MemberId,
    domain_id: DomainId,
}

fn member_weight_map(weights: &[MemberPlacementWeight]) -> BTreeMap<MemberId, u32> {
    weights
        .iter()
        .map(|weight| (weight.member_id, weight.weight))
        .collect()
}

fn member_weight(member_id: MemberId, weights: &BTreeMap<MemberId, u32>) -> u32 {
    weights.get(&member_id).copied().unwrap_or(1)
}

fn pick_keyed_member(
    candidates: &[DomainCandidate],
    used_member_ids: &BTreeSet<MemberId>,
    used_domain_ids: &BTreeSet<DomainId>,
    strict_domains: bool,
    placement_key: u64,
    replica_index: u64,
) -> Option<PickedMember> {
    let mut best: Option<(u128, PickedMember)> = None;

    for domain in candidates {
        if strict_domains && used_domain_ids.contains(&domain.domain_id) {
            continue;
        }
        for (member_id, weight) in &domain.members {
            if used_member_ids.contains(member_id) {
                continue;
            }
            let score = keyed_draw_score(
                placement_key,
                replica_index,
                domain.domain_id,
                *member_id,
                *weight,
            );
            let picked = PickedMember {
                member_id: *member_id,
                domain_id: domain.domain_id,
            };
            match best {
                None => best = Some((score, picked)),
                Some((best_score, best_picked))
                    if score > best_score
                        || (score == best_score
                            && (picked.domain_id, picked.member_id)
                                < (best_picked.domain_id, best_picked.member_id)) =>
                {
                    best = Some((score, picked));
                }
                Some(_) => {}
            }
        }
    }

    best.map(|(_, picked)| picked)
}

fn keyed_draw_score(
    placement_key: u64,
    replica_index: u64,
    domain_id: DomainId,
    member_id: MemberId,
    weight: u32,
) -> u128 {
    let mixed = mix64(
        placement_key
            ^ replica_index.wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ domain_id.0.rotate_left(17)
            ^ member_id.0.rotate_left(31),
    );
    u128::from(mixed) * u128::from(weight.max(1))
}

const fn mix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

// ---------------------------------------------------------------------------

// ===========================================================================
// PlacementDecision, DeviceHealthCapacity, AllocationRequest
// ===========================================================================

const PLACEMENT_REPLAY_RECEIPT_CONTEXT: &str = "TideFS PlacementReplayReceipt v1";

/// Role of a target recorded by a placement replay receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementReplayShardRole {
    /// Data replica or data erasure shard.
    Data,
    /// Parity erasure shard.
    Parity,
}

impl PlacementReplayShardRole {
    const fn code(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Parity => 1,
        }
    }
}

/// One target in persisted placement order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacementReplayTarget {
    /// Ordered target position within the receipt.
    pub target_index: u16,
    /// Logical shard index within the redundancy policy.
    pub shard_index: u16,
    /// Whether the target carries data or parity.
    pub shard_role: PlacementReplayShardRole,
    /// Pool device selected by the planner.
    pub device_id: u64,
    /// Failure-domain key that was authoritative when the receipt was issued.
    pub failure_domain_key: u64,
}

/// Errors produced while minting or consuming placement replay receipts.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlacementReplayError {
    #[error("placement receipt target width mismatch: expected {expected}, got {actual}")]
    TargetWidthMismatch { expected: usize, actual: usize },
    #[error("placement receipt target width {actual} exceeds receipt format")]
    TargetWidthTooLarge { actual: usize },
    #[error("placement receipt target device {device_id} is absent from the issuing topology")]
    TargetDeviceMissing { device_id: u64 },
    #[error("placement receipt seal verification failed")]
    SealMismatch,
}

/// Replayable authority for a planner decision.
///
/// The receipt records the policy width, target order, failure-domain level,
/// topology epoch, and deterministic seed that were authoritative at allocation
/// time. Read, scrub, rebuild, and relocation code can replay the target order
/// from this record without recomputing placement against a newer topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementReplayReceipt {
    /// Object or chunk identifier being placed.
    pub object_id: u64,
    /// Placement key used for deterministic spreading.
    pub placement_key: u64,
    /// Allocation size hint used for capacity-aware target eligibility.
    pub size_hint_bytes: u64,
    /// Bytes each selected target needed to admit for this allocation.
    pub per_target_bytes: u64,
    /// Topology epoch that issued this placement authority.
    pub topology_epoch: u64,
    /// Deterministic ring seed used by the planner.
    pub deterministic_seed: u64,
    /// Durability policy that determines target width and shard roles.
    pub policy: DurabilityPolicy,
    /// Failure-domain level enforced by the planner.
    pub failure_domain_level: FailureDomainLevel,
    /// Whether strict failure-domain separation held for this decision.
    pub failure_domain_separation: bool,
    /// Persisted target order.
    pub targets: Vec<PlacementReplayTarget>,
    /// BLAKE3 seal over every recorded authority field.
    pub seal: [u8; 32],
}

impl PlacementReplayReceipt {
    /// Mint a replay receipt from a placement decision and the topology that
    /// was authoritative when that decision was made.
    pub fn from_decision(
        decision: &PlacementDecision,
        layout: &DurabilityLayoutV1,
        devices: &[DeviceHealthCapacity],
        request: &AllocationRequest,
        topology_epoch: u64,
    ) -> Result<Self, PlacementReplayError> {
        let expected = layout.policy.total_shards();
        let actual = decision.device_targets.len();
        if actual != expected || decision.replica_count != expected {
            return Err(PlacementReplayError::TargetWidthMismatch { expected, actual });
        }
        if actual > u16::MAX as usize {
            return Err(PlacementReplayError::TargetWidthTooLarge { actual });
        }

        let mut targets = Vec::with_capacity(actual);
        for (target_index, device_id) in decision.device_targets.iter().copied().enumerate() {
            let Some(device) = devices.iter().find(|device| device.device_id == device_id) else {
                return Err(PlacementReplayError::TargetDeviceMissing { device_id });
            };
            let (shard_index, shard_role) =
                replay_shard_for_slot(layout.policy, target_index as u16);
            targets.push(PlacementReplayTarget {
                target_index: target_index as u16,
                shard_index,
                shard_role,
                device_id,
                failure_domain_key: device.failure_domain_key(decision.failure_domain_level),
            });
        }

        let mut receipt = Self {
            object_id: decision.object_id,
            placement_key: request.placement_key,
            size_hint_bytes: request.size_hint_bytes,
            per_target_bytes: per_target_capacity_bytes(layout, request),
            topology_epoch,
            deterministic_seed: decision.deterministic_seed,
            policy: layout.policy,
            failure_domain_level: decision.failure_domain_level,
            failure_domain_separation: decision.failure_domain_separation,
            targets,
            seal: [0; 32],
        };
        receipt.seal = receipt.compute_seal();
        Ok(receipt)
    }

    /// Return the receipt seal.
    #[must_use]
    pub const fn seal(&self) -> [u8; 32] {
        self.seal
    }

    /// Verify the receipt seal against the recorded authority fields.
    #[must_use]
    pub fn verify_seal(&self) -> bool {
        constant_time_eq_32(&self.seal, &self.compute_seal())
    }

    /// Replay target device order from the receipt.
    #[must_use]
    pub fn device_targets(&self) -> Vec<u64> {
        self.targets.iter().map(|target| target.device_id).collect()
    }

    /// Rebuild a placement decision from receipt authority.
    ///
    /// This consumes only persisted receipt fields: it verifies the seal and
    /// policy width, then returns the recorded target order without consulting
    /// any current topology inventory.
    pub fn replay_decision(&self) -> Result<PlacementDecision, PlacementReplayError> {
        if !self.verify_seal() {
            return Err(PlacementReplayError::SealMismatch);
        }
        let expected = self.policy.total_shards();
        let actual = self.targets.len();
        if actual != expected {
            return Err(PlacementReplayError::TargetWidthMismatch { expected, actual });
        }

        Ok(PlacementDecision::new(
            self.device_targets(),
            expected,
            self.failure_domain_separation,
            self.deterministic_seed,
            self.object_id,
            self.failure_domain_level,
        ))
    }

    fn compute_seal(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(PLACEMENT_REPLAY_RECEIPT_CONTEXT);
        hasher.update(&self.object_id.to_le_bytes());
        hasher.update(&self.placement_key.to_le_bytes());
        hasher.update(&self.size_hint_bytes.to_le_bytes());
        hasher.update(&self.per_target_bytes.to_le_bytes());
        hasher.update(&self.topology_epoch.to_le_bytes());
        hasher.update(&self.deterministic_seed.to_le_bytes());
        seal_policy(&mut hasher, self.policy);
        hasher.update(&[self.failure_domain_level.discriminant()]);
        hasher.update(&[self.failure_domain_separation as u8]);
        hasher.update(&(self.targets.len() as u64).to_le_bytes());
        for target in &self.targets {
            hasher.update(&target.target_index.to_le_bytes());
            hasher.update(&target.shard_index.to_le_bytes());
            hasher.update(&[target.shard_role.code()]);
            hasher.update(&target.device_id.to_le_bytes());
            hasher.update(&target.failure_domain_key.to_le_bytes());
        }
        hasher.finalize().into()
    }
}

/// A placement decision produced by a [`PlacementPlanner`].
///
/// Encodes which devices receive replicas or shards for a given allocation
/// request, the failure-domain separation guarantee, and the deterministic
/// seed used to compute the decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementDecision {
    /// The device IDs selected as placement targets, in replica/shard order.
    pub device_targets: Vec<u64>,
    /// Number of replicas or shards in this decision.
    pub replica_count: usize,
    /// Whether failure-domain separation is guaranteed for this placement.
    ///
    /// When `true`, no two device targets share the same failure domain at
    /// the level specified by the durability layout's [`FailureDomainV1`].
    pub failure_domain_separation: bool,
    /// The deterministic seed used to compute this decision.
    ///
    /// Replaying with the same seed and inputs produces the same targets.
    pub deterministic_seed: u64,
    /// The object or chunk identifier this placement is for.
    pub object_id: u64,
    /// The failure-domain level at which separation was enforced.
    pub failure_domain_level: FailureDomainLevel,
}

impl PlacementDecision {
    /// Create a new placement decision.
    #[must_use]
    pub fn new(
        device_targets: Vec<u64>,
        replica_count: usize,
        failure_domain_separation: bool,
        deterministic_seed: u64,
        object_id: u64,
        failure_domain_level: FailureDomainLevel,
    ) -> Self {
        Self {
            device_targets,
            replica_count,
            failure_domain_separation,
            deterministic_seed,
            object_id,
            failure_domain_level,
        }
    }

    /// Returns `true` when all requested replicas were assigned.
    #[must_use]
    pub fn satisfied(&self) -> bool {
        self.device_targets.len() >= self.replica_count
    }

    /// Mint a replay receipt for this decision.
    pub fn to_replay_receipt(
        &self,
        layout: &DurabilityLayoutV1,
        devices: &[DeviceHealthCapacity],
        request: &AllocationRequest,
        topology_epoch: u64,
    ) -> Result<PlacementReplayReceipt, PlacementReplayError> {
        PlacementReplayReceipt::from_decision(self, layout, devices, request, topology_epoch)
    }
}

/// Per-device health and capacity information for placement planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceHealthCapacity {
    /// Unique device identifier.
    pub device_id: u64,
    /// Node (host) identifier, for node-level failure domains.
    pub node_id: u64,
    /// Rack identifier, for rack-level failure domains.
    pub rack_id: u64,
    /// Total capacity in bytes.
    pub total_bytes: u64,
    /// Currently used bytes.
    pub used_bytes: u64,
    /// Whether this device is healthy and accepting new placements.
    pub healthy: bool,
}

impl DeviceHealthCapacity {
    /// Create a new device health/capacity record.
    #[must_use]
    pub fn new(device_id: u64, node_id: u64, rack_id: u64, total_bytes: u64) -> Self {
        Self {
            device_id,
            node_id,
            rack_id,
            total_bytes,
            used_bytes: 0,
            healthy: true,
        }
    }

    /// Available capacity in bytes.
    #[must_use]
    pub fn available_bytes(&self) -> u64 {
        self.total_bytes.saturating_sub(self.used_bytes)
    }

    /// Whether this device can accept new placements.
    #[must_use]
    pub fn can_accept(&self) -> bool {
        self.healthy && self.available_bytes() > 0
    }

    /// Whether this device can accept a placement with the given byte budget.
    #[must_use]
    pub fn can_accept_bytes(&self, required_bytes: u64) -> bool {
        self.healthy && self.available_bytes() >= required_bytes.max(1)
    }

    /// Failure-domain key at the given level.
    #[must_use]
    pub fn failure_domain_key(&self, level: FailureDomainLevel) -> u64 {
        match level {
            FailureDomainLevel::Device => self.device_id,
            FailureDomainLevel::Node => self.node_id,
            FailureDomainLevel::Rack => self.rack_id,
            FailureDomainLevel::Datacenter => self.rack_id,
        }
    }
}

/// An allocation request submitted to the placement planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationRequest {
    /// The object or chunk identifier being placed.
    pub object_id: u64,
    /// Estimated byte size of the object (for capacity-aware placement).
    pub size_hint_bytes: u64,
    /// Placement key for deterministic hash-ring positioning.
    ///
    /// Different keys produce different target orders, enabling natural
    /// load spreading across objects.
    pub placement_key: u64,
}

impl AllocationRequest {
    /// Create a new allocation request.
    #[must_use]
    pub fn new(object_id: u64, size_hint_bytes: u64, placement_key: u64) -> Self {
        Self {
            object_id,
            size_hint_bytes,
            placement_key,
        }
    }
}
// ===========================================================================
// PlacementInput
// ===========================================================================

/// Bundled input for a placement planner.
///
/// Groups the durability layout, failure-domain constraints, device pool
/// topology, allocation request, and existing object-to-device mappings
/// into a single parameter object consumed by [`PlacementPlanner`].
///
/// # Existing Object-to-Member Mappings
///
/// `existing_placements` maps an object identifier to the set of device IDs
/// already assigned to that object. The planner uses this to avoid placing
/// two objects that must not collide (e.g., replicas of the same logical
/// dataset) onto devices that share a failure domain. An empty map means
/// no prior placements exist (cold pool or first allocation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementInput {
    /// Durability layout defining the replication or erasure policy.
    pub layout: DurabilityLayoutV1,
    /// Failure-domain level for anti-affinity enforcement.
    pub failure_domain: FailureDomainV1,
    /// Available devices with health and capacity metadata.
    pub devices: Vec<DeviceHealthCapacity>,
    /// The allocation request being planned.
    pub request: AllocationRequest,
    /// Existing object-to-device assignments, keyed by object identifier.
    ///
    /// Used to avoid placing objects that should not share failure domains
    /// onto devices in the same domain. An empty map means no prior placements.
    pub existing_placements: BTreeMap<u64, BTreeSet<u64>>,
}

impl PlacementInput {
    /// Create a new placement input bundle.
    #[must_use]
    pub fn new(
        layout: DurabilityLayoutV1,
        failure_domain: FailureDomainV1,
        devices: Vec<DeviceHealthCapacity>,
        request: AllocationRequest,
    ) -> Self {
        Self {
            layout,
            failure_domain,
            devices,
            request,
            existing_placements: BTreeMap::new(),
        }
    }

    /// Add existing object-to-device mappings for collision avoidance.
    ///
    /// Each entry maps an object ID to the set of device IDs already
    /// assigned to that object. The planner will avoid placing a new
    /// allocation onto devices that share a failure domain with these
    /// existing assignments when the objects must be separated.
    #[must_use]
    pub fn with_existing_placements(mut self, placements: BTreeMap<u64, BTreeSet<u64>>) -> Self {
        self.existing_placements = placements;
        self
    }

    /// Return the total shard count required by the durability layout.
    #[must_use]
    pub fn required_shards(&self) -> usize {
        self.layout.policy.total_shards()
    }

    /// Return the number of healthy devices that can accept new placements.
    #[must_use]
    pub fn eligible_device_count(&self) -> usize {
        self.devices.iter().filter(|d| d.can_accept()).count()
    }

    /// Return the number of distinct failure domains at the configured level.
    #[must_use]
    pub fn distinct_domain_count(&self) -> usize {
        let keys: BTreeSet<u64> = self
            .devices
            .iter()
            .filter(|d| d.can_accept())
            .map(|d| d.failure_domain_key(self.failure_domain.level))
            .collect();
        keys.len()
    }

    /// Build a [`PlacementConstraint`] from this input's layout and
    /// failure domain, with a BLAKE3-verified integrity digest.
    #[must_use]
    pub fn constraint(&self) -> crate::constraint::PlacementConstraint {
        crate::constraint::PlacementConstraint::new(&self.layout, &self.failure_domain)
    }

    /// Run pre-flight constraint satisfaction checking against this
    /// input's device pool.
    #[must_use]
    pub fn check_satisfaction(&self) -> crate::constraint::ConstraintSatisfaction {
        let c = self.constraint();
        crate::constraint::check_satisfaction(&c, &self.devices)
    }

    /// Plan placement using the given planner, delegating to
    /// [`PlacementPlanner::plan_placement`].
    ///
    /// This is a convenience method that unpacks `self` and forwards to the
    /// planner. The existing placements map is passed separately so
    /// placement-runtime can integrate collision avoidance.
    pub fn plan_with(
        &self,
        planner: &impl PlacementPlanner,
    ) -> Result<PlacementDecision, PlacementError> {
        planner.plan_placement(
            &self.layout,
            &self.failure_domain,
            &self.devices,
            &self.request,
        )
    }
}

// ===========================================================================
// PlacementPlanner trait
// ===========================================================================

/// Trait for deterministic placement planning.
///
/// Implementations consume a [`DurabilityLayoutV1`] (mirror or erasure),
/// a [`FailureDomainV1`] (device/node/rack separation level), device
/// health/capacity data, and an allocation request, and produce a
/// deterministic [`PlacementDecision`].
pub trait PlacementPlanner {
    /// Plan placement for a single allocation request.
    ///
    /// # Arguments
    ///
    /// * `layout` - Durability layout defining mirror copies or erasure k+m.
    /// * `failure_domain` - Failure-domain level for anti-affinity enforcement.
    /// * `devices` - Available devices with health and capacity.
    /// * `request` - The allocation request (object ID, size, placement key).
    ///
    /// # Returns
    ///
    /// A [`PlacementDecision`] with device targets, or an error if placement
    /// cannot be satisfied.
    fn plan_placement(
        &self,
        layout: &DurabilityLayoutV1,
        failure_domain: &FailureDomainV1,
        devices: &[DeviceHealthCapacity],
        request: &AllocationRequest,
    ) -> Result<PlacementDecision, PlacementError>;
}

// ===========================================================================
// HashRingPlacementPlanner
// ===========================================================================

/// A hash-ring-based placement planner using virtual nodes.
///
/// Each device is mapped to multiple virtual nodes on a 64-bit ring,
/// weighted by available capacity. Object placement walks the ring
/// clockwise from a key-derived starting position, respecting
/// failure-domain anti-affinity constraints.
///
/// # Determinism
///
/// For the same inputs (layout, failure domain, devices, request), the
/// output is deterministic. Different placement keys spread objects
/// across the ring for natural load balancing.
#[derive(Debug, Clone)]
pub struct HashRingPlacementPlanner {
    /// Number of virtual nodes per GB of available capacity.
    virtual_nodes_per_gb: u64,
    /// Seed mixed into all ring positions for randomization across planners.
    ring_seed: u64,
}

impl HashRingPlacementPlanner {
    /// Create a new hash-ring placement planner.
    ///
    /// `virtual_nodes_per_gb` controls the granularity of the hash ring.
    /// Higher values give finer load distribution at the cost of more
    /// memory per device. A typical value is 8-64.
    ///
    /// `ring_seed` is mixed into all hash computations. Different seeds
    /// produce different ring layouts, enabling independent placement
    /// planes (e.g., primary vs. archive tier).
    #[must_use]
    pub fn new(virtual_nodes_per_gb: u64, ring_seed: u64) -> Self {
        Self {
            virtual_nodes_per_gb: virtual_nodes_per_gb.max(1),
            ring_seed,
        }
    }

    /// Build the hash ring from a list of devices.
    ///
    /// Returns a sorted vector of `(ring_position, device_index, failure_domain_key)`
    /// entries. The device_index refers to the input `devices` slice.
    fn build_ring(
        &self,
        devices: &[DeviceHealthCapacity],
        failure_domain: &FailureDomainV1,
        required_bytes: u64,
    ) -> Vec<(u64, usize, u64)> {
        let mut ring = Vec::new();

        for (idx, device) in devices.iter().enumerate() {
            if !device.can_accept_bytes(required_bytes) {
                continue;
            }

            // Number of virtual nodes scales with available capacity.
            let avail_gb = device.available_bytes() / (1024 * 1024 * 1024);
            let vnodes = ((avail_gb.max(1) * self.virtual_nodes_per_gb) as usize).min(4096);
            let domain_key = device.failure_domain_key(failure_domain.level);

            for v in 0..vnodes {
                let pos = hash_ring_position(device.device_id, v as u64, self.ring_seed);
                ring.push((pos, idx, domain_key));
            }
        }

        ring.sort_by_key(|(pos, _idx, _key)| *pos);
        ring
    }
}

impl PlacementPlanner for HashRingPlacementPlanner {
    fn plan_placement(
        &self,
        layout: &DurabilityLayoutV1,
        failure_domain: &FailureDomainV1,
        devices: &[DeviceHealthCapacity],
        request: &AllocationRequest,
    ) -> Result<PlacementDecision, PlacementError> {
        let required = layout.policy.total_shards();
        if required == 0 {
            return Err(PlacementError::NotEnoughMembers {
                required: 0,
                available: 0,
            });
        }
        let target_bytes = per_target_capacity_bytes(layout, request);

        // Pre-flight constraint satisfaction check.
        let constraint = crate::constraint::PlacementConstraint::new(layout, failure_domain);
        let sat = crate::constraint::check_satisfaction(&constraint, devices);
        if !sat.satisfiable {
            return match sat.failure_reason {
                Some(crate::constraint::ConstraintFailureReason::NotEnoughDevices {
                    required,
                    available,
                }) => Err(PlacementError::NotEnoughMembers {
                    required,
                    available,
                }),
                Some(crate::constraint::ConstraintFailureReason::NoHealthyDevices)
                | Some(crate::constraint::ConstraintFailureReason::AllDevicesFull) => {
                    Err(PlacementError::AllMembersExcluded)
                }
                _ => Err(PlacementError::NotEnoughMembers {
                    required,
                    available: sat.eligible_devices,
                }),
            };
        }

        let capacity_eligible = devices
            .iter()
            .filter(|device| device.can_accept_bytes(target_bytes))
            .count();
        if capacity_eligible < required {
            return Err(PlacementError::NotEnoughMembers {
                required,
                available: capacity_eligible,
            });
        }

        // Build the hash ring.
        let ring = self.build_ring(devices, failure_domain, target_bytes);
        if ring.is_empty() {
            return Err(PlacementError::NoMatchingDomainClass);
        }

        let ring_len = ring.len();
        let mut selected_devices: Vec<u64> = Vec::with_capacity(required);
        let mut used_domains: BTreeSet<u64> = BTreeSet::new();
        let mut used_devices: BTreeSet<u64> = BTreeSet::new();
        let mut separation_maintained = true;

        for slot in 0..required {
            // Starting position on the ring for this slot.
            let start_pos = hash_ring_position(
                request.object_id ^ request.placement_key,
                slot as u64,
                self.ring_seed,
            );

            // Binary search to find the ring entry at or after start_pos.
            let start_idx = match ring.binary_search_by_key(&start_pos, |(pos, _, _)| *pos) {
                Ok(idx) => idx,
                Err(idx) => idx % ring_len,
            };

            let mut found = false;
            // First pass: strict failure-domain separation.
            for offset in 0..ring_len {
                let idx = (start_idx + offset) % ring_len;
                let (_pos, dev_idx, domain_key) = ring[idx];
                let device_id = devices[dev_idx].device_id;

                if used_devices.contains(&device_id) {
                    continue;
                }
                if used_domains.contains(&domain_key) {
                    continue;
                }

                selected_devices.push(device_id);
                used_devices.insert(device_id);
                used_domains.insert(domain_key);
                found = true;
                break;
            }

            if !found {
                // Second pass: allow domain reuse (degraded mode).
                for offset in 0..ring_len {
                    let idx = (start_idx + offset) % ring_len;
                    let (_pos, dev_idx, domain_key) = ring[idx];
                    let device_id = devices[dev_idx].device_id;

                    if used_devices.contains(&device_id) {
                        continue;
                    }

                    selected_devices.push(device_id);
                    used_devices.insert(device_id);
                    used_domains.insert(domain_key);
                    separation_maintained = false;
                    found = true;
                    break;
                }
            }

            if !found {
                break;
            }
        }

        if selected_devices.len() < required {
            return Err(PlacementError::NotEnoughMembers {
                required,
                available: selected_devices.len(),
            });
        }

        Ok(PlacementDecision::new(
            selected_devices,
            required,
            separation_maintained,
            self.ring_seed,
            request.object_id,
            failure_domain.level,
        ))
    }
}

// ===========================================================================
// Hash ring helper
// ===========================================================================

/// Compute a deterministic 64-bit position on the hash ring.
///
/// Uses a triple-mix construction similar to `mix64` but with additional
/// input mixing for ring distribution.
const fn hash_ring_position(primary: u64, slot: u64, seed: u64) -> u64 {
    let mixed = primary
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(slot)
        .wrapping_add(seed)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    mix64(mixed)
}

fn per_target_capacity_bytes(layout: &DurabilityLayoutV1, request: &AllocationRequest) -> u64 {
    match layout.policy {
        DurabilityPolicy::Mirror { .. } => request.size_hint_bytes,
        DurabilityPolicy::ErasureStyle { data_shards, .. }
        | DurabilityPolicy::Hybrid { data_shards, .. } => {
            div_ceil_u64(request.size_hint_bytes, u64::from(data_shards).max(1))
        }
    }
}

const fn div_ceil_u64(value: u64, divisor: u64) -> u64 {
    if value == 0 {
        0
    } else {
        ((value - 1) / divisor) + 1
    }
}

fn replay_shard_for_slot(
    policy: DurabilityPolicy,
    target_index: u16,
) -> (u16, PlacementReplayShardRole) {
    match policy {
        DurabilityPolicy::Mirror { .. } => (target_index, PlacementReplayShardRole::Data),
        DurabilityPolicy::ErasureStyle { data_shards, .. } => {
            let role = if target_index < u16::from(data_shards) {
                PlacementReplayShardRole::Data
            } else {
                PlacementReplayShardRole::Parity
            };
            (target_index, role)
        }
        DurabilityPolicy::Hybrid {
            data_shards,
            parity_shards,
            ..
        } => {
            let copy_width = u16::from(data_shards) + u16::from(parity_shards);
            let shard_index = target_index % copy_width;
            let role = if shard_index < u16::from(data_shards) {
                PlacementReplayShardRole::Data
            } else {
                PlacementReplayShardRole::Parity
            };
            (shard_index, role)
        }
    }
}

fn seal_policy(hasher: &mut blake3::Hasher, policy: DurabilityPolicy) {
    hasher.update(&[policy.discriminant()]);
    match policy {
        DurabilityPolicy::Mirror { copies } => {
            hasher.update(&[copies]);
        }
        DurabilityPolicy::ErasureStyle {
            data_shards,
            parity_shards,
        } => {
            hasher.update(&[data_shards, parity_shards]);
        }
        DurabilityPolicy::Hybrid {
            mirror_copies,
            data_shards,
            parity_shards,
        } => {
            hasher.update(&[mirror_copies, data_shards, parity_shards]);
        }
    }
}

fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut acc = 0u8;
    for i in 0..32 {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::{
        AntiAffinityClass, FailureDomainClass, FailureDomainPlacementPolicy, FailureDomainRecord,
        HealthClass,
    };

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    const GIB: u64 = 1024 * 1024 * 1024;

    fn make_member(id: u64) -> MemberId {
        MemberId(id)
    }

    fn make_domain(id: u64) -> DomainId {
        DomainId(id)
    }

    fn make_domain_record(
        domain_id: u64,
        class: FailureDomainClass,
        members: &[u64],
        health: HealthClass,
    ) -> FailureDomainRecord {
        FailureDomainRecord {
            failure_domain_id: make_domain(domain_id),
            failure_domain_class_ref: class,
            parent_domain_ref: DomainId(0),
            member_refs: members.iter().map(|&m| make_member(m)).collect(),
            separation_policy_ref: AntiAffinityClass::Strict,
            health_class: health,
            availability_receipt_ref: ReceiptId::ZERO,
            storage_tier: None,
            digest: 0,
        }
    }

    fn strict_policy(replicas: usize, class: FailureDomainClass) -> FailureDomainPlacementPolicy {
        FailureDomainPlacementPolicy::strict_replica_targets(replicas, class)
    }

    fn degraded_policy(replicas: usize, class: FailureDomainClass) -> FailureDomainPlacementPolicy {
        FailureDomainPlacementPolicy::degraded_visible_replica_targets(replicas, class)
    }

    const E0: EpochId = EpochId::ZERO;

    // -----------------------------------------------------------------------
    // Basic correctness
    // -----------------------------------------------------------------------

    #[test]
    fn three_rack_strict_primary_ok() {
        let policy = strict_policy(3, FailureDomainClass::Rack);
        let domains = vec![
            make_domain_record(1, FailureDomainClass::Rack, &[10], HealthClass::Healthy),
            make_domain_record(2, FailureDomainClass::Rack, &[20], HealthClass::Healthy),
            make_domain_record(3, FailureDomainClass::Rack, &[30], HealthClass::Healthy),
        ];

        let plan = compute_replica_target_set(&policy, &domains, TierGoal::Primary, E0).unwrap();
        assert_eq!(plan.selected_member_refs.len(), 3);
        assert_eq!(plan.selected_domain_refs.len(), 3);
        assert!(matches!(plan.verdict.verdict_class, VerdictClass::Admit));
        // All three domains should be distinct (strict anti-affinity).
        let mut set = BTreeSet::new();
        for d in &plan.selected_domain_refs {
            assert!(set.insert(*d), "duplicate domain: {d:?}");
        }
    }

    #[test]
    fn many_racks_chooses_least_loaded() {
        let policy = strict_policy(2, FailureDomainClass::Rack);
        let domains = vec![
            // Domain 1 has 3 members, domain 2 has 1 — domain 2 should be picked first.
            make_domain_record(
                1,
                FailureDomainClass::Rack,
                &[10, 11, 12],
                HealthClass::Healthy,
            ),
            make_domain_record(2, FailureDomainClass::Rack, &[20], HealthClass::Healthy),
            make_domain_record(3, FailureDomainClass::Rack, &[30], HealthClass::Healthy),
        ];

        let plan = compute_replica_target_set(&policy, &domains, TierGoal::Primary, E0).unwrap();
        assert_eq!(plan.selected_member_refs.len(), 2);
        // Domain 2 (least loaded) should be first.
        assert_eq!(plan.selected_member_refs[0], make_member(20));
    }

    #[test]
    fn degraded_policy_allows_domain_reuse() {
        let policy = degraded_policy(3, FailureDomainClass::Node);
        let domains = vec![
            make_domain_record(1, FailureDomainClass::Node, &[10, 11], HealthClass::Healthy),
            make_domain_record(2, FailureDomainClass::Node, &[20], HealthClass::Healthy),
        ];

        let plan = compute_replica_target_set(&policy, &domains, TierGoal::Primary, E0).unwrap();
        assert_eq!(plan.selected_member_refs.len(), 3);
        // With degraded policy: domain 1 contributes 2 members, domain 2 contributes 1.
        let m10 = make_member(10);
        let m11 = make_member(11);
        let m20 = make_member(20);
        assert!(plan.selected_member_refs.contains(&m10));
        assert!(plan.selected_member_refs.contains(&m11));
        assert!(plan.selected_member_refs.contains(&m20));
        assert!(matches!(plan.verdict.verdict_class, VerdictClass::Admit));
    }

    #[test]
    fn archive_tier_relaxes_anti_affinity() {
        let policy = strict_policy(4, FailureDomainClass::Rack);
        let domains = vec![
            make_domain_record(1, FailureDomainClass::Rack, &[10, 11], HealthClass::Healthy),
            make_domain_record(2, FailureDomainClass::Rack, &[20, 21], HealthClass::Healthy),
        ];

        let plan = compute_replica_target_set(&policy, &domains, TierGoal::Archive, E0).unwrap();
        assert_eq!(plan.selected_member_refs.len(), 4);
        // Archive tier: no strict anti-affinity, all 4 members from 2 domains.
    }

    #[test]
    fn strict_falls_back_to_degraded_when_short() {
        let policy = strict_policy(3, FailureDomainClass::Rack); // need 3
        let domains = vec![
            make_domain_record(1, FailureDomainClass::Rack, &[10, 11], HealthClass::Healthy),
            make_domain_record(2, FailureDomainClass::Rack, &[20], HealthClass::Healthy),
        ];

        let plan = compute_replica_target_set(&policy, &domains, TierGoal::Primary, E0).unwrap();
        assert_eq!(plan.selected_member_refs.len(), 3);
        // Should have fallen back to degraded (2 domains, need 3 replicas).
        assert!(matches!(
            plan.verdict.verdict_class,
            VerdictClass::AdmitDegraded
        ));
    }

    #[test]
    fn secondary_tier_allows_degraded_even_with_strict_policy() {
        let policy = strict_policy(3, FailureDomainClass::Rack);
        let domains = vec![
            make_domain_record(1, FailureDomainClass::Rack, &[10, 11], HealthClass::Healthy),
            make_domain_record(2, FailureDomainClass::Rack, &[20], HealthClass::Healthy),
        ];

        let plan = compute_replica_target_set(&policy, &domains, TierGoal::Secondary, E0).unwrap();
        assert_eq!(plan.selected_member_refs.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Error cases
    // -----------------------------------------------------------------------

    #[test]
    fn not_enough_domains() {
        let policy = strict_policy(5, FailureDomainClass::Rack);
        let domains = vec![make_domain_record(
            1,
            FailureDomainClass::Rack,
            &[10],
            HealthClass::Healthy,
        )];

        let err = compute_replica_target_set(&policy, &domains, TierGoal::Primary, E0).unwrap_err();
        assert!(matches!(err, PlacementError::NotEnoughMembers { .. }));
    }

    #[test]
    fn no_matching_domain_class() {
        let policy = strict_policy(3, FailureDomainClass::Region);
        let domains = vec![make_domain_record(
            1,
            FailureDomainClass::Rack,
            &[10],
            HealthClass::Healthy,
        )];

        let err = compute_replica_target_set(&policy, &domains, TierGoal::Primary, E0).unwrap_err();
        assert!(matches!(err, PlacementError::NoMatchingDomainClass));
    }

    #[test]
    fn dead_domains_excluded_for_primary() {
        let policy = strict_policy(1, FailureDomainClass::Rack);
        let domains = vec![make_domain_record(
            1,
            FailureDomainClass::Rack,
            &[10],
            HealthClass::Down,
        )];

        let err = compute_replica_target_set(&policy, &domains, TierGoal::Primary, E0).unwrap_err();
        assert!(matches!(err, PlacementError::NoMatchingDomainClass));
    }

    #[test]
    fn suspect_domains_accepted_for_archive() {
        let policy = strict_policy(1, FailureDomainClass::Rack);
        let domains = vec![make_domain_record(
            1,
            FailureDomainClass::Rack,
            &[10],
            HealthClass::Suspect,
        )];

        let plan = compute_replica_target_set(&policy, &domains, TierGoal::Archive, E0).unwrap();
        assert_eq!(plan.selected_member_refs.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Member selection across domains
    // -----------------------------------------------------------------------

    #[test]
    fn picks_unique_members_across_domains() {
        let policy = strict_policy(3, FailureDomainClass::Rack);
        let domains = vec![
            make_domain_record(1, FailureDomainClass::Rack, &[10, 11], HealthClass::Healthy),
            make_domain_record(2, FailureDomainClass::Rack, &[20, 21], HealthClass::Healthy),
            make_domain_record(3, FailureDomainClass::Rack, &[30], HealthClass::Healthy),
        ];

        let plan = compute_replica_target_set(&policy, &domains, TierGoal::Primary, E0).unwrap();
        let mut set = BTreeSet::new();
        for m in &plan.selected_member_refs {
            assert!(set.insert(*m), "duplicate member: {m:?}");
        }
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn excluded_members_tracked() {
        let policy = strict_policy(2, FailureDomainClass::Rack);
        let domains = vec![
            make_domain_record(1, FailureDomainClass::Rack, &[10, 11], HealthClass::Healthy),
            make_domain_record(2, FailureDomainClass::Rack, &[20], HealthClass::Healthy),
        ];

        let plan = compute_replica_target_set(&policy, &domains, TierGoal::Primary, E0).unwrap();
        // 10, 11, 20 — 2 selected, 1 excluded.
        assert_eq!(plan.excluded_member_refs.len(), 1);
    }

    #[test]
    fn zero_replicas_trivial() {
        // Actually, required_replica_count must be > 0 to be meaningful.
        // But let's test with 1.
        let policy = strict_policy(1, FailureDomainClass::Rack);
        let domains = vec![make_domain_record(
            1,
            FailureDomainClass::Rack,
            &[10],
            HealthClass::Healthy,
        )];
        let plan = compute_replica_target_set(&policy, &domains, TierGoal::Primary, E0).unwrap();
        assert_eq!(plan.selected_member_refs.len(), 1);
    }

    #[test]
    fn large_cluster_even_distribution() {
        let policy = strict_policy(5, FailureDomainClass::Rack);
        let mut domains = Vec::new();
        for i in 0..10 {
            domains.push(make_domain_record(
                i + 1,
                FailureDomainClass::Rack,
                &[100 + i * 10, 100 + i * 10 + 1],
                HealthClass::Healthy,
            ));
        }

        let plan = compute_replica_target_set(&policy, &domains, TierGoal::Primary, E0).unwrap();
        assert_eq!(plan.selected_member_refs.len(), 5);
        assert_eq!(plan.selected_domain_refs.len(), 5);
        assert!(matches!(plan.verdict.verdict_class, VerdictClass::Admit));
    }

    #[test]
    fn keyed_selection_is_stable_for_same_key() {
        let policy = strict_policy(3, FailureDomainClass::Rack);
        let domains = vec![
            make_domain_record(1, FailureDomainClass::Rack, &[10, 11], HealthClass::Healthy),
            make_domain_record(2, FailureDomainClass::Rack, &[20, 21], HealthClass::Healthy),
            make_domain_record(3, FailureDomainClass::Rack, &[30, 31], HealthClass::Healthy),
            make_domain_record(4, FailureDomainClass::Rack, &[40, 41], HealthClass::Healthy),
        ];

        let first =
            compute_keyed_replica_target_set(&policy, &domains, TierGoal::Primary, E0, 42, &[])
                .unwrap();
        let second =
            compute_keyed_replica_target_set(&policy, &domains, TierGoal::Primary, E0, 42, &[])
                .unwrap();

        assert_eq!(first.selected_member_refs, second.selected_member_refs);
        assert_eq!(first.selected_domain_refs, second.selected_domain_refs);
    }

    #[test]
    fn keyed_selection_spreads_different_keys() {
        let policy = strict_policy(3, FailureDomainClass::Rack);
        let domains = vec![
            make_domain_record(1, FailureDomainClass::Rack, &[10, 11], HealthClass::Healthy),
            make_domain_record(2, FailureDomainClass::Rack, &[20, 21], HealthClass::Healthy),
            make_domain_record(3, FailureDomainClass::Rack, &[30, 31], HealthClass::Healthy),
            make_domain_record(4, FailureDomainClass::Rack, &[40, 41], HealthClass::Healthy),
            make_domain_record(5, FailureDomainClass::Rack, &[50, 51], HealthClass::Healthy),
        ];

        let mut seen = BTreeSet::new();
        for key in 0..32 {
            let plan = compute_keyed_replica_target_set(
                &policy,
                &domains,
                TierGoal::Primary,
                E0,
                key,
                &[],
            )
            .unwrap();
            seen.insert(plan.selected_member_refs);
        }

        assert!(
            seen.len() > 1,
            "different placement keys should not collapse to one target order"
        );
    }

    #[test]
    fn keyed_selection_preserves_strict_failure_domain_spread() {
        let policy = strict_policy(3, FailureDomainClass::Rack);
        let domains = vec![
            make_domain_record(1, FailureDomainClass::Rack, &[10, 11], HealthClass::Healthy),
            make_domain_record(2, FailureDomainClass::Rack, &[20, 21], HealthClass::Healthy),
            make_domain_record(3, FailureDomainClass::Rack, &[30, 31], HealthClass::Healthy),
        ];

        let plan =
            compute_keyed_replica_target_set(&policy, &domains, TierGoal::Primary, E0, 99, &[])
                .unwrap();
        let unique_domains: BTreeSet<DomainId> =
            plan.selected_domain_refs.iter().copied().collect();

        assert_eq!(plan.selected_member_refs.len(), 3);
        assert_eq!(unique_domains.len(), 3);
        assert!(plan.duplicate_domain_member_refs.is_empty());
    }

    #[test]
    fn keyed_selection_honors_zero_weight_exclusion() {
        let policy = strict_policy(1, FailureDomainClass::Rack);
        let domains = vec![make_domain_record(
            1,
            FailureDomainClass::Rack,
            &[10, 11],
            HealthClass::Healthy,
        )];

        let plan = compute_keyed_replica_target_set(
            &policy,
            &domains,
            TierGoal::Primary,
            E0,
            7,
            &[MemberPlacementWeight {
                member_id: make_member(10),
                weight: 0,
            }],
        )
        .unwrap();

        assert_eq!(plan.selected_member_refs, vec![make_member(11)]);
        assert!(plan.excluded_member_refs.contains(&make_member(10)));
    }

    #[test]
    fn keyed_selection_weight_biases_distribution() {
        let policy = degraded_policy(1, FailureDomainClass::Rack);
        let domains = vec![make_domain_record(
            1,
            FailureDomainClass::Rack,
            &[10, 20],
            HealthClass::Healthy,
        )];
        let weights = [
            MemberPlacementWeight {
                member_id: make_member(10),
                weight: 1,
            },
            MemberPlacementWeight {
                member_id: make_member(20),
                weight: 16,
            },
        ];

        let heavy_wins = (0..128)
            .filter(|key| {
                let plan = compute_keyed_replica_target_set(
                    &policy,
                    &domains,
                    TierGoal::Archive,
                    E0,
                    *key,
                    &weights,
                )
                .unwrap();
                plan.selected_member_refs[0] == make_member(20)
            })
            .count();

        assert!(
            heavy_wins > 96,
            "higher placement weight should win most keyed draws, won {heavy_wins}/128"
        );
    }
    // -----------------------------------------------------------------------
    // HashRingPlacementPlanner tests
    // -----------------------------------------------------------------------

    fn make_device(id: u64, node: u64, rack: u64, total_gb: u64) -> DeviceHealthCapacity {
        DeviceHealthCapacity {
            device_id: id,
            node_id: node,
            rack_id: rack,
            total_bytes: total_gb * GIB,
            used_bytes: 0,
            healthy: true,
        }
    }

    fn make_device_used(
        id: u64,
        node: u64,
        rack: u64,
        total_gb: u64,
        used_gb: u64,
    ) -> DeviceHealthCapacity {
        DeviceHealthCapacity {
            device_id: id,
            node_id: node,
            rack_id: rack,
            total_bytes: total_gb * GIB,
            used_bytes: used_gb * GIB,
            healthy: true,
        }
    }

    fn make_device_unhealthy(id: u64, node: u64, rack: u64) -> DeviceHealthCapacity {
        DeviceHealthCapacity {
            device_id: id,
            node_id: node,
            rack_id: rack,
            total_bytes: 100 * GIB,
            used_bytes: 0,
            healthy: false,
        }
    }

    fn mirror_layout(copies: u8) -> DurabilityLayoutV1 {
        DurabilityLayoutV1::mirror(copies).unwrap()
    }

    fn erasure_layout(k: u8, m: u8) -> DurabilityLayoutV1 {
        DurabilityLayoutV1::erasure(k, m).unwrap()
    }

    fn device_fd() -> FailureDomainV1 {
        FailureDomainV1::new(FailureDomainLevel::Device, 64).unwrap()
    }

    fn node_fd() -> FailureDomainV1 {
        FailureDomainV1::new(FailureDomainLevel::Node, 64).unwrap()
    }

    fn rack_fd() -> FailureDomainV1 {
        FailureDomainV1::new(FailureDomainLevel::Rack, 64).unwrap()
    }

    fn request(obj_id: u64, key: u64) -> AllocationRequest {
        AllocationRequest::new(obj_id, 1024 * 1024, key)
    }

    fn request_bytes(obj_id: u64, key: u64, bytes: u64) -> AllocationRequest {
        AllocationRequest::new(obj_id, bytes, key)
    }

    fn default_planner() -> HashRingPlacementPlanner {
        HashRingPlacementPlanner::new(8, 0)
    }

    // -- Determinism -----------------------------------------------

    #[test]
    fn hash_ring_deterministic_same_input_same_output() {
        let planner = default_planner();
        let layout = mirror_layout(3);
        let fd = node_fd();
        let devices = vec![
            make_device(1, 10, 100, 100),
            make_device(2, 20, 200, 100),
            make_device(3, 30, 300, 100),
            make_device(4, 40, 400, 100),
            make_device(5, 50, 500, 100),
        ];
        let req = request(42, 7);

        let a = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        let b = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.device_targets.len(), 3);
    }

    #[test]
    fn hash_ring_different_keys_spread() {
        let planner = default_planner();
        let layout = mirror_layout(2);
        let fd = node_fd();
        let devices: Vec<_> = (0..32).map(|i| make_device(i, i, i / 4, 100)).collect();

        let mut seen = BTreeSet::new();
        for key in 0..64 {
            let req = request(1, key);
            let dec = planner
                .plan_placement(&layout, &fd, &devices, &req)
                .unwrap();
            seen.insert(dec.device_targets);
        }
        assert!(seen.len() > 1, "only one unique device set across 64 keys");
    }

    #[test]
    fn hash_ring_different_planner_seeds_diverge() {
        let layout = mirror_layout(3);
        let fd = node_fd();
        let devices: Vec<_> = (0..10).map(|i| make_device(i, i, i, 100)).collect();
        let req = request(1, 1);

        let p1 = HashRingPlacementPlanner::new(8, 0);
        let p2 = HashRingPlacementPlanner::new(8, 0xDEAD_BEEF);
        let d1 = p1.plan_placement(&layout, &fd, &devices, &req).unwrap();
        let d2 = p2.plan_placement(&layout, &fd, &devices, &req).unwrap();
        assert_ne!(
            d1.device_targets, d2.device_targets,
            "different ring seeds should diverge placement"
        );
    }

    #[test]
    fn replay_receipt_preserves_old_epoch_targets() {
        let layout = mirror_layout(3);
        let fd = node_fd();
        let old_devices: Vec<_> = (0..10).map(|i| make_device(i, i, i, 100)).collect();
        let new_devices: Vec<_> = (0..14).map(|i| make_device(i, i, i, 100)).collect();
        let req = request(1, 1);

        let old_epoch = 0;
        let old_planner = HashRingPlacementPlanner::new(8, old_epoch);
        let old_decision = old_planner
            .plan_placement(&layout, &fd, &old_devices, &req)
            .unwrap();
        let receipt = old_decision
            .to_replay_receipt(&layout, &old_devices, &req, old_epoch)
            .unwrap();

        let mut new_decision = None;
        for new_epoch in 1..64 {
            let planner = HashRingPlacementPlanner::new(8, new_epoch);
            let candidate = planner
                .plan_placement(&layout, &fd, &new_devices, &req)
                .unwrap();
            if candidate.device_targets != old_decision.device_targets {
                new_decision = Some(candidate);
                break;
            }
        }
        let new_decision =
            new_decision.expect("new topology epoch should choose a different target order");

        assert!(receipt.verify_seal());
        assert_eq!(receipt.topology_epoch, old_epoch);
        assert_eq!(receipt.policy.total_shards(), 3);
        assert_ne!(new_decision.device_targets, old_decision.device_targets);

        let replayed = receipt.replay_decision().unwrap();
        assert_eq!(replayed.device_targets, old_decision.device_targets);
        assert_ne!(replayed.device_targets, new_decision.device_targets);
        assert_eq!(replayed.deterministic_seed, old_epoch);
    }

    #[test]
    fn replay_receipt_records_erasure_width_and_roles() {
        let planner = default_planner();
        let layout = erasure_layout(4, 2);
        let fd = device_fd();
        let devices: Vec<_> = (1..=6).map(|i| make_device(i, i, i, 1)).collect();
        let req = request_bytes(7, 9, 4 * GIB);
        let decision = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();

        let receipt = decision
            .to_replay_receipt(&layout, &devices, &req, 0)
            .unwrap();

        assert_eq!(receipt.targets.len(), 6);
        assert_eq!(receipt.per_target_bytes, GIB);
        assert_eq!(
            receipt
                .targets
                .iter()
                .filter(|target| target.shard_role == PlacementReplayShardRole::Data)
                .count(),
            4
        );
        assert_eq!(
            receipt
                .targets
                .iter()
                .filter(|target| target.shard_role == PlacementReplayShardRole::Parity)
                .count(),
            2
        );
        assert_eq!(receipt.replay_decision().unwrap(), decision);
    }

    #[test]
    fn replay_receipt_seal_rejects_tampered_targets() {
        let planner = default_planner();
        let layout = mirror_layout(2);
        let fd = device_fd();
        let devices = vec![make_device(1, 1, 1, 100), make_device(2, 2, 2, 100)];
        let req = request(11, 13);
        let decision = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        let mut receipt = decision
            .to_replay_receipt(&layout, &devices, &req, 0)
            .unwrap();

        assert!(receipt.verify_seal());
        receipt.targets[0].device_id ^= 0x55;

        assert!(!receipt.verify_seal());
        assert!(matches!(
            receipt.replay_decision(),
            Err(PlacementReplayError::SealMismatch)
        ));
    }

    // -- Failure-domain separation ---------------------------------

    #[test]
    fn hash_ring_device_level_separates_devices() {
        let planner = default_planner();
        let layout = mirror_layout(3);
        let fd = device_fd();
        let devices = vec![
            make_device(1, 10, 100, 100),
            make_device(2, 10, 100, 100),
            make_device(3, 10, 100, 100),
        ];
        let req = request(1, 1);
        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();

        assert_eq!(dec.device_targets.len(), 3);
        assert!(dec.failure_domain_separation);
        let unique: BTreeSet<u64> = dec.device_targets.iter().copied().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn hash_ring_node_level_separates_nodes() {
        let planner = default_planner();
        let layout = mirror_layout(3);
        let fd = node_fd();
        let devices = vec![
            make_device(1, 10, 100, 100),
            make_device(2, 10, 100, 100),
            make_device(3, 20, 200, 100),
            make_device(4, 30, 300, 100),
        ];
        let req = request(1, 1);
        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();

        assert_eq!(dec.device_targets.len(), 3);
        assert!(dec.failure_domain_separation);

        let selected_nodes: BTreeSet<u64> = dec
            .device_targets
            .iter()
            .map(|id| devices.iter().find(|d| d.device_id == *id).unwrap().node_id)
            .collect();
        assert_eq!(
            selected_nodes.len(),
            3,
            "all 3 replicas should land on distinct nodes"
        );
    }

    #[test]
    fn hash_ring_rack_level_separates_racks() {
        let planner = default_planner();
        let layout = mirror_layout(2);
        let fd = rack_fd();
        let devices = vec![
            make_device(1, 10, 100, 100),
            make_device(2, 20, 200, 100),
            make_device(3, 30, 300, 100),
        ];
        let req = request(1, 1);
        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();

        assert_eq!(dec.device_targets.len(), 2);
        assert!(dec.failure_domain_separation);
        let selected_racks: BTreeSet<u64> = dec
            .device_targets
            .iter()
            .map(|id| devices.iter().find(|d| d.device_id == *id).unwrap().rack_id)
            .collect();
        assert_eq!(selected_racks.len(), 2);
    }

    #[test]
    fn hash_ring_degraded_when_insufficient_domains() {
        let planner = default_planner();
        let layout = mirror_layout(3);
        let fd = node_fd();
        let devices = vec![
            make_device(1, 10, 100, 100),
            make_device(2, 10, 100, 100),
            make_device(3, 20, 200, 100),
            make_device(4, 20, 200, 100),
        ];
        let req = request(1, 1);
        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();

        assert_eq!(dec.device_targets.len(), 3);
        assert!(
            !dec.failure_domain_separation,
            "should report degraded separation when insufficient domains"
        );
    }

    // -- No same-device reuse --------------------------------------

    #[test]
    fn hash_ring_no_duplicate_device_targets() {
        let planner = default_planner();
        let layout = mirror_layout(5);
        let fd = node_fd();
        let devices: Vec<_> = (0..10).map(|i| make_device(i, i, i, 100)).collect();
        let req = request(1, 1);
        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();

        let unique: BTreeSet<u64> = dec.device_targets.iter().copied().collect();
        assert_eq!(
            unique.len(),
            dec.device_targets.len(),
            "no device should be selected more than once"
        );
    }

    // -- Capacity-aware distribution -------------------------------

    #[test]
    fn hash_ring_larger_devices_win_more_draws() {
        let layout = mirror_layout(1);
        let fd = node_fd();
        let devices = vec![
            make_device(1, 10, 100, 10),   // 10 GB
            make_device(2, 20, 200, 1000), // 1000 GB
        ];

        let mut big_wins = 0u32;
        for key in 0..256 {
            let planner = HashRingPlacementPlanner::new(8, 0);
            let req = request(key, key);
            let dec = planner
                .plan_placement(&layout, &fd, &devices, &req)
                .unwrap();
            if dec.device_targets[0] == 2 {
                big_wins += 1;
            }
        }
        assert!(
            big_wins > 192,
            "big device should win most draws, won {big_wins}/256"
        );
    }

    // -- Edge cases ------------------------------------------------

    #[test]
    fn hash_ring_single_device_mirror_1() {
        let planner = default_planner();
        let layout = mirror_layout(1);
        let fd = device_fd();
        let devices = vec![make_device(42, 1, 1, 100)];
        let req = request(1, 1);
        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        assert_eq!(dec.device_targets, vec![42]);
        assert!(dec.satisfied());
    }

    #[test]
    fn hash_ring_not_enough_devices_errors() {
        let planner = default_planner();
        let layout = mirror_layout(3);
        let fd = device_fd();
        let devices = vec![make_device(1, 1, 1, 100), make_device(2, 2, 2, 100)];
        let req = request(1, 1);
        let err = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap_err();
        assert!(matches!(err, PlacementError::NotEnoughMembers { .. }));
    }

    #[test]
    fn hash_ring_all_devices_unhealthy_errors() {
        let planner = default_planner();
        let layout = mirror_layout(1);
        let fd = device_fd();
        let devices = vec![make_device_unhealthy(1, 1, 1)];
        let req = request(1, 1);
        let err = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap_err();
        assert!(matches!(err, PlacementError::AllMembersExcluded));
    }

    #[test]
    fn hash_ring_full_device_skipped() {
        let planner = default_planner();
        let layout = mirror_layout(2);
        let fd = device_fd();
        let devices = vec![
            make_device_used(1, 1, 1, 100, 100),
            make_device(2, 2, 2, 100),
            make_device(3, 3, 3, 100),
        ];
        let req = request(1, 1);
        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        assert!(!dec.device_targets.contains(&1));
        assert_eq!(dec.device_targets.len(), 2);
    }

    #[test]
    fn hash_ring_nearly_full_device_below_request_size_skipped() {
        let planner = default_planner();
        let layout = mirror_layout(2);
        let fd = device_fd();
        let mut nearly_full = make_device(1, 1, 1, 2);
        nearly_full.used_bytes = nearly_full.total_bytes - (512 * 1024 * 1024);
        let devices = vec![
            nearly_full,
            make_device(2, 2, 2, 2),
            make_device(3, 3, 3, 2),
        ];
        let req = request_bytes(1, 1, GIB);
        let target_bytes = per_target_capacity_bytes(&layout, &req);

        let ring = planner.build_ring(&devices, &fd, target_bytes);
        let ring_devices: BTreeSet<u64> = ring
            .iter()
            .map(|(_, dev_idx, _)| devices[*dev_idx].device_id)
            .collect();
        assert!(!ring_devices.contains(&1));

        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        let replay = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        assert_eq!(dec, replay);
        assert_eq!(dec.device_targets.len(), 2);
        assert!(!dec.device_targets.contains(&1));
    }

    #[test]
    fn hash_ring_refuses_when_non_full_devices_lack_request_capacity() {
        let planner = default_planner();
        let layout = mirror_layout(2);
        let fd = device_fd();
        let mut first = make_device(1, 1, 1, 2);
        let mut second = make_device(2, 2, 2, 2);
        first.used_bytes = first.total_bytes - (512 * 1024 * 1024);
        second.used_bytes = second.total_bytes - (512 * 1024 * 1024);
        let devices = vec![first, second];
        let req = request_bytes(1, 1, GIB);

        let err = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap_err();
        assert!(matches!(
            err,
            PlacementError::NotEnoughMembers {
                required: 2,
                available: 0
            }
        ));
    }

    #[test]
    fn hash_ring_erasure_capacity_budget_is_per_data_shard() {
        let planner = default_planner();
        let layout = erasure_layout(4, 2);
        let fd = device_fd();
        let devices: Vec<_> = (1..=6).map(|i| make_device(i, i, i, 1)).collect();

        let req = request_bytes(1, 1, 4 * GIB);
        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        assert_eq!(dec.device_targets.len(), 6);

        let oversized = request_bytes(1, 1, 4 * GIB + 1);
        let err = planner
            .plan_placement(&layout, &fd, &devices, &oversized)
            .unwrap_err();
        assert!(matches!(
            err,
            PlacementError::NotEnoughMembers {
                required: 6,
                available: 0
            }
        ));
    }

    #[test]
    fn hash_ring_mixed_healthy_unhealthy() {
        let planner = default_planner();
        let layout = mirror_layout(2);
        let fd = device_fd();
        let devices = vec![
            make_device_unhealthy(1, 1, 1),
            make_device(2, 2, 2, 100),
            make_device(3, 3, 3, 100),
        ];
        let req = request(1, 1);
        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        assert!(!dec.device_targets.contains(&1));
        assert_eq!(dec.device_targets.len(), 2);
    }

    #[test]
    fn hash_ring_erasure_placement_respects_shard_count() {
        let planner = default_planner();
        let layout = erasure_layout(4, 2);
        let fd = node_fd();
        let devices: Vec<_> = (0..12).map(|i| make_device(i, i, i / 2, 100)).collect();
        let req = request(1, 1);
        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        assert_eq!(dec.device_targets.len(), 6);
        assert_eq!(dec.replica_count, 6);
    }

    // -- Large topology --------------------------------------------

    #[test]
    fn hash_ring_large_topology_100_devices() {
        let planner = default_planner();
        let layout = mirror_layout(5);
        let fd = rack_fd();
        let devices: Vec<_> = (0..100)
            .map(|i| make_device(i, i % 10, i % 20, 100))
            .collect();
        let req = request(1, 1);
        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        assert_eq!(dec.device_targets.len(), 5);
        assert!(dec.satisfied());
    }

    // -----------------------------------------------------------------------
    // PlacementInput tests
    // -----------------------------------------------------------------------

    #[test]
    fn placement_input_construction() {
        let input = PlacementInput::new(
            mirror_layout(2),
            node_fd(),
            vec![make_device(1, 10, 100, 100), make_device(2, 20, 200, 100)],
            request(42, 7),
        );
        assert_eq!(input.required_shards(), 2);
        assert_eq!(input.eligible_device_count(), 2);
        assert_eq!(input.distinct_domain_count(), 2);
    }

    #[test]
    fn placement_input_with_existing_placements() {
        let mut existing = BTreeMap::new();
        existing.insert(99, BTreeSet::from([1, 2]));

        let input = PlacementInput::new(
            mirror_layout(2),
            node_fd(),
            vec![make_device(1, 10, 100, 100), make_device(2, 20, 200, 100)],
            request(42, 7),
        )
        .with_existing_placements(existing);

        assert_eq!(input.existing_placements.len(), 1);
        assert!(input.existing_placements.contains_key(&99));
    }

    #[test]
    fn placement_input_eligibility_filters_unhealthy() {
        let input = PlacementInput::new(
            mirror_layout(2),
            node_fd(),
            vec![
                make_device(1, 10, 100, 100),
                make_device_unhealthy(2, 20, 200),
                make_device_used(3, 30, 300, 100, 100),
            ],
            request(42, 7),
        );
        assert_eq!(input.eligible_device_count(), 1);
    }

    #[test]
    fn placement_input_distinct_domains_node_level() {
        let input = PlacementInput::new(
            mirror_layout(3),
            node_fd(),
            vec![
                make_device(1, 10, 100, 100),
                make_device(2, 10, 100, 100),
                make_device(3, 20, 200, 100),
                make_device(4, 30, 300, 100),
            ],
            request(42, 7),
        );
        assert_eq!(input.distinct_domain_count(), 3);
    }

    #[test]
    fn placement_input_plan_with_delegates() {
        let planner = default_planner();
        let input = PlacementInput::new(
            mirror_layout(2),
            node_fd(),
            vec![
                make_device(1, 10, 100, 100),
                make_device(2, 20, 200, 100),
                make_device(3, 30, 300, 100),
            ],
            request(42, 7),
        );
        let dec = input.plan_with(&planner).unwrap();
        assert_eq!(dec.device_targets.len(), 2);
        assert_eq!(dec.object_id, 42);
        assert!(dec.satisfied());
    }

    // -----------------------------------------------------------------------
    // Constraint-to-decision pipeline integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn constraint_pipeline_mirror_3_strict() {
        let planner = default_planner();
        let layout = mirror_layout(3);
        let fd = node_fd();
        let devices = vec![
            make_device(1, 10, 100, 100),
            make_device(2, 20, 200, 100),
            make_device(3, 30, 300, 100),
            make_device(4, 40, 400, 100),
        ];
        let req = request(42, 7);

        // Step 1: Build constraint and check satisfaction.
        let constraint = constraint::PlacementConstraint::new(&layout, &fd);
        assert!(constraint.verify());
        let sat = constraint::check_satisfaction(&constraint, &devices);
        assert!(sat.satisfiable);
        assert!(sat.strict_separation_possible);

        // Step 2: Plan placement.
        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        assert_eq!(dec.device_targets.len(), 3);
        assert!(dec.failure_domain_separation);
        assert!(dec.satisfied());

        // Step 3: Seal and verify assignment.
        let seal = constraint::seal_assignment(
            &constraint,
            dec.object_id,
            req.placement_key,
            dec.deterministic_seed,
            &dec.device_targets,
        );
        assert!(constraint::verify_assignment(
            &constraint,
            dec.object_id,
            req.placement_key,
            dec.deterministic_seed,
            &dec.device_targets,
            &seal,
        ));
    }

    #[test]
    fn constraint_pipeline_erasure_4_2() {
        let planner = default_planner();
        let layout = erasure_layout(4, 2);
        let fd = rack_fd();
        let devices: Vec<_> = (0..12).map(|i| make_device(i, i % 6, i, 100)).collect();
        let req = request(99, 13);

        let constraint = constraint::PlacementConstraint::new(&layout, &fd);
        let sat = constraint::check_satisfaction(&constraint, &devices);
        assert!(sat.satisfiable);
        assert_eq!(sat.distinct_domains, 12);

        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        assert_eq!(dec.device_targets.len(), 6);
        assert!(dec.failure_domain_separation);
    }

    #[test]
    fn constraint_pipeline_preflight_rejection() {
        let planner = default_planner();
        let layout = mirror_layout(5);
        let fd = node_fd();
        let devices = vec![make_device(1, 10, 100, 100), make_device(2, 20, 200, 100)];
        let req = request(1, 1);

        let constraint = constraint::PlacementConstraint::new(&layout, &fd);
        let sat = constraint::check_satisfaction(&constraint, &devices);
        assert!(!sat.satisfiable);
        assert!(matches!(
            sat.failure_reason,
            Some(constraint::ConstraintFailureReason::NotEnoughDevices {
                required: 5,
                available: 2
            })
        ));

        let err = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap_err();
        assert!(matches!(err, PlacementError::NotEnoughMembers { .. }));
    }

    #[test]
    fn constraint_pipeline_degraded_placement() {
        let planner = default_planner();
        let layout = mirror_layout(3);
        let fd = node_fd();
        // Only 2 distinct nodes for 3 replicas.
        let devices = vec![
            make_device(1, 10, 100, 100),
            make_device(2, 10, 100, 100),
            make_device(3, 20, 200, 100),
        ];
        let req = request(1, 1);

        let constraint = constraint::PlacementConstraint::new(&layout, &fd);
        let sat = constraint::check_satisfaction(&constraint, &devices);
        assert!(sat.satisfiable);
        assert!(!sat.strict_separation_possible);
        assert_eq!(sat.distinct_domains, 2);

        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        assert_eq!(dec.device_targets.len(), 3);
    }

    #[test]
    fn constraint_pipeline_deterministic_full_roundtrip() {
        let planner = default_planner();
        let layout = mirror_layout(2);
        let fd = node_fd();
        let devices = vec![
            make_device(1, 10, 100, 100),
            make_device(2, 20, 200, 100),
            make_device(3, 30, 300, 100),
        ];
        let req = request(42, 7);

        let constraint = constraint::PlacementConstraint::new(&layout, &fd);

        let dec1 = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        let dec2 = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        assert_eq!(dec1, dec2);

        let seal1 = constraint::seal_assignment(
            &constraint,
            dec1.object_id,
            req.placement_key,
            dec1.deterministic_seed,
            &dec1.device_targets,
        );
        let seal2 = constraint::seal_assignment(
            &constraint,
            dec2.object_id,
            req.placement_key,
            dec2.deterministic_seed,
            &dec2.device_targets,
        );
        assert_eq!(seal1, seal2);
    }

    #[test]
    fn constraint_pipeline_placement_input_integration() {
        let planner = default_planner();
        let input = PlacementInput::new(
            mirror_layout(3),
            node_fd(),
            vec![
                make_device(1, 10, 100, 100),
                make_device(2, 20, 200, 100),
                make_device(3, 30, 300, 100),
                make_device(4, 40, 400, 100),
            ],
            request(42, 7),
        );

        let c = input.constraint();
        assert!(c.verify());
        assert_eq!(c.required_shards, 3);

        let sat = input.check_satisfaction();
        assert!(sat.satisfiable);
        assert!(sat.strict_separation_possible);

        let dec = input.plan_with(&planner).unwrap();
        assert_eq!(dec.device_targets.len(), 3);
        assert!(dec.satisfied());

        let seal = constraint::seal_assignment(
            &c,
            dec.object_id,
            input.request.placement_key,
            dec.deterministic_seed,
            &dec.device_targets,
        );
        assert!(constraint::verify_assignment(
            &c,
            dec.object_id,
            input.request.placement_key,
            dec.deterministic_seed,
            &dec.device_targets,
            &seal,
        ));
    }

    #[test]
    fn constraint_pipeline_group_by_domain_then_plan() {
        let planner = default_planner();
        let layout = mirror_layout(2);
        let fd = node_fd();
        let devices = vec![
            make_device(1, 10, 100, 100),
            make_device(2, 10, 100, 100),
            make_device(3, 20, 200, 100),
            make_device(4, 20, 200, 100),
            make_device(5, 30, 300, 100),
        ];

        let constraint = constraint::PlacementConstraint::new(&layout, &fd);
        let groups = constraint::group_by_domain(&constraint, &devices);
        assert_eq!(groups.len(), 3);

        let sorted = constraint::sorted_domain_groups(&constraint, &devices);
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[0].0, 30); // node 30 has 1 device

        let req = request(1, 1);
        let dec = planner
            .plan_placement(&layout, &fd, &devices, &req)
            .unwrap();
        assert_eq!(dec.device_targets.len(), 2);

        let domain_keys =
            constraint::domain_keys_for_targets(&constraint, &devices, &dec.device_targets);
        assert_eq!(domain_keys.len(), 2);
    }

    #[test]
    fn constraint_pipeline_all_unhealthy_rejected_by_preflight() {
        let layout = mirror_layout(2);
        let fd = node_fd();
        let devices = vec![
            make_device_unhealthy(1, 10, 100),
            make_device_unhealthy(2, 20, 200),
        ];

        let constraint = constraint::PlacementConstraint::new(&layout, &fd);
        let sat = constraint::check_satisfaction(&constraint, &devices);
        assert!(!sat.satisfiable);
        assert!(matches!(
            sat.failure_reason,
            Some(constraint::ConstraintFailureReason::NoHealthyDevices)
        ));
    }
}
