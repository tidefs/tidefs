// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Storage-intent policy source compilation.
//!
//! This crate is the first #855 source slice. It turns typed policy sources
//! into the dataset-scoped prefetch/residency envelope consumed by #967. It
//! does not render operator UAPI, emit receipts, score placement, execute
//! prefetch, move data, or publish product claims.

use tidefs_storage_intent_core::{
    PrefetchResidencyActionMask, PrefetchResidencyCandidateClass,
    PrefetchResidencyDecisionEvidenceRefs, PrefetchResidencyPolicyEnvelope,
    PrefetchResidencyPolicyFlags, PrefetchResidencyPolicyScope, StorageIntentDomainId,
    StorageIntentEvidenceKind, StorageIntentEvidenceRef, StorageIntentPolicyId,
    StorageIntentPolicyRevision, StorageIntentRefusalReason,
};

/// Version of the policy-source compiler surface.
pub const STORAGE_INTENT_POLICY_SOURCE_VERSION: u16 = 1;

/// Stable compiler identifier for evidence and fixture tests.
pub const STORAGE_INTENT_POLICY_SOURCE_SPEC: &str = "tidefs-storage-intent-policy-v1-issue-855";

const LOW_RISK_DEFAULT_FLAGS: PrefetchResidencyPolicyFlags =
    PrefetchResidencyPolicyFlags::REQUIRE_DATASET_SCOPE
        .union(PrefetchResidencyPolicyFlags::REQUIRE_READ_SERVING_BOUNDARY)
        .union(PrefetchResidencyPolicyFlags::PROTECT_FOREGROUND_TAIL);

const MOVEMENT_EVIDENCE_FLAGS: PrefetchResidencyPolicyFlags =
    PrefetchResidencyPolicyFlags::REQUIRE_PAYBACK_FOR_MOVEMENT
        .union(PrefetchResidencyPolicyFlags::REQUIRE_RELOCATION_BOUNDARY_FOR_AUTHORITY)
        .union(PrefetchResidencyPolicyFlags::REQUIRE_COST_WEAR_EVIDENCE)
        .union(PrefetchResidencyPolicyFlags::REQUIRE_CAPACITY_RESERVE);

const fn bytes16_are_zero(bytes: [u8; 16]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

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

const fn evidence_ref_has_id(evidence: StorageIntentEvidenceRef) -> bool {
    evidence.kind as u16 != StorageIntentEvidenceKind::Unknown as u16
        && !bytes32_are_zero(evidence.id.0)
}

const fn domain_id_is_zero(id: StorageIntentDomainId) -> bool {
    bytes16_are_zero(id.0)
}

const fn policy_id_is_zero(id: StorageIntentPolicyId) -> bool {
    bytes16_are_zero(id.0)
}

/// Policy source class participating in typed merge/refusal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(u8)]
pub enum StorageIntentPolicySourceClass {
    /// No source is present.
    #[default]
    Absent = 0,
    /// Pool default. Inheritance only; never enough by itself.
    PoolDefault = 1,
    /// Dataset-inherited source.
    InheritedDataset = 2,
    /// Dataset-local source.
    Dataset = 3,
    /// Mount profile policy.
    MountProfile = 4,
    /// Product profile policy.
    ProductProfile = 5,
    /// Dataset-admitted subject/range override.
    SubjectRangeOverride = 6,
    /// Caller request flags such as sync/direct/FUA/barrier/stable-write.
    CallerFlags = 7,
    /// Caller hints such as hotness, lifetime, and cache bypass.
    CallerHints = 8,
    /// Internal repair, evacuation, rebake, relocation, or geo catch-up intent.
    InternalMaintenance = 9,
}

/// Bitset of policy sources used to compile an envelope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct StorageIntentPolicySourceMask(pub u32);

impl StorageIntentPolicySourceMask {
    /// Empty provenance set.
    pub const EMPTY: Self = Self(0);

    /// Add a source class.
    #[must_use]
    pub const fn with(self, class: StorageIntentPolicySourceClass) -> Self {
        Self(self.0 | (1_u32 << class as u8))
    }

    /// Returns true when a class participated.
    #[must_use]
    pub const fn contains(self, class: StorageIntentPolicySourceClass) -> bool {
        (self.0 & (1_u32 << class as u8)) != 0
    }
}

/// One typed prefetch/residency policy source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrefetchResidencyPolicySource {
    pub class: StorageIntentPolicySourceClass,
    pub present: bool,
    pub source_revision: u64,
    pub allowed_actions: PrefetchResidencyActionMask,
    pub refused_actions: PrefetchResidencyActionMask,
    pub required_flags: PrefetchResidencyPolicyFlags,
    pub has_prefetch_window_limit: bool,
    pub max_prefetch_window_bytes: u64,
    pub has_staging_limit: bool,
    pub max_staging_bytes: u64,
    pub min_sample_mass: u32,
    pub min_observation_window_ms: u64,
    pub max_decay_age_ms: u64,
    pub dwell_min_ms: u64,
    pub cooldown_ms: u64,
    pub admits_subject_range_overrides: bool,
    pub explicit_unsafe_opt_in: bool,
}

impl PrefetchResidencyPolicySource {
    /// Absent source; it has no merge effect.
    pub const ABSENT: Self = Self {
        class: StorageIntentPolicySourceClass::Absent,
        present: false,
        source_revision: 0,
        allowed_actions: PrefetchResidencyActionMask::EMPTY,
        refused_actions: PrefetchResidencyActionMask::EMPTY,
        required_flags: PrefetchResidencyPolicyFlags::EMPTY,
        has_prefetch_window_limit: false,
        max_prefetch_window_bytes: 0,
        has_staging_limit: false,
        max_staging_bytes: 0,
        min_sample_mass: 0,
        min_observation_window_ms: 0,
        max_decay_age_ms: 0,
        dwell_min_ms: 0,
        cooldown_ms: 0,
        admits_subject_range_overrides: false,
        explicit_unsafe_opt_in: false,
    };

    /// Construct a present source with an explicit allow-list.
    #[must_use]
    pub const fn new(
        class: StorageIntentPolicySourceClass,
        allowed_actions: PrefetchResidencyActionMask,
    ) -> Self {
        Self {
            class,
            present: true,
            source_revision: 0,
            allowed_actions,
            refused_actions: PrefetchResidencyActionMask::EMPTY,
            required_flags: PrefetchResidencyPolicyFlags::EMPTY,
            has_prefetch_window_limit: false,
            max_prefetch_window_bytes: 0,
            has_staging_limit: false,
            max_staging_bytes: 0,
            min_sample_mass: 0,
            min_observation_window_ms: 0,
            max_decay_age_ms: 0,
            dwell_min_ms: 0,
            cooldown_ms: 0,
            admits_subject_range_overrides: false,
            explicit_unsafe_opt_in: false,
        }
    }

    /// Refuse selected actions even if an earlier source allowed them.
    #[must_use]
    pub const fn refusing(mut self, refused_actions: PrefetchResidencyActionMask) -> Self {
        self.refused_actions = refused_actions;
        self
    }

    /// Require additional evidence/compile flags.
    #[must_use]
    pub const fn requiring(mut self, required_flags: PrefetchResidencyPolicyFlags) -> Self {
        self.required_flags = required_flags;
        self
    }

    /// Apply a prefetch-window ceiling.
    #[must_use]
    pub const fn with_prefetch_window_limit(mut self, bytes: u64) -> Self {
        self.has_prefetch_window_limit = true;
        self.max_prefetch_window_bytes = bytes;
        self
    }

    /// Apply a staging-capacity ceiling.
    #[must_use]
    pub const fn with_staging_limit(mut self, bytes: u64) -> Self {
        self.has_staging_limit = true;
        self.max_staging_bytes = bytes;
        self
    }

    /// Apply predictor quality floors.
    #[must_use]
    pub const fn with_signal_floor(
        mut self,
        min_sample_mass: u32,
        min_observation_window_ms: u64,
        max_decay_age_ms: u64,
    ) -> Self {
        self.min_sample_mass = min_sample_mass;
        self.min_observation_window_ms = min_observation_window_ms;
        self.max_decay_age_ms = max_decay_age_ms;
        self
    }

    /// Apply dwell and cooldown constraints for movement.
    #[must_use]
    pub const fn with_movement_timers(mut self, dwell_min_ms: u64, cooldown_ms: u64) -> Self {
        self.dwell_min_ms = dwell_min_ms;
        self.cooldown_ms = cooldown_ms;
        self
    }

    /// Admit subject/range overrides for this dataset policy.
    #[must_use]
    pub const fn admitting_subject_range_overrides(mut self) -> Self {
        self.admits_subject_range_overrides = true;
        self
    }

    /// Mark a visible unsafe/volatile opt-in. This never overrides caller
    /// durable flags; it only prevents hidden downgrades.
    #[must_use]
    pub const fn with_explicit_unsafe_opt_in(mut self) -> Self {
        self.explicit_unsafe_opt_in = true;
        self
    }
}

impl Default for PrefetchResidencyPolicySource {
    fn default() -> Self {
        Self::ABSENT
    }
}

/// Caller request flags that may tighten but never weaken a compiled floor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct CallerRequestFlags {
    pub sync: bool,
    pub direct: bool,
    pub fua: bool,
    pub barrier: bool,
    pub stable_write: bool,
    pub cache_bypass: bool,
}

impl CallerRequestFlags {
    /// Returns true when the caller requested durable/ordered semantics.
    #[must_use]
    pub const fn durable_floor(self) -> bool {
        self.sync || self.fua || self.barrier || self.stable_write
    }
}

/// Caller hints influence prediction only; they cannot create authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallerHintSource {
    pub present: bool,
    pub hotness_hint: bool,
    pub lifetime_hint: bool,
    pub cache_bypass_hint: bool,
    pub requested_candidate: PrefetchResidencyCandidateClass,
}

impl CallerHintSource {
    pub const ABSENT: Self = Self {
        present: false,
        hotness_hint: false,
        lifetime_hint: false,
        cache_bypass_hint: false,
        requested_candidate: PrefetchResidencyCandidateClass::NoPrefetch,
    };
}

impl Default for CallerHintSource {
    fn default() -> Self {
        Self::ABSENT
    }
}

/// Internal maintenance intent source.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct InternalMaintenanceIntent {
    pub present: bool,
    pub repair: bool,
    pub evacuation: bool,
    pub rebake: bool,
    pub relocation: bool,
    pub geo_catchup: bool,
    pub receipt_retirement: bool,
    pub protected_reserves_available: bool,
}

impl InternalMaintenanceIntent {
    /// Returns true when the intent may request authority-changing movement.
    #[must_use]
    pub const fn requests_movement(self) -> bool {
        self.repair
            || self.evacuation
            || self.rebake
            || self.relocation
            || self.geo_catchup
            || self.receipt_retirement
    }
}

/// Evidence presence known at policy compile time.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct PrefetchResidencyPolicyEvidenceState {
    pub service_objective: bool,
    pub evidence_query: bool,
    pub fresh_media_capability: bool,
    pub cost_wear: bool,
    pub egress_restore_cost: bool,
    pub payback: bool,
    pub capacity_reserve: bool,
    pub tenant_isolation: bool,
    pub read_serving_boundary: bool,
    pub relocation_boundary: bool,
    pub scheduler_admission: bool,
    pub trust_domain: bool,
    pub transport_budget: bool,
}

/// Stable identity of the compiled policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageIntentPolicyIdentity {
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub pool_id: StorageIntentDomainId,
    pub dataset_id: StorageIntentDomainId,
    pub budget_owner: StorageIntentDomainId,
}

impl Default for StorageIntentPolicyIdentity {
    fn default() -> Self {
        Self {
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            pool_id: StorageIntentDomainId::ZERO,
            dataset_id: StorageIntentDomainId::ZERO,
            budget_owner: StorageIntentDomainId::ZERO,
        }
    }
}

/// Fixed source set for the first #855 prefetch/residency compiler.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PrefetchResidencyPolicySources {
    pub identity: StorageIntentPolicyIdentity,
    pub pool_default: PrefetchResidencyPolicySource,
    pub inherited_dataset: PrefetchResidencyPolicySource,
    pub dataset: PrefetchResidencyPolicySource,
    pub mount_profile: PrefetchResidencyPolicySource,
    pub product_profile: PrefetchResidencyPolicySource,
    pub subject_range_override: PrefetchResidencyPolicySource,
    pub caller_flags: CallerRequestFlags,
    pub caller_hints: CallerHintSource,
    pub internal_maintenance: InternalMaintenanceIntent,
    pub evidence_state: PrefetchResidencyPolicyEvidenceState,
    pub evidence_refs: PrefetchResidencyDecisionEvidenceRefs,
}

/// Policy compile status.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(u8)]
pub enum StorageIntentPolicyCompileStatus {
    /// No usable policy was produced.
    #[default]
    Refused = 0,
    /// A policy was compiled without lowering.
    Compiled = 1,
    /// A policy was compiled but unsafe, stale, costly, or conflicting actions
    /// were lowered out of the action set.
    Lowered = 2,
    /// The remaining policy is explicitly weaker/unsafe and receipt-visible.
    UnsafeVisible = 3,
    /// The remaining policy is degraded but visible to consumers.
    DegradedVisible = 4,
}

/// Result of compiling source policy into a #967 envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageIntentPolicyCompileResult {
    pub status: StorageIntentPolicyCompileStatus,
    pub envelope: PrefetchResidencyPolicyEnvelope,
    pub source_mask: StorageIntentPolicySourceMask,
    pub refusal: StorageIntentRefusalReason,
    pub explicit_unsafe_opt_in: bool,
    pub subject_range_override_admitted: bool,
}

impl Default for StorageIntentPolicyCompileResult {
    fn default() -> Self {
        Self {
            status: StorageIntentPolicyCompileStatus::Refused,
            envelope: PrefetchResidencyPolicyEnvelope::default(),
            source_mask: StorageIntentPolicySourceMask::EMPTY,
            refusal: StorageIntentRefusalReason::EvidenceNotUsable,
            explicit_unsafe_opt_in: false,
            subject_range_override_admitted: false,
        }
    }
}

/// Compile pool, dataset, mount, caller, and maintenance sources into the #967
/// prefetch/residency policy envelope.
#[must_use]
pub fn compile_prefetch_residency_policy(
    sources: PrefetchResidencyPolicySources,
) -> StorageIntentPolicyCompileResult {
    let mut result = StorageIntentPolicyCompileResult::default();

    if policy_id_is_zero(sources.identity.policy_id)
        || sources.identity.policy_revision.0 == 0
        || domain_id_is_zero(sources.identity.pool_id)
        || domain_id_is_zero(sources.identity.dataset_id)
        || domain_id_is_zero(sources.identity.budget_owner)
    {
        result.refusal = StorageIntentRefusalReason::EvidenceNotUsable;
        return result;
    }

    result.refusal = StorageIntentRefusalReason::None;

    let mut source_mask = StorageIntentPolicySourceMask::EMPTY;
    let mut actions = PrefetchResidencyActionMask::ALL_DEFINED;
    let mut has_dataset_policy = false;
    let mut flags = LOW_RISK_DEFAULT_FLAGS;
    let mut max_prefetch_window_bytes = u64::MAX;
    let mut max_staging_bytes = u64::MAX;
    let mut min_sample_mass = 0_u32;
    let mut min_observation_window_ms = 0_u64;
    let mut max_decay_age_ms = 0_u64;
    let mut dwell_min_ms = 0_u64;
    let mut cooldown_ms = 0_u64;
    let mut explicit_unsafe_opt_in = false;
    let mut subject_range_override_admitted = false;

    if sources.pool_default.present {
        source_mask = source_mask.with(StorageIntentPolicySourceClass::PoolDefault);
    }

    has_dataset_policy |= apply_source(
        sources.inherited_dataset,
        &mut source_mask,
        &mut actions,
        &mut flags,
        &mut max_prefetch_window_bytes,
        &mut max_staging_bytes,
        &mut min_sample_mass,
        &mut min_observation_window_ms,
        &mut max_decay_age_ms,
        &mut dwell_min_ms,
        &mut cooldown_ms,
        &mut explicit_unsafe_opt_in,
    );
    subject_range_override_admitted |= sources.inherited_dataset.admits_subject_range_overrides;

    has_dataset_policy |= apply_source(
        sources.dataset,
        &mut source_mask,
        &mut actions,
        &mut flags,
        &mut max_prefetch_window_bytes,
        &mut max_staging_bytes,
        &mut min_sample_mass,
        &mut min_observation_window_ms,
        &mut max_decay_age_ms,
        &mut dwell_min_ms,
        &mut cooldown_ms,
        &mut explicit_unsafe_opt_in,
    );
    subject_range_override_admitted |= sources.dataset.admits_subject_range_overrides;

    apply_source(
        sources.mount_profile,
        &mut source_mask,
        &mut actions,
        &mut flags,
        &mut max_prefetch_window_bytes,
        &mut max_staging_bytes,
        &mut min_sample_mass,
        &mut min_observation_window_ms,
        &mut max_decay_age_ms,
        &mut dwell_min_ms,
        &mut cooldown_ms,
        &mut explicit_unsafe_opt_in,
    );

    apply_source(
        sources.product_profile,
        &mut source_mask,
        &mut actions,
        &mut flags,
        &mut max_prefetch_window_bytes,
        &mut max_staging_bytes,
        &mut min_sample_mass,
        &mut min_observation_window_ms,
        &mut max_decay_age_ms,
        &mut dwell_min_ms,
        &mut cooldown_ms,
        &mut explicit_unsafe_opt_in,
    );

    if sources.subject_range_override.present {
        source_mask = source_mask.with(StorageIntentPolicySourceClass::SubjectRangeOverride);
        if subject_range_override_admitted {
            apply_source(
                sources.subject_range_override,
                &mut source_mask,
                &mut actions,
                &mut flags,
                &mut max_prefetch_window_bytes,
                &mut max_staging_bytes,
                &mut min_sample_mass,
                &mut min_observation_window_ms,
                &mut max_decay_age_ms,
                &mut dwell_min_ms,
                &mut cooldown_ms,
                &mut explicit_unsafe_opt_in,
            );
        } else {
            actions = mask_intersection(actions, PrefetchResidencyActionMask::LOW_RISK_PREFETCH);
            result.status = StorageIntentPolicyCompileStatus::Lowered;
            result.refusal = StorageIntentRefusalReason::MissingAuthorization;
        }
    }

    if !has_dataset_policy {
        result.source_mask = source_mask;
        result.refusal = StorageIntentRefusalReason::EvidenceNotUsable;
        return result;
    }

    if !explicit_unsafe_opt_in && actions_contain_volatile(actions) {
        let before = actions;
        actions = remove_volatile_or_hidden_unsafe(actions);
        if before.0 != actions.0 {
            result.status = StorageIntentPolicyCompileStatus::Lowered;
            result.refusal = StorageIntentRefusalReason::MissingAuthorization;
        }
    }

    if sources.caller_flags.durable_floor() {
        source_mask = source_mask.with(StorageIntentPolicySourceClass::CallerFlags);
        let before = actions;
        actions = remove_volatile_or_hidden_unsafe(actions);
        flags = flags
            .union(PrefetchResidencyPolicyFlags::REQUIRE_READ_SERVING_BOUNDARY)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_FRESH_MEDIA_CAPABILITY);
        if before.0 != actions.0 {
            result.status = StorageIntentPolicyCompileStatus::Lowered;
            result.refusal = StorageIntentRefusalReason::VolatileRamCannotSatisfyDurableIntent;
        }
    }

    if sources.caller_flags.direct || sources.caller_flags.cache_bypass {
        source_mask = source_mask.with(StorageIntentPolicySourceClass::CallerFlags);
        actions = mask_intersection(
            actions,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::NoPrefetch,
            )
            .with(PrefetchResidencyCandidateClass::Refused),
        );
        result.status = StorageIntentPolicyCompileStatus::Lowered;
        result.refusal = StorageIntentRefusalReason::EvidenceNotUsable;
    }

    if sources.caller_hints.present {
        source_mask = source_mask.with(StorageIntentPolicySourceClass::CallerHints);
        if prefetch_candidate_changes_authority_local(sources.caller_hints.requested_candidate) {
            actions = remove_authority_movement(actions);
            result.status = StorageIntentPolicyCompileStatus::Lowered;
            result.refusal = StorageIntentRefusalReason::EvidenceNotUsable;
        }
    }

    if sources.internal_maintenance.present {
        source_mask = source_mask.with(StorageIntentPolicySourceClass::InternalMaintenance);
        if sources.internal_maintenance.requests_movement() {
            flags = flags.union(MOVEMENT_EVIDENCE_FLAGS);
            if !sources.internal_maintenance.protected_reserves_available {
                actions = remove_authority_movement(actions);
                result.status = StorageIntentPolicyCompileStatus::Lowered;
                result.refusal = StorageIntentRefusalReason::MovementDebtNotPaidBack;
            }
        }
    }

    flags = flags.union(infer_action_evidence_flags(actions));

    let before_evidence = actions;
    let evidence_refusal = apply_evidence_state(
        flags,
        sources.evidence_state,
        sources.evidence_refs,
        &mut actions,
    );
    if evidence_refusal != StorageIntentRefusalReason::None {
        result.status = StorageIntentPolicyCompileStatus::Lowered;
        result.refusal = evidence_refusal;
    }

    if before_evidence.0 != actions.0 && actions.is_empty() {
        actions = PrefetchResidencyActionMask::from_candidate(
            PrefetchResidencyCandidateClass::NeedMoreEvidence,
        )
        .with(PrefetchResidencyCandidateClass::Refused);
    }

    if actions.is_empty() {
        result.source_mask = source_mask;
        result.status = StorageIntentPolicyCompileStatus::Refused;
        if result.refusal == StorageIntentRefusalReason::None {
            result.refusal = StorageIntentRefusalReason::NoLegalReceiptSet;
        }
        return result;
    }

    let policy_scope = if sources.subject_range_override.present && subject_range_override_admitted
    {
        PrefetchResidencyPolicyScope::SubjectRange
    } else {
        PrefetchResidencyPolicyScope::Dataset
    };

    if max_prefetch_window_bytes == u64::MAX {
        max_prefetch_window_bytes = 0;
    }
    if max_staging_bytes == u64::MAX {
        max_staging_bytes = 0;
    }

    let envelope = PrefetchResidencyPolicyEnvelope {
        policy_id: sources.identity.policy_id,
        policy_revision: sources.identity.policy_revision,
        policy_scope,
        pool_id: sources.identity.pool_id,
        dataset_id: sources.identity.dataset_id,
        budget_owner: sources.identity.budget_owner,
        allowed_actions: actions,
        flags,
        max_prefetch_window_bytes,
        max_staging_bytes,
        min_sample_mass,
        min_observation_window_ms,
        max_decay_age_ms,
        dwell_min_ms,
        cooldown_ms,
        evidence_refs: sources.evidence_refs,
    };

    result.envelope = envelope;
    result.source_mask = source_mask;
    result.explicit_unsafe_opt_in = explicit_unsafe_opt_in;
    result.subject_range_override_admitted = subject_range_override_admitted;
    if result.refusal == StorageIntentRefusalReason::None {
        if result.status != StorageIntentPolicyCompileStatus::Lowered {
            result.status = if explicit_unsafe_opt_in {
                StorageIntentPolicyCompileStatus::UnsafeVisible
            } else {
                StorageIntentPolicyCompileStatus::Compiled
            };
        }
    } else if result.status == StorageIntentPolicyCompileStatus::Refused {
        result.status = StorageIntentPolicyCompileStatus::Lowered;
    }
    result
}

fn apply_source(
    source: PrefetchResidencyPolicySource,
    source_mask: &mut StorageIntentPolicySourceMask,
    actions: &mut PrefetchResidencyActionMask,
    flags: &mut PrefetchResidencyPolicyFlags,
    max_prefetch_window_bytes: &mut u64,
    max_staging_bytes: &mut u64,
    min_sample_mass: &mut u32,
    min_observation_window_ms: &mut u64,
    max_decay_age_ms: &mut u64,
    dwell_min_ms: &mut u64,
    cooldown_ms: &mut u64,
    explicit_unsafe_opt_in: &mut bool,
) -> bool {
    if !source.present {
        return false;
    }

    *source_mask = source_mask.with(source.class);
    *actions = mask_intersection(*actions, source.allowed_actions);
    *actions = mask_without(*actions, source.refused_actions);
    *flags = flags.union(source.required_flags);

    if source.has_prefetch_window_limit {
        *max_prefetch_window_bytes =
            min_u64_nonzero(*max_prefetch_window_bytes, source.max_prefetch_window_bytes);
    }
    if source.has_staging_limit {
        *max_staging_bytes = min_u64_nonzero(*max_staging_bytes, source.max_staging_bytes);
    }
    *min_sample_mass = (*min_sample_mass).max(source.min_sample_mass);
    *min_observation_window_ms = (*min_observation_window_ms).max(source.min_observation_window_ms);
    if source.max_decay_age_ms != 0 {
        *max_decay_age_ms = min_u64_nonzero(*max_decay_age_ms, source.max_decay_age_ms);
    }
    *dwell_min_ms = (*dwell_min_ms).max(source.dwell_min_ms);
    *cooldown_ms = (*cooldown_ms).max(source.cooldown_ms);
    *explicit_unsafe_opt_in |= source.explicit_unsafe_opt_in;

    matches!(
        source.class,
        StorageIntentPolicySourceClass::InheritedDataset | StorageIntentPolicySourceClass::Dataset
    )
}

fn apply_evidence_state(
    flags: PrefetchResidencyPolicyFlags,
    state: PrefetchResidencyPolicyEvidenceState,
    refs: PrefetchResidencyDecisionEvidenceRefs,
    actions: &mut PrefetchResidencyActionMask,
) -> StorageIntentRefusalReason {
    let mut refusal = StorageIntentRefusalReason::None;

    if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_SERVICE_OBJECTIVE)
        && (!state.service_objective || !evidence_ref_has_id(refs.service_objective_ref))
    {
        *actions = mask_intersection(*actions, PrefetchResidencyActionMask::LOW_RISK_PREFETCH);
        refusal = StorageIntentRefusalReason::EvidenceNotUsable;
    }

    if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_EVIDENCE_QUERY)
        && (!state.evidence_query || !evidence_ref_has_id(refs.evidence_query_ref))
    {
        *actions = mask_intersection(*actions, PrefetchResidencyActionMask::LOW_RISK_PREFETCH);
        refusal = StorageIntentRefusalReason::EvidenceNotUsable;
    }

    if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_FRESH_MEDIA_CAPABILITY)
        && (!state.fresh_media_capability || !evidence_ref_has_id(refs.media_capability_ref))
    {
        *actions = mask_intersection(*actions, PrefetchResidencyActionMask::LOW_RISK_PREFETCH);
        refusal = StorageIntentRefusalReason::MissingMediaCapabilityEvidence;
    }

    if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_COST_WEAR_EVIDENCE)
        && (!state.cost_wear || !evidence_ref_has_id(refs.cost_wear_ref))
    {
        *actions = mask_without_flash_or_pmem(*actions);
        refusal = StorageIntentRefusalReason::FlashWearBudgetExceeded;
    }

    if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_EGRESS_RESTORE_EVIDENCE)
        && (!state.egress_restore_cost || !evidence_ref_has_id(refs.egress_restore_cost_ref))
    {
        *actions = mask_without_remote_archive(*actions);
        refusal = StorageIntentRefusalReason::EvidenceNotUsable;
    }

    if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_PAYBACK_FOR_MOVEMENT)
        && !state.payback
    {
        *actions = remove_authority_movement(*actions);
        refusal = StorageIntentRefusalReason::MovementDebtNotPaidBack;
    }

    if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_CAPACITY_RESERVE)
        && (!state.capacity_reserve || !evidence_ref_has_id(refs.capacity_reserve_ref))
    {
        *actions = remove_capacity_spending_actions(*actions);
        refusal = StorageIntentRefusalReason::EvidenceNotUsable;
    }

    if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_TENANT_ISOLATION)
        && (!state.tenant_isolation || !evidence_ref_has_id(refs.tenant_isolation_ref))
    {
        *actions = mask_intersection(*actions, PrefetchResidencyActionMask::LOW_RISK_PREFETCH);
        refusal = StorageIntentRefusalReason::WrongDomain;
    }

    if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_READ_SERVING_BOUNDARY)
        && (!state.read_serving_boundary || !evidence_ref_has_id(refs.read_serving_boundary_ref))
    {
        *actions = remove_authority_movement(*actions);
        refusal = StorageIntentRefusalReason::EvidenceNotUsable;
    }

    if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_RELOCATION_BOUNDARY_FOR_AUTHORITY)
        && (!state.relocation_boundary || !evidence_ref_has_id(refs.relocation_boundary_ref))
    {
        *actions = remove_authority_movement(*actions);
        refusal = StorageIntentRefusalReason::EvidenceNotUsable;
    }

    if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_SCHEDULER_ADMISSION)
        && (!state.scheduler_admission || !evidence_ref_has_id(refs.scheduler_admission_ref))
    {
        *actions = mask_intersection(*actions, PrefetchResidencyActionMask::LOW_RISK_PREFETCH);
        refusal = StorageIntentRefusalReason::EvidenceNotUsable;
    }

    if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_TRUST_DOMAIN)
        && (!state.trust_domain || !evidence_ref_has_id(refs.trust_domain_ref))
    {
        *actions = mask_without_remote_archive(*actions);
        refusal = StorageIntentRefusalReason::WrongDomain;
    }

    if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_TRANSPORT_BUDGET)
        && (!state.transport_budget || !evidence_ref_has_id(refs.transport_budget_ref))
    {
        *actions = mask_without_remote_archive(*actions);
        refusal = StorageIntentRefusalReason::EvidenceNotUsable;
    }

    refusal
}

fn infer_action_evidence_flags(
    actions: PrefetchResidencyActionMask,
) -> PrefetchResidencyPolicyFlags {
    let mut flags = PrefetchResidencyPolicyFlags::EMPTY;

    if mask_overlaps(actions, ACTIVE_PREFETCH_ACTIONS) {
        flags = flags
            .union(PrefetchResidencyPolicyFlags::REQUIRE_SERVICE_OBJECTIVE)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_EVIDENCE_QUERY)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_SCHEDULER_ADMISSION)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_TENANT_ISOLATION);
    }

    if mask_overlaps(actions, MEDIA_STAGING_ACTIONS) {
        flags = flags
            .union(PrefetchResidencyPolicyFlags::REQUIRE_FRESH_MEDIA_CAPABILITY)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_COST_WEAR_EVIDENCE)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_CAPACITY_RESERVE)
            .union(PrefetchResidencyPolicyFlags::PROTECT_FLASH_LIFETIME);
    }

    if mask_overlaps(actions, AUTHORITY_MOVEMENT_ACTIONS) {
        flags = flags.union(MOVEMENT_EVIDENCE_FLAGS);
    }

    if mask_overlaps(actions, REMOTE_OR_ARCHIVE_ACTIONS) {
        flags = flags
            .union(PrefetchResidencyPolicyFlags::REQUIRE_FRESH_MEDIA_CAPABILITY)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_EGRESS_RESTORE_EVIDENCE)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_TRANSPORT_BUDGET)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_TRUST_DOMAIN)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_CAPACITY_RESERVE);
    }

    flags
}

const ACTIVE_PREFETCH_ACTIONS: PrefetchResidencyActionMask = PrefetchResidencyActionMask::EMPTY
    .with(PrefetchResidencyCandidateClass::BoundedReadahead)
    .with(PrefetchResidencyCandidateClass::StridedVectorPrefetch)
    .with(PrefetchResidencyCandidateClass::MetadataNamespacePrefetch)
    .with(PrefetchResidencyCandidateClass::SmallRandomHotsetTrial)
    .with(PrefetchResidencyCandidateClass::ManifestIndexPrefetch)
    .with(PrefetchResidencyCandidateClass::SnapshotClonePrefetch)
    .with(PrefetchResidencyCandidateClass::DegradedReadPrefetch)
    .with(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch)
    .with(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage)
    .with(PrefetchResidencyCandidateClass::CacheOnlyTrial)
    .with(PrefetchResidencyCandidateClass::VolatileRamTrial)
    .with(PrefetchResidencyCandidateClass::IntentBackedRam)
    .with(PrefetchResidencyCandidateClass::PmemDurable)
    .with(PrefetchResidencyCandidateClass::FlashHotServing)
    .with(PrefetchResidencyCandidateClass::HddLocalityOptimized)
    .with(PrefetchResidencyCandidateClass::AuthorityPromotionCandidate)
    .with(PrefetchResidencyCandidateClass::DemotionCandidate);

const MEDIA_STAGING_ACTIONS: PrefetchResidencyActionMask = PrefetchResidencyActionMask::EMPTY
    .with(PrefetchResidencyCandidateClass::IntentBackedRam)
    .with(PrefetchResidencyCandidateClass::PmemDurable)
    .with(PrefetchResidencyCandidateClass::FlashHotServing)
    .with(PrefetchResidencyCandidateClass::AuthorityPromotionCandidate)
    .with(PrefetchResidencyCandidateClass::DemotionCandidate);

const AUTHORITY_MOVEMENT_ACTIONS: PrefetchResidencyActionMask = PrefetchResidencyActionMask::EMPTY
    .with(PrefetchResidencyCandidateClass::IntentBackedRam)
    .with(PrefetchResidencyCandidateClass::PmemDurable)
    .with(PrefetchResidencyCandidateClass::AuthorityPromotionCandidate)
    .with(PrefetchResidencyCandidateClass::DemotionCandidate);

const REMOTE_OR_ARCHIVE_ACTIONS: PrefetchResidencyActionMask = PrefetchResidencyActionMask::EMPTY
    .with(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch)
    .with(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage);

const fn mask_intersection(
    left: PrefetchResidencyActionMask,
    right: PrefetchResidencyActionMask,
) -> PrefetchResidencyActionMask {
    PrefetchResidencyActionMask(left.0 & right.0)
}

const fn mask_without(
    left: PrefetchResidencyActionMask,
    right: PrefetchResidencyActionMask,
) -> PrefetchResidencyActionMask {
    PrefetchResidencyActionMask(left.0 & !right.0)
}

const fn mask_overlaps(
    left: PrefetchResidencyActionMask,
    right: PrefetchResidencyActionMask,
) -> bool {
    (left.0 & right.0) != 0
}

const fn min_u64_nonzero(left: u64, right: u64) -> u64 {
    if left == 0 {
        right
    } else if right == 0 || left < right {
        left
    } else {
        right
    }
}

fn remove_volatile_or_hidden_unsafe(
    actions: PrefetchResidencyActionMask,
) -> PrefetchResidencyActionMask {
    mask_without(
        actions,
        PrefetchResidencyActionMask::from_candidate(
            PrefetchResidencyCandidateClass::VolatileRamTrial,
        ),
    )
}

fn actions_contain_volatile(actions: PrefetchResidencyActionMask) -> bool {
    actions.contains_candidate(PrefetchResidencyCandidateClass::VolatileRamTrial)
}

fn remove_authority_movement(actions: PrefetchResidencyActionMask) -> PrefetchResidencyActionMask {
    mask_without(
        actions,
        PrefetchResidencyActionMask::from_candidate(
            PrefetchResidencyCandidateClass::IntentBackedRam,
        )
        .with(PrefetchResidencyCandidateClass::PmemDurable)
        .with(PrefetchResidencyCandidateClass::AuthorityPromotionCandidate)
        .with(PrefetchResidencyCandidateClass::DemotionCandidate),
    )
}

fn mask_without_flash_or_pmem(actions: PrefetchResidencyActionMask) -> PrefetchResidencyActionMask {
    mask_without(
        remove_authority_movement(actions),
        PrefetchResidencyActionMask::from_candidate(
            PrefetchResidencyCandidateClass::FlashHotServing,
        ),
    )
}

fn remove_capacity_spending_actions(
    actions: PrefetchResidencyActionMask,
) -> PrefetchResidencyActionMask {
    mask_without(
        remove_authority_movement(actions),
        PrefetchResidencyActionMask::from_candidate(
            PrefetchResidencyCandidateClass::FlashHotServing,
        )
        .with(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch)
        .with(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage),
    )
}

fn mask_without_remote_archive(
    actions: PrefetchResidencyActionMask,
) -> PrefetchResidencyActionMask {
    mask_without(
        actions,
        PrefetchResidencyActionMask::from_candidate(
            PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch,
        )
        .with(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage),
    )
}

const fn prefetch_candidate_changes_authority_local(
    candidate: PrefetchResidencyCandidateClass,
) -> bool {
    matches!(
        candidate,
        PrefetchResidencyCandidateClass::IntentBackedRam
            | PrefetchResidencyCandidateClass::PmemDurable
            | PrefetchResidencyCandidateClass::AuthorityPromotionCandidate
            | PrefetchResidencyCandidateClass::DemotionCandidate
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_storage_intent_core::StorageIntentEvidenceId;

    const POLICY: StorageIntentPolicyId = StorageIntentPolicyId([1_u8; 16]);
    const POOL: StorageIntentDomainId = StorageIntentDomainId([2_u8; 16]);
    const DATASET_A: StorageIntentDomainId = StorageIntentDomainId([3_u8; 16]);
    const DATASET_B: StorageIntentDomainId = StorageIntentDomainId([4_u8; 16]);
    const BUDGET: StorageIntentDomainId = StorageIntentDomainId([5_u8; 16]);

    fn evidence(kind: StorageIntentEvidenceKind, byte: u8) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef {
            kind,
            id: StorageIntentEvidenceId([byte; 32]),
            generation: 7,
            version: 1,
        }
    }

    fn evidence_refs() -> PrefetchResidencyDecisionEvidenceRefs {
        PrefetchResidencyDecisionEvidenceRefs {
            compiled_policy_ref: evidence(StorageIntentEvidenceKind::PolicyRolloutEvidence, 1),
            service_objective_ref: evidence(StorageIntentEvidenceKind::ServiceObjectiveEvidence, 2),
            evidence_query_ref: evidence(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 3),
            decision_frontier_ref: evidence(StorageIntentEvidenceKind::DecisionFrontierEvidence, 4),
            media_capability_ref: evidence(StorageIntentEvidenceKind::MediaCapabilityEvidence, 15),
            scheduler_admission_ref: evidence(
                StorageIntentEvidenceKind::SchedulerAdmissionRecord,
                5,
            ),
            capacity_reserve_ref: evidence(StorageIntentEvidenceKind::CapacityAdmissionEvidence, 6),
            tenant_isolation_ref: evidence(StorageIntentEvidenceKind::TenantIsolationEvidence, 7),
            cost_wear_ref: evidence(StorageIntentEvidenceKind::MediaCostWearLedger, 8),
            egress_restore_cost_ref: evidence(StorageIntentEvidenceKind::TransportPathEvidence, 9),
            transport_budget_ref: evidence(StorageIntentEvidenceKind::TransportPathEvidence, 10),
            trust_domain_ref: evidence(StorageIntentEvidenceKind::TrustDomainEvidence, 11),
            read_serving_boundary_ref: evidence(
                StorageIntentEvidenceKind::ReadFreshnessEvidence,
                12,
            ),
            relocation_boundary_ref: evidence(StorageIntentEvidenceKind::RelocationReceipt, 13),
            result_refusal_ref: evidence(StorageIntentEvidenceKind::ResultRefusalEvidence, 14),
        }
    }

    fn all_evidence() -> PrefetchResidencyPolicyEvidenceState {
        PrefetchResidencyPolicyEvidenceState {
            service_objective: true,
            evidence_query: true,
            fresh_media_capability: true,
            cost_wear: true,
            egress_restore_cost: true,
            payback: true,
            capacity_reserve: true,
            tenant_isolation: true,
            read_serving_boundary: true,
            relocation_boundary: true,
            scheduler_admission: true,
            trust_domain: true,
            transport_budget: true,
        }
    }

    fn identity(dataset_id: StorageIntentDomainId, revision: u64) -> StorageIntentPolicyIdentity {
        StorageIntentPolicyIdentity {
            policy_id: POLICY,
            policy_revision: StorageIntentPolicyRevision(revision),
            pool_id: POOL,
            dataset_id,
            budget_owner: BUDGET,
        }
    }

    fn baseline_sources(dataset_id: StorageIntentDomainId) -> PrefetchResidencyPolicySources {
        PrefetchResidencyPolicySources {
            identity: identity(dataset_id, 1),
            pool_default: PrefetchResidencyPolicySource::new(
                StorageIntentPolicySourceClass::PoolDefault,
                PrefetchResidencyActionMask::ALL_DEFINED,
            ),
            dataset: PrefetchResidencyPolicySource::new(
                StorageIntentPolicySourceClass::Dataset,
                PrefetchResidencyActionMask::LOW_RISK_PREFETCH,
            )
            .requiring(PrefetchResidencyPolicyFlags::REQUIRE_READ_SERVING_BOUNDARY)
            .with_prefetch_window_limit(1 << 20)
            .with_staging_limit(8 << 20)
            .with_signal_floor(32, 5_000, 60_000),
            evidence_state: all_evidence(),
            evidence_refs: evidence_refs(),
            ..PrefetchResidencyPolicySources::default()
        }
    }

    #[test]
    fn dataset_policy_is_required_over_pool_default() {
        let result = compile_prefetch_residency_policy(PrefetchResidencyPolicySources {
            identity: identity(DATASET_A, 1),
            pool_default: PrefetchResidencyPolicySource::new(
                StorageIntentPolicySourceClass::PoolDefault,
                PrefetchResidencyActionMask::ALL_DEFINED,
            ),
            evidence_state: all_evidence(),
            evidence_refs: evidence_refs(),
            ..PrefetchResidencyPolicySources::default()
        });

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Refused);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(result
            .source_mask
            .contains(StorageIntentPolicySourceClass::PoolDefault));
    }

    #[test]
    fn same_pool_can_compile_different_dataset_media_policies() {
        let mut dataset_a = baseline_sources(DATASET_A);
        dataset_a.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH
                .with(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch)
                .with(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage)
                .with(PrefetchResidencyCandidateClass::HddLocalityOptimized),
        )
        .requiring(
            PrefetchResidencyPolicyFlags::REQUIRE_EGRESS_RESTORE_EVIDENCE
                .union(PrefetchResidencyPolicyFlags::REQUIRE_TRANSPORT_BUDGET)
                .union(PrefetchResidencyPolicyFlags::REQUIRE_TRUST_DOMAIN),
        );

        let mut dataset_b = baseline_sources(DATASET_B);
        dataset_b.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH,
        )
        .refusing(
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::FlashHotServing,
            )
            .with(PrefetchResidencyCandidateClass::AuthorityPromotionCandidate),
        );

        let compiled_a = compile_prefetch_residency_policy(dataset_a);
        let compiled_b = compile_prefetch_residency_policy(dataset_b);

        assert_eq!(
            compiled_a.status,
            StorageIntentPolicyCompileStatus::Compiled
        );
        assert!(compiled_a
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage));
        assert!(compiled_a
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::HddLocalityOptimized));
        assert_eq!(
            compiled_b.status,
            StorageIntentPolicyCompileStatus::Compiled
        );
        assert!(!compiled_b
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::FlashHotServing));
        assert_eq!(compiled_a.envelope.pool_id, compiled_b.envelope.pool_id);
        assert_ne!(
            compiled_a.envelope.dataset_id,
            compiled_b.envelope.dataset_id
        );
    }

    #[test]
    fn pool_default_is_not_a_pool_wide_hard_ceiling() {
        let mut sources = baseline_sources(DATASET_A);
        sources.pool_default = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::PoolDefault,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::NoPrefetch,
            ),
        );
        sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::HddLocalityOptimized,
            )
            .with(PrefetchResidencyCandidateClass::BoundedReadahead),
        )
        .requiring(PrefetchResidencyPolicyFlags::REQUIRE_READ_SERVING_BOUNDARY);

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Compiled);
        assert!(result
            .source_mask
            .contains(StorageIntentPolicySourceClass::PoolDefault));
        assert!(result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::HddLocalityOptimized));
        assert!(!result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::NoPrefetch));
    }

    #[test]
    fn pool_default_cannot_relax_stricter_dataset_policy() {
        let mut sources = baseline_sources(DATASET_A);
        sources.pool_default = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::PoolDefault,
            PrefetchResidencyActionMask::ALL_DEFINED,
        );
        sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::BoundedReadahead,
            )
            .with(PrefetchResidencyCandidateClass::NoPrefetch),
        );

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Compiled);
        assert!(result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::BoundedReadahead));
        assert!(!result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::FlashHotServing));
    }

    #[test]
    fn caller_hotness_hint_cannot_authorize_authority_movement() {
        let mut sources = baseline_sources(DATASET_A);
        sources.caller_hints = CallerHintSource {
            present: true,
            hotness_hint: true,
            lifetime_hint: false,
            cache_bypass_hint: false,
            requested_candidate: PrefetchResidencyCandidateClass::AuthorityPromotionCandidate,
        };

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Lowered);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(!result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::AuthorityPromotionCandidate));
        assert!(result
            .source_mask
            .contains(StorageIntentPolicySourceClass::CallerHints));
    }

    #[test]
    fn volatile_mode_requires_explicit_operator_opt_in() {
        let mut sources = baseline_sources(DATASET_A);
        sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::VolatileRamTrial,
            ),
        );

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Refused);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::MissingAuthorization
        );
        assert!(!result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::VolatileRamTrial));
    }

    #[test]
    fn explicit_unsafe_opt_in_is_visible_when_volatile_mode_remains() {
        let mut sources = baseline_sources(DATASET_A);
        sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::VolatileRamTrial,
            )
            .with(PrefetchResidencyCandidateClass::NoPrefetch),
        )
        .with_explicit_unsafe_opt_in();

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(
            result.status,
            StorageIntentPolicyCompileStatus::UnsafeVisible
        );
        assert!(result.explicit_unsafe_opt_in);
        assert!(result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::VolatileRamTrial));
    }

    #[test]
    fn durable_caller_flags_refuse_hidden_volatile_mode() {
        let mut sources = baseline_sources(DATASET_A);
        sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::VolatileRamTrial,
            )
            .with(PrefetchResidencyCandidateClass::NoPrefetch),
        )
        .with_explicit_unsafe_opt_in();
        sources.caller_flags = CallerRequestFlags {
            sync: true,
            ..CallerRequestFlags::default()
        };

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Lowered);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::VolatileRamCannotSatisfyDurableIntent
        );
        assert!(!result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::VolatileRamTrial));
    }

    #[test]
    fn direct_io_flag_disables_cache_warming_actions() {
        let mut sources = baseline_sources(DATASET_A);
        sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH
                .with(PrefetchResidencyCandidateClass::CacheOnlyTrial)
                .with(PrefetchResidencyCandidateClass::FlashHotServing),
        );
        sources.caller_flags = CallerRequestFlags {
            direct: true,
            ..CallerRequestFlags::default()
        };

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Lowered);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(result
            .source_mask
            .contains(StorageIntentPolicySourceClass::CallerFlags));
        assert_eq!(
            result.envelope.allowed_actions,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::NoPrefetch
            )
            .with(PrefetchResidencyCandidateClass::Refused)
        );
    }

    #[test]
    fn dataset_policy_admits_flash_serving_with_fresh_wear_evidence() {
        let mut sources = baseline_sources(DATASET_A);
        sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH
                .with(PrefetchResidencyCandidateClass::FlashHotServing),
        )
        .requiring(
            PrefetchResidencyPolicyFlags::REQUIRE_COST_WEAR_EVIDENCE
                .union(PrefetchResidencyPolicyFlags::REQUIRE_FRESH_MEDIA_CAPABILITY)
                .union(PrefetchResidencyPolicyFlags::REQUIRE_READ_SERVING_BOUNDARY),
        );

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Compiled);
        assert_eq!(result.refusal, StorageIntentRefusalReason::None);
        assert!(result
            .envelope
            .flags
            .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_COST_WEAR_EVIDENCE));
        assert!(result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::FlashHotServing));
    }

    #[test]
    fn flash_serving_infers_media_evidence_floors() {
        let mut sources = baseline_sources(DATASET_A);
        sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::FlashHotServing,
            ),
        );

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Compiled);
        assert!(result
            .envelope
            .flags
            .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_COST_WEAR_EVIDENCE));
        assert!(result
            .envelope
            .flags
            .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_FRESH_MEDIA_CAPABILITY));
        assert!(result
            .envelope
            .flags
            .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_CAPACITY_RESERVE));
        assert!(result
            .envelope
            .flags
            .contains_all(PrefetchResidencyPolicyFlags::PROTECT_FLASH_LIFETIME));
    }

    #[test]
    fn missing_media_capability_ref_lowers_media_actions() {
        let mut sources = baseline_sources(DATASET_A);
        sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::FlashHotServing,
            ),
        );
        sources.evidence_refs.media_capability_ref = StorageIntentEvidenceRef::default();

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Lowered);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence
        );
        assert!(!result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::FlashHotServing));
        assert!(result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::NeedMoreEvidence));
    }

    #[test]
    fn missing_wear_lowers_flash_even_without_source_flag() {
        let mut sources = baseline_sources(DATASET_A);
        sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::FlashHotServing,
            ),
        );
        sources.evidence_state.cost_wear = false;
        sources.evidence_refs.cost_wear_ref = StorageIntentEvidenceRef::default();

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Lowered);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::FlashWearBudgetExceeded
        );
        assert!(!result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::FlashHotServing));
        assert!(result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::NeedMoreEvidence));
    }

    #[test]
    fn wan_and_archive_actions_infer_remote_cost_floors() {
        let mut sources = baseline_sources(DATASET_A);
        sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch,
            )
            .with(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage),
        );

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Compiled);
        assert!(result
            .envelope
            .flags
            .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_EGRESS_RESTORE_EVIDENCE));
        assert!(result
            .envelope
            .flags
            .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_TRANSPORT_BUDGET));
        assert!(result
            .envelope
            .flags
            .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_TRUST_DOMAIN));
        assert!(result
            .envelope
            .flags
            .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_CAPACITY_RESERVE));
    }

    #[test]
    fn missing_egress_cost_lowers_remote_staging_without_source_flag() {
        let mut sources = baseline_sources(DATASET_A);
        sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch,
            )
            .with(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage),
        );
        sources.evidence_state.egress_restore_cost = false;
        sources.evidence_refs.egress_restore_cost_ref = StorageIntentEvidenceRef::default();

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Lowered);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(!result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch));
        assert!(!result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage));
        assert!(result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::NeedMoreEvidence));
    }

    #[test]
    fn missing_wear_or_freshness_lowers_flash_and_movement() {
        let mut sources = baseline_sources(DATASET_A);
        sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH
                .with(PrefetchResidencyCandidateClass::FlashHotServing)
                .with(PrefetchResidencyCandidateClass::AuthorityPromotionCandidate),
        )
        .requiring(
            PrefetchResidencyPolicyFlags::REQUIRE_COST_WEAR_EVIDENCE
                .union(PrefetchResidencyPolicyFlags::REQUIRE_FRESH_MEDIA_CAPABILITY)
                .union(PrefetchResidencyPolicyFlags::REQUIRE_RELOCATION_BOUNDARY_FOR_AUTHORITY),
        );
        sources.evidence_state.cost_wear = false;
        sources.evidence_refs.cost_wear_ref = StorageIntentEvidenceRef::default();

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Lowered);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::FlashWearBudgetExceeded
        );
        assert!(!result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::FlashHotServing));
        assert!(!result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::AuthorityPromotionCandidate));
    }

    #[test]
    fn subject_range_override_requires_dataset_permission() {
        let mut sources = baseline_sources(DATASET_A);
        sources.subject_range_override = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::SubjectRangeOverride,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::FlashHotServing,
            ),
        );

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Lowered);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::MissingAuthorization
        );
        assert_eq!(
            result.envelope.policy_scope,
            PrefetchResidencyPolicyScope::Dataset
        );
        assert!(!result.subject_range_override_admitted);
    }

    #[test]
    fn policy_revision_is_preserved_for_in_flight_attribution() {
        let old = compile_prefetch_residency_policy(baseline_sources(DATASET_A));
        let mut newer_sources = baseline_sources(DATASET_A);
        newer_sources.identity = identity(DATASET_A, 2);
        newer_sources.dataset = newer_sources.dataset.with_prefetch_window_limit(128 * 1024);
        let new = compile_prefetch_residency_policy(newer_sources);

        assert_eq!(old.envelope.policy_revision, StorageIntentPolicyRevision(1));
        assert_eq!(new.envelope.policy_revision, StorageIntentPolicyRevision(2));
        assert_eq!(old.envelope.max_prefetch_window_bytes, 1 << 20);
        assert_eq!(new.envelope.max_prefetch_window_bytes, 128 * 1024);
    }
}
