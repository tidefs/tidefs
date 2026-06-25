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

/// Bounded source provenance fan-in for one compiled policy snapshot.
pub const STORAGE_INTENT_POLICY_SOURCE_TRACE_REFS: usize = 10;

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

/// Persisted source revision evidence preserved in a compiled snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StorageIntentPolicySourceStamp {
    pub class: StorageIntentPolicySourceClass,
    pub revision: u64,
    pub generation: u64,
    pub epoch: u64,
    pub evidence_ref: StorageIntentEvidenceRef,
}

impl StorageIntentPolicySourceStamp {
    /// Empty provenance stamp.
    pub const EMPTY: Self = Self {
        class: StorageIntentPolicySourceClass::Absent,
        revision: 0,
        generation: 0,
        epoch: 0,
        evidence_ref: StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: tidefs_storage_intent_core::StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        },
    };

    /// Returns true when the stamp names a real source class.
    #[must_use]
    pub const fn is_present(self) -> bool {
        !matches!(self.class, StorageIntentPolicySourceClass::Absent)
    }
}

/// Errors while constructing a bounded source trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum StorageIntentPolicySourceTraceError {
    /// The trace is full.
    Full,
    /// The stamp does not name a source class.
    AbsentClass,
}

/// Bounded provenance list for sources that participated in compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageIntentPolicySourceTrace {
    len: u8,
    stamps: [StorageIntentPolicySourceStamp; STORAGE_INTENT_POLICY_SOURCE_TRACE_REFS],
}

impl StorageIntentPolicySourceTrace {
    /// Empty source trace.
    pub const EMPTY: Self = Self {
        len: 0,
        stamps: [StorageIntentPolicySourceStamp::EMPTY; STORAGE_INTENT_POLICY_SOURCE_TRACE_REFS],
    };

    /// Number of source stamps present.
    #[must_use]
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Returns true when the trace is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Return the backing array and valid length.
    #[must_use]
    pub const fn as_parts(
        &self,
    ) -> (
        &[StorageIntentPolicySourceStamp; STORAGE_INTENT_POLICY_SOURCE_TRACE_REFS],
        u8,
    ) {
        (&self.stamps, self.len)
    }

    /// Append one source stamp.
    pub fn push(
        &mut self,
        stamp: StorageIntentPolicySourceStamp,
    ) -> Result<(), StorageIntentPolicySourceTraceError> {
        if !stamp.is_present() {
            return Err(StorageIntentPolicySourceTraceError::AbsentClass);
        }
        if self.len as usize >= STORAGE_INTENT_POLICY_SOURCE_TRACE_REFS {
            return Err(StorageIntentPolicySourceTraceError::Full);
        }

        self.stamps[self.len as usize] = stamp;
        self.len += 1;
        Ok(())
    }

    /// Returns true when a source class is present in the trace.
    #[must_use]
    pub const fn contains_class(self, class: StorageIntentPolicySourceClass) -> bool {
        let mut index = 0;
        while index < self.len as usize {
            if self.stamps[index].class as u8 == class as u8 {
                return true;
            }
            index += 1;
        }
        false
    }

    /// Return the stamp for a source class, if present.
    #[must_use]
    pub fn stamp_for_class(
        self,
        class: StorageIntentPolicySourceClass,
    ) -> Option<StorageIntentPolicySourceStamp> {
        let mut index = 0;
        while index < self.len as usize {
            if self.stamps[index].class as u8 == class as u8 {
                return Some(self.stamps[index]);
            }
            index += 1;
        }
        None
    }

    /// Highest source epoch carried by the trace.
    #[must_use]
    pub const fn max_epoch(self) -> u64 {
        let mut max_epoch = 0_u64;
        let mut index = 0;
        while index < self.len as usize {
            if self.stamps[index].epoch > max_epoch {
                max_epoch = self.stamps[index].epoch;
            }
            index += 1;
        }
        max_epoch
    }
}

impl Default for StorageIntentPolicySourceTrace {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// One typed prefetch/residency policy source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrefetchResidencyPolicySource {
    pub class: StorageIntentPolicySourceClass,
    pub present: bool,
    pub source_revision: u64,
    pub source_generation: u64,
    pub source_epoch: u64,
    pub source_ref: StorageIntentEvidenceRef,
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
        source_generation: 0,
        source_epoch: 0,
        source_ref: StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: tidefs_storage_intent_core::StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        },
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
            source_generation: 0,
            source_epoch: 0,
            source_ref: StorageIntentEvidenceRef {
                kind: StorageIntentEvidenceKind::Unknown,
                id: tidefs_storage_intent_core::StorageIntentEvidenceId::ZERO,
                generation: 0,
                version: 0,
            },
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

    /// Attach persisted source revision, generation, epoch, and evidence ref.
    #[must_use]
    pub const fn with_source_stamp(
        mut self,
        revision: u64,
        generation: u64,
        epoch: u64,
        evidence_ref: StorageIntentEvidenceRef,
    ) -> Self {
        self.source_revision = revision;
        self.source_generation = generation;
        self.source_epoch = epoch;
        self.source_ref = evidence_ref;
        self
    }

    /// Convert this source into a trace stamp.
    #[must_use]
    pub const fn source_stamp(self) -> StorageIntentPolicySourceStamp {
        StorageIntentPolicySourceStamp {
            class: self.class,
            revision: self.source_revision,
            generation: self.source_generation,
            epoch: self.source_epoch,
            evidence_ref: self.source_ref,
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

// ---------------------------------------------------------------------------
// Dataset policy config — persistence and inheritance storage
// ---------------------------------------------------------------------------

/// Per-dataset policy configuration entry stored in the dataset property set.
///
/// Every field is optional (`None` means "inherit from parent"). When
/// [`resolve_effective_dataset_policy`] walks the parent chain, it fills
/// unset fields from the resolved parent, and ultimately from pool defaults.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DatasetPrefetchResidencyPolicyConfig {
    /// Dataset-local prefetch/residency source. `None` means inherit.
    pub dataset: Option<PrefetchResidencyPolicySource>,
    /// Mount profile. `None` means inherit.
    pub mount_profile: Option<PrefetchResidencyPolicySource>,
    /// Product profile. `None` means inherit.
    pub product_profile: Option<PrefetchResidencyPolicySource>,
    /// Whether per-file/per-range overrides are admitted.
    /// `None` means inherit.
    pub admits_subject_range_overrides: Option<bool>,
    /// Explicit unsafe/volatile opt-in. `None` means inherit.
    pub explicit_unsafe_opt_in: Option<bool>,
    /// Default caller request flags for operations. `None` means inherit.
    pub default_caller_flags: Option<CallerRequestFlags>,
    /// Default caller hints. `None` means inherit.
    pub default_caller_hints: Option<CallerHintSource>,
    /// Default internal maintenance intent. `None` means inherit.
    pub default_maintenance_intent: Option<InternalMaintenanceIntent>,
    /// Per-dataset prefetch window cap in bytes. `None` means inherit;
    /// `Some(0)` means no cap is set locally.
    pub prefetch_window_limit: Option<u64>,
    /// Per-dataset staging cap in bytes. `None` means inherit;
    /// `Some(0)` means no cap is set locally.
    pub staging_limit: Option<u64>,
    /// Per-dataset signal mass/decay floors. `None` means inherit.
    pub min_sample_mass: Option<u32>,
    pub min_observation_window_ms: Option<u64>,
    pub max_decay_age_ms: Option<u64>,
    /// Per-dataset dwell/cooldown floors in ms. `None` means inherit.
    pub dwell_min_ms: Option<u64>,
    pub cooldown_ms: Option<u64>,
    /// Monotonic revision of this config entry.
    pub revision: u64,
    /// Generation number for epoch tracking.
    pub generation: u64,
    /// Epoch for in-flight operation attribution.
    pub epoch: u64,
}

impl DatasetPrefetchResidencyPolicyConfig {
    /// Empty config with no local overrides.
    pub const EMPTY: Self = Self {
        dataset: None,
        mount_profile: None,
        product_profile: None,
        admits_subject_range_overrides: None,
        explicit_unsafe_opt_in: None,
        default_caller_flags: None,
        default_caller_hints: None,
        default_maintenance_intent: None,
        prefetch_window_limit: None,
        staging_limit: None,
        min_sample_mass: None,
        min_observation_window_ms: None,
        max_decay_age_ms: None,
        dwell_min_ms: None,
        cooldown_ms: None,
        revision: 0,
        generation: 0,
        epoch: 0,
    };
}

/// Pool-wide prefetch/residency policy defaults — the root of inheritance.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PoolPrefetchResidencyPolicyDefaults {
    /// Pool-level default source.
    pub pool_default: PrefetchResidencyPolicySource,
    /// Pool-level prefetch window cap, or 0 for unlimited.
    pub prefetch_window_limit: u64,
    /// Pool-level staging cap, or 0 for unlimited.
    pub staging_limit: u64,
    /// Pool-level signal floors.
    pub min_sample_mass: u32,
    pub min_observation_window_ms: u64,
    pub max_decay_age_ms: u64,
    /// Pool-level dwell/cooldown floors.
    pub dwell_min_ms: u64,
    pub cooldown_ms: u64,
    /// Monotonic revision of pool defaults.
    pub revision: u64,
    pub generation: u64,
    pub epoch: u64,
}

impl PoolPrefetchResidencyPolicyDefaults {
    /// Pool defaults with only the low-risk action mask.
    pub const fn minimal() -> Self {
        Self {
            pool_default: PrefetchResidencyPolicySource::new(
                StorageIntentPolicySourceClass::PoolDefault,
                PrefetchResidencyActionMask::LOW_RISK_PREFETCH,
            ),
            prefetch_window_limit: 0,
            staging_limit: 0,
            min_sample_mass: 0,
            min_observation_window_ms: 0,
            max_decay_age_ms: 0,
            dwell_min_ms: 0,
            cooldown_ms: 0,
            revision: 0,
            generation: 0,
            epoch: 0,
        }
    }
}

/// Walk the dataset inheritance chain to resolve the effective policy.
///
/// Resolution order:
/// 1. Pool defaults form the root.
/// 2. Inherited (parent) config overrides pool defaults where set.
/// 3. Local (child) config overrides inherited where set.
///
/// A `PrefetchResidencyPolicySource` field that has `present == false`
/// (default-constructed) is treated as unset, regardless of the `Option`
/// wrapper — the caller should only wrap a source whose `present` is true.
#[must_use]
pub fn resolve_effective_dataset_policy(
    local: &DatasetPrefetchResidencyPolicyConfig,
    inherited: Option<&DatasetPrefetchResidencyPolicyConfig>,
    pool_defaults: &PoolPrefetchResidencyPolicyDefaults,
) -> DatasetPrefetchResidencyPolicyConfig {
    let mut resolved = DatasetPrefetchResidencyPolicyConfig::EMPTY;

    // Layer 1: pool defaults
    resolved.dataset = Some(pool_defaults.pool_default);
    resolved.prefetch_window_limit = maybe(pool_defaults.prefetch_window_limit);
    resolved.staging_limit = maybe(pool_defaults.staging_limit);
    resolved.min_sample_mass = maybe(pool_defaults.min_sample_mass);
    resolved.min_observation_window_ms = maybe(pool_defaults.min_observation_window_ms);
    resolved.max_decay_age_ms = maybe(pool_defaults.max_decay_age_ms);
    resolved.dwell_min_ms = maybe(pool_defaults.dwell_min_ms);
    resolved.cooldown_ms = maybe(pool_defaults.cooldown_ms);
    resolved.revision = pool_defaults.revision;
    resolved.generation = pool_defaults.generation;
    resolved.epoch = pool_defaults.epoch;

    // Layer 2: inherited parent overrides
    if let Some(parent) = inherited {
        override_if_set(&mut resolved.dataset, &parent.dataset);
        override_if_set(&mut resolved.mount_profile, &parent.mount_profile);
        override_if_set(&mut resolved.product_profile, &parent.product_profile);
        override_if_set(&mut resolved.admits_subject_range_overrides, &parent.admits_subject_range_overrides);
        override_if_set(&mut resolved.explicit_unsafe_opt_in, &parent.explicit_unsafe_opt_in);
        override_if_set(&mut resolved.default_caller_flags, &parent.default_caller_flags);
        override_if_set(&mut resolved.default_caller_hints, &parent.default_caller_hints);
        override_if_set(
            &mut resolved.default_maintenance_intent,
            &parent.default_maintenance_intent,
        );
        override_if_set(&mut resolved.prefetch_window_limit, &parent.prefetch_window_limit);
        override_if_set(&mut resolved.staging_limit, &parent.staging_limit);
        override_if_set(&mut resolved.min_sample_mass, &parent.min_sample_mass);
        override_if_set(&mut resolved.min_observation_window_ms, &parent.min_observation_window_ms);
        override_if_set(&mut resolved.max_decay_age_ms, &parent.max_decay_age_ms);
        override_if_set(&mut resolved.dwell_min_ms, &parent.dwell_min_ms);
        override_if_set(&mut resolved.cooldown_ms, &parent.cooldown_ms);
        resolved.revision = parent.revision.max(resolved.revision);
        resolved.generation = parent.generation.max(resolved.generation);
        resolved.epoch = parent.epoch.max(resolved.epoch);
    }

    // Layer 3: local overrides
    override_if_set(&mut resolved.dataset, &local.dataset);
    override_if_set(&mut resolved.mount_profile, &local.mount_profile);
    override_if_set(&mut resolved.product_profile, &local.product_profile);
    override_if_set(&mut resolved.admits_subject_range_overrides, &local.admits_subject_range_overrides);
    override_if_set(&mut resolved.explicit_unsafe_opt_in, &local.explicit_unsafe_opt_in);
    override_if_set(&mut resolved.default_caller_flags, &local.default_caller_flags);
    override_if_set(&mut resolved.default_caller_hints, &local.default_caller_hints);
    override_if_set(
        &mut resolved.default_maintenance_intent,
        &local.default_maintenance_intent,
    );
    override_if_set(&mut resolved.prefetch_window_limit, &local.prefetch_window_limit);
    override_if_set(&mut resolved.staging_limit, &local.staging_limit);
    override_if_set(&mut resolved.min_sample_mass, &local.min_sample_mass);
    override_if_set(&mut resolved.min_observation_window_ms, &local.min_observation_window_ms);
    override_if_set(&mut resolved.max_decay_age_ms, &local.max_decay_age_ms);
    override_if_set(&mut resolved.dwell_min_ms, &local.dwell_min_ms);
    override_if_set(&mut resolved.cooldown_ms, &local.cooldown_ms);
    resolved.revision = local.revision.max(resolved.revision);
    resolved.generation = local.generation.max(resolved.generation);
    resolved.epoch = local.epoch.max(resolved.epoch);

    resolved
}

/// Convert a resolved effective dataset policy config into compiler input.
#[must_use]
pub fn config_to_prefetch_residency_sources(
    config: &DatasetPrefetchResidencyPolicyConfig,
    identity: StorageIntentPolicyIdentity,
    evidence_state: PrefetchResidencyPolicyEvidenceState,
    evidence_refs: PrefetchResidencyDecisionEvidenceRefs,
    caller_flags: Option<CallerRequestFlags>,
    caller_hints: Option<CallerHintSource>,
    internal_maintenance: Option<InternalMaintenanceIntent>,
    subject_range_override: Option<PrefetchResidencyPolicySource>,
) -> PrefetchResidencyPolicySources {
    let dataset = materialize_dataset_source(config);

    PrefetchResidencyPolicySources {
        identity,
        pool_default: dataset,
        inherited_dataset: PrefetchResidencyPolicySource::ABSENT,
        dataset,
        mount_profile: config
            .mount_profile
            .unwrap_or(PrefetchResidencyPolicySource::ABSENT),
        product_profile: config
            .product_profile
            .unwrap_or(PrefetchResidencyPolicySource::ABSENT),
        subject_range_override: subject_range_override
            .unwrap_or(PrefetchResidencyPolicySource::ABSENT),
        caller_flags: caller_flags
            .or(config.default_caller_flags)
            .unwrap_or_default(),
        caller_hints: caller_hints
            .or(config.default_caller_hints)
            .unwrap_or_default(),
        internal_maintenance: internal_maintenance
            .or(config.default_maintenance_intent)
            .unwrap_or_default(),
        evidence_state,
        evidence_refs,
    }
}

fn materialize_dataset_source(
    config: &DatasetPrefetchResidencyPolicyConfig,
) -> PrefetchResidencyPolicySource {
    let mut source = config
        .dataset
        .unwrap_or(PrefetchResidencyPolicySource::ABSENT);

    if !source.present {
        return source;
    }

    if let Some(admit) = config.admits_subject_range_overrides {
        source.admits_subject_range_overrides = admit;
    }
    if let Some(opt_in) = config.explicit_unsafe_opt_in {
        source.explicit_unsafe_opt_in = opt_in;
    }
    if let Some(bytes) = config.prefetch_window_limit {
        source.has_prefetch_window_limit = bytes != 0;
        source.max_prefetch_window_bytes = bytes;
    }
    if let Some(bytes) = config.staging_limit {
        source.has_staging_limit = bytes != 0;
        source.max_staging_bytes = bytes;
    }
    if let Some(sample_mass) = config.min_sample_mass {
        source.min_sample_mass = sample_mass;
    }
    if let Some(window_ms) = config.min_observation_window_ms {
        source.min_observation_window_ms = window_ms;
    }
    if let Some(decay_ms) = config.max_decay_age_ms {
        source.max_decay_age_ms = decay_ms;
    }
    if let Some(dwell_ms) = config.dwell_min_ms {
        source.dwell_min_ms = dwell_ms;
    }
    if let Some(cooldown_ms) = config.cooldown_ms {
        source.cooldown_ms = cooldown_ms;
    }

    source
}

fn maybe<T: Copy>(v: T) -> Option<T> {
    Some(v)
}

fn override_if_set<T: Copy>(target: &mut Option<T>, source: &Option<T>) {
    if let Some(v) = source {
        *target = Some(*v);
    }
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
    pub source_trace: StorageIntentPolicySourceTrace,
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
            source_trace: StorageIntentPolicySourceTrace::EMPTY,
            refusal: StorageIntentRefusalReason::EvidenceNotUsable,
            explicit_unsafe_opt_in: false,
            subject_range_override_admitted: false,
        }
    }
}

/// Rollout class for replacing one compiled policy snapshot with another.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(u8)]
pub enum StorageIntentPolicyChangeClass {
    /// The snapshots are byte-for-byte equal.
    #[default]
    Unchanged = 0,
    /// Only the compiled revision changed.
    EquivalentRevision = 1,
    /// The new snapshot is stricter or removes optional actions.
    Tightening = 2,
    /// The new snapshot relaxes caps, floors, flags, or action admission.
    Relaxing = 3,
    /// The new snapshot admits authority/remote movement that must converge.
    ConvergenceRequired = 4,
    /// The new snapshot enables weaker volatile/unsafe behavior.
    UnsafeDowngrade = 5,
    /// Budget ownership changes and must be operator-visible.
    BudgetOwnerChange = 6,
    /// Snapshots do not describe the same dataset policy lineage.
    Incompatible = 7,
}

/// Rollout requirements produced by policy change classification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct StorageIntentPolicyRolloutRequirements(pub u32);

impl StorageIntentPolicyRolloutRequirements {
    /// No special rollout requirement.
    pub const EMPTY: Self = Self(0);
    /// Named operator consent is required.
    pub const OPERATOR_CONSENT: Self = Self(1_u32 << 0);
    /// Apply to new writes only until other evidence says otherwise.
    pub const NEW_WRITES_ONLY: Self = Self(1_u32 << 1);
    /// Relocation/convergence evidence is required before satisfaction.
    pub const CONVERGENCE_REQUIRED: Self = Self(1_u32 << 2);
    /// Policy rollout evidence is required for the revision transition.
    pub const ROLLOUT_EVIDENCE: Self = Self(1_u32 << 3);
    /// Any weaker result must stay receipt-visible.
    pub const RECEIPT_VISIBLE_DEGRADATION: Self = Self(1_u32 << 4);

    /// Merge two requirement sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true when all requested flags are present.
    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }
}

/// Evidence available when classifying a policy rollout.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StorageIntentPolicyRolloutEvidence {
    pub operator_consent: bool,
    pub rollout_evidence: bool,
    pub convergence_evidence: bool,
    pub operator_consent_ref: StorageIntentEvidenceRef,
    pub rollout_ref: StorageIntentEvidenceRef,
    pub convergence_ref: StorageIntentEvidenceRef,
}

/// Result of classifying a policy revision transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageIntentPolicyChangeDecision {
    pub change_class: StorageIntentPolicyChangeClass,
    pub requirements: StorageIntentPolicyRolloutRequirements,
    pub refused: bool,
    pub refusal: StorageIntentRefusalReason,
}

impl StorageIntentPolicyChangeDecision {
    /// Build an accepted rollout classification.
    #[must_use]
    pub const fn accepted(
        change_class: StorageIntentPolicyChangeClass,
        requirements: StorageIntentPolicyRolloutRequirements,
    ) -> Self {
        Self {
            change_class,
            requirements,
            refused: false,
            refusal: StorageIntentRefusalReason::None,
        }
    }

    /// Build a refused rollout classification.
    #[must_use]
    pub const fn refused(
        change_class: StorageIntentPolicyChangeClass,
        requirements: StorageIntentPolicyRolloutRequirements,
        refusal: StorageIntentRefusalReason,
    ) -> Self {
        Self {
            change_class,
            requirements,
            refused: true,
            refusal,
        }
    }
}

impl Default for StorageIntentPolicyChangeDecision {
    fn default() -> Self {
        Self::refused(
            StorageIntentPolicyChangeClass::Incompatible,
            StorageIntentPolicyRolloutRequirements::EMPTY,
            StorageIntentRefusalReason::EvidenceNotUsable,
        )
    }
}

/// Classify how a compiled prefetch/residency policy revision may roll out.
#[must_use]
pub fn classify_prefetch_residency_policy_change(
    old: PrefetchResidencyPolicyEnvelope,
    new: PrefetchResidencyPolicyEnvelope,
    evidence: StorageIntentPolicyRolloutEvidence,
) -> StorageIntentPolicyChangeDecision {
    if old == new {
        return StorageIntentPolicyChangeDecision::accepted(
            StorageIntentPolicyChangeClass::Unchanged,
            StorageIntentPolicyRolloutRequirements::EMPTY,
        );
    }

    if !same_policy_lineage(old, new) {
        return StorageIntentPolicyChangeDecision::refused(
            StorageIntentPolicyChangeClass::Incompatible,
            StorageIntentPolicyRolloutRequirements::EMPTY,
            StorageIntentRefusalReason::WrongDomain,
        );
    }

    if new.policy_revision.0 <= old.policy_revision.0 {
        return StorageIntentPolicyChangeDecision::refused(
            StorageIntentPolicyChangeClass::Incompatible,
            StorageIntentPolicyRolloutRequirements::ROLLOUT_EVIDENCE,
            StorageIntentRefusalReason::ReceiptWouldWeaken,
        );
    }

    let mut change_class = if prefetch_envelopes_equivalent_except_revision(old, new) {
        StorageIntentPolicyChangeClass::EquivalentRevision
    } else {
        StorageIntentPolicyChangeClass::Tightening
    };
    let mut requirements = StorageIntentPolicyRolloutRequirements::ROLLOUT_EVIDENCE;

    if old.budget_owner != new.budget_owner {
        change_class = StorageIntentPolicyChangeClass::BudgetOwnerChange;
        requirements = requirements
            .union(StorageIntentPolicyRolloutRequirements::OPERATOR_CONSENT)
            .union(StorageIntentPolicyRolloutRequirements::NEW_WRITES_ONLY);
    } else if unsafe_or_volatile_added(old.allowed_actions, new.allowed_actions) {
        change_class = StorageIntentPolicyChangeClass::UnsafeDowngrade;
        requirements = requirements
            .union(StorageIntentPolicyRolloutRequirements::OPERATOR_CONSENT)
            .union(StorageIntentPolicyRolloutRequirements::NEW_WRITES_ONLY)
            .union(StorageIntentPolicyRolloutRequirements::RECEIPT_VISIBLE_DEGRADATION);
    } else if authority_or_remote_action_added(old.allowed_actions, new.allowed_actions) {
        change_class = StorageIntentPolicyChangeClass::ConvergenceRequired;
        requirements = requirements
            .union(StorageIntentPolicyRolloutRequirements::NEW_WRITES_ONLY)
            .union(StorageIntentPolicyRolloutRequirements::CONVERGENCE_REQUIRED);
    } else if prefetch_policy_relaxes(old, new) {
        change_class = StorageIntentPolicyChangeClass::Relaxing;
        requirements = requirements
            .union(StorageIntentPolicyRolloutRequirements::OPERATOR_CONSENT)
            .union(StorageIntentPolicyRolloutRequirements::NEW_WRITES_ONLY);
    } else if !prefetch_envelopes_equivalent_except_revision(old, new) {
        requirements = requirements.union(StorageIntentPolicyRolloutRequirements::NEW_WRITES_ONLY);
    }

    if requirements.contains_all(StorageIntentPolicyRolloutRequirements::OPERATOR_CONSENT)
        && (!evidence.operator_consent || !evidence_ref_has_id(evidence.operator_consent_ref))
    {
        return StorageIntentPolicyChangeDecision::refused(
            change_class,
            requirements,
            StorageIntentRefusalReason::MissingAuthorization,
        );
    }
    if requirements.contains_all(StorageIntentPolicyRolloutRequirements::ROLLOUT_EVIDENCE)
        && (!evidence.rollout_evidence || !evidence_ref_has_id(evidence.rollout_ref))
    {
        return StorageIntentPolicyChangeDecision::refused(
            change_class,
            requirements,
            StorageIntentRefusalReason::EvidenceNotUsable,
        );
    }
    if requirements.contains_all(StorageIntentPolicyRolloutRequirements::CONVERGENCE_REQUIRED)
        && (!evidence.convergence_evidence || !evidence_ref_has_id(evidence.convergence_ref))
    {
        return StorageIntentPolicyChangeDecision::refused(
            change_class,
            requirements,
            StorageIntentRefusalReason::MovementDebtNotPaidBack,
        );
    }

    StorageIntentPolicyChangeDecision::accepted(change_class, requirements)
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
    let mut source_trace = StorageIntentPolicySourceTrace::EMPTY;
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
        push_source_trace(&mut source_trace, sources.pool_default);
    }

    has_dataset_policy |= apply_source(
        sources.inherited_dataset,
        &mut source_mask,
        &mut source_trace,
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
        &mut source_trace,
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
        &mut source_trace,
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
        &mut source_trace,
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
                &mut source_trace,
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
            push_source_trace(&mut source_trace, sources.subject_range_override);
            actions = mask_intersection(actions, PrefetchResidencyActionMask::LOW_RISK_PREFETCH);
            result.status = StorageIntentPolicyCompileStatus::Lowered;
            result.refusal = StorageIntentRefusalReason::MissingAuthorization;
        }
    }

    if !has_dataset_policy {
        result.source_mask = source_mask;
        result.source_trace = source_trace;
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
        result.source_trace = source_trace;
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
    result.source_trace = source_trace;
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
    source_trace: &mut StorageIntentPolicySourceTrace,
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
    push_source_trace(source_trace, source);
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

fn push_source_trace(
    source_trace: &mut StorageIntentPolicySourceTrace,
    source: PrefetchResidencyPolicySource,
) {
    let _ = source_trace.push(source.source_stamp());
}

fn same_policy_lineage(
    old: PrefetchResidencyPolicyEnvelope,
    new: PrefetchResidencyPolicyEnvelope,
) -> bool {
    !policy_id_is_zero(old.policy_id)
        && old.policy_id == new.policy_id
        && !domain_id_is_zero(old.pool_id)
        && old.pool_id == new.pool_id
        && !domain_id_is_zero(old.dataset_id)
        && old.dataset_id == new.dataset_id
}

fn prefetch_envelopes_equivalent_except_revision(
    old: PrefetchResidencyPolicyEnvelope,
    new: PrefetchResidencyPolicyEnvelope,
) -> bool {
    old.policy_id == new.policy_id
        && old.policy_scope == new.policy_scope
        && old.pool_id == new.pool_id
        && old.dataset_id == new.dataset_id
        && old.budget_owner == new.budget_owner
        && old.allowed_actions == new.allowed_actions
        && old.flags == new.flags
        && old.max_prefetch_window_bytes == new.max_prefetch_window_bytes
        && old.max_staging_bytes == new.max_staging_bytes
        && old.min_sample_mass == new.min_sample_mass
        && old.min_observation_window_ms == new.min_observation_window_ms
        && old.max_decay_age_ms == new.max_decay_age_ms
        && old.dwell_min_ms == new.dwell_min_ms
        && old.cooldown_ms == new.cooldown_ms
        && old.evidence_refs == new.evidence_refs
}

fn unsafe_or_volatile_added(
    old_actions: PrefetchResidencyActionMask,
    new_actions: PrefetchResidencyActionMask,
) -> bool {
    let added = mask_without(new_actions, old_actions);
    added.contains_candidate(PrefetchResidencyCandidateClass::VolatileRamTrial)
}

fn authority_or_remote_action_added(
    old_actions: PrefetchResidencyActionMask,
    new_actions: PrefetchResidencyActionMask,
) -> bool {
    let added = mask_without(new_actions, old_actions);
    mask_overlaps(added, AUTHORITY_MOVEMENT_ACTIONS)
        || mask_overlaps(added, REMOTE_OR_ARCHIVE_ACTIONS)
}

fn prefetch_policy_relaxes(
    old: PrefetchResidencyPolicyEnvelope,
    new: PrefetchResidencyPolicyEnvelope,
) -> bool {
    let actions_added = (new.allowed_actions.0 & !old.allowed_actions.0) != 0;
    let actions_removed = (old.allowed_actions.0 & !new.allowed_actions.0) != 0;
    let flags_relaxed = (old.flags.0 & !new.flags.0) != 0;
    // Flag relaxation only overrides when actions are not also tightened.
    let net_flag_relax = !actions_removed && flags_relaxed;

    actions_added
        || net_flag_relax
        || max_ceiling_relaxed(old.max_prefetch_window_bytes, new.max_prefetch_window_bytes)
        || max_ceiling_relaxed(old.max_staging_bytes, new.max_staging_bytes)
        || max_ceiling_relaxed(old.max_decay_age_ms, new.max_decay_age_ms)
        || min_floor_relaxed(old.min_sample_mass, new.min_sample_mass)
        || min_floor_relaxed(old.min_observation_window_ms, new.min_observation_window_ms)
        || min_floor_relaxed(old.dwell_min_ms, new.dwell_min_ms)
        || min_floor_relaxed(old.cooldown_ms, new.cooldown_ms)
}

fn max_ceiling_relaxed(old: u64, new: u64) -> bool {
    old != 0 && (new == 0 || new > old)
}

fn min_floor_relaxed<T: Ord>(old: T, new: T) -> bool {
    new < old
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
            operator_policy_ref: evidence(StorageIntentEvidenceKind::PolicyRolloutEvidence, 16),
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

    fn rollout_evidence(
        operator_consent: bool,
        rollout: bool,
        convergence: bool,
    ) -> StorageIntentPolicyRolloutEvidence {
        StorageIntentPolicyRolloutEvidence {
            operator_consent,
            rollout_evidence: rollout,
            convergence_evidence: convergence,
            operator_consent_ref: if operator_consent {
                evidence(StorageIntentEvidenceKind::PolicyRolloutEvidence, 70)
            } else {
                StorageIntentEvidenceRef::default()
            },
            rollout_ref: if rollout {
                evidence(StorageIntentEvidenceKind::PolicyRolloutEvidence, 71)
            } else {
                StorageIntentEvidenceRef::default()
            },
            convergence_ref: if convergence {
                evidence(StorageIntentEvidenceKind::RecoveryDegradationEvidence, 72)
            } else {
                StorageIntentEvidenceRef::default()
            },
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

    #[test]
    fn source_trace_preserves_revision_generation_epoch_and_ref() {
        let mut sources = baseline_sources(DATASET_A);
        sources.pool_default = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::PoolDefault,
            PrefetchResidencyActionMask::ALL_DEFINED,
        )
        .with_source_stamp(
            10,
            20,
            30,
            evidence(StorageIntentEvidenceKind::PolicyRolloutEvidence, 73),
        );
        sources.dataset = sources.dataset.with_source_stamp(
            11,
            21,
            31,
            evidence(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 74),
        );
        sources.mount_profile = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::MountProfile,
            PrefetchResidencyActionMask::ALL_DEFINED,
        )
        .with_source_stamp(
            12,
            22,
            32,
            evidence(StorageIntentEvidenceKind::ServiceObjectiveEvidence, 75),
        );

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Compiled);
        assert_eq!(result.source_trace.len(), 3);
        assert!(result
            .source_trace
            .contains_class(StorageIntentPolicySourceClass::PoolDefault));
        assert!(result
            .source_trace
            .contains_class(StorageIntentPolicySourceClass::MountProfile));
        assert_eq!(result.source_trace.max_epoch(), 32);

        let dataset_stamp = result
            .source_trace
            .stamp_for_class(StorageIntentPolicySourceClass::Dataset)
            .unwrap();
        assert_eq!(dataset_stamp.revision, 11);
        assert_eq!(dataset_stamp.generation, 21);
        assert_eq!(dataset_stamp.epoch, 31);
        assert_eq!(
            dataset_stamp.evidence_ref,
            evidence(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 74)
        );
    }

    #[test]
    fn unsafe_rollout_requires_named_operator_consent() {
        let old = compile_prefetch_residency_policy(baseline_sources(DATASET_A)).envelope;
        let mut new_sources = baseline_sources(DATASET_A);
        new_sources.identity = identity(DATASET_A, 2);
        new_sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH
                .with(PrefetchResidencyCandidateClass::VolatileRamTrial),
        )
        .with_explicit_unsafe_opt_in();
        let new = compile_prefetch_residency_policy(new_sources).envelope;

        let refused = classify_prefetch_residency_policy_change(
            old,
            new,
            rollout_evidence(false, true, false),
        );

        assert_eq!(
            refused.change_class,
            StorageIntentPolicyChangeClass::UnsafeDowngrade
        );
        assert!(refused.refused);
        assert_eq!(
            refused.refusal,
            StorageIntentRefusalReason::MissingAuthorization
        );
        assert!(refused
            .requirements
            .contains_all(StorageIntentPolicyRolloutRequirements::OPERATOR_CONSENT));
        assert!(refused
            .requirements
            .contains_all(StorageIntentPolicyRolloutRequirements::RECEIPT_VISIBLE_DEGRADATION));

        let accepted = classify_prefetch_residency_policy_change(
            old,
            new,
            rollout_evidence(true, true, false),
        );
        assert!(!accepted.refused);
        assert_eq!(
            accepted.change_class,
            StorageIntentPolicyChangeClass::UnsafeDowngrade
        );
    }

    #[test]
    fn authority_expansion_requires_convergence_before_satisfied() {
        let old = compile_prefetch_residency_policy(baseline_sources(DATASET_A)).envelope;
        let mut new_sources = baseline_sources(DATASET_A);
        new_sources.identity = identity(DATASET_A, 2);
        new_sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH
                .with(PrefetchResidencyCandidateClass::AuthorityPromotionCandidate),
        );
        let new = compile_prefetch_residency_policy(new_sources).envelope;

        let refused = classify_prefetch_residency_policy_change(
            old,
            new,
            rollout_evidence(false, true, false),
        );

        assert_eq!(
            refused.change_class,
            StorageIntentPolicyChangeClass::ConvergenceRequired
        );
        assert!(refused.refused);
        assert_eq!(
            refused.refusal,
            StorageIntentRefusalReason::MovementDebtNotPaidBack
        );
        assert!(refused
            .requirements
            .contains_all(StorageIntentPolicyRolloutRequirements::CONVERGENCE_REQUIRED));

        let accepted = classify_prefetch_residency_policy_change(
            old,
            new,
            rollout_evidence(false, true, true),
        );
        assert!(!accepted.refused);
        assert_eq!(
            accepted.change_class,
            StorageIntentPolicyChangeClass::ConvergenceRequired
        );
    }

    #[test]
    fn tightening_rollout_applies_to_new_writes_without_operator_consent() {
        let old = compile_prefetch_residency_policy(baseline_sources(DATASET_A)).envelope;
        let mut new_sources = baseline_sources(DATASET_A);
        new_sources.identity = identity(DATASET_A, 2);
        new_sources.dataset = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::BoundedReadahead,
            ),
        )
        .requiring(PrefetchResidencyPolicyFlags::REQUIRE_READ_SERVING_BOUNDARY)
        .with_prefetch_window_limit(128 * 1024)
        .with_staging_limit(4 << 20)
        .with_signal_floor(64, 10_000, 30_000);
        let new = compile_prefetch_residency_policy(new_sources).envelope;

        let decision = classify_prefetch_residency_policy_change(
            old,
            new,
            rollout_evidence(false, true, false),
        );

        assert_eq!(
            decision.change_class,
            StorageIntentPolicyChangeClass::Tightening
        );
        assert!(!decision.refused);
        assert!(decision
            .requirements
            .contains_all(StorageIntentPolicyRolloutRequirements::NEW_WRITES_ONLY));
        assert!(!decision
            .requirements
            .contains_all(StorageIntentPolicyRolloutRequirements::OPERATOR_CONSENT));
    }

    #[test]
    fn pool_defaults_provide_base_values_for_inheritance() {
        let pool = PoolPrefetchResidencyPolicyDefaults::minimal();
        let local = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        let resolved = resolve_effective_dataset_policy(&local, None, &pool);

        assert!(resolved.dataset.is_some());
        let ds = resolved.dataset.unwrap();
        assert!(ds.present);
        assert_eq!(ds.class, StorageIntentPolicySourceClass::PoolDefault);
    }

    #[test]
    fn local_config_overrides_inherited_parent_config() {
        let pool = PoolPrefetchResidencyPolicyDefaults::minimal();

        let mut parent = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        parent.dataset = Some(PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::InheritedDataset,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH
                .with(PrefetchResidencyCandidateClass::BoundedReadahead),
        ));
        parent.prefetch_window_limit = Some(256 * 1024);
        parent.admits_subject_range_overrides = Some(false);

        let mut local = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        local.dataset = Some(PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH
                .with(PrefetchResidencyCandidateClass::BoundedReadahead)
                .with(PrefetchResidencyCandidateClass::StridedVectorPrefetch),
        ));
        local.prefetch_window_limit = Some(512 * 1024);
        local.admits_subject_range_overrides = Some(true);
        local.revision = 5;

        let resolved = resolve_effective_dataset_policy(&local, Some(&parent), &pool);

        // Local dataset source overrides inherited
        let ds = resolved.dataset.unwrap();
        assert_eq!(ds.class, StorageIntentPolicySourceClass::Dataset);
        assert!(ds
            .allowed_actions.contains_candidate(PrefetchResidencyCandidateClass::StridedVectorPrefetch));

        // Local limit overrides parent limit
        assert_eq!(resolved.prefetch_window_limit, Some(512 * 1024));

        // Local override for admits_subject_range_overrides
        assert_eq!(resolved.admits_subject_range_overrides, Some(true));

        // Revision should be the max of all layers
        assert_eq!(resolved.revision, 5);
    }

    #[test]
    fn inherited_parent_preserves_values_when_local_is_unset() {
        let pool = PoolPrefetchResidencyPolicyDefaults::minimal();

        let mut parent = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        parent.dataset = Some(PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::InheritedDataset,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH
                .with(PrefetchResidencyCandidateClass::FlashHotServing),
        ));
        parent.prefetch_window_limit = Some(1024 * 1024);
        parent.dwell_min_ms = Some(30_000);
        parent.revision = 3;

        let local = DatasetPrefetchResidencyPolicyConfig::EMPTY;

        let resolved = resolve_effective_dataset_policy(&local, Some(&parent), &pool);

        // Inherited values preserved when local has no override
        let ds = resolved.dataset.unwrap();
        assert!(ds
            .allowed_actions.contains_candidate(PrefetchResidencyCandidateClass::FlashHotServing));
        assert_eq!(resolved.prefetch_window_limit, Some(1024 * 1024));
        assert_eq!(resolved.dwell_min_ms, Some(30_000));
        assert_eq!(resolved.revision, 3);
    }

    #[test]
    fn pool_default_cannot_relax_dataset_policy_through_inheritance() {
        // Pool has only low-risk prefetch; parent dataset tightens to
        // readahead-only; child inherits the tightened policy.
        let mut pool = PoolPrefetchResidencyPolicyDefaults::minimal();
        pool.pool_default = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::PoolDefault,
            PrefetchResidencyActionMask::ALL_DEFINED,
        );

        let mut parent = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        parent.dataset = Some(PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::BoundedReadahead,
            ),
        ));
        parent.revision = 1;

        let local = DatasetPrefetchResidencyPolicyConfig::EMPTY;

        let resolved = resolve_effective_dataset_policy(&local, Some(&parent), &pool);

        // The dataset policy (via parent) restricts actions; pool doesn't widen
        let ds = resolved.dataset.unwrap();
        assert!(!ds
            .allowed_actions.contains_candidate(PrefetchResidencyCandidateClass::FlashHotServing));
        assert!(ds
            .allowed_actions.contains_candidate(PrefetchResidencyCandidateClass::BoundedReadahead));
    }

    #[test]
    fn multi_level_inheritance_chain_resolves_correctly() {
        let mut pool = PoolPrefetchResidencyPolicyDefaults::minimal();
        pool.pool_default = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::PoolDefault,
            PrefetchResidencyActionMask::ALL_DEFINED,
        );
        pool.prefetch_window_limit = 64 * 1024;
        pool.revision = 0;

        // grandparent: tightens to readahead, sets dwell
        let mut grandparent = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        grandparent.dataset = Some(PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::BoundedReadahead,
            ),
        ));
        grandparent.dwell_min_ms = Some(60_000);
        grandparent.revision = 1;

        // parent: adds stride prefetch, tightens window
        let mut parent = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        parent.dataset = Some(PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::BoundedReadahead,
            )
            .with(PrefetchResidencyCandidateClass::StridedVectorPrefetch),
        ));
        parent.prefetch_window_limit = Some(128 * 1024);
        parent.revision = 2;

        // child: adds flash serving, further tightens window
        let mut child = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        child.dataset = Some(PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::BoundedReadahead,
            )
            .with(PrefetchResidencyCandidateClass::StridedVectorPrefetch)
            .with(PrefetchResidencyCandidateClass::FlashHotServing),
        ));
        child.prefetch_window_limit = Some(256 * 1024);
        child.revision = 3;

        // Resolve grandparent first
        let resolved_gp = resolve_effective_dataset_policy(&grandparent, None, &pool);
        // Resolve parent inheriting from grandparent
        let resolved_p = resolve_effective_dataset_policy(&parent, Some(&resolved_gp), &pool);
        // Resolve child inheriting from parent
        let resolved_c = resolve_effective_dataset_policy(&child, Some(&resolved_p), &pool);

        let ds = resolved_c.dataset.unwrap();
        assert!(ds
            .allowed_actions.contains_candidate(PrefetchResidencyCandidateClass::BoundedReadahead));
        assert!(ds
            .allowed_actions.contains_candidate(PrefetchResidencyCandidateClass::StridedVectorPrefetch));
        assert!(ds
            .allowed_actions.contains_candidate(PrefetchResidencyCandidateClass::FlashHotServing));

        // Dwell comes from grandparent
        assert_eq!(resolved_c.dwell_min_ms, Some(60_000));
        // Window limit from child (most restrictive? no — child overrides, child's limit wins)
        assert_eq!(resolved_c.prefetch_window_limit, Some(256 * 1024));
        // Revision from child (max)
        assert_eq!(resolved_c.revision, 3);
    }

    #[test]
    fn explicit_unsafe_opt_in_preserved_through_inheritance() {
        let pool = PoolPrefetchResidencyPolicyDefaults::minimal();

        let mut parent = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        parent.dataset = Some(
            PrefetchResidencyPolicySource::new(
                StorageIntentPolicySourceClass::Dataset,
                PrefetchResidencyActionMask::LOW_RISK_PREFETCH
                    .with(PrefetchResidencyCandidateClass::VolatileRamTrial),
            )
            .with_explicit_unsafe_opt_in(),
        );
        parent.explicit_unsafe_opt_in = Some(true);

        let local = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        let resolved = resolve_effective_dataset_policy(&local, Some(&parent), &pool);

        // Unsafe opt-in preserved from parent
        assert_eq!(resolved.explicit_unsafe_opt_in, Some(true));
        let ds = resolved.dataset.unwrap();
        assert!(ds.explicit_unsafe_opt_in);
    }

    #[test]
    fn config_to_sources_produces_valid_compiler_input() {
        let pool = PoolPrefetchResidencyPolicyDefaults::minimal();
        let local = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        let resolved = resolve_effective_dataset_policy(&local, None, &pool);

        let identity = StorageIntentPolicyIdentity {
            policy_id: StorageIntentPolicyId([1u8; 16]),
            policy_revision: StorageIntentPolicyRevision(1),
            pool_id: StorageIntentDomainId([2u8; 16]),
            dataset_id: StorageIntentDomainId([3u8; 16]),
            budget_owner: StorageIntentDomainId([4u8; 16]),
        };

        let evidence_state = PrefetchResidencyPolicyEvidenceState::default();
        let evidence_refs = PrefetchResidencyDecisionEvidenceRefs::default();

        let sources = config_to_prefetch_residency_sources(
            &resolved,
            identity,
            evidence_state,
            evidence_refs,
            None,
            None,
            None,
            None,
        );

        assert_eq!(sources.identity.policy_id, identity.policy_id);
        assert!(sources.dataset.present);
        assert!(!sources.subject_range_override.present);
        assert!(!sources.caller_flags.durable_floor());
    }

    #[test]
    fn config_to_sources_preserves_caps_defaults_and_override_admission() {
        let mut config = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        config.dataset = Some(PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH,
        ));
        config.admits_subject_range_overrides = Some(true);
        config.explicit_unsafe_opt_in = Some(true);
        config.default_caller_flags = Some(CallerRequestFlags {
            barrier: true,
            ..CallerRequestFlags::default()
        });
        config.default_caller_hints = Some(CallerHintSource {
            present: true,
            hotness_hint: true,
            lifetime_hint: false,
            cache_bypass_hint: false,
            requested_candidate: PrefetchResidencyCandidateClass::NoPrefetch,
        });
        config.default_maintenance_intent = Some(InternalMaintenanceIntent {
            present: true,
            protected_reserves_available: true,
            ..InternalMaintenanceIntent::default()
        });
        config.prefetch_window_limit = Some(64 * 1024);
        config.staging_limit = Some(2 << 20);
        config.min_sample_mass = Some(48);
        config.min_observation_window_ms = Some(10_000);
        config.max_decay_age_ms = Some(120_000);
        config.dwell_min_ms = Some(30_000);
        config.cooldown_ms = Some(90_000);

        let subject_range_override = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::SubjectRangeOverride,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH,
        )
        .with_prefetch_window_limit(32 * 1024);
        let sources = config_to_prefetch_residency_sources(
            &config,
            identity(DATASET_A, 1),
            all_evidence(),
            evidence_refs(),
            None,
            None,
            None,
            Some(subject_range_override),
        );

        assert!(sources.dataset.admits_subject_range_overrides);
        assert!(sources.dataset.explicit_unsafe_opt_in);
        assert!(sources.caller_flags.barrier);
        assert!(sources.caller_hints.present);
        assert!(sources.internal_maintenance.present);

        let result = compile_prefetch_residency_policy(sources);

        assert_eq!(
            result.status,
            StorageIntentPolicyCompileStatus::UnsafeVisible
        );
        assert!(result.subject_range_override_admitted);
        assert_eq!(
            result.envelope.policy_scope,
            PrefetchResidencyPolicyScope::SubjectRange
        );
        assert_eq!(result.envelope.max_prefetch_window_bytes, 32 * 1024);
        assert_eq!(result.envelope.max_staging_bytes, 2 << 20);
        assert_eq!(result.envelope.min_sample_mass, 48);
        assert_eq!(result.envelope.min_observation_window_ms, 10_000);
        assert_eq!(result.envelope.max_decay_age_ms, 120_000);
        assert_eq!(result.envelope.dwell_min_ms, 30_000);
        assert_eq!(result.envelope.cooldown_ms, 90_000);
        assert!(result
            .source_mask
            .contains(StorageIntentPolicySourceClass::CallerFlags));
        assert!(result
            .source_mask
            .contains(StorageIntentPolicySourceClass::CallerHints));
        assert!(result
            .source_mask
            .contains(StorageIntentPolicySourceClass::InternalMaintenance));
    }

    #[test]
    fn config_default_hints_and_maintenance_cannot_authorize_movement() {
        let mut config = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        config.dataset = Some(PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH
                .with(PrefetchResidencyCandidateClass::AuthorityPromotionCandidate),
        ));
        config.default_caller_hints = Some(CallerHintSource {
            present: true,
            hotness_hint: true,
            lifetime_hint: true,
            cache_bypass_hint: false,
            requested_candidate: PrefetchResidencyCandidateClass::AuthorityPromotionCandidate,
        });
        config.default_maintenance_intent = Some(InternalMaintenanceIntent {
            present: true,
            relocation: true,
            protected_reserves_available: false,
            ..InternalMaintenanceIntent::default()
        });

        let result = compile_prefetch_residency_policy(config_to_prefetch_residency_sources(
            &config,
            identity(DATASET_A, 1),
            all_evidence(),
            evidence_refs(),
            None,
            None,
            None,
            None,
        ));

        assert_eq!(result.status, StorageIntentPolicyCompileStatus::Lowered);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::MovementDebtNotPaidBack
        );
        assert!(result
            .source_mask
            .contains(StorageIntentPolicySourceClass::CallerHints));
        assert!(result
            .source_mask
            .contains(StorageIntentPolicySourceClass::InternalMaintenance));
        assert!(!result
            .envelope
            .allowed_actions
            .contains_candidate(PrefetchResidencyCandidateClass::AuthorityPromotionCandidate));
    }

    #[test]
    fn same_pool_different_datasets_get_distinct_compiled_policies() {
        let mut pool = PoolPrefetchResidencyPolicyDefaults::minimal();
        pool.pool_default = PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::PoolDefault,
            PrefetchResidencyActionMask::ALL_DEFINED,
        );

        // Dataset A: aggressive slow-media prefetch
        let mut ds_a = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        ds_a.dataset = Some(PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH
                .with(PrefetchResidencyCandidateClass::BoundedReadahead)
                .with(PrefetchResidencyCandidateClass::StridedVectorPrefetch)
                .with(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch)
                .with(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage),
        ));
        ds_a.prefetch_window_limit = Some(8 << 20);
        ds_a.revision = 1;

        // Dataset B: refuses all prefetch
        let mut ds_b = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        ds_b.dataset = Some(PrefetchResidencyPolicySource::refusing(
            PrefetchResidencyPolicySource::new(
                StorageIntentPolicySourceClass::Dataset,
                PrefetchResidencyActionMask::ALL_DEFINED,
            ),
            PrefetchResidencyActionMask::ALL_DEFINED,
        ));
        ds_b.revision = 2;

        let resolved_a = resolve_effective_dataset_policy(&ds_a, None, &pool);
        let resolved_b = resolve_effective_dataset_policy(&ds_b, None, &pool);

        let ds_source_a = resolved_a.dataset.unwrap();
        let ds_source_b = resolved_b.dataset.unwrap();

        // Dataset A allows several action classes
        assert!(ds_source_a
            .allowed_actions.contains_candidate(PrefetchResidencyCandidateClass::BoundedReadahead));
        assert!(ds_source_a
            .allowed_actions.contains_candidate(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch));

        // Dataset B refuses all
        assert!(!ds_source_b.refused_actions.is_empty());
    }

    #[test]
    fn revision_tracking_maximises_across_inheritance_layers() {
        let pool = PoolPrefetchResidencyPolicyDefaults {
            revision: 10,
            ..PoolPrefetchResidencyPolicyDefaults::minimal()
        };

        let parent = DatasetPrefetchResidencyPolicyConfig {
            revision: 20,
            ..DatasetPrefetchResidencyPolicyConfig::EMPTY
        };

        let local = DatasetPrefetchResidencyPolicyConfig {
            revision: 5,
            ..DatasetPrefetchResidencyPolicyConfig::EMPTY
        };

        let resolved = resolve_effective_dataset_policy(&local, Some(&parent), &pool);
        assert_eq!(resolved.revision, 20); // max of 10, 20, 5
        assert_eq!(resolved.generation, 0);
        assert_eq!(resolved.epoch, 0);
    }

    #[test]
    fn budget_exhaustion_visible_in_compiled_output() {
        // Pool sets a cost/wear budget; dataset exceeds it => the compiler
        // should produce a lowered/refused status when evidence is missing.
        let pool = PoolPrefetchResidencyPolicyDefaults::minimal();

        let mut ds = DatasetPrefetchResidencyPolicyConfig::EMPTY;
        // Request flash serving but provide no wear evidence
        ds.dataset = Some(PrefetchResidencyPolicySource::new(
            StorageIntentPolicySourceClass::Dataset,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH
                .with(PrefetchResidencyCandidateClass::FlashHotServing),
        ));
        ds.revision = 1;

        let resolved = resolve_effective_dataset_policy(&ds, None, &pool);

        let identity = StorageIntentPolicyIdentity {
            policy_id: StorageIntentPolicyId([1u8; 16]),
            policy_revision: StorageIntentPolicyRevision(1),
            pool_id: StorageIntentDomainId([2u8; 16]),
            dataset_id: StorageIntentDomainId([3u8; 16]),
            budget_owner: StorageIntentDomainId([4u8; 16]),
        };

        // No wear, freshness, or media capability evidence
        let evidence_state = PrefetchResidencyPolicyEvidenceState::default();
        let evidence_refs = PrefetchResidencyDecisionEvidenceRefs::default();

        let sources = config_to_prefetch_residency_sources(
            &resolved,
            identity,
            evidence_state,
            evidence_refs,
            None,
            None,
            None,
            None,
        );

        let result = compile_prefetch_residency_policy(sources);

        // Missing wear/freshness evidence should lower flash actions
        assert!(matches!(
            result.status,
            StorageIntentPolicyCompileStatus::Lowered
                | StorageIntentPolicyCompileStatus::Refused
        ));
        assert_ne!(result.refusal, StorageIntentRefusalReason::None);
    }
}
