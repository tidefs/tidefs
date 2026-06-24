// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Media-capability freshness and invalidation model for storage intent.
//!
//! This crate is the first #962 source slice. It does not probe devices,
//! measure remote services, score placement, move data, emit receipts, or
//! render operator UAPI. It consumes the #904/#960/#961
//! [`StorageIntentMediaCapabilityRecord`] shape and decides whether that
//! record is still fresh enough for a requested storage-intent role.

use tidefs_storage_intent_core::{
    media_capability_satisfies_role, MediaCapabilityFlags, MediaCapabilityFreshnessState,
    MediaHealthState, MediaRoleMask, MediaRoleRequirement, StorageIntentEvidenceId,
    StorageIntentEvidenceKind, StorageIntentEvidenceRef, StorageIntentGuaranteeClass,
    StorageIntentMediaCapabilityRecord, StorageIntentRefusalReason, StorageMediaClass,
    StorageMediaRole,
};
use tidefs_storage_intent_local_media_capability::{
    produce_local_media_capability, LocalMediaCapabilityFacts,
};
use tidefs_storage_intent_remote_media_capability::{
    produce_remote_media_capability, RemoteMediaCapabilityFacts,
};

/// Canonical identifier for this authority surface.
pub const STORAGE_INTENT_MEDIA_CAPABILITY_REFRESH_SPEC: &str =
    "tidefs-storage-intent-media-capability-refresh-v1-issue-962";

/// Current syntactic record version for refresh evidence.
pub const STORAGE_INTENT_MEDIA_CAPABILITY_REFRESH_VERSION: u16 = 1;

/// Capability consumer role whose freshness requirements are being evaluated.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(u8)]
pub enum MediaCapabilityUseRole {
    /// Cache-only read or diagnostic use. Never authority.
    #[default]
    CacheOnly = 0,
    /// Durable sync-intent, FUA, barrier, or stable-write role.
    DurableSyncIntent = 1,
    /// Full placement authority.
    FullPlacement = 2,
    /// Persistent-memory durable authority with flush/fence evidence.
    PmemDurableAuthority = 3,
    /// Block-volume flush/FUA passthrough authority.
    BlockVolumeFuaFlush = 4,
    /// Remote/object durable placement or read-source authority.
    RemoteDurable = 5,
    /// Archive/object retention authority.
    ArchiveAuthority = 6,
    /// Geo/remote freshness role.
    GeoReplica = 7,
    /// Non-authority prefetch, cache warm, or restore staging.
    PrefetchOrStaging = 8,
    /// Promotion, demotion, or source-retirement candidate.
    PromotionDemotion = 9,
    /// Feedback/payback evidence that may train confidence upward.
    FeedbackTraining = 10,
}

impl MediaCapabilityUseRole {
    /// Returns true when the role may keep stale evidence only as cache/trial
    /// evidence if the requirement explicitly allows it.
    #[must_use]
    pub const fn may_degrade_to_cache_only(self) -> bool {
        matches!(self, Self::CacheOnly | Self::PrefetchOrStaging)
    }

    /// Returns true when the role can change or justify durable authority.
    #[must_use]
    pub const fn requires_authority_freshness(self) -> bool {
        !matches!(self, Self::CacheOnly | Self::PrefetchOrStaging)
    }
}

/// Refresh outcome projected to planners, executors, feedback, and explainers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(u8)]
pub enum MediaCapabilityRefreshOutcome {
    /// No usable capability or freshness evidence was present.
    #[default]
    Unknown = 0,
    /// Capability is fresh for the requested role.
    FreshForRole = 1,
    /// Capability may be retained for cache/trial use only.
    StaleCacheOnly = 2,
    /// Capability must be revalidated before the requested role may use it.
    RevalidationRequired = 3,
    /// Capability is degraded and any downgrade must be visible.
    DegradedVisible = 4,
    /// Capability is blocked by missing or compacted proof roots.
    Blocked = 5,
    /// Producer or policy refused this capability.
    Refused = 6,
    /// Target is quarantined or trust/key epoch changed beyond safe use.
    Quarantined = 7,
    /// Evidence contradicted itself or the current target generation.
    Contradictory = 8,
}

/// Retention state for the evidence needed to justify capability freshness.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(u8)]
pub enum MediaCapabilityRetentionState {
    /// Exact proof roots are retained.
    #[default]
    Exact = 0,
    /// Evidence was summarized but still names the same generation.
    Summarized = 1,
    /// Evidence was compacted beyond authority use.
    CompactedBeyondAuthority = 2,
    /// Evidence was redacted beyond role proof.
    RedactedBeyondUse = 3,
}

/// Invalidation trigger set for a media-capability generation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct MediaCapabilityInvalidationMask(pub u64);

impl MediaCapabilityInvalidationMask {
    pub const EMPTY: Self = Self(0);
    pub const DEVICE_RESET: Self = Self(1_u64 << 0);
    pub const DETACH_REATTACH: Self = Self(1_u64 << 1);
    pub const NAMESPACE_IDENTITY_CHANGED: Self = Self(1_u64 << 2);
    pub const POOL_MEMBER_BINDING_CHANGED: Self = Self(1_u64 << 3);
    pub const FIRMWARE_OR_SETTINGS_CHANGED: Self = Self(1_u64 << 4);
    pub const PATH_OR_MULTIPATH_CHANGED: Self = Self(1_u64 << 5);
    pub const WRITE_CACHE_POLICY_CHANGED: Self = Self(1_u64 << 6);
    pub const FLUSH_FUA_POLICY_CHANGED: Self = Self(1_u64 << 7);
    pub const ZONE_WRITE_POINTER_RESET: Self = Self(1_u64 << 8);
    pub const HEALTH_DEGRADED: Self = Self(1_u64 << 9);
    pub const PMEM_FLUSH_FENCE_CHANGED: Self = Self(1_u64 << 10);
    pub const REMOTE_ENDPOINT_CHANGED: Self = Self(1_u64 << 11);
    pub const CREDENTIAL_KEY_EPOCH_CHANGED: Self = Self(1_u64 << 12);
    pub const TRUST_OR_QUARANTINE_CHANGED: Self = Self(1_u64 << 13);
    pub const ARCHIVE_RETENTION_CHANGED: Self = Self(1_u64 << 14);
    pub const STALE_PROBE_AGE: Self = Self(1_u64 << 15);
    pub const CONTRADICTED: Self = Self(1_u64 << 16);
    pub const COMPACTED_BEYOND_AUTHORITY: Self = Self(1_u64 << 17);
    pub const REDACTED_BEYOND_USE: Self = Self(1_u64 << 18);
    pub const PRODUCER_CHANGED: Self = Self(1_u64 << 19);
    pub const TARGET_IDENTITY_CHANGED: Self = Self(1_u64 << 20);

    /// Merge two invalidation masks.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true when the mask has no invalidation triggers.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns true when all `other` triggers are present.
    #[must_use]
    pub const fn contains_all(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns true when any `other` trigger is present.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

/// Generation and freshness source record derived from a capability record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaCapabilityGenerationRecord {
    pub producer_id: StorageIntentEvidenceId,
    pub capability_ref: StorageIntentEvidenceRef,
    pub target_identity_ref: StorageIntentEvidenceRef,
    pub freshness_ref: StorageIntentEvidenceRef,
    pub evidence_cut_ref: StorageIntentEvidenceRef,
    pub retention_ref: StorageIntentEvidenceRef,
    pub timebase_ref: StorageIntentEvidenceRef,
    pub clock_skew_ref: StorageIntentEvidenceRef,
    pub media_class: StorageMediaClass,
    pub freshness: MediaCapabilityFreshnessState,
    pub health: MediaHealthState,
    pub identity_generation: u64,
    pub namespace_generation: u64,
    pub firmware_generation: u64,
    pub settings_generation: u64,
    pub pool_member_generation: u64,
    pub path_generation: u64,
    pub multipath_generation: u64,
    pub remote_endpoint_generation: u64,
    pub credential_key_epoch: u64,
    pub trust_generation: u64,
    pub quarantine_generation: u64,
    pub archive_retention_generation: u64,
    pub sample_frontier_ms: u64,
    pub observed_frontier_ms: u64,
    pub max_sample_age_ms: u64,
    pub retention: MediaCapabilityRetentionState,
    pub invalidations: MediaCapabilityInvalidationMask,
}

impl MediaCapabilityGenerationRecord {
    /// Build a generation record from the landed media-capability producer
    /// shape. Callers add #913 evidence-cut and timebase facts with builder
    /// methods.
    #[must_use]
    pub const fn from_capability(capability: StorageIntentMediaCapabilityRecord) -> Self {
        Self {
            producer_id: StorageIntentEvidenceId::ZERO,
            capability_ref: capability.evidence,
            target_identity_ref: capability.stable_identity_ref,
            freshness_ref: capability.freshness_ref,
            evidence_cut_ref: StorageIntentEvidenceRef {
                kind: StorageIntentEvidenceKind::Unknown,
                id: StorageIntentEvidenceId::ZERO,
                generation: 0,
                version: 0,
            },
            retention_ref: StorageIntentEvidenceRef {
                kind: StorageIntentEvidenceKind::Unknown,
                id: StorageIntentEvidenceId::ZERO,
                generation: 0,
                version: 0,
            },
            timebase_ref: StorageIntentEvidenceRef {
                kind: StorageIntentEvidenceKind::Unknown,
                id: StorageIntentEvidenceId::ZERO,
                generation: 0,
                version: 0,
            },
            clock_skew_ref: StorageIntentEvidenceRef {
                kind: StorageIntentEvidenceKind::Unknown,
                id: StorageIntentEvidenceId::ZERO,
                generation: 0,
                version: 0,
            },
            media_class: capability.media_class,
            freshness: capability.freshness,
            health: capability.health,
            identity_generation: capability.identity_generation,
            namespace_generation: capability.namespace_generation,
            firmware_generation: capability.firmware_generation,
            settings_generation: capability.settings_generation,
            pool_member_generation: capability.pool_member_generation,
            path_generation: 0,
            multipath_generation: 0,
            remote_endpoint_generation: 0,
            credential_key_epoch: 0,
            trust_generation: 0,
            quarantine_generation: 0,
            archive_retention_generation: 0,
            sample_frontier_ms: 0,
            observed_frontier_ms: 0,
            max_sample_age_ms: u64::MAX,
            retention: MediaCapabilityRetentionState::Exact,
            invalidations: MediaCapabilityInvalidationMask::EMPTY,
        }
    }

    /// Build a generation record directly from the #960 local producer input.
    ///
    /// The landed local producer shape carries identity, namespace, firmware,
    /// settings, pool-member, health, and freshness generations. It does not
    /// yet expose separate path or multipath generation fields, so those remain
    /// explicit refresh-layer inputs through [`Self::with_path_generations`].
    #[must_use]
    pub const fn from_local_producer_facts(facts: LocalMediaCapabilityFacts) -> Self {
        Self::from_capability(produce_local_media_capability(facts))
            .with_local_producer_facts(facts)
    }

    /// Overlay the #960 local producer generations onto an existing refresh
    /// generation record.
    #[must_use]
    pub const fn with_local_producer_facts(mut self, facts: LocalMediaCapabilityFacts) -> Self {
        self.capability_ref = facts.evidence;
        self.target_identity_ref = facts.identity.stable_identity_ref;
        self.freshness_ref = facts.freshness.freshness_ref;
        self.media_class = facts.media_class;
        self.freshness = facts.freshness.freshness;
        self.health = facts.health.health;
        self.identity_generation = facts.identity.identity_generation;
        self.namespace_generation = facts.identity.namespace_generation;
        self.firmware_generation = facts.identity.firmware_generation;
        self.settings_generation = facts.identity.settings_generation;
        self.pool_member_generation = facts.identity.pool_member_generation;
        self
    }

    /// Build a generation record directly from the #961 remote/object/archive
    /// producer input.
    ///
    /// The remote producer stores endpoint and key epochs in the shared
    /// media-capability record for #904 role predicates. The refresh model also
    /// projects them into remote-specific generation fields so endpoint failover
    /// and key rotation cannot be mistaken for ordinary firmware/settings drift.
    #[must_use]
    pub const fn from_remote_producer_facts(facts: RemoteMediaCapabilityFacts) -> Self {
        Self::from_capability(produce_remote_media_capability(facts))
            .with_remote_producer_facts(facts)
    }

    /// Overlay the #961 remote producer generations onto an existing refresh
    /// generation record.
    #[must_use]
    pub const fn with_remote_producer_facts(mut self, facts: RemoteMediaCapabilityFacts) -> Self {
        self.capability_ref = facts.evidence;
        self.target_identity_ref = facts.identity.stable_identity_ref;
        self.freshness_ref = facts.freshness.freshness_ref;
        self.media_class = facts.media_class;
        self.freshness = facts.freshness.freshness;
        self.health = facts.health.health;
        self.identity_generation = facts.identity.identity_generation;
        self.namespace_generation = facts.identity.namespace_generation;
        self.firmware_generation = facts.identity.endpoint_generation;
        self.settings_generation = facts.identity.credential_key_epoch;
        self.pool_member_generation = facts.identity.pool_member_generation;
        self.path_generation = facts.path.path_ref.generation;
        self.remote_endpoint_generation = facts.identity.endpoint_generation;
        self.credential_key_epoch = facts.identity.credential_key_epoch;
        self.trust_generation = facts.trust.trust_ref.generation;
        self.quarantine_generation = match facts.health.health {
            MediaHealthState::Quarantined => facts.health.health_ref.generation,
            _ => 0,
        };
        self.archive_retention_generation = facts.archive.archive_restore_ref.generation;
        self
    }

    #[must_use]
    pub const fn with_producer_id(mut self, producer_id: StorageIntentEvidenceId) -> Self {
        self.producer_id = producer_id;
        self
    }

    #[must_use]
    pub const fn with_target_identity(
        mut self,
        target_identity_ref: StorageIntentEvidenceRef,
    ) -> Self {
        self.target_identity_ref = target_identity_ref;
        self
    }

    #[must_use]
    pub const fn with_evidence_cut(mut self, evidence_cut_ref: StorageIntentEvidenceRef) -> Self {
        self.evidence_cut_ref = evidence_cut_ref;
        self
    }

    #[must_use]
    pub const fn with_retention(
        mut self,
        retention: MediaCapabilityRetentionState,
        retention_ref: StorageIntentEvidenceRef,
    ) -> Self {
        self.retention = retention;
        self.retention_ref = retention_ref;
        self
    }

    #[must_use]
    pub const fn with_timebase(mut self, timebase_ref: StorageIntentEvidenceRef) -> Self {
        self.timebase_ref = timebase_ref;
        self
    }

    #[must_use]
    pub const fn with_clock_skew(mut self, clock_skew_ref: StorageIntentEvidenceRef) -> Self {
        self.clock_skew_ref = clock_skew_ref;
        self
    }

    #[must_use]
    pub const fn with_path_generations(
        mut self,
        path_generation: u64,
        multipath_generation: u64,
    ) -> Self {
        self.path_generation = path_generation;
        self.multipath_generation = multipath_generation;
        self
    }

    #[must_use]
    pub const fn with_remote_generations(
        mut self,
        remote_endpoint_generation: u64,
        credential_key_epoch: u64,
        trust_generation: u64,
        quarantine_generation: u64,
    ) -> Self {
        self.remote_endpoint_generation = remote_endpoint_generation;
        self.credential_key_epoch = credential_key_epoch;
        self.trust_generation = trust_generation;
        self.quarantine_generation = quarantine_generation;
        self
    }

    #[must_use]
    pub const fn with_archive_retention_generation(
        mut self,
        archive_retention_generation: u64,
    ) -> Self {
        self.archive_retention_generation = archive_retention_generation;
        self
    }

    #[must_use]
    pub const fn with_sample_window(
        mut self,
        sample_frontier_ms: u64,
        observed_frontier_ms: u64,
        max_sample_age_ms: u64,
    ) -> Self {
        self.sample_frontier_ms = sample_frontier_ms;
        self.observed_frontier_ms = observed_frontier_ms;
        self.max_sample_age_ms = max_sample_age_ms;
        self
    }

    #[must_use]
    pub const fn with_invalidations(
        mut self,
        invalidations: MediaCapabilityInvalidationMask,
    ) -> Self {
        self.invalidations = invalidations;
        self
    }
}

impl Default for MediaCapabilityGenerationRecord {
    fn default() -> Self {
        Self::from_capability(StorageIntentMediaCapabilityRecord::default())
    }
}

/// Freshness requirement for one consumer role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaCapabilityRefreshRequirement {
    pub role: MediaCapabilityUseRole,
    pub require_evidence_cut: bool,
    pub require_exact_retention: bool,
    pub allow_cache_only_when_stale: bool,
}

impl MediaCapabilityRefreshRequirement {
    /// Conservative defaults for a role.
    #[must_use]
    pub const fn for_role(role: MediaCapabilityUseRole) -> Self {
        Self {
            role,
            require_evidence_cut: !matches!(role, MediaCapabilityUseRole::CacheOnly),
            require_exact_retention: !matches!(
                role,
                MediaCapabilityUseRole::CacheOnly | MediaCapabilityUseRole::PrefetchOrStaging
            ),
            allow_cache_only_when_stale: role.may_degrade_to_cache_only(),
        }
    }
}

impl Default for MediaCapabilityRefreshRequirement {
    fn default() -> Self {
        Self::for_role(MediaCapabilityUseRole::CacheOnly)
    }
}

/// Evaluation input for one capability record and consumer role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaCapabilityRefreshInput {
    pub capability: StorageIntentMediaCapabilityRecord,
    pub generation: MediaCapabilityGenerationRecord,
    pub requirement: MediaCapabilityRefreshRequirement,
}

impl MediaCapabilityRefreshInput {
    #[must_use]
    pub const fn new(
        capability: StorageIntentMediaCapabilityRecord,
        generation: MediaCapabilityGenerationRecord,
        requirement: MediaCapabilityRefreshRequirement,
    ) -> Self {
        Self {
            capability,
            generation,
            requirement,
        }
    }
}

/// Role-specific freshness verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaCapabilityRefreshVerdict {
    pub outcome: MediaCapabilityRefreshOutcome,
    pub refusal: StorageIntentRefusalReason,
    pub authority_usable: bool,
    pub cache_only_usable: bool,
    pub revalidation_required: bool,
    pub capability_ref: StorageIntentEvidenceRef,
    pub freshness_ref: StorageIntentEvidenceRef,
    pub evidence_cut_ref: StorageIntentEvidenceRef,
    pub invalidations: MediaCapabilityInvalidationMask,
}

impl MediaCapabilityRefreshVerdict {
    fn new(
        input: MediaCapabilityRefreshInput,
        outcome: MediaCapabilityRefreshOutcome,
        refusal: StorageIntentRefusalReason,
        authority_usable: bool,
        cache_only_usable: bool,
        revalidation_required: bool,
    ) -> Self {
        Self {
            outcome,
            refusal,
            authority_usable,
            cache_only_usable,
            revalidation_required,
            capability_ref: input.capability.evidence,
            freshness_ref: input.capability.freshness_ref,
            evidence_cut_ref: input.generation.evidence_cut_ref,
            invalidations: input.generation.invalidations,
        }
    }
}

/// Compare two producer generation snapshots and return the invalidation
/// triggers that prevent silent reuse.
#[must_use]
pub fn media_capability_generation_drift(
    baseline: StorageIntentMediaCapabilityRecord,
    observed: StorageIntentMediaCapabilityRecord,
) -> MediaCapabilityInvalidationMask {
    let mut mask = MediaCapabilityInvalidationMask::EMPTY;

    if baseline.media_class != observed.media_class
        || baseline.identity_generation != observed.identity_generation
    {
        mask = mask.union(MediaCapabilityInvalidationMask::DEVICE_RESET);
    }
    if baseline.namespace_generation != observed.namespace_generation {
        mask = mask.union(MediaCapabilityInvalidationMask::NAMESPACE_IDENTITY_CHANGED);
    }
    if baseline.pool_member_generation != observed.pool_member_generation {
        mask = mask.union(MediaCapabilityInvalidationMask::POOL_MEMBER_BINDING_CHANGED);
    }
    if baseline.firmware_generation != observed.firmware_generation
        || baseline.settings_generation != observed.settings_generation
    {
        mask = mask.union(MediaCapabilityInvalidationMask::FIRMWARE_OR_SETTINGS_CHANGED);
    }
    if baseline.persistence != observed.persistence
        || baseline
            .flags
            .contains_all(MediaCapabilityFlags::WRITE_CACHE_SAFE)
            != observed
                .flags
                .contains_all(MediaCapabilityFlags::WRITE_CACHE_SAFE)
    {
        mask = mask.union(MediaCapabilityInvalidationMask::WRITE_CACHE_POLICY_CHANGED);
    }
    if baseline.flush_ordering != observed.flush_ordering {
        mask = mask.union(MediaCapabilityInvalidationMask::FLUSH_FUA_POLICY_CHANGED);
    }
    if baseline.media_class.is_zoned()
        && (baseline.geometry != observed.geometry
            || baseline.optimal_io_bytes != observed.optimal_io_bytes)
    {
        mask = mask.union(MediaCapabilityInvalidationMask::ZONE_WRITE_POINTER_RESET);
    }
    if baseline.health != observed.health
        && matches!(
            observed.health,
            MediaHealthState::Degraded | MediaHealthState::Failed | MediaHealthState::Quarantined
        )
    {
        mask = mask.union(MediaCapabilityInvalidationMask::HEALTH_DEGRADED);
    }
    if baseline.media_class == StorageMediaClass::PersistentMemory
        && (baseline.flush_ordering != observed.flush_ordering
            || baseline
                .flags
                .contains_all(MediaCapabilityFlags::PMEM_FLUSH_FENCE)
                != observed
                    .flags
                    .contains_all(MediaCapabilityFlags::PMEM_FLUSH_FENCE))
    {
        mask = mask.union(MediaCapabilityInvalidationMask::PMEM_FLUSH_FENCE_CHANGED);
    }
    if baseline.remote_commit != observed.remote_commit {
        mask = mask.union(MediaCapabilityInvalidationMask::REMOTE_ENDPOINT_CHANGED);
    }
    if baseline.archive_restore != observed.archive_restore {
        mask = mask.union(MediaCapabilityInvalidationMask::ARCHIVE_RETENTION_CHANGED);
    }
    match observed.freshness {
        MediaCapabilityFreshnessState::Stale | MediaCapabilityFreshnessState::Missing => {
            mask = mask.union(MediaCapabilityInvalidationMask::STALE_PROBE_AGE);
        }
        MediaCapabilityFreshnessState::Contradictory => {
            mask = mask.union(MediaCapabilityInvalidationMask::CONTRADICTED);
        }
        MediaCapabilityFreshnessState::Refused => {
            mask = mask.union(MediaCapabilityInvalidationMask::TRUST_OR_QUARANTINE_CHANGED);
        }
        MediaCapabilityFreshnessState::Fresh => {}
    }

    mask
}

/// Compare two generation/freshness records and return the typed
/// invalidations that make old capability evidence unsafe to reuse silently.
#[must_use]
pub fn media_capability_generation_record_drift(
    baseline: MediaCapabilityGenerationRecord,
    observed: MediaCapabilityGenerationRecord,
) -> MediaCapabilityInvalidationMask {
    let mut mask = MediaCapabilityInvalidationMask::EMPTY;

    if baseline.producer_id != observed.producer_id {
        mask = mask.union(MediaCapabilityInvalidationMask::PRODUCER_CHANGED);
    }
    if baseline.target_identity_ref != observed.target_identity_ref
        || baseline.identity_generation != observed.identity_generation
        || baseline.media_class != observed.media_class
    {
        mask = mask.union(MediaCapabilityInvalidationMask::TARGET_IDENTITY_CHANGED);
    }
    if baseline.namespace_generation != observed.namespace_generation {
        mask = mask.union(MediaCapabilityInvalidationMask::NAMESPACE_IDENTITY_CHANGED);
    }
    if baseline.firmware_generation != observed.firmware_generation
        || baseline.settings_generation != observed.settings_generation
    {
        mask = mask.union(MediaCapabilityInvalidationMask::FIRMWARE_OR_SETTINGS_CHANGED);
    }
    if baseline.pool_member_generation != observed.pool_member_generation {
        mask = mask.union(MediaCapabilityInvalidationMask::POOL_MEMBER_BINDING_CHANGED);
    }
    if baseline.path_generation != observed.path_generation
        || baseline.multipath_generation != observed.multipath_generation
    {
        mask = mask.union(MediaCapabilityInvalidationMask::PATH_OR_MULTIPATH_CHANGED);
    }
    if baseline.remote_endpoint_generation != observed.remote_endpoint_generation {
        mask = mask.union(MediaCapabilityInvalidationMask::REMOTE_ENDPOINT_CHANGED);
    }
    if baseline.credential_key_epoch != observed.credential_key_epoch {
        mask = mask.union(MediaCapabilityInvalidationMask::CREDENTIAL_KEY_EPOCH_CHANGED);
    }
    if baseline.trust_generation != observed.trust_generation
        || baseline.quarantine_generation != observed.quarantine_generation
    {
        mask = mask.union(MediaCapabilityInvalidationMask::TRUST_OR_QUARANTINE_CHANGED);
    }
    if baseline.archive_retention_generation != observed.archive_retention_generation {
        mask = mask.union(MediaCapabilityInvalidationMask::ARCHIVE_RETENTION_CHANGED);
    }
    if observed.retention == MediaCapabilityRetentionState::CompactedBeyondAuthority {
        mask = mask.union(MediaCapabilityInvalidationMask::COMPACTED_BEYOND_AUTHORITY);
    }
    if observed.retention == MediaCapabilityRetentionState::RedactedBeyondUse {
        mask = mask.union(MediaCapabilityInvalidationMask::REDACTED_BEYOND_USE);
    }
    if matches!(
        observed.freshness,
        MediaCapabilityFreshnessState::Missing | MediaCapabilityFreshnessState::Stale
    ) || sample_age_exceeded(observed)
    {
        mask = mask.union(MediaCapabilityInvalidationMask::STALE_PROBE_AGE);
    }
    if observed.freshness == MediaCapabilityFreshnessState::Contradictory {
        mask = mask.union(MediaCapabilityInvalidationMask::CONTRADICTED);
    }
    if baseline.health != observed.health
        && matches!(
            observed.health,
            MediaHealthState::Degraded | MediaHealthState::Failed | MediaHealthState::Quarantined
        )
    {
        mask = mask.union(MediaCapabilityInvalidationMask::HEALTH_DEGRADED);
        if observed.health == MediaHealthState::Quarantined {
            mask = mask.union(MediaCapabilityInvalidationMask::TRUST_OR_QUARANTINE_CHANGED);
        }
    }

    mask
}

/// Evaluate whether a capability record remains fresh enough for a role.
#[must_use]
pub fn media_capability_refresh_evaluate(
    input: MediaCapabilityRefreshInput,
) -> MediaCapabilityRefreshVerdict {
    if !input.capability.has_media_capability_evidence() {
        return MediaCapabilityRefreshVerdict::new(
            input,
            MediaCapabilityRefreshOutcome::Unknown,
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence,
            false,
            false,
            true,
        );
    }

    if input.requirement.require_evidence_cut
        && !evidence_ref_has_id(input.generation.evidence_cut_ref)
    {
        return MediaCapabilityRefreshVerdict::new(
            input,
            MediaCapabilityRefreshOutcome::Blocked,
            StorageIntentRefusalReason::EvidenceNotUsable,
            false,
            false,
            true,
        );
    }

    if input.requirement.require_exact_retention
        && matches!(
            input.generation.retention,
            MediaCapabilityRetentionState::CompactedBeyondAuthority
                | MediaCapabilityRetentionState::RedactedBeyondUse
        )
    {
        return MediaCapabilityRefreshVerdict::new(
            input,
            MediaCapabilityRefreshOutcome::Blocked,
            StorageIntentRefusalReason::EvidenceNotUsable,
            false,
            false,
            true,
        );
    }

    if matches!(
        input.generation.retention,
        MediaCapabilityRetentionState::CompactedBeyondAuthority
            | MediaCapabilityRetentionState::RedactedBeyondUse
    ) {
        return stale_or_revalidate(input, StorageIntentRefusalReason::EvidenceNotUsable);
    }

    if input
        .generation
        .invalidations
        .intersects(MediaCapabilityInvalidationMask::CONTRADICTED)
        || matches!(
            input.capability.freshness,
            MediaCapabilityFreshnessState::Contradictory
        )
    {
        return MediaCapabilityRefreshVerdict::new(
            input,
            MediaCapabilityRefreshOutcome::Contradictory,
            StorageIntentRefusalReason::EvidenceNotUsable,
            false,
            false,
            true,
        );
    }

    if input.generation.invalidations.intersects(
        MediaCapabilityInvalidationMask::TRUST_OR_QUARANTINE_CHANGED
            .union(MediaCapabilityInvalidationMask::CREDENTIAL_KEY_EPOCH_CHANGED),
    ) || matches!(input.capability.health, MediaHealthState::Quarantined)
    {
        return MediaCapabilityRefreshVerdict::new(
            input,
            MediaCapabilityRefreshOutcome::Quarantined,
            StorageIntentRefusalReason::QuarantinedSource,
            false,
            false,
            true,
        );
    }

    if !input.generation.invalidations.is_empty() {
        return stale_or_revalidate(
            input,
            StorageIntentRefusalReason::StaleMediaCapabilityEvidence,
        );
    }

    match input.capability.freshness {
        MediaCapabilityFreshnessState::Missing => {
            return MediaCapabilityRefreshVerdict::new(
                input,
                MediaCapabilityRefreshOutcome::Unknown,
                StorageIntentRefusalReason::MissingMediaCapabilityEvidence,
                false,
                false,
                true,
            );
        }
        MediaCapabilityFreshnessState::Stale => {
            return stale_or_revalidate(
                input,
                StorageIntentRefusalReason::StaleMediaCapabilityEvidence,
            );
        }
        MediaCapabilityFreshnessState::Refused => {
            return MediaCapabilityRefreshVerdict::new(
                input,
                MediaCapabilityRefreshOutcome::Refused,
                StorageIntentRefusalReason::EvidenceNotUsable,
                false,
                false,
                true,
            );
        }
        MediaCapabilityFreshnessState::Contradictory => {
            return MediaCapabilityRefreshVerdict::new(
                input,
                MediaCapabilityRefreshOutcome::Contradictory,
                StorageIntentRefusalReason::EvidenceNotUsable,
                false,
                false,
                true,
            );
        }
        MediaCapabilityFreshnessState::Fresh => {}
    }

    if sample_age_exceeded(input.generation) {
        return stale_or_revalidate(
            input,
            StorageIntentRefusalReason::StaleMediaCapabilityEvidence,
        );
    }

    if matches!(
        input.capability.health,
        MediaHealthState::Degraded | MediaHealthState::Failed
    ) {
        return MediaCapabilityRefreshVerdict::new(
            input,
            MediaCapabilityRefreshOutcome::DegradedVisible,
            StorageIntentRefusalReason::DegradedMediaHealth,
            false,
            false,
            true,
        );
    }

    if input.requirement.role == MediaCapabilityUseRole::PmemDurableAuthority
        && !matches!(
            input.capability.media_class,
            StorageMediaClass::PersistentMemory
        )
    {
        return MediaCapabilityRefreshVerdict::new(
            input,
            MediaCapabilityRefreshOutcome::Refused,
            StorageIntentRefusalReason::PersistentMediaRequired,
            false,
            false,
            false,
        );
    }

    let predicate = role_predicate(input.requirement.role, input.capability);
    if !predicate.satisfied {
        return MediaCapabilityRefreshVerdict::new(
            input,
            MediaCapabilityRefreshOutcome::Refused,
            predicate.refusal,
            false,
            false,
            false,
        );
    }

    let authority_usable = input.requirement.role.requires_authority_freshness();
    MediaCapabilityRefreshVerdict::new(
        input,
        MediaCapabilityRefreshOutcome::FreshForRole,
        StorageIntentRefusalReason::None,
        authority_usable,
        !authority_usable,
        false,
    )
}

fn stale_or_revalidate(
    input: MediaCapabilityRefreshInput,
    refusal: StorageIntentRefusalReason,
) -> MediaCapabilityRefreshVerdict {
    if input.requirement.allow_cache_only_when_stale {
        MediaCapabilityRefreshVerdict::new(
            input,
            MediaCapabilityRefreshOutcome::StaleCacheOnly,
            refusal,
            false,
            true,
            true,
        )
    } else {
        MediaCapabilityRefreshVerdict::new(
            input,
            MediaCapabilityRefreshOutcome::RevalidationRequired,
            refusal,
            false,
            false,
            true,
        )
    }
}

fn role_predicate(
    role: MediaCapabilityUseRole,
    capability: StorageIntentMediaCapabilityRecord,
) -> tidefs_storage_intent_core::ReceiptPredicateResult {
    match role {
        MediaCapabilityUseRole::CacheOnly | MediaCapabilityUseRole::PrefetchOrStaging => {
            media_capability_satisfies_role(
                MediaRoleRequirement {
                    allowed_roles: MediaRoleMask::from_role(StorageMediaRole::ReadCache)
                        .with(StorageMediaRole::RamCache),
                    require_authority_role: false,
                },
                StorageIntentGuaranteeClass::VolatileLocal,
                StorageMediaRole::ReadCache,
                capability,
            )
        }
        MediaCapabilityUseRole::DurableSyncIntent | MediaCapabilityUseRole::BlockVolumeFuaFlush => {
            media_capability_satisfies_role(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::SyncIntent,
                capability,
            )
        }
        MediaCapabilityUseRole::FullPlacement
        | MediaCapabilityUseRole::RemoteDurable
        | MediaCapabilityUseRole::PromotionDemotion
        | MediaCapabilityUseRole::FeedbackTraining => media_capability_satisfies_role(
            MediaRoleRequirement::AUTHORITY,
            StorageIntentGuaranteeClass::FullPlacement,
            StorageMediaRole::PlacementAuthority,
            capability,
        ),
        MediaCapabilityUseRole::PmemDurableAuthority => media_capability_satisfies_role(
            MediaRoleRequirement::AUTHORITY,
            StorageIntentGuaranteeClass::LocalIntent,
            StorageMediaRole::RamIntentBackedAuthority,
            capability,
        ),
        MediaCapabilityUseRole::ArchiveAuthority => media_capability_satisfies_role(
            MediaRoleRequirement::AUTHORITY,
            StorageIntentGuaranteeClass::ArchiveEc,
            StorageMediaRole::ArchiveEc,
            capability,
        ),
        MediaCapabilityUseRole::GeoReplica => media_capability_satisfies_role(
            MediaRoleRequirement::AUTHORITY,
            StorageIntentGuaranteeClass::GeoAsync,
            StorageMediaRole::GeoAsyncReplica,
            capability,
        ),
    }
}

fn sample_age_exceeded(generation: MediaCapabilityGenerationRecord) -> bool {
    generation.max_sample_age_ms != u64::MAX
        && (generation.observed_frontier_ms < generation.sample_frontier_ms
            || generation.observed_frontier_ms - generation.sample_frontier_ms
                > generation.max_sample_age_ms)
}

fn evidence_ref_has_id(evidence: StorageIntentEvidenceRef) -> bool {
    evidence.kind != StorageIntentEvidenceKind::Unknown
        && evidence.id != StorageIntentEvidenceId::ZERO
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_storage_intent_core::{
        MediaArchiveRestoreSemantics, MediaAtomicityClass, MediaFlushOrderingClass,
        MediaPersistenceDomain, MediaProtocolGeometryClass, MediaRemoteCommitSemantics,
    };
    use tidefs_storage_intent_local_media_capability::{
        LocalFreshnessFacts, LocalMediaIdentityFacts,
    };
    use tidefs_storage_intent_remote_media_capability::{
        RemoteArchiveFacts, RemoteCommitFacts, RemoteCostRecoveryFacts, RemoteFreshnessFacts,
        RemoteHealthFacts, RemotePathFacts, RemoteTargetIdentityFacts, RemoteTrustFacts,
    };

    fn evidence_id(seed: u8) -> StorageIntentEvidenceId {
        StorageIntentEvidenceId([seed; 32])
    }

    fn evidence(kind: StorageIntentEvidenceKind, seed: u8) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(
            kind,
            evidence_id(seed),
            u64::from(seed),
            STORAGE_INTENT_MEDIA_CAPABILITY_REFRESH_VERSION,
        )
    }

    fn evidence_with_generation(
        kind: StorageIntentEvidenceKind,
        seed: u8,
        generation: u64,
    ) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(
            kind,
            evidence_id(seed),
            generation,
            STORAGE_INTENT_MEDIA_CAPABILITY_REFRESH_VERSION,
        )
    }

    fn capability_evidence(seed: u8) -> StorageIntentEvidenceRef {
        evidence(StorageIntentEvidenceKind::MediaCapabilityEvidence, seed)
    }

    fn evidence_cut(seed: u8) -> StorageIntentEvidenceRef {
        evidence(StorageIntentEvidenceKind::EvidenceQuerySnapshot, seed)
    }

    fn retention_ref(seed: u8) -> StorageIntentEvidenceRef {
        evidence(StorageIntentEvidenceKind::EvidenceRetentionEvidence, seed)
    }

    fn block_capability(seed: u8) -> StorageIntentMediaCapabilityRecord {
        StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::NvmeFlash,
            flags: MediaCapabilityFlags::STABLE_DEVICE_IDENTITY
                .union(MediaCapabilityFlags::STABLE_NAMESPACE_IDENTITY)
                .union(MediaCapabilityFlags::POOL_MEMBER_BINDING)
                .union(MediaCapabilityFlags::FIRMWARE_CAPABILITY_GENERATION)
                .union(MediaCapabilityFlags::PERSISTENCE_DOMAIN)
                .union(MediaCapabilityFlags::FLUSH_FUA_ORDERING)
                .union(MediaCapabilityFlags::ATOMICITY_GRANULARITY)
                .union(MediaCapabilityFlags::PROTOCOL_GEOMETRY)
                .union(MediaCapabilityFlags::HEALTH)
                .union(MediaCapabilityFlags::FRESHNESS),
            identity_generation: 100 + u64::from(seed),
            namespace_generation: 200 + u64::from(seed),
            firmware_generation: 300 + u64::from(seed),
            settings_generation: 400 + u64::from(seed),
            pool_member_generation: 500 + u64::from(seed),
            persistence: MediaPersistenceDomain::OrdinaryPersistent,
            flush_ordering: MediaFlushOrderingClass::FlushAndFua,
            atomicity: MediaAtomicityClass::LogicalBlockAtomic,
            geometry: MediaProtocolGeometryClass::RandomBlock,
            health: MediaHealthState::Healthy,
            freshness: MediaCapabilityFreshnessState::Fresh,
            remote_commit: MediaRemoteCommitSemantics::NotRemote,
            archive_restore: MediaArchiveRestoreSemantics::NotArchive,
            logical_block_bytes: 4096,
            physical_block_bytes: 4096,
            atomic_write_unit_bytes: 4096,
            optimal_io_bytes: 131_072,
            max_queue_depth: 64,
            latency_class_us: 80,
            evidence: capability_evidence(seed),
            stable_identity_ref: capability_evidence(seed.wrapping_add(1)),
            namespace_identity_ref: capability_evidence(seed.wrapping_add(2)),
            persistence_ref: capability_evidence(seed.wrapping_add(3)),
            flush_ref: capability_evidence(seed.wrapping_add(4)),
            atomicity_ref: capability_evidence(seed.wrapping_add(5)),
            geometry_ref: capability_evidence(seed.wrapping_add(6)),
            health_ref: capability_evidence(seed.wrapping_add(7)),
            freshness_ref: capability_evidence(seed.wrapping_add(8)),
            remote_commit_ref: StorageIntentEvidenceRef::default(),
            archive_restore_ref: StorageIntentEvidenceRef::default(),
        }
    }

    fn pmem_capability(seed: u8) -> StorageIntentMediaCapabilityRecord {
        StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::PersistentMemory,
            flags: block_capability(seed)
                .flags
                .union(MediaCapabilityFlags::PMEM_FLUSH_FENCE),
            persistence: MediaPersistenceDomain::PersistentMemory,
            flush_ordering: MediaFlushOrderingClass::PmemFlushFence,
            geometry: MediaProtocolGeometryClass::PmemByteAddressable,
            ..block_capability(seed)
        }
    }

    fn remote_object_capability(seed: u8) -> StorageIntentMediaCapabilityRecord {
        StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::CloudObject,
            flags: block_capability(seed)
                .flags
                .union(MediaCapabilityFlags::REMOTE_COMMIT)
                .union(MediaCapabilityFlags::TRANSPORT_RDMA_ABSENT_LEGAL),
            persistence: MediaPersistenceDomain::ObjectDurable,
            flush_ordering: MediaFlushOrderingClass::ObjectCommit,
            atomicity: MediaAtomicityClass::IdempotentObjectPut,
            geometry: MediaProtocolGeometryClass::RemoteObject,
            remote_commit: MediaRemoteCommitSemantics::ObjectConditionalDurable,
            remote_commit_ref: capability_evidence(seed.wrapping_add(9)),
            ..block_capability(seed)
        }
    }

    fn archive_capability(seed: u8) -> StorageIntentMediaCapabilityRecord {
        StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::TapeArchive,
            flags: remote_object_capability(seed)
                .flags
                .union(MediaCapabilityFlags::ARCHIVE_RESTORE_RETENTION),
            persistence: MediaPersistenceDomain::ArchiveDurable,
            flush_ordering: MediaFlushOrderingClass::ArchiveCommit,
            atomicity: MediaAtomicityClass::AppendRecordAtomic,
            geometry: MediaProtocolGeometryClass::ArchiveSequential,
            archive_restore: MediaArchiveRestoreSemantics::RestoreAudited,
            remote_commit: MediaRemoteCommitSemantics::ArchiveRetained,
            archive_restore_ref: capability_evidence(seed.wrapping_add(10)),
            ..remote_object_capability(seed)
        }
    }

    fn local_producer_facts(seed: u8) -> LocalMediaCapabilityFacts {
        LocalMediaCapabilityFacts::new(StorageMediaClass::NvmeFlash, capability_evidence(seed))
            .with_identity(LocalMediaIdentityFacts::stable(
                100 + u64::from(seed),
                capability_evidence(seed.wrapping_add(1)),
                capability_evidence(seed.wrapping_add(2)),
            ))
            .with_freshness(LocalFreshnessFacts::new(
                MediaCapabilityFreshnessState::Fresh,
                capability_evidence(seed.wrapping_add(3)),
            ))
    }

    fn remote_archive_facts(seed: u8) -> RemoteMediaCapabilityFacts {
        RemoteMediaCapabilityFacts::new(StorageMediaClass::TapeArchive, capability_evidence(seed))
            .with_identity(RemoteTargetIdentityFacts::stable(
                500 + u64::from(seed),
                capability_evidence(seed.wrapping_add(1)),
                capability_evidence(seed.wrapping_add(2)),
            ))
            .with_path(RemotePathFacts::tcp_or_internet_legal(
                evidence_with_generation(
                    StorageIntentEvidenceKind::TransportPathEvidence,
                    seed.wrapping_add(3),
                    1_000 + u64::from(seed),
                ),
            ))
            .with_commit(
                RemoteCommitFacts::new(
                    MediaPersistenceDomain::ArchiveDurable,
                    MediaFlushOrderingClass::ArchiveCommit,
                    MediaAtomicityClass::AppendRecordAtomic,
                    MediaProtocolGeometryClass::ArchiveSequential,
                    MediaRemoteCommitSemantics::ArchiveRetained,
                    capability_evidence(seed.wrapping_add(4)),
                )
                .with_units(4096, 4096, 262_144),
            )
            .with_archive(RemoteArchiveFacts::new(
                MediaArchiveRestoreSemantics::RestoreAudited,
                evidence_with_generation(
                    StorageIntentEvidenceKind::MediaCapabilityEvidence,
                    seed.wrapping_add(5),
                    2_000 + u64::from(seed),
                ),
            ))
            .with_freshness(RemoteFreshnessFacts::fresh_zero_lag(evidence(
                StorageIntentEvidenceKind::TemporalEvidence,
                seed.wrapping_add(6),
            )))
            .with_trust(RemoteTrustFacts::trusted(evidence_with_generation(
                StorageIntentEvidenceKind::TrustDomainEvidence,
                seed.wrapping_add(7),
                3_000 + u64::from(seed),
            )))
            .with_cost_recovery(RemoteCostRecoveryFacts::bounded(
                evidence(
                    StorageIntentEvidenceKind::MediaCostWearLedger,
                    seed.wrapping_add(8),
                ),
                evidence(
                    StorageIntentEvidenceKind::RecoveryDegradationEvidence,
                    seed.wrapping_add(9),
                ),
            ))
            .with_health(RemoteHealthFacts::new(
                MediaHealthState::Healthy,
                evidence_with_generation(
                    StorageIntentEvidenceKind::MediaCapabilityEvidence,
                    seed.wrapping_add(10),
                    4_000 + u64::from(seed),
                ),
            ))
            .with_max_queue_depth(32)
            .with_latency_class_us(5_000)
    }

    fn generation(
        capability: StorageIntentMediaCapabilityRecord,
    ) -> MediaCapabilityGenerationRecord {
        MediaCapabilityGenerationRecord::from_capability(capability)
            .with_producer_id(evidence_id(90))
            .with_evidence_cut(evidence_cut(91))
            .with_timebase(evidence(StorageIntentEvidenceKind::TemporalEvidence, 92))
            .with_clock_skew(evidence(StorageIntentEvidenceKind::TemporalEvidence, 95))
            .with_retention(MediaCapabilityRetentionState::Exact, retention_ref(93))
            .with_path_generations(10_000, 11_000)
            .with_remote_generations(12_000, 13_000, 14_000, 15_000)
            .with_archive_retention_generation(16_000)
            .with_sample_window(1_000, 1_050, 10_000)
    }

    fn evaluate(
        capability: StorageIntentMediaCapabilityRecord,
        generation: MediaCapabilityGenerationRecord,
        role: MediaCapabilityUseRole,
    ) -> MediaCapabilityRefreshVerdict {
        media_capability_refresh_evaluate(MediaCapabilityRefreshInput::new(
            capability,
            generation,
            MediaCapabilityRefreshRequirement::for_role(role),
        ))
    }

    #[test]
    fn local_producer_facts_feed_refresh_generations_and_fail_closed_on_drift() {
        let baseline_facts = local_producer_facts(27);
        let mut observed_facts = baseline_facts;
        observed_facts.identity.namespace_generation += 1;
        observed_facts.identity.settings_generation += 1;
        observed_facts.freshness = LocalFreshnessFacts::new(
            MediaCapabilityFreshnessState::Stale,
            capability_evidence(31),
        );

        let baseline = MediaCapabilityGenerationRecord::from_local_producer_facts(baseline_facts)
            .with_evidence_cut(evidence_cut(97));
        let observed = MediaCapabilityGenerationRecord::from_local_producer_facts(observed_facts)
            .with_evidence_cut(evidence_cut(97));

        assert_eq!(
            baseline.target_identity_ref,
            baseline_facts.identity.stable_identity_ref
        );
        assert_eq!(
            baseline.namespace_generation,
            baseline_facts.identity.namespace_generation
        );
        assert_eq!(
            baseline.settings_generation,
            baseline_facts.identity.settings_generation
        );
        assert_eq!(
            baseline.freshness_ref,
            baseline_facts.freshness.freshness_ref
        );

        let drift = media_capability_generation_record_drift(baseline, observed);
        assert!(drift.intersects(MediaCapabilityInvalidationMask::NAMESPACE_IDENTITY_CHANGED));
        assert!(drift.intersects(MediaCapabilityInvalidationMask::FIRMWARE_OR_SETTINGS_CHANGED));
        assert!(drift.intersects(MediaCapabilityInvalidationMask::STALE_PROBE_AGE));

        let capability = produce_local_media_capability(observed_facts);
        let verdict = evaluate(
            capability,
            observed.with_invalidations(drift),
            MediaCapabilityUseRole::DurableSyncIntent,
        );
        assert_eq!(
            verdict.outcome,
            MediaCapabilityRefreshOutcome::RevalidationRequired
        );
        assert_eq!(
            verdict.refusal,
            StorageIntentRefusalReason::StaleMediaCapabilityEvidence
        );
        assert!(!verdict.authority_usable);
    }

    #[test]
    fn remote_producer_facts_feed_endpoint_key_trust_and_archive_generations() {
        let baseline_facts = remote_archive_facts(41);
        let mut observed_facts = baseline_facts;
        observed_facts.identity.endpoint_generation += 1;
        observed_facts.identity.credential_key_epoch += 1;
        observed_facts.path = RemotePathFacts::tcp_or_internet_legal(evidence_with_generation(
            StorageIntentEvidenceKind::TransportPathEvidence,
            44,
            baseline_facts.path.path_ref.generation + 1,
        ));
        observed_facts.archive = RemoteArchiveFacts::new(
            MediaArchiveRestoreSemantics::RestoreAudited,
            evidence_with_generation(
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
                45,
                baseline_facts.archive.archive_restore_ref.generation + 1,
            ),
        );
        observed_facts.trust = RemoteTrustFacts::trusted(evidence_with_generation(
            StorageIntentEvidenceKind::TrustDomainEvidence,
            46,
            baseline_facts.trust.trust_ref.generation + 1,
        ));

        let baseline = MediaCapabilityGenerationRecord::from_remote_producer_facts(baseline_facts)
            .with_evidence_cut(evidence_cut(98));
        let observed = MediaCapabilityGenerationRecord::from_remote_producer_facts(observed_facts)
            .with_evidence_cut(evidence_cut(98));

        assert_eq!(
            baseline.remote_endpoint_generation,
            baseline_facts.identity.endpoint_generation
        );
        assert_eq!(
            baseline.credential_key_epoch,
            baseline_facts.identity.credential_key_epoch
        );
        assert_eq!(
            baseline.path_generation,
            baseline_facts.path.path_ref.generation
        );
        assert_eq!(
            baseline.trust_generation,
            baseline_facts.trust.trust_ref.generation
        );
        assert_eq!(
            baseline.archive_retention_generation,
            baseline_facts.archive.archive_restore_ref.generation
        );

        let drift = media_capability_generation_record_drift(baseline, observed);
        assert!(drift.intersects(MediaCapabilityInvalidationMask::PATH_OR_MULTIPATH_CHANGED));
        assert!(drift.intersects(MediaCapabilityInvalidationMask::REMOTE_ENDPOINT_CHANGED));
        assert!(drift.intersects(MediaCapabilityInvalidationMask::CREDENTIAL_KEY_EPOCH_CHANGED));
        assert!(drift.intersects(MediaCapabilityInvalidationMask::TRUST_OR_QUARANTINE_CHANGED));
        assert!(drift.intersects(MediaCapabilityInvalidationMask::ARCHIVE_RETENTION_CHANGED));

        let capability = produce_remote_media_capability(observed_facts);
        let verdict = evaluate(
            capability,
            observed.with_invalidations(drift),
            MediaCapabilityUseRole::RemoteDurable,
        );
        assert_eq!(verdict.outcome, MediaCapabilityRefreshOutcome::Quarantined);
        assert_eq!(
            verdict.refusal,
            StorageIntentRefusalReason::QuarantinedSource
        );
        assert!(!verdict.authority_usable);
    }

    #[test]
    fn generation_record_health_degradation_is_an_invalidation_source() {
        let baseline = generation(block_capability(47));
        let observed = MediaCapabilityGenerationRecord {
            health: MediaHealthState::Degraded,
            ..baseline
        };

        let drift = media_capability_generation_record_drift(baseline, observed);
        assert!(drift.intersects(MediaCapabilityInvalidationMask::HEALTH_DEGRADED));

        let verdict = evaluate(
            block_capability(47),
            observed.with_invalidations(drift),
            MediaCapabilityUseRole::FullPlacement,
        );
        assert_eq!(
            verdict.outcome,
            MediaCapabilityRefreshOutcome::RevalidationRequired
        );
        assert_eq!(
            verdict.refusal,
            StorageIntentRefusalReason::StaleMediaCapabilityEvidence
        );
        assert!(!verdict.authority_usable);
    }

    #[test]
    fn stale_probe_blocks_durable_but_can_remain_cache_only() {
        let capability = block_capability(1);
        let generation = generation(capability).with_sample_window(1_000, 20_000, 1_000);

        let durable = evaluate(
            capability,
            generation,
            MediaCapabilityUseRole::DurableSyncIntent,
        );
        assert_eq!(
            durable.outcome,
            MediaCapabilityRefreshOutcome::RevalidationRequired
        );
        assert_eq!(
            durable.refusal,
            StorageIntentRefusalReason::StaleMediaCapabilityEvidence
        );
        assert!(!durable.authority_usable);

        let cache = evaluate(capability, generation, MediaCapabilityUseRole::CacheOnly);
        assert_eq!(cache.outcome, MediaCapabilityRefreshOutcome::StaleCacheOnly);
        assert!(cache.cache_only_usable);
        assert!(!cache.authority_usable);
    }

    #[test]
    fn generation_drift_invalidates_namespace_settings_and_pmem_fence() {
        let baseline = pmem_capability(3);
        let mut observed = baseline;
        observed.namespace_generation += 1;
        observed.settings_generation += 1;
        observed.flush_ordering = MediaFlushOrderingClass::FlushOnly;
        observed.flags = observed
            .flags
            .without(MediaCapabilityFlags::PMEM_FLUSH_FENCE);

        let drift = media_capability_generation_drift(baseline, observed);
        assert!(drift.intersects(MediaCapabilityInvalidationMask::NAMESPACE_IDENTITY_CHANGED));
        assert!(drift.intersects(MediaCapabilityInvalidationMask::FIRMWARE_OR_SETTINGS_CHANGED));
        assert!(drift.intersects(MediaCapabilityInvalidationMask::PMEM_FLUSH_FENCE_CHANGED));

        let verdict = evaluate(
            observed,
            generation(observed).with_invalidations(drift),
            MediaCapabilityUseRole::PmemDurableAuthority,
        );
        assert_eq!(
            verdict.outcome,
            MediaCapabilityRefreshOutcome::RevalidationRequired
        );
        assert!(!verdict.authority_usable);
    }

    #[test]
    fn volatile_cache_and_fua_policy_drift_require_revalidation() {
        let baseline = block_capability(5);
        let observed = StorageIntentMediaCapabilityRecord {
            persistence: MediaPersistenceDomain::PlpBackedVolatileCache,
            flush_ordering: MediaFlushOrderingClass::FlushOnly,
            ..baseline
        };

        let drift = media_capability_generation_drift(baseline, observed);
        assert!(drift.intersects(MediaCapabilityInvalidationMask::WRITE_CACHE_POLICY_CHANGED));
        assert!(drift.intersects(MediaCapabilityInvalidationMask::FLUSH_FUA_POLICY_CHANGED));

        let verdict = evaluate(
            observed,
            generation(observed).with_invalidations(drift),
            MediaCapabilityUseRole::BlockVolumeFuaFlush,
        );
        assert_eq!(
            verdict.outcome,
            MediaCapabilityRefreshOutcome::RevalidationRequired
        );
        assert_eq!(
            verdict.refusal,
            StorageIntentRefusalReason::StaleMediaCapabilityEvidence
        );
        assert!(!verdict.authority_usable);
    }

    #[test]
    fn device_reset_drift_blocks_full_placement_and_geo_replica() {
        let baseline = remote_object_capability(6);
        let observed = StorageIntentMediaCapabilityRecord {
            identity_generation: baseline.identity_generation + 1,
            ..baseline
        };

        let drift = media_capability_generation_drift(baseline, observed);
        assert!(drift.intersects(MediaCapabilityInvalidationMask::DEVICE_RESET));

        let full_placement = evaluate(
            observed,
            generation(observed).with_invalidations(drift),
            MediaCapabilityUseRole::FullPlacement,
        );
        assert_eq!(
            full_placement.outcome,
            MediaCapabilityRefreshOutcome::RevalidationRequired
        );
        assert!(!full_placement.authority_usable);

        let geo = evaluate(
            observed,
            generation(observed).with_invalidations(drift),
            MediaCapabilityUseRole::GeoReplica,
        );
        assert_eq!(
            geo.outcome,
            MediaCapabilityRefreshOutcome::RevalidationRequired
        );
        assert!(!geo.authority_usable);
    }

    #[test]
    fn rdma_absence_is_not_a_remote_correctness_blocker_but_key_epoch_is() {
        let capability = remote_object_capability(7);

        let fresh = evaluate(
            capability,
            generation(capability),
            MediaCapabilityUseRole::RemoteDurable,
        );
        assert_eq!(fresh.outcome, MediaCapabilityRefreshOutcome::FreshForRole);
        assert!(fresh.authority_usable);

        let invalidated = generation(capability)
            .with_invalidations(MediaCapabilityInvalidationMask::CREDENTIAL_KEY_EPOCH_CHANGED);
        let durable = evaluate(
            capability,
            invalidated,
            MediaCapabilityUseRole::RemoteDurable,
        );
        assert_eq!(durable.outcome, MediaCapabilityRefreshOutcome::Quarantined);
        assert!(!durable.authority_usable);

        let feedback = evaluate(
            capability,
            invalidated,
            MediaCapabilityUseRole::FeedbackTraining,
        );
        assert_eq!(feedback.outcome, MediaCapabilityRefreshOutcome::Quarantined);
        assert!(!feedback.authority_usable);
    }

    #[test]
    fn remote_generation_drift_blocks_remote_durable_feedback_and_archive_reuse() {
        let capability = remote_object_capability(9);
        let baseline = generation(capability);
        let observed = generation(capability)
            .with_path_generations(
                baseline.path_generation + 1,
                baseline.multipath_generation + 1,
            )
            .with_remote_generations(
                baseline.remote_endpoint_generation + 1,
                baseline.credential_key_epoch + 1,
                baseline.trust_generation + 1,
                baseline.quarantine_generation + 1,
            )
            .with_archive_retention_generation(baseline.archive_retention_generation + 1);

        let drift = media_capability_generation_record_drift(baseline, observed);
        assert!(drift.intersects(MediaCapabilityInvalidationMask::PATH_OR_MULTIPATH_CHANGED));
        assert!(drift.intersects(MediaCapabilityInvalidationMask::REMOTE_ENDPOINT_CHANGED));
        assert!(drift.intersects(MediaCapabilityInvalidationMask::CREDENTIAL_KEY_EPOCH_CHANGED));
        assert!(drift.intersects(MediaCapabilityInvalidationMask::TRUST_OR_QUARANTINE_CHANGED));
        assert!(drift.intersects(MediaCapabilityInvalidationMask::ARCHIVE_RETENTION_CHANGED));

        let remote = evaluate(
            capability,
            observed.with_invalidations(drift),
            MediaCapabilityUseRole::RemoteDurable,
        );
        assert_eq!(remote.outcome, MediaCapabilityRefreshOutcome::Quarantined);
        assert!(!remote.authority_usable);

        let feedback = evaluate(
            capability,
            observed.with_invalidations(drift),
            MediaCapabilityUseRole::FeedbackTraining,
        );
        assert_eq!(feedback.outcome, MediaCapabilityRefreshOutcome::Quarantined);
        assert!(!feedback.authority_usable);
    }

    #[test]
    fn compacted_history_blocks_promotion_but_not_cache_only_diagnosis() {
        let capability = block_capability(11);
        let compacted = generation(capability).with_retention(
            MediaCapabilityRetentionState::CompactedBeyondAuthority,
            retention_ref(94),
        );

        let promotion = evaluate(
            capability,
            compacted,
            MediaCapabilityUseRole::PromotionDemotion,
        );
        assert_eq!(promotion.outcome, MediaCapabilityRefreshOutcome::Blocked);
        assert_eq!(
            promotion.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let cache = evaluate(capability, compacted, MediaCapabilityUseRole::CacheOnly);
        assert_eq!(cache.outcome, MediaCapabilityRefreshOutcome::StaleCacheOnly);
        assert!(cache.cache_only_usable);
    }

    #[test]
    fn redacted_history_blocks_geo_but_not_prefetch_staging() {
        let capability = remote_object_capability(13);
        let redacted = generation(capability).with_retention(
            MediaCapabilityRetentionState::RedactedBeyondUse,
            retention_ref(96),
        );

        let geo = evaluate(capability, redacted, MediaCapabilityUseRole::GeoReplica);
        assert_eq!(geo.outcome, MediaCapabilityRefreshOutcome::Blocked);
        assert_eq!(geo.refusal, StorageIntentRefusalReason::EvidenceNotUsable);
        assert!(!geo.authority_usable);

        let prefetch = evaluate(
            capability,
            redacted,
            MediaCapabilityUseRole::PrefetchOrStaging,
        );
        assert_eq!(
            prefetch.outcome,
            MediaCapabilityRefreshOutcome::StaleCacheOnly
        );
        assert!(prefetch.cache_only_usable);
        assert!(!prefetch.authority_usable);
    }

    #[test]
    fn contradictory_and_quarantined_evidence_fail_closed() {
        let capability = block_capability(17);
        let contradicted = generation(capability)
            .with_invalidations(MediaCapabilityInvalidationMask::CONTRADICTED);
        let verdict = evaluate(
            capability,
            contradicted,
            MediaCapabilityUseRole::DurableSyncIntent,
        );
        assert_eq!(
            verdict.outcome,
            MediaCapabilityRefreshOutcome::Contradictory
        );
        assert_eq!(
            verdict.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let quarantined = StorageIntentMediaCapabilityRecord {
            health: MediaHealthState::Quarantined,
            ..capability
        };
        let verdict = evaluate(
            quarantined,
            generation(quarantined),
            MediaCapabilityUseRole::DurableSyncIntent,
        );
        assert_eq!(verdict.outcome, MediaCapabilityRefreshOutcome::Quarantined);
        assert_eq!(
            verdict.refusal,
            StorageIntentRefusalReason::QuarantinedSource
        );
    }

    #[test]
    fn archive_retention_change_blocks_archive_authority() {
        let baseline = archive_capability(23);
        let observed = StorageIntentMediaCapabilityRecord {
            archive_restore: MediaArchiveRestoreSemantics::RestoreUnbounded,
            ..baseline
        };
        let drift = media_capability_generation_drift(baseline, observed);
        assert!(drift.intersects(MediaCapabilityInvalidationMask::ARCHIVE_RETENTION_CHANGED));

        let verdict = evaluate(
            observed,
            generation(observed).with_invalidations(drift),
            MediaCapabilityUseRole::ArchiveAuthority,
        );
        assert_eq!(
            verdict.outcome,
            MediaCapabilityRefreshOutcome::RevalidationRequired
        );
        assert_eq!(
            verdict.refusal,
            StorageIntentRefusalReason::StaleMediaCapabilityEvidence
        );
    }
}
