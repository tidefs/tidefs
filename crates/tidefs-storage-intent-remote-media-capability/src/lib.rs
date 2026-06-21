// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Remote, object, and archive media-capability producer records.
//!
//! This crate is the first #961 source slice. It does not measure transport,
//! contact object services, execute remote movers, emit receipts, or score
//! placement. It maps already-collected remote facts into
//! [`StorageIntentMediaCapabilityRecord`] so downstream storage-intent
//! consumers can use the #904 role predicate instead of treating remote
//! reachability, object `put`, service labels, or RDMA capability as proof.

use tidefs_storage_intent_core::{
    MediaArchiveRestoreSemantics, MediaAtomicityClass, MediaCapabilityFlags,
    MediaCapabilityFreshnessState, MediaFlushOrderingClass, MediaHealthState,
    MediaPersistenceDomain, MediaProtocolGeometryClass, MediaRemoteCommitSemantics,
    StorageIntentEvidenceId, StorageIntentEvidenceKind, StorageIntentEvidenceRef,
    StorageIntentMediaCapabilityRecord, StorageIntentRefusalReason, StorageMediaClass,
};

/// Version of the remote media-capability producer record shape.
pub const REMOTE_MEDIA_CAPABILITY_PRODUCER_VERSION: u16 = 1;

/// Stable producer identifier for operator explanations and fixture tests.
pub const REMOTE_MEDIA_CAPABILITY_PRODUCER_SPEC: &str =
    "tidefs-storage-intent-remote-media-capability-v1-issue-961";

const EMPTY_EVIDENCE_REF: StorageIntentEvidenceRef = StorageIntentEvidenceRef {
    kind: StorageIntentEvidenceKind::Unknown,
    id: StorageIntentEvidenceId::ZERO,
    generation: 0,
    version: 0,
};

/// Stable identity and generation facts for a remote target.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RemoteTargetIdentityFacts {
    pub stable_target_identity: bool,
    pub stable_namespace_identity: bool,
    pub pool_member_binding: bool,
    pub endpoint_generation_proven: bool,
    pub credential_key_epoch_proven: bool,
    pub identity_generation: u64,
    pub namespace_generation: u64,
    pub endpoint_generation: u64,
    pub credential_key_epoch: u64,
    pub pool_member_generation: u64,
    pub stable_identity_ref: StorageIntentEvidenceRef,
    pub namespace_identity_ref: StorageIntentEvidenceRef,
}

impl RemoteTargetIdentityFacts {
    /// Build identity facts that satisfy durable remote-role identity gates.
    #[must_use]
    pub const fn stable(
        generation: u64,
        stable_identity_ref: StorageIntentEvidenceRef,
        namespace_identity_ref: StorageIntentEvidenceRef,
    ) -> Self {
        Self {
            stable_target_identity: true,
            stable_namespace_identity: true,
            pool_member_binding: true,
            endpoint_generation_proven: true,
            credential_key_epoch_proven: true,
            identity_generation: generation,
            namespace_generation: generation,
            endpoint_generation: generation,
            credential_key_epoch: generation,
            pool_member_generation: generation,
            stable_identity_ref,
            namespace_identity_ref,
        }
    }
}

/// Remote path and carrier facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemotePathFacts {
    pub rdma_absent_is_legal: bool,
    pub rdma_required_for_correctness: bool,
    pub path_ref: StorageIntentEvidenceRef,
}

impl Default for RemotePathFacts {
    fn default() -> Self {
        Self {
            rdma_absent_is_legal: false,
            rdma_required_for_correctness: false,
            path_ref: EMPTY_EVIDENCE_REF,
        }
    }
}

impl RemotePathFacts {
    #[must_use]
    pub const fn tcp_or_internet_legal(path_ref: StorageIntentEvidenceRef) -> Self {
        Self {
            rdma_absent_is_legal: true,
            rdma_required_for_correctness: false,
            path_ref,
        }
    }

    #[must_use]
    pub const fn rdma_only(path_ref: StorageIntentEvidenceRef) -> Self {
        Self {
            rdma_absent_is_legal: false,
            rdma_required_for_correctness: true,
            path_ref,
        }
    }
}

/// Remote/object/archive commit and protocol facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteCommitFacts {
    pub persistence: MediaPersistenceDomain,
    pub flush_ordering: MediaFlushOrderingClass,
    pub atomicity: MediaAtomicityClass,
    pub geometry: MediaProtocolGeometryClass,
    pub remote_commit: MediaRemoteCommitSemantics,
    pub logical_unit_bytes: u32,
    pub atomic_unit_bytes: u32,
    pub optimal_io_bytes: u32,
    pub remote_commit_ref: StorageIntentEvidenceRef,
}

impl Default for RemoteCommitFacts {
    fn default() -> Self {
        Self {
            persistence: MediaPersistenceDomain::Unknown,
            flush_ordering: MediaFlushOrderingClass::Unknown,
            atomicity: MediaAtomicityClass::Unknown,
            geometry: MediaProtocolGeometryClass::Unknown,
            remote_commit: MediaRemoteCommitSemantics::Unknown,
            logical_unit_bytes: 0,
            atomic_unit_bytes: 0,
            optimal_io_bytes: 0,
            remote_commit_ref: EMPTY_EVIDENCE_REF,
        }
    }
}

impl RemoteCommitFacts {
    #[must_use]
    pub const fn new(
        persistence: MediaPersistenceDomain,
        flush_ordering: MediaFlushOrderingClass,
        atomicity: MediaAtomicityClass,
        geometry: MediaProtocolGeometryClass,
        remote_commit: MediaRemoteCommitSemantics,
        remote_commit_ref: StorageIntentEvidenceRef,
    ) -> Self {
        Self {
            persistence,
            flush_ordering,
            atomicity,
            geometry,
            remote_commit,
            logical_unit_bytes: 0,
            atomic_unit_bytes: 0,
            optimal_io_bytes: 0,
            remote_commit_ref,
        }
    }

    #[must_use]
    pub const fn with_units(
        mut self,
        logical_unit_bytes: u32,
        atomic_unit_bytes: u32,
        optimal_io_bytes: u32,
    ) -> Self {
        self.logical_unit_bytes = logical_unit_bytes;
        self.atomic_unit_bytes = atomic_unit_bytes;
        self.optimal_io_bytes = optimal_io_bytes;
        self
    }
}

/// Archive restore and retention facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteArchiveFacts {
    pub restore: MediaArchiveRestoreSemantics,
    pub archive_restore_ref: StorageIntentEvidenceRef,
}

impl Default for RemoteArchiveFacts {
    fn default() -> Self {
        Self {
            restore: MediaArchiveRestoreSemantics::NotArchive,
            archive_restore_ref: EMPTY_EVIDENCE_REF,
        }
    }
}

impl RemoteArchiveFacts {
    #[must_use]
    pub const fn new(
        restore: MediaArchiveRestoreSemantics,
        archive_restore_ref: StorageIntentEvidenceRef,
    ) -> Self {
        Self {
            restore,
            archive_restore_ref,
        }
    }
}

/// Freshness, lag, and timebase facts for a remote target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteFreshnessFacts {
    pub freshness: MediaCapabilityFreshnessState,
    pub rpo_lag_known: bool,
    pub rpo_lag_ms: u64,
    pub timebase_fresh: bool,
    pub freshness_ref: StorageIntentEvidenceRef,
}

impl Default for RemoteFreshnessFacts {
    fn default() -> Self {
        Self {
            freshness: MediaCapabilityFreshnessState::Missing,
            rpo_lag_known: false,
            rpo_lag_ms: 0,
            timebase_fresh: false,
            freshness_ref: EMPTY_EVIDENCE_REF,
        }
    }
}

impl RemoteFreshnessFacts {
    #[must_use]
    pub const fn fresh_zero_lag(freshness_ref: StorageIntentEvidenceRef) -> Self {
        Self {
            freshness: MediaCapabilityFreshnessState::Fresh,
            rpo_lag_known: true,
            rpo_lag_ms: 0,
            timebase_fresh: true,
            freshness_ref,
        }
    }

    #[must_use]
    pub const fn with_lag_ms(mut self, lag_ms: u64) -> Self {
        self.rpo_lag_ms = lag_ms;
        self
    }
}

/// Trust, key, authorization, audit, and residency facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteTrustFacts {
    pub authenticated_principal: bool,
    pub domain_compatible: bool,
    pub key_epoch_fresh: bool,
    pub authorization_present: bool,
    pub audit_present: bool,
    pub residency_compatible: bool,
    pub trust_ref: StorageIntentEvidenceRef,
}

impl Default for RemoteTrustFacts {
    fn default() -> Self {
        Self {
            authenticated_principal: false,
            domain_compatible: false,
            key_epoch_fresh: false,
            authorization_present: false,
            audit_present: false,
            residency_compatible: false,
            trust_ref: EMPTY_EVIDENCE_REF,
        }
    }
}

impl RemoteTrustFacts {
    #[must_use]
    pub const fn trusted(trust_ref: StorageIntentEvidenceRef) -> Self {
        Self {
            authenticated_principal: true,
            domain_compatible: true,
            key_epoch_fresh: true,
            authorization_present: true,
            audit_present: true,
            residency_compatible: true,
            trust_ref,
        }
    }
}

/// Cost, egress, restore, and degraded-recovery visibility facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteCostRecoveryFacts {
    pub egress_budget_known: bool,
    pub egress_budget_exhausted: bool,
    pub restore_cost_known: bool,
    pub recovery_bandwidth_known: bool,
    pub degraded_visibility_known: bool,
    pub cost_ref: StorageIntentEvidenceRef,
    pub recovery_ref: StorageIntentEvidenceRef,
}

impl Default for RemoteCostRecoveryFacts {
    fn default() -> Self {
        Self {
            egress_budget_known: false,
            egress_budget_exhausted: false,
            restore_cost_known: false,
            recovery_bandwidth_known: false,
            degraded_visibility_known: false,
            cost_ref: EMPTY_EVIDENCE_REF,
            recovery_ref: EMPTY_EVIDENCE_REF,
        }
    }
}

impl RemoteCostRecoveryFacts {
    #[must_use]
    pub const fn bounded(
        cost_ref: StorageIntentEvidenceRef,
        recovery_ref: StorageIntentEvidenceRef,
    ) -> Self {
        Self {
            egress_budget_known: true,
            egress_budget_exhausted: false,
            restore_cost_known: true,
            recovery_bandwidth_known: true,
            degraded_visibility_known: true,
            cost_ref,
            recovery_ref,
        }
    }
}

/// Remote health verdict facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteHealthFacts {
    pub health: MediaHealthState,
    pub health_ref: StorageIntentEvidenceRef,
}

impl Default for RemoteHealthFacts {
    fn default() -> Self {
        Self {
            health: MediaHealthState::Unknown,
            health_ref: EMPTY_EVIDENCE_REF,
        }
    }
}

impl RemoteHealthFacts {
    #[must_use]
    pub const fn new(health: MediaHealthState, health_ref: StorageIntentEvidenceRef) -> Self {
        Self { health, health_ref }
    }
}

/// Complete remote producer input for one target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteMediaCapabilityFacts {
    pub media_class: StorageMediaClass,
    pub evidence: StorageIntentEvidenceRef,
    pub identity: RemoteTargetIdentityFacts,
    pub path: RemotePathFacts,
    pub commit: RemoteCommitFacts,
    pub archive: RemoteArchiveFacts,
    pub freshness: RemoteFreshnessFacts,
    pub trust: RemoteTrustFacts,
    pub cost_recovery: RemoteCostRecoveryFacts,
    pub health: RemoteHealthFacts,
    pub max_queue_depth: u32,
    pub latency_class_us: u32,
}

impl RemoteMediaCapabilityFacts {
    #[must_use]
    pub const fn new(media_class: StorageMediaClass, evidence: StorageIntentEvidenceRef) -> Self {
        Self {
            media_class,
            evidence,
            identity: RemoteTargetIdentityFacts {
                stable_target_identity: false,
                stable_namespace_identity: false,
                pool_member_binding: false,
                endpoint_generation_proven: false,
                credential_key_epoch_proven: false,
                identity_generation: 0,
                namespace_generation: 0,
                endpoint_generation: 0,
                credential_key_epoch: 0,
                pool_member_generation: 0,
                stable_identity_ref: EMPTY_EVIDENCE_REF,
                namespace_identity_ref: EMPTY_EVIDENCE_REF,
            },
            path: RemotePathFacts {
                rdma_absent_is_legal: false,
                rdma_required_for_correctness: false,
                path_ref: EMPTY_EVIDENCE_REF,
            },
            commit: RemoteCommitFacts {
                persistence: MediaPersistenceDomain::Unknown,
                flush_ordering: MediaFlushOrderingClass::Unknown,
                atomicity: MediaAtomicityClass::Unknown,
                geometry: MediaProtocolGeometryClass::Unknown,
                remote_commit: MediaRemoteCommitSemantics::Unknown,
                logical_unit_bytes: 0,
                atomic_unit_bytes: 0,
                optimal_io_bytes: 0,
                remote_commit_ref: EMPTY_EVIDENCE_REF,
            },
            archive: RemoteArchiveFacts {
                restore: MediaArchiveRestoreSemantics::NotArchive,
                archive_restore_ref: EMPTY_EVIDENCE_REF,
            },
            freshness: RemoteFreshnessFacts {
                freshness: MediaCapabilityFreshnessState::Missing,
                rpo_lag_known: false,
                rpo_lag_ms: 0,
                timebase_fresh: false,
                freshness_ref: EMPTY_EVIDENCE_REF,
            },
            trust: RemoteTrustFacts {
                authenticated_principal: false,
                domain_compatible: false,
                key_epoch_fresh: false,
                authorization_present: false,
                audit_present: false,
                residency_compatible: false,
                trust_ref: EMPTY_EVIDENCE_REF,
            },
            cost_recovery: RemoteCostRecoveryFacts {
                egress_budget_known: false,
                egress_budget_exhausted: false,
                restore_cost_known: false,
                recovery_bandwidth_known: false,
                degraded_visibility_known: false,
                cost_ref: EMPTY_EVIDENCE_REF,
                recovery_ref: EMPTY_EVIDENCE_REF,
            },
            health: RemoteHealthFacts {
                health: MediaHealthState::Unknown,
                health_ref: EMPTY_EVIDENCE_REF,
            },
            max_queue_depth: 0,
            latency_class_us: 0,
        }
    }

    #[must_use]
    pub const fn with_identity(mut self, identity: RemoteTargetIdentityFacts) -> Self {
        self.identity = identity;
        self
    }

    #[must_use]
    pub const fn with_path(mut self, path: RemotePathFacts) -> Self {
        self.path = path;
        self
    }

    #[must_use]
    pub const fn with_commit(mut self, commit: RemoteCommitFacts) -> Self {
        self.commit = commit;
        self
    }

    #[must_use]
    pub const fn with_archive(mut self, archive: RemoteArchiveFacts) -> Self {
        self.archive = archive;
        self
    }

    #[must_use]
    pub const fn with_freshness(mut self, freshness: RemoteFreshnessFacts) -> Self {
        self.freshness = freshness;
        self
    }

    #[must_use]
    pub const fn with_trust(mut self, trust: RemoteTrustFacts) -> Self {
        self.trust = trust;
        self
    }

    #[must_use]
    pub const fn with_cost_recovery(mut self, cost_recovery: RemoteCostRecoveryFacts) -> Self {
        self.cost_recovery = cost_recovery;
        self
    }

    #[must_use]
    pub const fn with_health(mut self, health: RemoteHealthFacts) -> Self {
        self.health = health;
        self
    }

    #[must_use]
    pub const fn with_max_queue_depth(mut self, max_queue_depth: u32) -> Self {
        self.max_queue_depth = max_queue_depth;
        self
    }

    #[must_use]
    pub const fn with_latency_class_us(mut self, latency_class_us: u32) -> Self {
        self.latency_class_us = latency_class_us;
        self
    }
}

const fn evidence_ref_has_kind(
    evidence_ref: StorageIntentEvidenceRef,
    kind: StorageIntentEvidenceKind,
) -> bool {
    if evidence_ref.kind as u16 != kind as u16 {
        return false;
    }
    let mut index = 0;
    while index < evidence_ref.id.0.len() {
        if evidence_ref.id.0[index] != 0 {
            return true;
        }
        index += 1;
    }
    false
}

const fn remote_commit_flush_satisfies(
    commit: MediaRemoteCommitSemantics,
    flush_ordering: MediaFlushOrderingClass,
) -> bool {
    match commit {
        MediaRemoteCommitSemantics::DurableAck | MediaRemoteCommitSemantics::QuorumDurableAck => {
            flush_ordering.supports_remote_or_object_commit()
        }
        MediaRemoteCommitSemantics::ObjectConditionalDurable => {
            matches!(flush_ordering, MediaFlushOrderingClass::ObjectCommit)
        }
        MediaRemoteCommitSemantics::ArchiveRetained => flush_ordering.supports_archive_commit(),
        MediaRemoteCommitSemantics::Unknown
        | MediaRemoteCommitSemantics::NotRemote
        | MediaRemoteCommitSemantics::VolatileAckOnly
        | MediaRemoteCommitSemantics::RdmaRequiredOnly => false,
    }
}

const fn remote_target_is_archive(facts: RemoteMediaCapabilityFacts) -> bool {
    facts.media_class.is_archive()
        || matches!(
            facts.commit.persistence,
            MediaPersistenceDomain::ArchiveDurable
        )
        || matches!(
            facts.commit.remote_commit,
            MediaRemoteCommitSemantics::ArchiveRetained
        )
}

/// Return the first authority-blocking reason for a remote durable role.
#[must_use]
pub const fn remote_authority_preflight_refusal(
    facts: RemoteMediaCapabilityFacts,
) -> StorageIntentRefusalReason {
    if !evidence_ref_has_kind(
        facts.evidence,
        StorageIntentEvidenceKind::MediaCapabilityEvidence,
    ) {
        return StorageIntentRefusalReason::MissingMediaCapabilityEvidence;
    }
    match facts.freshness.freshness {
        MediaCapabilityFreshnessState::Fresh => {}
        MediaCapabilityFreshnessState::Missing => {
            return StorageIntentRefusalReason::MissingMediaCapabilityEvidence;
        }
        MediaCapabilityFreshnessState::Stale => {
            return StorageIntentRefusalReason::StaleMediaCapabilityEvidence;
        }
        MediaCapabilityFreshnessState::Contradictory | MediaCapabilityFreshnessState::Refused => {
            return StorageIntentRefusalReason::EvidenceNotUsable;
        }
    }
    if !facts.identity.stable_target_identity
        || !facts.identity.stable_namespace_identity
        || !facts.identity.pool_member_binding
        || !facts.identity.endpoint_generation_proven
        || !facts.identity.credential_key_epoch_proven
    {
        return StorageIntentRefusalReason::UnstableNamespaceIdentity;
    }
    if matches!(facts.health.health, MediaHealthState::Unknown) {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    if matches!(
        facts.health.health,
        MediaHealthState::Degraded | MediaHealthState::Failed | MediaHealthState::Quarantined
    ) {
        return StorageIntentRefusalReason::DegradedMediaHealth;
    }
    if facts.path.rdma_required_for_correctness
        || matches!(
            facts.commit.remote_commit,
            MediaRemoteCommitSemantics::RdmaRequiredOnly
        )
    {
        return StorageIntentRefusalReason::RdmaRequiredForCorrectness;
    }
    if !facts.commit.remote_commit.supports_durable_commit()
        || !remote_commit_flush_satisfies(facts.commit.remote_commit, facts.commit.flush_ordering)
    {
        return StorageIntentRefusalReason::UnsupportedRemoteCommitSemantics;
    }
    if !facts.freshness.rpo_lag_known || !facts.freshness.timebase_fresh {
        return StorageIntentRefusalReason::DurabilityOrRpoNotMet;
    }
    if !facts.trust.authenticated_principal {
        return StorageIntentRefusalReason::MissingAuthenticatedPrincipal;
    }
    if !facts.trust.domain_compatible {
        return StorageIntentRefusalReason::WrongDomain;
    }
    if !facts.trust.key_epoch_fresh {
        return StorageIntentRefusalReason::StaleKeyEpoch;
    }
    if !facts.trust.authorization_present {
        return StorageIntentRefusalReason::MissingAuthorization;
    }
    if !facts.trust.audit_present {
        return StorageIntentRefusalReason::MissingAudit;
    }
    if !facts.trust.residency_compatible {
        return StorageIntentRefusalReason::ResidencyViolation;
    }
    if !facts.cost_recovery.egress_budget_known
        || facts.cost_recovery.egress_budget_exhausted
        || !facts.cost_recovery.recovery_bandwidth_known
        || !facts.cost_recovery.degraded_visibility_known
    {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    if remote_target_is_archive(facts)
        && (!facts.cost_recovery.restore_cost_known
            || !facts.archive.restore.supports_retained_restore())
    {
        return StorageIntentRefusalReason::UnknownArchiveRestoreRetention;
    }
    StorageIntentRefusalReason::None
}

const fn remote_authority_ready(facts: RemoteMediaCapabilityFacts) -> bool {
    matches!(
        remote_authority_preflight_refusal(facts),
        StorageIntentRefusalReason::None
    )
}

/// Produce a #904 media-capability record from bounded remote facts.
#[must_use]
pub const fn produce_remote_media_capability(
    facts: RemoteMediaCapabilityFacts,
) -> StorageIntentMediaCapabilityRecord {
    let mut flags = MediaCapabilityFlags::EMPTY;

    if facts.identity.stable_target_identity {
        flags = flags.union(MediaCapabilityFlags::STABLE_DEVICE_IDENTITY);
    }
    if facts.identity.stable_namespace_identity {
        flags = flags.union(MediaCapabilityFlags::STABLE_NAMESPACE_IDENTITY);
    }
    if facts.identity.pool_member_binding {
        flags = flags.union(MediaCapabilityFlags::POOL_MEMBER_BINDING);
    }
    if facts.identity.endpoint_generation_proven && facts.identity.credential_key_epoch_proven {
        flags = flags.union(MediaCapabilityFlags::FIRMWARE_CAPABILITY_GENERATION);
    }
    if !matches!(facts.commit.persistence, MediaPersistenceDomain::Unknown) {
        flags = flags.union(MediaCapabilityFlags::PERSISTENCE_DOMAIN);
    }
    if !matches!(
        facts.commit.flush_ordering,
        MediaFlushOrderingClass::Unknown
    ) {
        flags = flags.union(MediaCapabilityFlags::FLUSH_FUA_ORDERING);
    }
    if !matches!(facts.commit.atomicity, MediaAtomicityClass::Unknown) {
        flags = flags.union(MediaCapabilityFlags::ATOMICITY_GRANULARITY);
    }
    if !matches!(facts.commit.geometry, MediaProtocolGeometryClass::Unknown) {
        flags = flags.union(MediaCapabilityFlags::PROTOCOL_GEOMETRY);
    }
    if !matches!(facts.health.health, MediaHealthState::Unknown) {
        flags = flags.union(MediaCapabilityFlags::HEALTH);
    }
    if !matches!(
        facts.freshness.freshness,
        MediaCapabilityFreshnessState::Missing
    ) {
        flags = flags.union(MediaCapabilityFlags::FRESHNESS);
    }
    if facts.path.rdma_absent_is_legal {
        flags = flags.union(MediaCapabilityFlags::TRANSPORT_RDMA_ABSENT_LEGAL);
    }
    if remote_authority_ready(facts)
        || facts.path.rdma_required_for_correctness
        || matches!(
            facts.commit.remote_commit,
            MediaRemoteCommitSemantics::RdmaRequiredOnly
        )
    {
        flags = flags.union(MediaCapabilityFlags::REMOTE_COMMIT);
    }
    if remote_authority_ready(facts)
        && facts.archive.restore.supports_retained_restore()
        && !facts.path.rdma_required_for_correctness
    {
        flags = flags.union(MediaCapabilityFlags::ARCHIVE_RESTORE_RETENTION);
    }

    StorageIntentMediaCapabilityRecord {
        media_class: facts.media_class,
        flags,
        identity_generation: facts.identity.identity_generation,
        namespace_generation: facts.identity.namespace_generation,
        firmware_generation: facts.identity.endpoint_generation,
        settings_generation: facts.identity.credential_key_epoch,
        pool_member_generation: facts.identity.pool_member_generation,
        persistence: facts.commit.persistence,
        flush_ordering: facts.commit.flush_ordering,
        atomicity: facts.commit.atomicity,
        geometry: facts.commit.geometry,
        health: facts.health.health,
        freshness: facts.freshness.freshness,
        remote_commit: facts.commit.remote_commit,
        archive_restore: facts.archive.restore,
        logical_block_bytes: facts.commit.logical_unit_bytes,
        physical_block_bytes: facts.commit.logical_unit_bytes,
        atomic_write_unit_bytes: facts.commit.atomic_unit_bytes,
        optimal_io_bytes: facts.commit.optimal_io_bytes,
        max_queue_depth: facts.max_queue_depth,
        latency_class_us: facts.latency_class_us,
        evidence: facts.evidence,
        stable_identity_ref: facts.identity.stable_identity_ref,
        namespace_identity_ref: facts.identity.namespace_identity_ref,
        persistence_ref: facts.commit.remote_commit_ref,
        flush_ref: facts.commit.remote_commit_ref,
        atomicity_ref: facts.commit.remote_commit_ref,
        geometry_ref: facts.path.path_ref,
        health_ref: facts.health.health_ref,
        freshness_ref: facts.freshness.freshness_ref,
        remote_commit_ref: facts.commit.remote_commit_ref,
        archive_restore_ref: facts.archive.archive_restore_ref,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_storage_intent_core::{
        media_capability_satisfies_role, MediaRoleRequirement, ReceiptPredicateResult,
        StorageIntentGuaranteeClass, StorageMediaRole,
    };

    fn evidence(kind: StorageIntentEvidenceKind, seed: u8) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(
            kind,
            StorageIntentEvidenceId([seed; 32]),
            u64::from(seed),
            REMOTE_MEDIA_CAPABILITY_PRODUCER_VERSION,
        )
    }

    fn media_evidence(seed: u8) -> StorageIntentEvidenceRef {
        evidence(StorageIntentEvidenceKind::MediaCapabilityEvidence, seed)
    }

    fn strong_object_facts() -> RemoteMediaCapabilityFacts {
        RemoteMediaCapabilityFacts::new(StorageMediaClass::CloudObject, media_evidence(1))
            .with_identity(RemoteTargetIdentityFacts::stable(
                21,
                media_evidence(2),
                media_evidence(3),
            ))
            .with_path(RemotePathFacts::tcp_or_internet_legal(evidence(
                StorageIntentEvidenceKind::TransportPathEvidence,
                4,
            )))
            .with_commit(
                RemoteCommitFacts::new(
                    MediaPersistenceDomain::ObjectDurable,
                    MediaFlushOrderingClass::ObjectCommit,
                    MediaAtomicityClass::IdempotentObjectPut,
                    MediaProtocolGeometryClass::RemoteObject,
                    MediaRemoteCommitSemantics::ObjectConditionalDurable,
                    media_evidence(5),
                )
                .with_units(1, 1, 4 * 1024 * 1024),
            )
            .with_archive(RemoteArchiveFacts::new(
                MediaArchiveRestoreSemantics::NotArchive,
                EMPTY_EVIDENCE_REF,
            ))
            .with_freshness(RemoteFreshnessFacts::fresh_zero_lag(evidence(
                StorageIntentEvidenceKind::TemporalEvidence,
                6,
            )))
            .with_trust(RemoteTrustFacts::trusted(evidence(
                StorageIntentEvidenceKind::TrustDomainEvidence,
                7,
            )))
            .with_cost_recovery(RemoteCostRecoveryFacts::bounded(
                evidence(StorageIntentEvidenceKind::MediaCostWearLedger, 8),
                evidence(StorageIntentEvidenceKind::RecoveryDegradationEvidence, 9),
            ))
            .with_health(RemoteHealthFacts::new(
                MediaHealthState::Healthy,
                media_evidence(10),
            ))
            .with_max_queue_depth(128)
            .with_latency_class_us(25_000)
    }

    fn strong_archive_facts() -> RemoteMediaCapabilityFacts {
        RemoteMediaCapabilityFacts::new(StorageMediaClass::TapeArchive, media_evidence(31))
            .with_identity(RemoteTargetIdentityFacts::stable(
                41,
                media_evidence(32),
                media_evidence(33),
            ))
            .with_path(RemotePathFacts::tcp_or_internet_legal(evidence(
                StorageIntentEvidenceKind::TransportPathEvidence,
                34,
            )))
            .with_commit(RemoteCommitFacts::new(
                MediaPersistenceDomain::ArchiveDurable,
                MediaFlushOrderingClass::ArchiveCommit,
                MediaAtomicityClass::AppendRecordAtomic,
                MediaProtocolGeometryClass::ArchiveSequential,
                MediaRemoteCommitSemantics::ArchiveRetained,
                media_evidence(35),
            ))
            .with_archive(RemoteArchiveFacts::new(
                MediaArchiveRestoreSemantics::RestoreAudited,
                media_evidence(36),
            ))
            .with_freshness(RemoteFreshnessFacts::fresh_zero_lag(evidence(
                StorageIntentEvidenceKind::TemporalEvidence,
                37,
            )))
            .with_trust(RemoteTrustFacts::trusted(evidence(
                StorageIntentEvidenceKind::TrustDomainEvidence,
                38,
            )))
            .with_cost_recovery(RemoteCostRecoveryFacts::bounded(
                evidence(StorageIntentEvidenceKind::MediaCostWearLedger, 39),
                evidence(StorageIntentEvidenceKind::RecoveryDegradationEvidence, 40),
            ))
            .with_health(RemoteHealthFacts::new(
                MediaHealthState::Healthy,
                media_evidence(41),
            ))
            .with_latency_class_us(5_000_000)
    }

    fn placement_result(record: StorageIntentMediaCapabilityRecord) -> ReceiptPredicateResult {
        media_capability_satisfies_role(
            MediaRoleRequirement::AUTHORITY,
            StorageIntentGuaranteeClass::FullPlacement,
            StorageMediaRole::PlacementAuthority,
            record,
        )
    }

    fn archive_result(record: StorageIntentMediaCapabilityRecord) -> ReceiptPredicateResult {
        media_capability_satisfies_role(
            MediaRoleRequirement::AUTHORITY,
            StorageIntentGuaranteeClass::ArchiveEc,
            StorageMediaRole::ArchiveEc,
            record,
        )
    }

    #[test]
    fn object_target_can_satisfy_remote_placement_without_rdma_requirement() {
        let facts = strong_object_facts();
        let record = produce_remote_media_capability(facts);
        let result = placement_result(record);

        assert_eq!(
            remote_authority_preflight_refusal(facts),
            StorageIntentRefusalReason::None
        );
        assert!(result.satisfied);
        assert!(record.flags.contains_all(
            MediaCapabilityFlags::REMOTE_COMMIT
                .union(MediaCapabilityFlags::TRANSPORT_RDMA_ABSENT_LEGAL)
        ));
    }

    #[test]
    fn object_put_or_endpoint_label_without_commit_semantics_refuses() {
        let facts = strong_object_facts().with_commit(RemoteCommitFacts::new(
            MediaPersistenceDomain::ObjectDurable,
            MediaFlushOrderingClass::Unknown,
            MediaAtomicityClass::IdempotentObjectPut,
            MediaProtocolGeometryClass::RemoteObject,
            MediaRemoteCommitSemantics::VolatileAckOnly,
            media_evidence(5),
        ));
        let record = produce_remote_media_capability(facts);

        assert_eq!(
            remote_authority_preflight_refusal(facts),
            StorageIntentRefusalReason::UnsupportedRemoteCommitSemantics
        );
        assert_eq!(
            placement_result(record).refusal,
            StorageIntentRefusalReason::UnsupportedRemoteCommitSemantics
        );
    }

    #[test]
    fn rdma_only_correctness_assumption_refuses_remote_authority() {
        let facts = strong_object_facts()
            .with_path(RemotePathFacts::rdma_only(evidence(
                StorageIntentEvidenceKind::TransportPathEvidence,
                4,
            )))
            .with_commit(RemoteCommitFacts::new(
                MediaPersistenceDomain::ObjectDurable,
                MediaFlushOrderingClass::ObjectCommit,
                MediaAtomicityClass::IdempotentObjectPut,
                MediaProtocolGeometryClass::RemoteObject,
                MediaRemoteCommitSemantics::RdmaRequiredOnly,
                media_evidence(5),
            ));
        let record = produce_remote_media_capability(facts);

        assert_eq!(
            remote_authority_preflight_refusal(facts),
            StorageIntentRefusalReason::RdmaRequiredForCorrectness
        );
        assert_eq!(
            placement_result(record).refusal,
            StorageIntentRefusalReason::RdmaRequiredForCorrectness
        );
    }

    #[test]
    fn stale_endpoint_or_namespace_identity_refuses() {
        let mut identity =
            RemoteTargetIdentityFacts::stable(21, media_evidence(2), media_evidence(3));
        identity.stable_namespace_identity = false;
        let facts = strong_object_facts().with_identity(identity);
        let record = produce_remote_media_capability(facts);

        assert_eq!(
            remote_authority_preflight_refusal(facts),
            StorageIntentRefusalReason::UnstableNamespaceIdentity
        );
        assert_eq!(
            placement_result(record).refusal,
            StorageIntentRefusalReason::UnstableNamespaceIdentity
        );
    }

    #[test]
    fn unknown_rpo_or_stale_freshness_fails_closed() {
        let unknown_rpo = strong_object_facts().with_freshness(RemoteFreshnessFacts {
            rpo_lag_known: false,
            ..RemoteFreshnessFacts::fresh_zero_lag(evidence(
                StorageIntentEvidenceKind::TemporalEvidence,
                6,
            ))
        });
        let stale = strong_object_facts().with_freshness(RemoteFreshnessFacts {
            freshness: MediaCapabilityFreshnessState::Stale,
            ..RemoteFreshnessFacts::fresh_zero_lag(evidence(
                StorageIntentEvidenceKind::TemporalEvidence,
                6,
            ))
        });

        assert_eq!(
            remote_authority_preflight_refusal(unknown_rpo),
            StorageIntentRefusalReason::DurabilityOrRpoNotMet
        );
        assert_eq!(
            placement_result(produce_remote_media_capability(unknown_rpo)).refusal,
            StorageIntentRefusalReason::UnsupportedRemoteCommitSemantics
        );
        assert_eq!(
            placement_result(produce_remote_media_capability(stale)).refusal,
            StorageIntentRefusalReason::StaleMediaCapabilityEvidence
        );
    }

    #[test]
    fn wrong_trust_domain_or_missing_audit_never_trains_into_authority() {
        let wrong_domain = strong_object_facts().with_trust(RemoteTrustFacts {
            domain_compatible: false,
            ..RemoteTrustFacts::trusted(evidence(StorageIntentEvidenceKind::TrustDomainEvidence, 7))
        });
        let missing_audit = strong_object_facts().with_trust(RemoteTrustFacts {
            audit_present: false,
            ..RemoteTrustFacts::trusted(evidence(StorageIntentEvidenceKind::TrustDomainEvidence, 7))
        });

        assert_eq!(
            remote_authority_preflight_refusal(wrong_domain),
            StorageIntentRefusalReason::WrongDomain
        );
        assert_eq!(
            remote_authority_preflight_refusal(missing_audit),
            StorageIntentRefusalReason::MissingAudit
        );
        assert_eq!(
            placement_result(produce_remote_media_capability(wrong_domain)).refusal,
            StorageIntentRefusalReason::UnsupportedRemoteCommitSemantics
        );
        assert_eq!(
            placement_result(produce_remote_media_capability(missing_audit)).refusal,
            StorageIntentRefusalReason::UnsupportedRemoteCommitSemantics
        );
    }

    #[test]
    fn egress_or_recovery_cost_unknown_refuses_authority_upgrade() {
        let exhausted = strong_object_facts().with_cost_recovery(RemoteCostRecoveryFacts {
            egress_budget_known: true,
            egress_budget_exhausted: true,
            restore_cost_known: true,
            recovery_bandwidth_known: true,
            degraded_visibility_known: true,
            cost_ref: evidence(StorageIntentEvidenceKind::MediaCostWearLedger, 8),
            recovery_ref: evidence(StorageIntentEvidenceKind::RecoveryDegradationEvidence, 9),
        });
        let record = produce_remote_media_capability(exhausted);

        assert_eq!(
            remote_authority_preflight_refusal(exhausted),
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert_eq!(
            placement_result(record).refusal,
            StorageIntentRefusalReason::UnsupportedRemoteCommitSemantics
        );
    }

    #[test]
    fn archive_requires_retained_restore_not_archive_label() {
        let unbounded = strong_archive_facts().with_archive(RemoteArchiveFacts::new(
            MediaArchiveRestoreSemantics::RestoreUnbounded,
            media_evidence(36),
        ));
        let record = produce_remote_media_capability(unbounded);

        assert_eq!(
            remote_authority_preflight_refusal(unbounded),
            StorageIntentRefusalReason::UnknownArchiveRestoreRetention
        );
        assert_eq!(
            archive_result(record).refusal,
            StorageIntentRefusalReason::UnknownArchiveRestoreRetention
        );
    }

    #[test]
    fn archive_restore_cost_must_be_bounded_before_archive_authority() {
        let missing_restore_cost =
            strong_archive_facts().with_cost_recovery(RemoteCostRecoveryFacts {
                restore_cost_known: false,
                ..RemoteCostRecoveryFacts::bounded(
                    evidence(StorageIntentEvidenceKind::MediaCostWearLedger, 39),
                    evidence(StorageIntentEvidenceKind::RecoveryDegradationEvidence, 40),
                )
            });
        let record = produce_remote_media_capability(missing_restore_cost);

        assert_eq!(
            remote_authority_preflight_refusal(missing_restore_cost),
            StorageIntentRefusalReason::UnknownArchiveRestoreRetention
        );
        assert_eq!(
            archive_result(record).refusal,
            StorageIntentRefusalReason::UnknownArchiveRestoreRetention
        );
    }

    #[test]
    fn archive_with_audited_restore_satisfies_archive_role() {
        let facts = strong_archive_facts();
        let record = produce_remote_media_capability(facts);

        assert_eq!(
            remote_authority_preflight_refusal(facts),
            StorageIntentRefusalReason::None
        );
        assert!(archive_result(record).satisfied);
        assert!(record.flags.contains_all(
            MediaCapabilityFlags::ARCHIVE_RESTORE_RETENTION
                .union(MediaCapabilityFlags::TRANSPORT_RDMA_ABSENT_LEGAL)
        ));
    }

    #[test]
    fn remote_ram_volatile_ack_cannot_be_durable_placement() {
        let facts = strong_object_facts()
            .with_commit(RemoteCommitFacts::new(
                MediaPersistenceDomain::VolatileRam,
                MediaFlushOrderingClass::OrderedRemoteCommit,
                MediaAtomicityClass::IdempotentObjectPut,
                MediaProtocolGeometryClass::RamByteAddressable,
                MediaRemoteCommitSemantics::VolatileAckOnly,
                media_evidence(5),
            ))
            .with_archive(RemoteArchiveFacts::default());
        let record = StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::RemoteRam,
            ..produce_remote_media_capability(facts)
        };

        assert_eq!(
            placement_result(record).refusal,
            StorageIntentRefusalReason::PersistentMediaRequired
        );
    }

    #[test]
    fn endpoint_name_only_is_not_media_capability_evidence() {
        let record = produce_remote_media_capability(RemoteMediaCapabilityFacts::new(
            StorageMediaClass::CloudObject,
            EMPTY_EVIDENCE_REF,
        ));

        assert_eq!(
            placement_result(record).refusal,
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence
        );
    }
}
