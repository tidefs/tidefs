// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Local media-capability producer records for storage intent.
//!
//! This crate is the first #960 source slice. It does not probe hardware,
//! execute I/O, emit receipts, score placement, or account wear. It maps
//! already-collected local facts into
//! [`StorageIntentMediaCapabilityRecord`] so downstream storage-intent
//! consumers can use the #904 role predicate instead of device labels.

use tidefs_kernel_storage_io::KernelStorageIoCapabilities;
use tidefs_storage_intent_core::{
    MediaArchiveRestoreSemantics, MediaAtomicityClass, MediaCapabilityFlags,
    MediaCapabilityFreshnessState, MediaFlushOrderingClass, MediaHealthState,
    MediaPersistenceDomain, MediaProtocolGeometryClass, MediaRemoteCommitSemantics,
    StorageIntentEvidenceId, StorageIntentEvidenceKind, StorageIntentEvidenceRef,
    StorageIntentMediaCapabilityRecord, StorageMediaClass,
};

/// Version of the local media-capability producer record shape.
pub const LOCAL_MEDIA_CAPABILITY_PRODUCER_VERSION: u16 = 1;

/// Stable producer identifier for operator explanations and fixture tests.
pub const LOCAL_MEDIA_CAPABILITY_PRODUCER_SPEC: &str =
    "tidefs-storage-intent-local-media-capability-v1-issue-960";

const EMPTY_EVIDENCE_REF: StorageIntentEvidenceRef = StorageIntentEvidenceRef {
    kind: StorageIntentEvidenceKind::Unknown,
    id: StorageIntentEvidenceId::ZERO,
    generation: 0,
    version: 0,
};

/// Stable identity and generation facts for a local target.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalMediaIdentityFacts {
    pub stable_device_identity: bool,
    pub stable_namespace_identity: bool,
    pub pool_member_binding: bool,
    pub firmware_capability_generation: bool,
    pub identity_generation: u64,
    pub namespace_generation: u64,
    pub firmware_generation: u64,
    pub settings_generation: u64,
    pub pool_member_generation: u64,
    pub stable_identity_ref: StorageIntentEvidenceRef,
    pub namespace_identity_ref: StorageIntentEvidenceRef,
}

impl LocalMediaIdentityFacts {
    /// Build identity facts that satisfy the durable-role identity gate.
    #[must_use]
    pub const fn stable(
        generation: u64,
        stable_identity_ref: StorageIntentEvidenceRef,
        namespace_identity_ref: StorageIntentEvidenceRef,
    ) -> Self {
        Self {
            stable_device_identity: true,
            stable_namespace_identity: true,
            pool_member_binding: true,
            firmware_capability_generation: true,
            identity_generation: generation,
            namespace_generation: generation,
            firmware_generation: generation,
            settings_generation: generation,
            pool_member_generation: generation,
            stable_identity_ref,
            namespace_identity_ref,
        }
    }
}

/// Persistence-domain proof for a local target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalPersistenceFacts {
    pub domain: MediaPersistenceDomain,
    pub write_cache_safe: bool,
    pub persistence_ref: StorageIntentEvidenceRef,
}

impl Default for LocalPersistenceFacts {
    fn default() -> Self {
        Self {
            domain: MediaPersistenceDomain::Unknown,
            write_cache_safe: false,
            persistence_ref: StorageIntentEvidenceRef::default(),
        }
    }
}

impl LocalPersistenceFacts {
    #[must_use]
    pub const fn new(
        domain: MediaPersistenceDomain,
        persistence_ref: StorageIntentEvidenceRef,
    ) -> Self {
        Self {
            domain,
            write_cache_safe: false,
            persistence_ref,
        }
    }

    #[must_use]
    pub const fn with_write_cache_safe(mut self) -> Self {
        self.write_cache_safe = true;
        self
    }
}

/// Local block-I/O shape and ordering facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalBlockIoFacts {
    pub capabilities: KernelStorageIoCapabilities,
    pub flush_ordering: MediaFlushOrderingClass,
    pub discard_zeroes_shape_proven: bool,
    pub max_queue_depth: u32,
    pub flush_ref: StorageIntentEvidenceRef,
}

impl Default for LocalBlockIoFacts {
    fn default() -> Self {
        Self {
            capabilities: KernelStorageIoCapabilities::unsupported(),
            flush_ordering: MediaFlushOrderingClass::Unknown,
            discard_zeroes_shape_proven: false,
            max_queue_depth: 0,
            flush_ref: StorageIntentEvidenceRef::default(),
        }
    }
}

impl LocalBlockIoFacts {
    /// Convert generic kernel-storage capability booleans into conservative
    /// producer input. `flush = true` becomes `FlushOnly`; it is not FUA or
    /// power-loss-safety proof.
    #[must_use]
    pub const fn from_kernel_capabilities(
        capabilities: KernelStorageIoCapabilities,
        flush_ref: StorageIntentEvidenceRef,
    ) -> Self {
        let flush_ordering = if capabilities.flush {
            MediaFlushOrderingClass::FlushOnly
        } else {
            MediaFlushOrderingClass::None
        };
        Self {
            capabilities,
            flush_ordering,
            discard_zeroes_shape_proven: false,
            max_queue_depth: 0,
            flush_ref,
        }
    }

    #[must_use]
    pub const fn with_flush_ordering(mut self, ordering: MediaFlushOrderingClass) -> Self {
        self.flush_ordering = ordering;
        self
    }

    #[must_use]
    pub const fn with_discard_zeroes_shape(mut self) -> Self {
        self.discard_zeroes_shape_proven = true;
        self
    }

    #[must_use]
    pub const fn with_max_queue_depth(mut self, max_queue_depth: u32) -> Self {
        self.max_queue_depth = max_queue_depth;
        self
    }
}

/// Local atomic write and replay granularity facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalAtomicityFacts {
    pub atomicity: MediaAtomicityClass,
    pub physical_block_bytes: u32,
    pub atomic_write_unit_bytes: u32,
    pub atomicity_ref: StorageIntentEvidenceRef,
}

impl Default for LocalAtomicityFacts {
    fn default() -> Self {
        Self {
            atomicity: MediaAtomicityClass::Unknown,
            physical_block_bytes: 0,
            atomic_write_unit_bytes: 0,
            atomicity_ref: StorageIntentEvidenceRef::default(),
        }
    }
}

impl LocalAtomicityFacts {
    #[must_use]
    pub const fn block_atomic(
        atomicity: MediaAtomicityClass,
        physical_block_bytes: u32,
        atomic_write_unit_bytes: u32,
        atomicity_ref: StorageIntentEvidenceRef,
    ) -> Self {
        Self {
            atomicity,
            physical_block_bytes,
            atomic_write_unit_bytes,
            atomicity_ref,
        }
    }
}

/// Local access geometry facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalGeometryFacts {
    pub geometry: MediaProtocolGeometryClass,
    pub optimal_io_bytes: u32,
    pub geometry_ref: StorageIntentEvidenceRef,
}

impl Default for LocalGeometryFacts {
    fn default() -> Self {
        Self {
            geometry: MediaProtocolGeometryClass::Unknown,
            optimal_io_bytes: 0,
            geometry_ref: StorageIntentEvidenceRef::default(),
        }
    }
}

impl LocalGeometryFacts {
    #[must_use]
    pub const fn new(
        geometry: MediaProtocolGeometryClass,
        optimal_io_bytes: u32,
        geometry_ref: StorageIntentEvidenceRef,
    ) -> Self {
        Self {
            geometry,
            optimal_io_bytes,
            geometry_ref,
        }
    }
}

/// Local health verdict facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalHealthFacts {
    pub health: MediaHealthState,
    pub health_ref: StorageIntentEvidenceRef,
}

impl Default for LocalHealthFacts {
    fn default() -> Self {
        Self {
            health: MediaHealthState::Unknown,
            health_ref: StorageIntentEvidenceRef::default(),
        }
    }
}

impl LocalHealthFacts {
    #[must_use]
    pub const fn new(health: MediaHealthState, health_ref: StorageIntentEvidenceRef) -> Self {
        Self { health, health_ref }
    }
}

/// Local capability freshness facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalFreshnessFacts {
    pub freshness: MediaCapabilityFreshnessState,
    pub freshness_ref: StorageIntentEvidenceRef,
}

impl Default for LocalFreshnessFacts {
    fn default() -> Self {
        Self {
            freshness: MediaCapabilityFreshnessState::Missing,
            freshness_ref: StorageIntentEvidenceRef::default(),
        }
    }
}

impl LocalFreshnessFacts {
    #[must_use]
    pub const fn new(
        freshness: MediaCapabilityFreshnessState,
        freshness_ref: StorageIntentEvidenceRef,
    ) -> Self {
        Self {
            freshness,
            freshness_ref,
        }
    }
}

/// Complete local producer input for one target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalMediaCapabilityFacts {
    pub media_class: StorageMediaClass,
    pub evidence: StorageIntentEvidenceRef,
    pub identity: LocalMediaIdentityFacts,
    pub persistence: LocalPersistenceFacts,
    pub block_io: LocalBlockIoFacts,
    pub atomicity: LocalAtomicityFacts,
    pub geometry: LocalGeometryFacts,
    pub health: LocalHealthFacts,
    pub freshness: LocalFreshnessFacts,
    pub latency_class_us: u32,
}

impl LocalMediaCapabilityFacts {
    #[must_use]
    pub const fn new(media_class: StorageMediaClass, evidence: StorageIntentEvidenceRef) -> Self {
        Self {
            media_class,
            evidence,
            identity: LocalMediaIdentityFacts {
                stable_device_identity: false,
                stable_namespace_identity: false,
                pool_member_binding: false,
                firmware_capability_generation: false,
                identity_generation: 0,
                namespace_generation: 0,
                firmware_generation: 0,
                settings_generation: 0,
                pool_member_generation: 0,
                stable_identity_ref: EMPTY_EVIDENCE_REF,
                namespace_identity_ref: EMPTY_EVIDENCE_REF,
            },
            persistence: LocalPersistenceFacts {
                domain: MediaPersistenceDomain::Unknown,
                write_cache_safe: false,
                persistence_ref: EMPTY_EVIDENCE_REF,
            },
            block_io: LocalBlockIoFacts {
                capabilities: KernelStorageIoCapabilities {
                    read: false,
                    write: false,
                    flush: false,
                    discard: false,
                    write_zeroes: false,
                    zero_range: false,
                    teardown: false,
                    sector_size: 0,
                    capacity_sectors: 0,
                },
                flush_ordering: MediaFlushOrderingClass::Unknown,
                discard_zeroes_shape_proven: false,
                max_queue_depth: 0,
                flush_ref: EMPTY_EVIDENCE_REF,
            },
            atomicity: LocalAtomicityFacts {
                atomicity: MediaAtomicityClass::Unknown,
                physical_block_bytes: 0,
                atomic_write_unit_bytes: 0,
                atomicity_ref: EMPTY_EVIDENCE_REF,
            },
            geometry: LocalGeometryFacts {
                geometry: MediaProtocolGeometryClass::Unknown,
                optimal_io_bytes: 0,
                geometry_ref: EMPTY_EVIDENCE_REF,
            },
            health: LocalHealthFacts {
                health: MediaHealthState::Unknown,
                health_ref: EMPTY_EVIDENCE_REF,
            },
            freshness: LocalFreshnessFacts {
                freshness: MediaCapabilityFreshnessState::Missing,
                freshness_ref: EMPTY_EVIDENCE_REF,
            },
            latency_class_us: 0,
        }
    }

    #[must_use]
    pub const fn with_identity(mut self, identity: LocalMediaIdentityFacts) -> Self {
        self.identity = identity;
        self
    }

    #[must_use]
    pub const fn with_persistence(mut self, persistence: LocalPersistenceFacts) -> Self {
        self.persistence = persistence;
        self
    }

    #[must_use]
    pub const fn with_block_io(mut self, block_io: LocalBlockIoFacts) -> Self {
        self.block_io = block_io;
        self
    }

    #[must_use]
    pub const fn with_atomicity(mut self, atomicity: LocalAtomicityFacts) -> Self {
        self.atomicity = atomicity;
        self
    }

    #[must_use]
    pub const fn with_geometry(mut self, geometry: LocalGeometryFacts) -> Self {
        self.geometry = geometry;
        self
    }

    #[must_use]
    pub const fn with_health(mut self, health: LocalHealthFacts) -> Self {
        self.health = health;
        self
    }

    #[must_use]
    pub const fn with_freshness(mut self, freshness: LocalFreshnessFacts) -> Self {
        self.freshness = freshness;
        self
    }

    #[must_use]
    pub const fn with_latency_class_us(mut self, latency_class_us: u32) -> Self {
        self.latency_class_us = latency_class_us;
        self
    }
}

/// Produce a #904 media-capability record from bounded local facts.
#[must_use]
pub const fn produce_local_media_capability(
    facts: LocalMediaCapabilityFacts,
) -> StorageIntentMediaCapabilityRecord {
    let mut flags = MediaCapabilityFlags::EMPTY;

    if facts.identity.stable_device_identity {
        flags = flags.union(MediaCapabilityFlags::STABLE_DEVICE_IDENTITY);
    }
    if facts.identity.stable_namespace_identity {
        flags = flags.union(MediaCapabilityFlags::STABLE_NAMESPACE_IDENTITY);
    }
    if facts.identity.pool_member_binding {
        flags = flags.union(MediaCapabilityFlags::POOL_MEMBER_BINDING);
    }
    if facts.identity.firmware_capability_generation {
        flags = flags.union(MediaCapabilityFlags::FIRMWARE_CAPABILITY_GENERATION);
    }
    if !matches!(facts.persistence.domain, MediaPersistenceDomain::Unknown) {
        flags = flags.union(MediaCapabilityFlags::PERSISTENCE_DOMAIN);
    }
    if facts.persistence.write_cache_safe {
        flags = flags.union(MediaCapabilityFlags::WRITE_CACHE_SAFE);
    }
    if !matches!(
        facts.block_io.flush_ordering,
        MediaFlushOrderingClass::Unknown
    ) {
        flags = flags.union(MediaCapabilityFlags::FLUSH_FUA_ORDERING);
    }
    if matches!(
        facts.block_io.flush_ordering,
        MediaFlushOrderingClass::PmemFlushFence
    ) {
        flags = flags.union(MediaCapabilityFlags::PMEM_FLUSH_FENCE);
    }
    if !matches!(facts.atomicity.atomicity, MediaAtomicityClass::Unknown) {
        flags = flags.union(MediaCapabilityFlags::ATOMICITY_GRANULARITY);
    }
    if !matches!(facts.geometry.geometry, MediaProtocolGeometryClass::Unknown) {
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
    if facts.block_io.discard_zeroes_shape_proven {
        flags = flags.union(MediaCapabilityFlags::DISCARD_ZEROES_SHAPE);
    }

    StorageIntentMediaCapabilityRecord {
        media_class: facts.media_class,
        flags,
        identity_generation: facts.identity.identity_generation,
        namespace_generation: facts.identity.namespace_generation,
        firmware_generation: facts.identity.firmware_generation,
        settings_generation: facts.identity.settings_generation,
        pool_member_generation: facts.identity.pool_member_generation,
        persistence: facts.persistence.domain,
        flush_ordering: facts.block_io.flush_ordering,
        atomicity: facts.atomicity.atomicity,
        geometry: facts.geometry.geometry,
        health: facts.health.health,
        freshness: facts.freshness.freshness,
        remote_commit: MediaRemoteCommitSemantics::NotRemote,
        archive_restore: MediaArchiveRestoreSemantics::NotArchive,
        logical_block_bytes: facts.block_io.capabilities.sector_size,
        physical_block_bytes: facts.atomicity.physical_block_bytes,
        atomic_write_unit_bytes: facts.atomicity.atomic_write_unit_bytes,
        optimal_io_bytes: facts.geometry.optimal_io_bytes,
        max_queue_depth: facts.block_io.max_queue_depth,
        latency_class_us: facts.latency_class_us,
        evidence: facts.evidence,
        stable_identity_ref: facts.identity.stable_identity_ref,
        namespace_identity_ref: facts.identity.namespace_identity_ref,
        persistence_ref: facts.persistence.persistence_ref,
        flush_ref: facts.block_io.flush_ref,
        atomicity_ref: facts.atomicity.atomicity_ref,
        geometry_ref: facts.geometry.geometry_ref,
        health_ref: facts.health.health_ref,
        freshness_ref: facts.freshness.freshness_ref,
        remote_commit_ref: EMPTY_EVIDENCE_REF,
        archive_restore_ref: EMPTY_EVIDENCE_REF,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_storage_intent_core::{
        media_capability_satisfies_role, MediaRoleRequirement, ReceiptPredicateResult,
        StorageIntentEvidenceId, StorageIntentEvidenceKind, StorageIntentGuaranteeClass,
        StorageIntentRefusalReason, StorageMediaRole,
    };

    fn evidence(seed: u8) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(
            StorageIntentEvidenceKind::MediaCapabilityEvidence,
            StorageIntentEvidenceId([seed; 32]),
            u64::from(seed),
            LOCAL_MEDIA_CAPABILITY_PRODUCER_VERSION,
        )
    }

    fn strong_nvme_facts() -> LocalMediaCapabilityFacts {
        let block = KernelStorageIoCapabilities {
            read: true,
            write: true,
            flush: true,
            discard: true,
            write_zeroes: true,
            zero_range: false,
            teardown: true,
            sector_size: 4096,
            capacity_sectors: 1024,
        };

        LocalMediaCapabilityFacts::new(StorageMediaClass::NvmeFlash, evidence(1))
            .with_identity(LocalMediaIdentityFacts::stable(
                11,
                evidence(2),
                evidence(3),
            ))
            .with_persistence(LocalPersistenceFacts::new(
                MediaPersistenceDomain::OrdinaryPersistent,
                evidence(4),
            ))
            .with_block_io(
                LocalBlockIoFacts::from_kernel_capabilities(block, evidence(5))
                    .with_flush_ordering(MediaFlushOrderingClass::FlushAndFua)
                    .with_discard_zeroes_shape()
                    .with_max_queue_depth(64),
            )
            .with_atomicity(LocalAtomicityFacts::block_atomic(
                MediaAtomicityClass::LogicalBlockAtomic,
                4096,
                4096,
                evidence(6),
            ))
            .with_geometry(LocalGeometryFacts::new(
                MediaProtocolGeometryClass::RandomBlock,
                131_072,
                evidence(7),
            ))
            .with_health(LocalHealthFacts::new(
                MediaHealthState::Healthy,
                evidence(8),
            ))
            .with_freshness(LocalFreshnessFacts::new(
                MediaCapabilityFreshnessState::Fresh,
                evidence(9),
            ))
            .with_latency_class_us(80)
    }

    fn durable_sync_result(record: StorageIntentMediaCapabilityRecord) -> ReceiptPredicateResult {
        media_capability_satisfies_role(
            MediaRoleRequirement::AUTHORITY,
            StorageIntentGuaranteeClass::LocalIntent,
            StorageMediaRole::SyncIntent,
            record,
        )
    }

    #[test]
    fn strong_local_block_facts_satisfy_sync_intent_role() {
        let record = produce_local_media_capability(strong_nvme_facts());
        let result = durable_sync_result(record);

        assert!(result.satisfied);
        assert_eq!(record.remote_commit, MediaRemoteCommitSemantics::NotRemote);
        assert_eq!(
            record.archive_restore,
            MediaArchiveRestoreSemantics::NotArchive
        );
        assert!(record.flags.contains_all(
            MediaCapabilityFlags::STABLE_DEVICE_IDENTITY
                .union(MediaCapabilityFlags::STABLE_NAMESPACE_IDENTITY)
                .union(MediaCapabilityFlags::POOL_MEMBER_BINDING)
                .union(MediaCapabilityFlags::PERSISTENCE_DOMAIN)
                .union(MediaCapabilityFlags::FLUSH_FUA_ORDERING)
                .union(MediaCapabilityFlags::ATOMICITY_GRANULARITY)
                .union(MediaCapabilityFlags::PROTOCOL_GEOMETRY)
                .union(MediaCapabilityFlags::HEALTH)
                .union(MediaCapabilityFlags::FRESHNESS)
        ));
    }

    #[test]
    fn kernel_flush_boolean_alone_does_not_prove_durable_ordering() {
        let kernel_flush_only = LocalBlockIoFacts::from_kernel_capabilities(
            KernelStorageIoCapabilities::read_write_flush(4096, 1024, true),
            evidence(5),
        );
        let record = produce_local_media_capability(
            strong_nvme_facts().with_block_io(kernel_flush_only.with_max_queue_depth(64)),
        );
        let result = durable_sync_result(record);

        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::UnsupportedFlushFuaSemantics
        );
        assert_eq!(record.flush_ordering, MediaFlushOrderingClass::FlushOnly);
    }

    #[test]
    fn label_only_nvme_remains_missing_capability_evidence() {
        let record = produce_local_media_capability(LocalMediaCapabilityFacts::new(
            StorageMediaClass::NvmeFlash,
            evidence(1),
        ));
        let result = durable_sync_result(record);

        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence
        );
    }

    #[test]
    fn cache_only_local_target_can_be_read_cache_but_not_authority() {
        let record = produce_local_media_capability(
            LocalMediaCapabilityFacts::new(StorageMediaClass::NvmeFlash, evidence(1))
                .with_identity(LocalMediaIdentityFacts::stable(
                    11,
                    evidence(2),
                    evidence(3),
                ))
                .with_persistence(LocalPersistenceFacts::new(
                    MediaPersistenceDomain::CacheOnlyVolatile,
                    evidence(4),
                ))
                .with_health(LocalHealthFacts::new(
                    MediaHealthState::Healthy,
                    evidence(8),
                ))
                .with_freshness(LocalFreshnessFacts::new(
                    MediaCapabilityFreshnessState::Fresh,
                    evidence(9),
                )),
        );

        let cache_result = media_capability_satisfies_role(
            MediaRoleRequirement {
                allowed_roles: tidefs_storage_intent_core::MediaRoleMask::from_role(
                    StorageMediaRole::ReadCache,
                ),
                require_authority_role: false,
            },
            StorageIntentGuaranteeClass::VolatileLocal,
            StorageMediaRole::ReadCache,
            record,
        );
        let authority_result = media_capability_satisfies_role(
            MediaRoleRequirement::AUTHORITY,
            StorageIntentGuaranteeClass::LocalIntent,
            StorageMediaRole::PlacementAuthority,
            record,
        );

        assert!(cache_result.satisfied);
        assert!(!authority_result.satisfied);
        assert_eq!(
            authority_result.refusal,
            StorageIntentRefusalReason::UnsafeVolatileWriteCache
        );
    }

    #[test]
    fn unknown_persistence_domain_refuses_durable_role() {
        let record = produce_local_media_capability(
            strong_nvme_facts().with_persistence(LocalPersistenceFacts::default()),
        );
        let result = durable_sync_result(record);

        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::UnknownPersistenceDomain
        );
    }

    #[test]
    fn stale_namespace_identity_refuses_durable_role() {
        let mut identity = LocalMediaIdentityFacts::stable(11, evidence(2), evidence(3));
        identity.stable_namespace_identity = false;
        let record = produce_local_media_capability(strong_nvme_facts().with_identity(identity));
        let result = durable_sync_result(record);

        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::UnstableNamespaceIdentity
        );
    }

    #[test]
    fn stale_probe_refuses_before_media_can_be_used() {
        let record = produce_local_media_capability(strong_nvme_facts().with_freshness(
            LocalFreshnessFacts::new(MediaCapabilityFreshnessState::Stale, evidence(9)),
        ));
        let result = durable_sync_result(record);

        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::StaleMediaCapabilityEvidence
        );
    }

    #[test]
    fn unknown_or_torn_atomicity_refuses_durable_role() {
        let unknown = produce_local_media_capability(
            strong_nvme_facts().with_atomicity(LocalAtomicityFacts::default()),
        );
        let torn = produce_local_media_capability(strong_nvme_facts().with_atomicity(
            LocalAtomicityFacts::block_atomic(
                MediaAtomicityClass::TornWritesPossible,
                4096,
                4096,
                evidence(6),
            ),
        ));

        assert_eq!(
            durable_sync_result(unknown).refusal,
            StorageIntentRefusalReason::WrongAtomicityGranularity
        );
        assert_eq!(
            durable_sync_result(torn).refusal,
            StorageIntentRefusalReason::WrongAtomicityGranularity
        );
    }

    #[test]
    fn zoned_sequential_target_refuses_random_sync_role() {
        let record = produce_local_media_capability(
            strong_nvme_facts()
                .with_geometry(LocalGeometryFacts::new(
                    MediaProtocolGeometryClass::ZonedSequential,
                    262_144,
                    evidence(7),
                ))
                .with_persistence(LocalPersistenceFacts::new(
                    MediaPersistenceDomain::OrdinaryPersistent,
                    evidence(4),
                )),
        );
        let record = StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::ZonedFlash,
            ..record
        };
        let result = durable_sync_result(record);

        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::UnsupportedZoneWritePointer
        );
    }

    #[test]
    fn degraded_health_refuses_durable_role() {
        let record = produce_local_media_capability(strong_nvme_facts().with_health(
            LocalHealthFacts::new(MediaHealthState::Degraded, evidence(8)),
        ));
        let result = durable_sync_result(record);

        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::DegradedMediaHealth
        );
    }

    #[test]
    fn pmem_requires_pmem_flush_fence_not_block_flush() {
        let record = produce_local_media_capability(
            strong_nvme_facts()
                .with_persistence(LocalPersistenceFacts::new(
                    MediaPersistenceDomain::PersistentMemory,
                    evidence(4),
                ))
                .with_block_io(
                    LocalBlockIoFacts::from_kernel_capabilities(
                        KernelStorageIoCapabilities::read_write_flush(4096, 1024, true),
                        evidence(5),
                    )
                    .with_flush_ordering(MediaFlushOrderingClass::FlushAndFua),
                ),
        );
        let record = StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::PersistentMemory,
            geometry: MediaProtocolGeometryClass::PmemByteAddressable,
            ..record
        };
        let result = durable_sync_result(record);

        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::PmemFlushFenceMissing
        );
    }
}
