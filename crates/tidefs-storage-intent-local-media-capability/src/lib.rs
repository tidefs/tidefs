// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Local media-capability producer records for storage intent.
//!
//! This crate owns the narrow #960 local producer surface. It does not probe
//! hardware, execute I/O, emit receipts, score placement, or account wear. It maps
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
use tidefs_types_pool_label_core::{
    DeviceClass as LabelDeviceClass, PoolLabelV1, PoolState as LabelPoolState,
};
use tidefs_ublk_abi::{
    UblkFeatureFlags, UblkParams, UBLK_ATTR_FUA, UBLK_ATTR_ROTATIONAL, UBLK_ATTR_VOLATILE_CACHE,
    UBLK_PARAM_TYPE_BASIC, UBLK_PARAM_TYPE_DISCARD, UBLK_PARAM_TYPE_ZONED,
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

const fn bytes16_nonzero(bytes: [u8; 16]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return true;
        }
        index += 1;
    }
    false
}

const fn ublk_param_type_present(params: UblkParams, ty: u32) -> bool {
    (params.types & ty) == ty
}

const fn block_bytes_from_shift(shift: u8) -> u32 {
    if shift < 32 {
        1_u32 << shift
    } else {
        0
    }
}

const fn label_media_class(device_class: LabelDeviceClass) -> StorageMediaClass {
    match device_class {
        LabelDeviceClass::Hdd => StorageMediaClass::HddRotational,
        LabelDeviceClass::Ssd => StorageMediaClass::SsdFlash,
        LabelDeviceClass::Nvme | LabelDeviceClass::LogDevice => StorageMediaClass::NvmeFlash,
        LabelDeviceClass::Cache => StorageMediaClass::SsdFlash,
        LabelDeviceClass::Special => StorageMediaClass::SsdFlash,
        LabelDeviceClass::Spare => StorageMediaClass::HddRotational,
    }
}

const fn label_health(device_health: u8) -> MediaHealthState {
    match device_health {
        0 => MediaHealthState::Healthy,
        1 => MediaHealthState::Degraded,
        2 => MediaHealthState::Failed,
        _ => MediaHealthState::Unknown,
    }
}

/// How the local path or multipath view identifies a target.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LocalPathIdentityClass {
    /// No usable path identity sample was supplied.
    #[default]
    Unknown,
    /// A path string exists, but no stable namespace or multipath binding does.
    PathOnly,
    /// One local path is bound to the sampled namespace for this generation.
    StableSinglePath,
    /// A multipath set is bound to the sampled namespace for this generation.
    StableMultipath,
}

impl LocalPathIdentityClass {
    #[must_use]
    pub const fn proves_stable_attach(self) -> bool {
        matches!(self, Self::StableSinglePath | Self::StableMultipath)
    }
}

/// Explicit firmware/settings generation evidence for the sampled device.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalFirmwareSettingsSnapshot {
    pub firmware_generation: u64,
    pub settings_generation: u64,
    pub generation_proven: bool,
}

impl LocalFirmwareSettingsSnapshot {
    #[must_use]
    pub const fn proven(firmware_generation: u64, settings_generation: u64) -> Self {
        Self {
            firmware_generation,
            settings_generation,
            generation_proven: true,
        }
    }
}

/// Pool-label and attach identity snapshot for one local pool member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalPoolMemberIdentitySnapshot {
    pub pool_guid: [u8; 16],
    pub device_guid: [u8; 16],
    pub pool_state: LabelPoolState,
    pub label_commit_group: u64,
    pub topology_generation: u64,
    pub device_index: u32,
    pub device_count: u32,
    pub device_class: LabelDeviceClass,
    pub device_capacity_bytes: u64,
    pub device_health: u8,
    pub checksum_verified: bool,
    pub namespace_matches_current_attach: bool,
    pub path_identity: LocalPathIdentityClass,
    pub multipath_generation: u64,
    pub stale_reattach: bool,
}

impl LocalPoolMemberIdentitySnapshot {
    /// Capture the stable fields from a decoded pool label plus attach proof.
    #[must_use]
    pub const fn from_pool_label(
        label: &PoolLabelV1,
        checksum_verified: bool,
        namespace_matches_current_attach: bool,
        path_identity: LocalPathIdentityClass,
        multipath_generation: u64,
    ) -> Self {
        Self {
            pool_guid: label.pool_guid,
            device_guid: label.device_guid,
            pool_state: label.pool_state,
            label_commit_group: label.label_commit_group,
            topology_generation: label.topology_generation,
            device_index: label.device_index,
            device_count: label.device_count,
            device_class: label.device_class,
            device_capacity_bytes: label.device_capacity_bytes,
            device_health: label.device_health,
            checksum_verified,
            namespace_matches_current_attach,
            path_identity,
            multipath_generation,
            stale_reattach: false,
        }
    }

    #[must_use]
    pub const fn with_stale_reattach(mut self) -> Self {
        self.stale_reattach = true;
        self
    }

    #[must_use]
    pub const fn media_class(self) -> StorageMediaClass {
        label_media_class(self.device_class)
    }

    #[must_use]
    pub const fn health_facts(self, health_ref: StorageIntentEvidenceRef) -> LocalHealthFacts {
        LocalHealthFacts::new(label_health(self.device_health_code()), health_ref)
    }

    #[must_use]
    pub const fn freshness_facts(
        self,
        freshness_ref: StorageIntentEvidenceRef,
    ) -> LocalFreshnessFacts {
        if self.stale_reattach {
            return LocalFreshnessFacts::new(MediaCapabilityFreshnessState::Stale, freshness_ref);
        }
        if self.checksum_verified && self.namespace_matches_current_attach {
            LocalFreshnessFacts::new(MediaCapabilityFreshnessState::Fresh, freshness_ref)
        } else if self.checksum_verified {
            LocalFreshnessFacts::new(MediaCapabilityFreshnessState::Contradictory, freshness_ref)
        } else {
            LocalFreshnessFacts::new(MediaCapabilityFreshnessState::Missing, freshness_ref)
        }
    }

    #[must_use]
    pub const fn identity_facts(
        self,
        firmware_settings: LocalFirmwareSettingsSnapshot,
        stable_identity_ref: StorageIntentEvidenceRef,
        namespace_identity_ref: StorageIntentEvidenceRef,
    ) -> LocalMediaIdentityFacts {
        let stable_label_identity = self.checksum_verified
            && bytes16_nonzero(self.pool_guid)
            && bytes16_nonzero(self.device_guid)
            && self.pool_state.is_importable()
            && self.namespace_matches_current_attach
            && self.path_identity.proves_stable_attach()
            && !self.stale_reattach;

        LocalMediaIdentityFacts {
            stable_device_identity: stable_label_identity,
            stable_namespace_identity: stable_label_identity,
            pool_member_binding: stable_label_identity && self.device_count > 0,
            firmware_capability_generation: stable_label_identity
                && firmware_settings.generation_proven,
            identity_generation: self.label_commit_group,
            namespace_generation: self.topology_generation,
            firmware_generation: firmware_settings.firmware_generation,
            settings_generation: firmware_settings.settings_generation,
            pool_member_generation: self
                .topology_generation
                .saturating_add(self.multipath_generation),
            stable_identity_ref,
            namespace_identity_ref,
        }
    }

    const fn device_health_code(self) -> u8 {
        if self.device_class as u8 == LabelDeviceClass::Spare as u8 {
            return 3;
        }
        if self.device_count == 0 {
            return 3;
        }
        self.device_health
    }
}

/// Explicit proof source for persistence-domain classification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LocalPersistenceProofKind {
    #[default]
    Missing,
    DeviceClassLabelOnly,
    OperatorHintOnly,
    ExplicitProbe,
}

/// Persistence-domain sample that refuses to treat labels as proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalPersistenceSnapshot {
    pub domain: MediaPersistenceDomain,
    pub proof_kind: LocalPersistenceProofKind,
    pub write_cache_safe: bool,
    pub persistence_ref: StorageIntentEvidenceRef,
}

impl Default for LocalPersistenceSnapshot {
    fn default() -> Self {
        Self {
            domain: MediaPersistenceDomain::Unknown,
            proof_kind: LocalPersistenceProofKind::Missing,
            write_cache_safe: false,
            persistence_ref: EMPTY_EVIDENCE_REF,
        }
    }
}

impl LocalPersistenceSnapshot {
    #[must_use]
    pub const fn label_only(persistence_ref: StorageIntentEvidenceRef) -> Self {
        Self {
            domain: MediaPersistenceDomain::Unknown,
            proof_kind: LocalPersistenceProofKind::DeviceClassLabelOnly,
            write_cache_safe: false,
            persistence_ref,
        }
    }

    #[must_use]
    pub const fn explicit(
        domain: MediaPersistenceDomain,
        write_cache_safe: bool,
        persistence_ref: StorageIntentEvidenceRef,
    ) -> Self {
        Self {
            domain,
            proof_kind: LocalPersistenceProofKind::ExplicitProbe,
            write_cache_safe,
            persistence_ref,
        }
    }

    #[must_use]
    pub const fn facts(self) -> LocalPersistenceFacts {
        if !matches!(self.proof_kind, LocalPersistenceProofKind::ExplicitProbe) {
            return LocalPersistenceFacts {
                domain: MediaPersistenceDomain::Unknown,
                write_cache_safe: false,
                persistence_ref: self.persistence_ref,
            };
        }
        LocalPersistenceFacts {
            domain: self.domain,
            write_cache_safe: self.write_cache_safe,
            persistence_ref: self.persistence_ref,
        }
    }
}

/// ublk queue and request-shape sample, not lower-media durability proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalUblkRequestShapeSnapshot {
    pub params: UblkParams,
    pub features: UblkFeatureFlags,
    pub queue_depth: u16,
    pub observed_flush_request: bool,
    pub observed_fua_write: bool,
    pub flush_passthrough_proven: bool,
    pub fua_passthrough_proven: bool,
    pub ordering_limitations_absent: bool,
}

impl Default for LocalUblkRequestShapeSnapshot {
    fn default() -> Self {
        Self {
            params: UblkParams::default(),
            features: UblkFeatureFlags(0),
            queue_depth: 0,
            observed_flush_request: false,
            observed_fua_write: false,
            flush_passthrough_proven: false,
            fua_passthrough_proven: false,
            ordering_limitations_absent: false,
        }
    }
}

impl LocalUblkRequestShapeSnapshot {
    #[must_use]
    pub const fn new(params: UblkParams, features: UblkFeatureFlags, queue_depth: u16) -> Self {
        Self {
            params,
            features,
            queue_depth,
            observed_flush_request: false,
            observed_fua_write: false,
            flush_passthrough_proven: false,
            fua_passthrough_proven: false,
            ordering_limitations_absent: false,
        }
    }

    #[must_use]
    pub const fn with_observed_flush_request(mut self) -> Self {
        self.observed_flush_request = true;
        self
    }

    #[must_use]
    pub const fn with_observed_fua_write(mut self) -> Self {
        self.observed_fua_write = true;
        self
    }

    #[must_use]
    pub const fn with_ordering_passthrough_proof(mut self) -> Self {
        self.flush_passthrough_proven = true;
        self.fua_passthrough_proven = true;
        self.ordering_limitations_absent = true;
        self
    }

    #[must_use]
    pub const fn block_io_facts(self, flush_ref: StorageIntentEvidenceRef) -> LocalBlockIoFacts {
        let logical_block_bytes = if ublk_param_type_present(self.params, UBLK_PARAM_TYPE_BASIC) {
            block_bytes_from_shift(self.params.basic.logical_bs_shift)
        } else {
            0
        };
        let capabilities = KernelStorageIoCapabilities {
            read: logical_block_bytes != 0 && self.params.basic.dev_sectors != 0,
            write: logical_block_bytes != 0 && self.params.basic.dev_sectors != 0,
            flush: self.observed_flush_request || self.flush_passthrough_proven,
            discard: ublk_param_type_present(self.params, UBLK_PARAM_TYPE_DISCARD)
                && self.params.discard.max_discard_sectors != 0,
            write_zeroes: ublk_param_type_present(self.params, UBLK_PARAM_TYPE_DISCARD)
                && self.params.discard.max_write_zeroes_sectors != 0,
            zero_range: false,
            teardown: false,
            sector_size: logical_block_bytes,
            capacity_sectors: self.params.basic.dev_sectors,
        };
        let flush_ordering = if self.flush_passthrough_proven
            && self.fua_passthrough_proven
            && self.ordering_limitations_absent
            && (self.params.basic.attrs & UBLK_ATTR_FUA) == UBLK_ATTR_FUA
        {
            MediaFlushOrderingClass::FlushAndFua
        } else if self.observed_flush_request || self.observed_fua_write {
            MediaFlushOrderingClass::FlushOnly
        } else {
            MediaFlushOrderingClass::Unknown
        };

        LocalBlockIoFacts {
            capabilities,
            flush_ordering,
            discard_zeroes_shape_proven: capabilities.discard || capabilities.write_zeroes,
            max_queue_depth: self.queue_depth as u32,
            flush_ref,
        }
    }

    #[must_use]
    pub const fn atomicity_facts(
        self,
        atomic_write_unit_bytes: u32,
        logical_block_atomic_proven: bool,
        atomicity_ref: StorageIntentEvidenceRef,
    ) -> LocalAtomicityFacts {
        let physical_block_bytes = if ublk_param_type_present(self.params, UBLK_PARAM_TYPE_BASIC) {
            block_bytes_from_shift(self.params.basic.physical_bs_shift)
        } else {
            0
        };
        let atomicity = if atomic_write_unit_bytes != 0 {
            MediaAtomicityClass::AtomicWriteUnit
        } else if logical_block_atomic_proven {
            MediaAtomicityClass::LogicalBlockAtomic
        } else {
            MediaAtomicityClass::Unknown
        };
        LocalAtomicityFacts::block_atomic(
            atomicity,
            physical_block_bytes,
            atomic_write_unit_bytes,
            atomicity_ref,
        )
    }

    #[must_use]
    pub const fn geometry_facts(
        self,
        geometry_ref: StorageIntentEvidenceRef,
    ) -> LocalGeometryFacts {
        let optimal_io_bytes = if ublk_param_type_present(self.params, UBLK_PARAM_TYPE_BASIC) {
            block_bytes_from_shift(self.params.basic.io_opt_shift)
        } else {
            0
        };
        let geometry = if self.features.contains(UblkFeatureFlags::ZONED)
            || ublk_param_type_present(self.params, UBLK_PARAM_TYPE_ZONED)
        {
            if self.params.zoned.max_zone_append_sectors != 0 {
                MediaProtocolGeometryClass::ZonedAppend
            } else {
                MediaProtocolGeometryClass::ZonedSequential
            }
        } else if (self.params.basic.attrs & UBLK_ATTR_ROTATIONAL) == UBLK_ATTR_ROTATIONAL {
            MediaProtocolGeometryClass::RotationalSeek
        } else if ublk_param_type_present(self.params, UBLK_PARAM_TYPE_BASIC) {
            MediaProtocolGeometryClass::RandomBlock
        } else {
            MediaProtocolGeometryClass::Unknown
        };

        LocalGeometryFacts::new(geometry, optimal_io_bytes, geometry_ref)
    }

    #[must_use]
    pub const fn volatile_write_cache_visible(self) -> bool {
        (self.params.basic.attrs & UBLK_ATTR_VOLATILE_CACHE) == UBLK_ATTR_VOLATILE_CACHE
    }
}

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

    fn pool_label() -> PoolLabelV1 {
        let mut label = PoolLabelV1::new([0xAA; 16], [0xBB; 16], "pool");
        label.label_commit_group = 42;
        label.topology_generation = 7;
        label.device_count = 2;
        label.device_index = 1;
        label.device_class = LabelDeviceClass::Nvme;
        label.device_capacity_bytes = 4 * 1024 * 1024;
        label.device_health = 0;
        label
    }

    fn ublk_params() -> UblkParams {
        let mut params = UblkParams {
            types: UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD,
            ..UblkParams::default()
        };
        params.basic.attrs = UBLK_ATTR_FUA;
        params.basic.logical_bs_shift = 12;
        params.basic.physical_bs_shift = 12;
        params.basic.io_opt_shift = 17;
        params.basic.dev_sectors = 2048;
        params.discard.max_discard_sectors = 128;
        params.discard.max_write_zeroes_sectors = 64;
        params
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
    fn pool_label_identity_without_firmware_generation_refuses_authority() {
        let identity = LocalPoolMemberIdentitySnapshot::from_pool_label(
            &pool_label(),
            true,
            true,
            LocalPathIdentityClass::StableMultipath,
            3,
        );
        let facts = strong_nvme_facts()
            .with_identity(identity.identity_facts(
                LocalFirmwareSettingsSnapshot::default(),
                evidence(2),
                evidence(3),
            ))
            .with_health(identity.health_facts(evidence(8)))
            .with_freshness(identity.freshness_facts(evidence(9)));
        let record = produce_local_media_capability(facts);
        let result = durable_sync_result(record);

        assert!(!record
            .flags
            .contains_all(MediaCapabilityFlags::FIRMWARE_CAPABILITY_GENERATION));
        assert_eq!(record.identity_generation, 42);
        assert_eq!(record.namespace_generation, 7);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::UnstableNamespaceIdentity
        );
    }

    #[test]
    fn stale_reattach_turns_pool_identity_into_stale_evidence() {
        let identity = LocalPoolMemberIdentitySnapshot::from_pool_label(
            &pool_label(),
            true,
            true,
            LocalPathIdentityClass::StableSinglePath,
            0,
        )
        .with_stale_reattach();
        let facts = strong_nvme_facts()
            .with_identity(identity.identity_facts(
                LocalFirmwareSettingsSnapshot::proven(8, 9),
                evidence(2),
                evidence(3),
            ))
            .with_freshness(identity.freshness_facts(evidence(9)));
        let record = produce_local_media_capability(facts);
        let result = durable_sync_result(record);

        assert_eq!(record.freshness, MediaCapabilityFreshnessState::Stale);
        assert!(!record
            .flags
            .contains_all(MediaCapabilityFlags::STABLE_NAMESPACE_IDENTITY));
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::StaleMediaCapabilityEvidence
        );
    }

    #[test]
    fn path_only_pool_label_identity_refuses_authority() {
        let identity = LocalPoolMemberIdentitySnapshot::from_pool_label(
            &pool_label(),
            true,
            true,
            LocalPathIdentityClass::PathOnly,
            0,
        );
        let facts = strong_nvme_facts().with_identity(identity.identity_facts(
            LocalFirmwareSettingsSnapshot::proven(8, 9),
            evidence(2),
            evidence(3),
        ));
        let record = produce_local_media_capability(facts);
        let result = durable_sync_result(record);

        assert!(!record
            .flags
            .contains_all(MediaCapabilityFlags::STABLE_DEVICE_IDENTITY));
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::UnstableNamespaceIdentity
        );
    }

    #[test]
    fn label_only_persistence_does_not_prove_persistent_domain() {
        let record = produce_local_media_capability(
            strong_nvme_facts()
                .with_persistence(LocalPersistenceSnapshot::label_only(evidence(4)).facts()),
        );
        let result = durable_sync_result(record);

        assert_eq!(record.persistence, MediaPersistenceDomain::Unknown);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::UnknownPersistenceDomain
        );
    }

    #[test]
    fn pool_label_degraded_health_refuses_durable_role() {
        let mut label = pool_label();
        label.device_health = 1;
        let identity = LocalPoolMemberIdentitySnapshot::from_pool_label(
            &label,
            true,
            true,
            LocalPathIdentityClass::StableMultipath,
            0,
        );
        let facts = strong_nvme_facts().with_health(identity.health_facts(evidence(8)));
        let record = produce_local_media_capability(facts);
        let result = durable_sync_result(record);

        assert_eq!(record.health, MediaHealthState::Degraded);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::DegradedMediaHealth
        );
    }

    #[test]
    fn ublk_fua_request_shape_without_passthrough_proof_is_flush_only() {
        let ublk = LocalUblkRequestShapeSnapshot::new(ublk_params(), UblkFeatureFlags(0), 32)
            .with_observed_flush_request()
            .with_observed_fua_write();
        let facts = strong_nvme_facts().with_block_io(ublk.block_io_facts(evidence(5)));
        let record = produce_local_media_capability(facts);
        let result = durable_sync_result(record);

        assert_eq!(record.logical_block_bytes, 4096);
        assert_eq!(record.max_queue_depth, 32);
        assert_eq!(record.flush_ordering, MediaFlushOrderingClass::FlushOnly);
        assert!(record
            .flags
            .contains_all(MediaCapabilityFlags::DISCARD_ZEROES_SHAPE));
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::UnsupportedFlushFuaSemantics
        );
    }

    #[test]
    fn ublk_and_pool_snapshots_can_produce_durable_local_capability() {
        let identity = LocalPoolMemberIdentitySnapshot::from_pool_label(
            &pool_label(),
            true,
            true,
            LocalPathIdentityClass::StableMultipath,
            5,
        );
        let ublk = LocalUblkRequestShapeSnapshot::new(ublk_params(), UblkFeatureFlags(0), 64)
            .with_observed_flush_request()
            .with_observed_fua_write()
            .with_ordering_passthrough_proof();
        let facts = LocalMediaCapabilityFacts::new(identity.media_class(), evidence(1))
            .with_identity(identity.identity_facts(
                LocalFirmwareSettingsSnapshot::proven(99, 100),
                evidence(2),
                evidence(3),
            ))
            .with_persistence(
                LocalPersistenceSnapshot::explicit(
                    MediaPersistenceDomain::OrdinaryPersistent,
                    false,
                    evidence(4),
                )
                .facts(),
            )
            .with_block_io(ublk.block_io_facts(evidence(5)))
            .with_atomicity(ublk.atomicity_facts(4096, true, evidence(6)))
            .with_geometry(ublk.geometry_facts(evidence(7)))
            .with_health(identity.health_facts(evidence(8)))
            .with_freshness(identity.freshness_facts(evidence(9)));
        let record = produce_local_media_capability(facts);
        let result = durable_sync_result(record);

        assert!(result.satisfied);
        assert_eq!(record.media_class, StorageMediaClass::NvmeFlash);
        assert_eq!(record.flush_ordering, MediaFlushOrderingClass::FlushAndFua);
        assert_eq!(record.physical_block_bytes, 4096);
        assert_eq!(record.atomic_write_unit_bytes, 4096);
        assert_eq!(record.optimal_io_bytes, 131_072);
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
