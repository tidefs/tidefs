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

const fn block_bytes_from_shift(shift: u8) -> u32 {
    if shift < 32 {
        1_u32 << shift
    } else {
        0
    }
}

const fn label_media_class(device_class: LocalPoolDeviceClass) -> StorageMediaClass {
    match device_class {
        LocalPoolDeviceClass::Hdd => StorageMediaClass::HddRotational,
        LocalPoolDeviceClass::Ssd => StorageMediaClass::SsdFlash,
        LocalPoolDeviceClass::Nvme | LocalPoolDeviceClass::LogDevice => {
            StorageMediaClass::NvmeFlash
        }
        LocalPoolDeviceClass::Pmem | LocalPoolDeviceClass::Nvdimm => {
            StorageMediaClass::PersistentMemory
        }
        LocalPoolDeviceClass::Cache => StorageMediaClass::SsdFlash,
        LocalPoolDeviceClass::Special => StorageMediaClass::SsdFlash,
        LocalPoolDeviceClass::Spare => StorageMediaClass::HddRotational,
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

/// Decoded operational state from a local pool-label sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalPoolLabelState {
    Active,
    Exported,
    Destroyed,
}

impl LocalPoolLabelState {
    #[must_use]
    pub const fn is_importable(self) -> bool {
        matches!(self, Self::Active | Self::Exported)
    }
}

/// Decoded allocation class from a local pool-label sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalPoolDeviceClass {
    Hdd,
    Ssd,
    Nvme,
    Pmem,
    Nvdimm,
    LogDevice,
    Cache,
    Special,
    Spare,
}

/// Stable fields decoded from one local pool label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalDecodedPoolLabel {
    pub pool_guid: [u8; 16],
    pub device_guid: [u8; 16],
    pub pool_state: LocalPoolLabelState,
    pub label_commit_group: u64,
    pub topology_generation: u64,
    pub device_index: u32,
    pub device_count: u32,
    pub device_class: LocalPoolDeviceClass,
    pub device_capacity_bytes: u64,
    pub device_health: u8,
}

impl LocalDecodedPoolLabel {
    #[must_use]
    pub const fn new(
        pool_guid: [u8; 16],
        device_guid: [u8; 16],
        pool_state: LocalPoolLabelState,
        device_class: LocalPoolDeviceClass,
    ) -> Self {
        Self {
            pool_guid,
            device_guid,
            pool_state,
            label_commit_group: 0,
            topology_generation: 0,
            device_index: 0,
            device_count: 0,
            device_class,
            device_capacity_bytes: 0,
            device_health: 0,
        }
    }
}

/// Local block-I/O capability sample for producer facts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalBlockIoCapabilities {
    pub read: bool,
    pub write: bool,
    pub flush: bool,
    pub discard: bool,
    pub write_zeroes: bool,
    pub zero_range: bool,
    pub teardown: bool,
    pub sector_size: u32,
    pub capacity_sectors: u64,
}

impl LocalBlockIoCapabilities {
    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            read: false,
            write: false,
            flush: false,
            discard: false,
            write_zeroes: false,
            zero_range: false,
            teardown: false,
            sector_size: 0,
            capacity_sectors: 0,
        }
    }

    #[must_use]
    pub const fn read_write_flush(sector_size: u32, capacity_sectors: u64, teardown: bool) -> Self {
        Self {
            read: true,
            write: true,
            flush: true,
            discard: false,
            write_zeroes: false,
            zero_range: false,
            teardown,
            sector_size,
            capacity_sectors,
        }
    }

    #[must_use]
    pub const fn from_kernel_storage_io(capabilities: KernelStorageIoCapabilities) -> Self {
        Self {
            read: capabilities.read,
            write: capabilities.write,
            flush: capabilities.flush,
            discard: capabilities.discard,
            write_zeroes: capabilities.write_zeroes,
            zero_range: capabilities.zero_range,
            teardown: capabilities.teardown,
            sector_size: capabilities.sector_size,
            capacity_sectors: capabilities.capacity_sectors,
        }
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
    pub pool_state: LocalPoolLabelState,
    pub label_commit_group: u64,
    pub topology_generation: u64,
    pub device_index: u32,
    pub device_count: u32,
    pub device_class: LocalPoolDeviceClass,
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
    pub const fn from_decoded_label(
        label: LocalDecodedPoolLabel,
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
        if matches!(self.device_class, LocalPoolDeviceClass::Spare) {
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
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalUblkShapeParams {
    pub basic_shape_present: bool,
    pub discard_shape_present: bool,
    pub zoned_shape_present: bool,
    pub fua_advertised: bool,
    pub rotational: bool,
    pub volatile_write_cache: bool,
    pub zoned_feature_advertised: bool,
    pub logical_bs_shift: u8,
    pub physical_bs_shift: u8,
    pub io_opt_shift: u8,
    pub dev_sectors: u64,
    pub max_discard_sectors: u32,
    pub max_write_zeroes_sectors: u32,
    pub max_zone_append_sectors: u32,
}

impl LocalUblkShapeParams {
    #[must_use]
    pub const fn block_device(
        logical_bs_shift: u8,
        physical_bs_shift: u8,
        io_opt_shift: u8,
        dev_sectors: u64,
    ) -> Self {
        Self {
            basic_shape_present: true,
            discard_shape_present: false,
            zoned_shape_present: false,
            fua_advertised: false,
            rotational: false,
            volatile_write_cache: false,
            zoned_feature_advertised: false,
            logical_bs_shift,
            physical_bs_shift,
            io_opt_shift,
            dev_sectors,
            max_discard_sectors: 0,
            max_write_zeroes_sectors: 0,
            max_zone_append_sectors: 0,
        }
    }

    #[must_use]
    pub const fn with_fua_advertised(mut self) -> Self {
        self.fua_advertised = true;
        self
    }

    #[must_use]
    pub const fn with_rotational(mut self) -> Self {
        self.rotational = true;
        self
    }

    #[must_use]
    pub const fn with_volatile_write_cache(mut self) -> Self {
        self.volatile_write_cache = true;
        self
    }

    #[must_use]
    pub const fn with_discard_shape(
        mut self,
        max_discard_sectors: u32,
        max_write_zeroes_sectors: u32,
    ) -> Self {
        self.discard_shape_present = true;
        self.max_discard_sectors = max_discard_sectors;
        self.max_write_zeroes_sectors = max_write_zeroes_sectors;
        self
    }

    #[must_use]
    pub const fn with_zoned_shape(mut self, max_zone_append_sectors: u32) -> Self {
        self.zoned_shape_present = true;
        self.max_zone_append_sectors = max_zone_append_sectors;
        self
    }

    #[must_use]
    pub const fn with_zoned_feature_advertised(mut self) -> Self {
        self.zoned_feature_advertised = true;
        self
    }
}

/// Normalized ublk queue and request-shape sample, not ublk ABI ownership.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalUblkRequestShapeSnapshot {
    pub params: LocalUblkShapeParams,
    pub queue_depth: u16,
    pub observed_flush_request: bool,
    pub observed_fua_write: bool,
    pub flush_passthrough_proven: bool,
    pub fua_passthrough_proven: bool,
    pub ordering_limitations_absent: bool,
}

impl LocalUblkRequestShapeSnapshot {
    #[must_use]
    pub const fn new(params: LocalUblkShapeParams, queue_depth: u16) -> Self {
        Self {
            params,
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
        let logical_block_bytes = if self.params.basic_shape_present {
            block_bytes_from_shift(self.params.logical_bs_shift)
        } else {
            0
        };
        let capabilities = LocalBlockIoCapabilities {
            read: logical_block_bytes != 0 && self.params.dev_sectors != 0,
            write: logical_block_bytes != 0 && self.params.dev_sectors != 0,
            flush: self.observed_flush_request || self.flush_passthrough_proven,
            discard: self.params.discard_shape_present && self.params.max_discard_sectors != 0,
            write_zeroes: self.params.discard_shape_present
                && self.params.max_write_zeroes_sectors != 0,
            zero_range: false,
            teardown: false,
            sector_size: logical_block_bytes,
            capacity_sectors: self.params.dev_sectors,
        };
        let flush_ordering = if self.flush_passthrough_proven
            && self.fua_passthrough_proven
            && self.ordering_limitations_absent
            && self.params.fua_advertised
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
        let physical_block_bytes = if self.params.basic_shape_present {
            block_bytes_from_shift(self.params.physical_bs_shift)
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
        let optimal_io_bytes = if self.params.basic_shape_present {
            block_bytes_from_shift(self.params.io_opt_shift)
        } else {
            0
        };
        let geometry = if self.params.zoned_feature_advertised || self.params.zoned_shape_present {
            if self.params.max_zone_append_sectors != 0 {
                MediaProtocolGeometryClass::ZonedAppend
            } else {
                MediaProtocolGeometryClass::ZonedSequential
            }
        } else if self.params.rotational {
            MediaProtocolGeometryClass::RotationalSeek
        } else if self.params.basic_shape_present {
            MediaProtocolGeometryClass::RandomBlock
        } else {
            MediaProtocolGeometryClass::Unknown
        };

        LocalGeometryFacts::new(geometry, optimal_io_bytes, geometry_ref)
    }

    #[must_use]
    pub const fn volatile_write_cache_visible(self) -> bool {
        self.params.volatile_write_cache
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
    pub capabilities: LocalBlockIoCapabilities,
    pub flush_ordering: MediaFlushOrderingClass,
    pub discard_zeroes_shape_proven: bool,
    pub max_queue_depth: u32,
    pub flush_ref: StorageIntentEvidenceRef,
}

impl Default for LocalBlockIoFacts {
    fn default() -> Self {
        Self {
            capabilities: LocalBlockIoCapabilities::unsupported(),
            flush_ordering: MediaFlushOrderingClass::Unknown,
            discard_zeroes_shape_proven: false,
            max_queue_depth: 0,
            flush_ref: StorageIntentEvidenceRef::default(),
        }
    }
}

impl LocalBlockIoFacts {
    /// Convert local block capability booleans into conservative producer
    /// input. `flush = true` becomes `FlushOnly`; it is not FUA or
    /// power-loss-safety proof.
    #[must_use]
    pub const fn from_block_capabilities(
        capabilities: LocalBlockIoCapabilities,
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
    pub const fn from_kernel_storage_io_capabilities(
        capabilities: KernelStorageIoCapabilities,
        flush_ref: StorageIntentEvidenceRef,
    ) -> Self {
        let local = LocalBlockIoCapabilities::from_kernel_storage_io(capabilities);
        let mut facts = Self::from_block_capabilities(local, flush_ref);
        facts.discard_zeroes_shape_proven = local.discard || local.write_zeroes || local.zero_range;
        facts
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

/// Runtime health sample normalized before building local capability facts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalRuntimeHealthSnapshot {
    pub sample_present: bool,
    pub degraded: bool,
    pub failed: bool,
    pub quarantined: bool,
    pub thermal_warning: bool,
    pub error_window_open: bool,
}

impl LocalRuntimeHealthSnapshot {
    #[must_use]
    pub const fn healthy() -> Self {
        Self {
            sample_present: true,
            degraded: false,
            failed: false,
            quarantined: false,
            thermal_warning: false,
            error_window_open: false,
        }
    }

    #[must_use]
    pub const fn with_degraded(mut self) -> Self {
        self.degraded = true;
        self
    }

    #[must_use]
    pub const fn with_failed(mut self) -> Self {
        self.failed = true;
        self
    }

    #[must_use]
    pub const fn with_quarantined(mut self) -> Self {
        self.quarantined = true;
        self
    }

    #[must_use]
    pub const fn with_thermal_warning(mut self) -> Self {
        self.thermal_warning = true;
        self
    }

    #[must_use]
    pub const fn with_error_window_open(mut self) -> Self {
        self.error_window_open = true;
        self
    }

    #[must_use]
    pub const fn health_facts(self, health_ref: StorageIntentEvidenceRef) -> LocalHealthFacts {
        let health = if !self.sample_present {
            MediaHealthState::Unknown
        } else if self.quarantined {
            MediaHealthState::Quarantined
        } else if self.failed {
            MediaHealthState::Failed
        } else if self.degraded || self.thermal_warning || self.error_window_open {
            MediaHealthState::Degraded
        } else {
            MediaHealthState::Healthy
        };

        LocalHealthFacts::new(health, health_ref)
    }
}

/// Runtime freshness sample normalized before building local capability facts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalRuntimeFreshnessSnapshot {
    pub sample_present: bool,
    pub sample_age_ms: u64,
    pub max_sample_age_ms: u64,
    pub identity_generation: u64,
    pub namespace_generation: u64,
    pub settings_generation: u64,
    pub pool_member_generation: u64,
    pub validated_reset_generation: u64,
    pub observed_reset_generation: u64,
    pub contradictory_sample: bool,
}

impl LocalRuntimeFreshnessSnapshot {
    #[must_use]
    pub const fn fresh_for_identity(
        identity: LocalMediaIdentityFacts,
        sample_age_ms: u64,
        max_sample_age_ms: u64,
        reset_generation: u64,
    ) -> Self {
        Self {
            sample_present: true,
            sample_age_ms,
            max_sample_age_ms,
            identity_generation: identity.identity_generation,
            namespace_generation: identity.namespace_generation,
            settings_generation: identity.settings_generation,
            pool_member_generation: identity.pool_member_generation,
            validated_reset_generation: reset_generation,
            observed_reset_generation: reset_generation,
            contradictory_sample: false,
        }
    }

    #[must_use]
    pub const fn with_sample_age_ms(mut self, sample_age_ms: u64) -> Self {
        self.sample_age_ms = sample_age_ms;
        self
    }

    #[must_use]
    pub const fn with_max_sample_age_ms(mut self, max_sample_age_ms: u64) -> Self {
        self.max_sample_age_ms = max_sample_age_ms;
        self
    }

    #[must_use]
    pub const fn with_identity_generation(mut self, identity_generation: u64) -> Self {
        self.identity_generation = identity_generation;
        self
    }

    #[must_use]
    pub const fn with_namespace_generation(mut self, namespace_generation: u64) -> Self {
        self.namespace_generation = namespace_generation;
        self
    }

    #[must_use]
    pub const fn with_settings_generation(mut self, settings_generation: u64) -> Self {
        self.settings_generation = settings_generation;
        self
    }

    #[must_use]
    pub const fn with_pool_member_generation(mut self, pool_member_generation: u64) -> Self {
        self.pool_member_generation = pool_member_generation;
        self
    }

    #[must_use]
    pub const fn with_observed_reset_generation(mut self, reset_generation: u64) -> Self {
        self.observed_reset_generation = reset_generation;
        self
    }

    #[must_use]
    pub const fn with_contradictory_sample(mut self) -> Self {
        self.contradictory_sample = true;
        self
    }

    #[must_use]
    pub const fn freshness_facts(
        self,
        expected_identity: LocalMediaIdentityFacts,
        freshness_ref: StorageIntentEvidenceRef,
    ) -> LocalFreshnessFacts {
        let freshness = if !self.sample_present {
            MediaCapabilityFreshnessState::Missing
        } else if self.sample_age_ms > self.max_sample_age_ms
            || self.observed_reset_generation != self.validated_reset_generation
        {
            MediaCapabilityFreshnessState::Stale
        } else if self.contradictory_sample
            || self.identity_generation != expected_identity.identity_generation
            || self.namespace_generation != expected_identity.namespace_generation
            || self.settings_generation != expected_identity.settings_generation
            || self.pool_member_generation != expected_identity.pool_member_generation
        {
            MediaCapabilityFreshnessState::Contradictory
        } else {
            MediaCapabilityFreshnessState::Fresh
        };

        LocalFreshnessFacts::new(freshness, freshness_ref)
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
                capabilities: LocalBlockIoCapabilities {
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
    pub const fn with_runtime_health(
        mut self,
        health: LocalRuntimeHealthSnapshot,
        health_ref: StorageIntentEvidenceRef,
    ) -> Self {
        self.health = health.health_facts(health_ref);
        self
    }

    #[must_use]
    pub const fn with_freshness(mut self, freshness: LocalFreshnessFacts) -> Self {
        self.freshness = freshness;
        self
    }

    #[must_use]
    pub const fn with_runtime_freshness(
        mut self,
        freshness: LocalRuntimeFreshnessSnapshot,
        freshness_ref: StorageIntentEvidenceRef,
    ) -> Self {
        self.freshness = freshness.freshness_facts(self.identity, freshness_ref);
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
        let block = LocalBlockIoCapabilities {
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
                LocalBlockIoFacts::from_block_capabilities(block, evidence(5))
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

    fn strong_pmem_facts() -> LocalMediaCapabilityFacts {
        let block = LocalBlockIoCapabilities {
            read: true,
            write: true,
            flush: true,
            discard: false,
            write_zeroes: false,
            zero_range: false,
            teardown: true,
            sector_size: 64,
            capacity_sectors: 4096,
        };

        LocalMediaCapabilityFacts::new(StorageMediaClass::PersistentMemory, evidence(21))
            .with_identity(LocalMediaIdentityFacts::stable(
                21,
                evidence(22),
                evidence(23),
            ))
            .with_persistence(LocalPersistenceFacts::new(
                MediaPersistenceDomain::PersistentMemory,
                evidence(24),
            ))
            .with_block_io(
                LocalBlockIoFacts::from_block_capabilities(block, evidence(25))
                    .with_flush_ordering(MediaFlushOrderingClass::PmemFlushFence)
                    .with_max_queue_depth(1),
            )
            .with_atomicity(LocalAtomicityFacts::block_atomic(
                MediaAtomicityClass::AtomicWriteUnit,
                64,
                64,
                evidence(26),
            ))
            .with_geometry(LocalGeometryFacts::new(
                MediaProtocolGeometryClass::PmemByteAddressable,
                64,
                evidence(27),
            ))
            .with_health(LocalHealthFacts::new(
                MediaHealthState::Healthy,
                evidence(28),
            ))
            .with_freshness(LocalFreshnessFacts::new(
                MediaCapabilityFreshnessState::Fresh,
                evidence(29),
            ))
            .with_latency_class_us(1)
    }

    fn durable_sync_result(record: StorageIntentMediaCapabilityRecord) -> ReceiptPredicateResult {
        media_capability_satisfies_role(
            MediaRoleRequirement::AUTHORITY,
            StorageIntentGuaranteeClass::LocalIntent,
            StorageMediaRole::SyncIntent,
            record,
        )
    }

    fn pool_label() -> LocalDecodedPoolLabel {
        let mut label = LocalDecodedPoolLabel::new(
            [0xAA; 16],
            [0xBB; 16],
            LocalPoolLabelState::Active,
            LocalPoolDeviceClass::Nvme,
        );
        label.label_commit_group = 42;
        label.topology_generation = 7;
        label.device_count = 2;
        label.device_index = 1;
        label.device_capacity_bytes = 4 * 1024 * 1024;
        label.device_health = 0;
        label
    }

    const fn ublk_params() -> LocalUblkShapeParams {
        LocalUblkShapeParams::block_device(12, 12, 17, 2048)
            .with_fua_advertised()
            .with_discard_shape(128, 64)
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
        let kernel_flush_only = LocalBlockIoFacts::from_block_capabilities(
            LocalBlockIoCapabilities::read_write_flush(4096, 1024, true),
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
    fn kernel_storage_io_capabilities_preserve_shape_but_not_ordering_proof() {
        let kernel = KernelStorageIoCapabilities {
            read: true,
            write: true,
            flush: true,
            discard: true,
            write_zeroes: true,
            zero_range: true,
            teardown: true,
            sector_size: 512,
            capacity_sectors: 4096,
        };
        let facts = LocalBlockIoFacts::from_kernel_storage_io_capabilities(kernel, evidence(5))
            .with_max_queue_depth(16);
        let record = produce_local_media_capability(strong_nvme_facts().with_block_io(facts));
        let result = durable_sync_result(record);

        assert_eq!(
            facts.capabilities,
            LocalBlockIoCapabilities::from_kernel_storage_io(kernel)
        );
        assert_eq!(record.logical_block_bytes, 512);
        assert_eq!(record.max_queue_depth, 16);
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
    fn kernel_storage_io_missing_flush_is_unsupported_for_durable_role() {
        let kernel = KernelStorageIoCapabilities {
            read: true,
            write: true,
            flush: false,
            discard: false,
            write_zeroes: false,
            zero_range: false,
            teardown: true,
            sector_size: 4096,
            capacity_sectors: 1024,
        };
        let facts = LocalBlockIoFacts::from_kernel_storage_io_capabilities(kernel, evidence(5));
        let record = produce_local_media_capability(strong_nvme_facts().with_block_io(facts));
        let result = durable_sync_result(record);

        assert_eq!(record.flush_ordering, MediaFlushOrderingClass::None);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::UnsupportedFlushFuaSemantics
        );
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
        let identity = LocalPoolMemberIdentitySnapshot::from_decoded_label(
            pool_label(),
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
        let identity = LocalPoolMemberIdentitySnapshot::from_decoded_label(
            pool_label(),
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
        let identity = LocalPoolMemberIdentitySnapshot::from_decoded_label(
            pool_label(),
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
        let identity = LocalPoolMemberIdentitySnapshot::from_decoded_label(
            label,
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
        let ublk = LocalUblkRequestShapeSnapshot::new(ublk_params(), 32)
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
        let identity = LocalPoolMemberIdentitySnapshot::from_decoded_label(
            pool_label(),
            true,
            true,
            LocalPathIdentityClass::StableMultipath,
            5,
        );
        let ublk = LocalUblkRequestShapeSnapshot::new(ublk_params(), 64)
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
    fn runtime_sample_age_refuses_as_stale_evidence() {
        let facts = strong_nvme_facts();
        let freshness =
            LocalRuntimeFreshnessSnapshot::fresh_for_identity(facts.identity, 30_001, 30_000, 4);
        let record =
            produce_local_media_capability(facts.with_runtime_freshness(freshness, evidence(9)));
        let result = durable_sync_result(record);

        assert_eq!(record.freshness, MediaCapabilityFreshnessState::Stale);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::StaleMediaCapabilityEvidence
        );
    }

    #[test]
    fn runtime_reset_generation_change_refuses_as_stale_evidence() {
        let facts = strong_nvme_facts();
        let freshness =
            LocalRuntimeFreshnessSnapshot::fresh_for_identity(facts.identity, 4, 30_000, 7)
                .with_observed_reset_generation(8);
        let record =
            produce_local_media_capability(facts.with_runtime_freshness(freshness, evidence(9)));
        let result = durable_sync_result(record);

        assert_eq!(record.freshness, MediaCapabilityFreshnessState::Stale);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::StaleMediaCapabilityEvidence
        );
    }

    #[test]
    fn runtime_generation_drift_refuses_as_contradictory_evidence() {
        let facts = strong_nvme_facts();
        let settings_change =
            LocalRuntimeFreshnessSnapshot::fresh_for_identity(facts.identity, 4, 30_000, 7)
                .with_settings_generation(facts.identity.settings_generation + 1);
        let multipath_failover =
            LocalRuntimeFreshnessSnapshot::fresh_for_identity(facts.identity, 4, 30_000, 7)
                .with_pool_member_generation(facts.identity.pool_member_generation + 1);

        let settings_record = produce_local_media_capability(
            facts.with_runtime_freshness(settings_change, evidence(9)),
        );
        let failover_record = produce_local_media_capability(
            facts.with_runtime_freshness(multipath_failover, evidence(9)),
        );

        assert_eq!(
            settings_record.freshness,
            MediaCapabilityFreshnessState::Contradictory
        );
        assert_eq!(
            failover_record.freshness,
            MediaCapabilityFreshnessState::Contradictory
        );
        assert_eq!(
            durable_sync_result(settings_record).refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert_eq!(
            durable_sync_result(failover_record).refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn runtime_thermal_or_error_health_refuses_durable_role() {
        let thermal = produce_local_media_capability(strong_nvme_facts().with_runtime_health(
            LocalRuntimeHealthSnapshot::healthy().with_thermal_warning(),
            evidence(8),
        ));
        let error_window = produce_local_media_capability(strong_nvme_facts().with_runtime_health(
            LocalRuntimeHealthSnapshot::healthy().with_error_window_open(),
            evidence(8),
        ));

        assert_eq!(thermal.health, MediaHealthState::Degraded);
        assert_eq!(error_window.health, MediaHealthState::Degraded);
        assert_eq!(
            durable_sync_result(thermal).refusal,
            StorageIntentRefusalReason::DegradedMediaHealth
        );
        assert_eq!(
            durable_sync_result(error_window).refusal,
            StorageIntentRefusalReason::DegradedMediaHealth
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
                    LocalBlockIoFacts::from_block_capabilities(
                        LocalBlockIoCapabilities::read_write_flush(4096, 1024, true),
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

    #[test]
    fn pmem_label_maps_media_class_without_persistence_receipt() {
        let mut label = pool_label();
        label.device_class = LocalPoolDeviceClass::Pmem;
        let identity = LocalPoolMemberIdentitySnapshot::from_decoded_label(
            label,
            true,
            true,
            LocalPathIdentityClass::StableSinglePath,
            3,
        );
        let facts = LocalMediaCapabilityFacts::new(identity.media_class(), evidence(31))
            .with_identity(identity.identity_facts(
                LocalFirmwareSettingsSnapshot::proven(13, 13),
                evidence(32),
                evidence(33),
            ))
            .with_persistence(LocalPersistenceSnapshot::label_only(evidence(34)).facts())
            .with_block_io(
                LocalBlockIoFacts::from_block_capabilities(
                    LocalBlockIoCapabilities::read_write_flush(64, 4096, true),
                    evidence(35),
                )
                .with_flush_ordering(MediaFlushOrderingClass::PmemFlushFence),
            )
            .with_atomicity(LocalAtomicityFacts::block_atomic(
                MediaAtomicityClass::AtomicWriteUnit,
                64,
                64,
                evidence(36),
            ))
            .with_geometry(LocalGeometryFacts::new(
                MediaProtocolGeometryClass::PmemByteAddressable,
                64,
                evidence(37),
            ))
            .with_health(identity.health_facts(evidence(38)))
            .with_freshness(LocalFreshnessFacts::new(
                MediaCapabilityFreshnessState::Fresh,
                evidence(39),
            ));

        let record = produce_local_media_capability(facts);
        let result = durable_sync_result(record);

        assert_eq!(record.media_class, StorageMediaClass::PersistentMemory);
        assert!(!record
            .flags
            .contains_all(MediaCapabilityFlags::PERSISTENCE_DOMAIN));
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::UnknownPersistenceDomain
        );
    }

    #[test]
    fn nvdimm_pmem_flush_fence_receipt_satisfies_sync_role() {
        let mut label = pool_label();
        label.device_class = LocalPoolDeviceClass::Nvdimm;
        let identity = LocalPoolMemberIdentitySnapshot::from_decoded_label(
            label,
            true,
            true,
            LocalPathIdentityClass::StableSinglePath,
            4,
        );

        let record = produce_local_media_capability(strong_pmem_facts().with_identity(
            identity.identity_facts(
                LocalFirmwareSettingsSnapshot::proven(14, 14),
                evidence(41),
                evidence(42),
            ),
        ));
        let result = durable_sync_result(record);

        assert!(result.satisfied);
        assert_eq!(record.media_class, StorageMediaClass::PersistentMemory);
        assert_eq!(record.persistence, MediaPersistenceDomain::PersistentMemory);
        assert_eq!(
            record.flush_ordering,
            MediaFlushOrderingClass::PmemFlushFence
        );
        assert_eq!(
            record.geometry,
            MediaProtocolGeometryClass::PmemByteAddressable
        );
        assert!(record.flags.contains_all(
            MediaCapabilityFlags::PERSISTENCE_DOMAIN
                .union(MediaCapabilityFlags::PMEM_FLUSH_FENCE)
                .union(MediaCapabilityFlags::STABLE_DEVICE_IDENTITY)
                .union(MediaCapabilityFlags::STABLE_NAMESPACE_IDENTITY)
        ));
    }
}
