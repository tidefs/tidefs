// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]
#![deny(dead_code)]
#![deny(unused_imports)]

//! Durable local object-store for TideFS.
//!
//! # Overview
//!
//! Append-only segment-log object store that writes real bytes to disk,
//! rebuilds a latest-object index on open, and serves as the persistence
//! foundation for `tidefs_local_filesystem`. Every object write appends a
//! payload followed by a versioned integrity trailer; incomplete (torn)
//! final records are detected and repaired on replay. Delete tombstones
//! are recorded inline so replayed state converges without operator repair.
//!
//! # Design
//!
//! Data lives under a caller-provided store root in
//! `segments/segment-NNN.vlos` files. Each segment is written sequentially;
//! the store never overwrites payload bytes inline. A footer commit marker
//! after each record carries magic bytes, a monotonic commit_group number, and a CRC
//! covering the full payload.
//!
//! ## Write Path
//!
//! Every object write flows through five stages inside this crate:
//!
//! 1. **Ingestion** — The caller (`tidefs_local_filesystem` via the
//!    [`ObjectStore::put`] trait) hands a payload to
//!    [`LocalObjectStore::put_content_addressed`]. The store derives a BLAKE3-256
//!    content key, checks for duplicate/collision, and passes the write to the
//!    `SegmentBuilder`.
//! 2. **Segment buffering** — `PendingWrite` entries accumulate in the
//!    `SegmentBuilder` in insertion order. Each entry captures the object key,
//!    record kind (Put or Delete), and payload bytes. The builder tracks total
//!    buffered bytes against the segment size threshold.
//! 3. **BLAKE3 checksum anchor** — When the threshold is reached or an explicit
//!    flush is requested, the builder finalizes the segment by computing a
//!    BLAKE3-256 checksum tree over all pending records. The resulting
//!    `WriteSegment` carries a self-describing header with record count, total
//!    bytes, and the root checksum for end-to-end integrity verification.
//! 4. **Segment flush** — [`LocalObjectStore::flush_segment`] serializes the
//!    `WriteSegment` into the current `segment-NNN.vlos` file. Each record
//!    gets a 96-byte header (magic, version, key, length, flags), the payload
//!    bytes, a 112-byte `IntegrityTrailerV2` with BLAKE3-256 digests, and a
//!    16-byte commit footer. The store updates the in-memory object index and
//!    writes a per-segment `SegmentIntegrityFooter` for hash-chain verification.
//! 5. **Commit marker** — After every record, a `COMMIT_MARKER_BASE`-tagged
//!    footer is fsynced to disk. On crash recovery, torn (incomplete) final
//!    records are detected by the missing commit marker and silently repaired
//!    during replay.
//!
//! ## Relationship to Sibling Crates
//!
//! This crate sits between the filesystem layer above and the I/O abstraction
//! below, bridging POSIX semantics to durable on-disk storage:
//!
//! - **`tidefs_local_filesystem`** — The primary caller. Translates FUSE
//!   operations (write, fsync, unlink) into [`ObjectKey`]-addressed object
//!   writes and reads against this store. It never accesses segment files
//!   directly; all persistence flows through the [`ObjectStore`] trait.
//! - **`tidefs_object_io`** — Provides the chunked I/O primitives
//!   (read/write/sync with scatter-gather) that the segment layer uses for
//!   raw device access. This crate's [`io_scheduler`] module sits above
//!   `tidefs_object_io`, adding I/O-class-aware token-bucket admission before
//!   dispatching to the raw I/O layer.
//! - **[`tidefs_checksum_tree`]** — Supplies the BLAKE3-256 Merkle tree
//!   construction used by `SegmentBuilder` for per-segment checksum
//!   anchoring and by the read path for payload verification.
//! - **[`tidefs_frame`]** — Re-exported as the [`compress`] module, providing
//!   optional frame-level compression before segment writes.
//!
//! ## Record versions
//!
//! | Version | Integrity trailer | Status |
//! |---------|-------------------|--------|
//! | v1 | None (development) | Compatibility replay only |
//! | v2 | FNV-1a 64-bit | Compatibility replay only |
//! | v3 | BLAKE3-256 | Current production format |
//!
//! On open, the store replays all segments, validates each record against
//! its trailer, and rebuilds a `latest_object_index`. Torn final records
//! are repaired silently. This crate forbids `unsafe` code.
//!
//! # Key types
//!
//! - [`ObjectKey`] — 32-byte object identifier.
//! - [`IntegrityDigest64`] — FNV-1a 64-bit checksum (v2 records).
//! - [`ProductionIntegrityDigest`] — BLAKE3-256 digest (v3 records).
//! - [`RecordKind`] — `Put` (write) or `Delete` (tombstone).
//! - [`StoreOptions`] — Open-time configuration.
//! - [`StoredObject`] — Replayed object with payload, key, and location.
//!
//! # Pool & Device
//!
//! The [`pool`] module provides a `Pool` abstraction: the top-level storage
//! container for one or more devices. A pool routes I/O by device class and
//! tracks health and statistics. Devices are configured via [`DeviceConfig`]
//! and support several [`DeviceKind`] variants.
//!
//! # I/O scheduling
//!
//! [`IoClass`] partitions I/O into `Data`, `Metadata`, `IntentLog`, and
//! `ReadCache` lanes. The `IoScheduler` routes each class to the
//! appropriate device set and enforces bandwidth budgets.
//!
//! # Fault injection
//!
//! The [`fault_catalog`] and [`fault_injection`] modules support
//! deterministic crash/post-crash test harnesses. Fault classes include
//! storage faults, process faults, and resource faults.
//!
//! # On-disk format rules
//!
//! [`LOCAL_OBJECT_STORE_ON_DISK_FORMAT_RULES`] encodes the implementation-tracked non-release
//! format contract as a slice of [`LocalObjectStoreFormatRule`] entries.
//!
//! # Production integrity policy
//!
//! [`PRODUCTION_INTEGRITY_POLICY_RULES`] defines the cryptographic integrity
//! contract for record versions and replay rules.
//!
//! # Import / Export
//!
//! `PoolImporter` discovers candidate pools from device scans and
//! validates label integrity. `PoolExporter` detaches a pool cleanly.
//!
//! # Compression & Encryption
//!
//! The [`compress`] module (re-exported from `tidefs_frame`) provides
//! frame-level compression.
//! Encryption is provided by the `tidefs-encryption` crate via `EncryptedObjectStore`.
//!
//! # Implementation boundary
//!
//! The local object store stays separate from filesystem semantics and I/O
//! scheduling. Append-only segment records carry inline integrity trailers and
//! are replayed into the latest-object index at open, keeping this crate
//! focused on object persistence plus pool/device plumbing.

use std::convert::TryFrom;
use std::fmt;
use std::fmt::Write as _;
use std::time::SystemTime;
use tidefs_durability_layout::DurabilityLayoutV1;

pub mod block_device_store;
pub mod constants;
pub mod device_layout;
pub mod fault_catalog;
pub mod fault_injection;
pub mod format_manifest;
pub mod integrity;
pub mod intent_log;
pub mod io_pressure;
pub mod media_cost_ledger;
pub mod txg_manager;
pub use compress::CompressionStats;
pub use compress::{CompressionAlgorithm, CompressionConfig};
pub use fault_injection::{CrashInjectionConfig, CrashInjectionPoint, FaultInjectionConfig};
pub use io_pressure::{IoPressureProbe, RebuildThrottleConfig};
pub use media_cost_ledger::*;
pub use tidefs_frame as compress;
pub mod encrypt;
pub mod snapshot;
pub use constants::*;
pub use snapshot::{SnapshotCatalog, SnapshotEntry, SNAPSHOT_ENTRY_PREFIX};

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(
    Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ObjectKey([u8; 32]);

impl ObjectKey {
    /// Returns a reference to the raw bytes of this key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) const POOL_PLACEMENT_RECEIPT_KEY_PREFIX: [u8; 8] = *b"TFSPRCPT";
pub(crate) const POOL_PLACEMENT_SHARD_KEY_PREFIX: [u8; 8] = *b"TFSPSHRD";
pub(crate) const POOL_RECEIPT_GENERATION_HIGH_WATER_KEY_PREFIX: [u8; 8] = *b"TFSPRGHW";

pub(crate) fn pool_receipt_generation_high_water_key() -> ObjectKey {
    let mut bytes = *blake3::hash(b"tidefs-pool-receipt-generation-high-water-v1").as_bytes();
    bytes[..8].copy_from_slice(&POOL_RECEIPT_GENERATION_HIGH_WATER_KEY_PREFIX);
    ObjectKey::from_bytes32(bytes)
}

pub(crate) fn is_pool_placement_receipt_key(key: ObjectKey) -> bool {
    let bytes = key.as_bytes();
    bytes[..8] == POOL_PLACEMENT_RECEIPT_KEY_PREFIX
}

pub(crate) fn is_pool_receipt_generation_high_water_key(key: ObjectKey) -> bool {
    let bytes = key.as_bytes();
    bytes[..8] == POOL_RECEIPT_GENERATION_HIGH_WATER_KEY_PREFIX
}

pub(crate) fn is_pool_placement_scan_internal_key(key: ObjectKey) -> bool {
    let bytes = key.as_bytes();
    bytes[..8] == POOL_PLACEMENT_RECEIPT_KEY_PREFIX
        || bytes[..8] == POOL_PLACEMENT_SHARD_KEY_PREFIX
        || is_pool_receipt_generation_high_water_key(key)
}

impl fmt::Debug for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectKey({self})")
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct IntegrityDigest64(pub u64);

impl IntegrityDigest64 {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ProductionIntegrityDigest([u8; PRODUCTION_INTEGRITY_DIGEST_LEN]);

impl ProductionIntegrityDigest {
    pub const ZERO: Self = Self([0_u8; PRODUCTION_INTEGRITY_DIGEST_LEN]);

    #[must_use]
    pub const fn from_bytes32(bytes: [u8; PRODUCTION_INTEGRITY_DIGEST_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes32(self) -> [u8; PRODUCTION_INTEGRITY_DIGEST_LEN] {
        self.0
    }
}

impl fmt::Debug for ProductionIntegrityDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProductionIntegrityDigest({self})")
    }
}

impl fmt::Display for ProductionIntegrityDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct ProductionIntegrityRecordDigests {
    pub payload_digest: ProductionIntegrityDigest,
    pub record_digest: ProductionIntegrityDigest,
}

impl fmt::Display for IntegrityDigest64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Put = 1,
    Delete = 2,
}

/// Decode error for `RecordKind::try_from(u16)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKindDecodeError {
    UnknownRecordKind(u16),
}

impl RecordKind {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::Put => "put object bytes",
            Self::Delete => "delete object tombstone",
        }
    }
}

impl TryFrom<u16> for RecordKind {
    type Error = RecordKindDecodeError;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Put),
            2 => Ok(Self::Delete),
            _ => Err(RecordKindDecodeError::UnknownRecordKind(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalObjectStoreFormatTopic {
    SegmentIdentity,
    SegmentGapPolicy,
    RecordVersions,
    HeaderLayout,
    FooterSemantics,
    TombstoneSemantics,
    VersionHistory,
    UpgradeRules,
}

impl LocalObjectStoreFormatTopic {
    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::SegmentIdentity => "segment-identity",
            Self::SegmentGapPolicy => "segment-gap-policy",
            Self::RecordVersions => "record-versions",
            Self::HeaderLayout => "header-layout",
            Self::FooterSemantics => "footer-semantics",
            Self::TombstoneSemantics => "tombstone-semantics",
            Self::VersionHistory => "version-history",
            Self::UpgradeRules => "upgrade-rules",
        }
    }

    #[must_use]
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::SegmentIdentity => "segment identity",
            Self::SegmentGapPolicy => "segment gaps",
            Self::RecordVersions => "record versions",
            Self::HeaderLayout => "header layout",
            Self::FooterSemantics => "footer semantics",
            Self::TombstoneSemantics => "tombstones",
            Self::VersionHistory => "history",
            Self::UpgradeRules => "upgrade rules",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalObjectStoreFormatRule {
    pub topic: LocalObjectStoreFormatTopic,
    pub rule: &'static str,
    pub source_marker: &'static str,
}

pub const LOCAL_OBJECT_STORE_ON_DISK_FORMAT_RULES: &[LocalObjectStoreFormatRule] = &[
    LocalObjectStoreFormatRule {
        topic: LocalObjectStoreFormatTopic::SegmentIdentity,
        rule: "segments live under the segments directory and use segment-0000000000000000.vlos style lower-hex u64 ids",
        source_marker: "segment_file_name and parse_segment_file_name",
    },
    LocalObjectStoreFormatRule {
        topic: LocalObjectStoreFormatTopic::SegmentGapPolicy,
        rule: "segment files are discovered by valid names, sorted, and replayed in id order; gaps are tolerated as absent segment ids, while corruption inside any discovered non-final segment is rejected",
        source_marker: "discover_segment_ids and replay_segment",
    },
    LocalObjectStoreFormatRule {
        topic: LocalObjectStoreFormatTopic::RecordVersions,
        rule: "record version 1 has a 96-byte header and payload only; record version 2 adds a 16-byte footer; record version 3 adds a BLAKE3-256 production-integrity trailer and is the only version written by current code",
        source_marker: "RECORD_FORMAT_VERSION_V1_NO_FOOTER, RECORD_FORMAT_VERSION_V2_FOOTER, and RECORD_FORMAT_VERSION",
    },
    LocalObjectStoreFormatRule {
        topic: LocalObjectStoreFormatTopic::HeaderLayout,
        rule: "the 96-byte little-endian header stores magic, version, kind, header length, reserved zeros, sequence, payload length, payload checksum, header checksum, commit marker, object key, and reserved zeros",
        source_marker: "encode_header and decode_header",
    },
    LocalObjectStoreFormatRule {
        topic: LocalObjectStoreFormatTopic::FooterSemantics,
        rule: "version 2 and version 3 records are committed for replay only when the post-payload footer magic and footer marker validate against the header fields",
        source_marker: "encode_footer and decode_footer",
    },
    LocalObjectStoreFormatRule {
        topic: LocalObjectStoreFormatTopic::TombstoneSemantics,
        rule: "delete records are zero-payload tombstones that remove the key from the live index and do not erase older put history",
        source_marker: "RecordKind::Delete and delete tombstone carries payload bytes",
    },
    LocalObjectStoreFormatRule {
        topic: LocalObjectStoreFormatTopic::VersionHistory,
        rule: "every fully replayable put location remains available through per-key history so higher layers can inspect older committed values",
        source_marker: "history: BTreeMap<ObjectKey, Vec<ObjectLocation>>",
    },
    LocalObjectStoreFormatRule {
        topic: LocalObjectStoreFormatTopic::UpgradeRules,
        rule: "current replay accepts v1 no-footer, v2 footer, and v3 production-integrity records, writes only v3 records, rejects unsupported future versions, and treats new format changes as explicit migrations",
        source_marker: "UnsupportedVersion, record_has_footer, and record_has_production_integrity_trailer",
    },
];

#[must_use]
pub const fn local_object_store_on_disk_format_rules() -> &'static [LocalObjectStoreFormatRule] {
    LOCAL_OBJECT_STORE_ON_DISK_FORMAT_RULES
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionIntegrityPolicyTopic {
    ChosenAlgorithms,
    DomainSeparation,
    CollisionPolicy,
    AuthenticatedRoot,
    MigrationPlan,
    CompatibilityBoundary,
    KeyHandling,
    Validation,
}

impl ProductionIntegrityPolicyTopic {
    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::ChosenAlgorithms => "chosen-algorithms",
            Self::DomainSeparation => "domain-separation",
            Self::CollisionPolicy => "collision-policy",
            Self::AuthenticatedRoot => "authenticated-root",
            Self::MigrationPlan => "migration-plan",
            Self::CompatibilityBoundary => "compatibility-boundary",
            Self::KeyHandling => "key-handling",
            Self::Validation => "validation",
        }
    }

    #[must_use]
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::ChosenAlgorithms => "chosen algorithms",
            Self::DomainSeparation => "domain separation",
            Self::CollisionPolicy => "collision policy",
            Self::AuthenticatedRoot => "authenticated root",
            Self::MigrationPlan => "migration plan",
            Self::CompatibilityBoundary => "compatibility boundary",
            Self::KeyHandling => "key handling",
            Self::Validation => "validation",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionIntegrityPolicyRule {
    pub topic: ProductionIntegrityPolicyTopic,
    pub rule: &'static str,
    pub source_marker: &'static str,
}

pub const PRODUCTION_INTEGRITY_POLICY_RULES: &[ProductionIntegrityPolicyRule] = &[
    ProductionIntegrityPolicyRule {
        topic: ProductionIntegrityPolicyTopic::ChosenAlgorithms,
        rule: "production object, record, manifest, and root digests use BLAKE3-256; authenticated roots use a keyed BLAKE3-256 root authentication code",
        source_marker: "PRODUCTION_INTEGRITY_OBJECT_DIGEST_ALGORITHM and PRODUCTION_INTEGRITY_ROOT_AUTHENTICATION_ALGORITHM",
    },
    ProductionIntegrityPolicyRule {
        topic: ProductionIntegrityPolicyTopic::DomainSeparation,
        rule: "every digest input is framed with an explicit TideFS integrity domain, format version, object family, record role, and payload length before hashing",
        source_marker: "PRODUCTION_INTEGRITY_KEY_DERIVATION_ALGORITHM",
    },
    ProductionIntegrityPolicyRule {
        topic: ProductionIntegrityPolicyTopic::CollisionPolicy,
        rule: "a digest or derived-key collision in one domain is an explicit integrity/media error; replay must not choose an arbitrary winner or repair namespace truth",
        source_marker: "ChecksumMismatch and ExplicitIntegrityOrMediaError",
    },
    ProductionIntegrityPolicyRule {
        topic: ProductionIntegrityPolicyTopic::AuthenticatedRoot,
        rule: "a committed filesystem root is mountable only when its authenticated root record covers root slot, generation, transaction id, manifest digest, superblock digest, and policy epoch",
        source_marker: "RootCommitRecord and transaction manifest checksum",
    },
    ProductionIntegrityPolicyRule {
        topic: ProductionIntegrityPolicyTopic::MigrationPlan,
        rule: "the production data path starts at record version 3; migration writes new v3 records and root authentication records without rewriting v1 or v2 records in place",
        source_marker: "PRODUCTION_INTEGRITY_MIGRATION_RECORD_VERSION",
    },
    ProductionIntegrityPolicyRule {
        topic: ProductionIntegrityPolicyTopic::CompatibilityBoundary,
        rule: "record versions 1 and 2 remain compatibility inputs with development checksums; they may be imported or verified, but they are not production-integrity validation",
        source_marker: "RECORD_FORMAT_VERSION_V1_NO_FOOTER and RECORD_FORMAT_VERSION",
    },
    ProductionIntegrityPolicyRule {
        topic: ProductionIntegrityPolicyTopic::KeyHandling,
        rule: "root authentication keys are external operator secrets or sealed local keys; raw authentication keys are never stored inside segment records",
        source_marker: "PRODUCTION_INTEGRITY_ROOT_AUTHENTICATION_ALGORITHM",
    },
    ProductionIntegrityPolicyRule {
        topic: ProductionIntegrityPolicyTopic::Validation,
        rule: "the integrity policy must stay bound to docs, demo output, source constants, unit tests, and the xtask production-integrity gate",
        source_marker: "production_integrity_policy_covers_storage_006_acceptance_gate",
    },
];

#[must_use]
pub const fn production_integrity_policy_rules() -> &'static [ProductionIntegrityPolicyRule] {
    PRODUCTION_INTEGRITY_POLICY_RULES
}

#[derive(Clone, Debug)]
pub struct StoreOptions {
    pub max_segment_bytes: u64,
    pub sync_on_write: bool,
    pub repair_torn_tail: bool,
    pub segment_rotation_interval_secs: u64,
    pub segment_rotation_write_limit: u64,
    pub background_scrub_interval_secs: u64,
    pub segment_count: u64,
    /// Optional path for a mirror store. When set, every write (`put`)
    /// is also fanned out to the mirror store, every delete is also
    /// issued on the mirror, reads try the primary index first and
    /// fall back to the mirror when the key is not found, and
    /// `sync_all` syncs both stores.
    ///
    /// This provides single-node multi-device write durability: a single
    /// device failure leaves a complete, consistent copy on the other device.
    pub mirror_path: Option<std::path::PathBuf>,
    /// Additional replica store paths for N-replica quorum writes.
    /// When non-empty, every write (`put`) fans out to all replica stores,
    /// quorum (primary + ceil(N/2)) must succeed to commit the write,
    /// and degraded writes (quorum reached but some replicas failed) are
    /// classified as DegradedCommitted with background repair scheduled.
    pub replica_paths: Vec<std::path::PathBuf>,
    /// Optional durability layout policy for failure-domain-aware placement.
    /// When set, the store consults this layout during writes to verify
    /// that object replicas are placed on correct failure domains.
    pub durability_layout: Option<DurabilityLayoutV1>,
    pub fault_injection_config: Option<FaultInjectionConfig>,
    /// Enable background segment reclaim (compaction) under space pressure.
    pub reclaim_enabled: bool,
    /// Enable write throttling when free segments drop below the low-watermark.
    /// When enabled, user writes that would require a new segment allocation
    /// are rejected with NoSpace to prevent pool-full deadlock.
    pub write_throttle_enabled: bool,
    /// When enabled (default), every `get()` and `get_range()` call
    /// verifies the read payload against the stored per-object BLAKE3
    /// checksum. Disable for performance-sensitive read-only workloads.
    pub verify_read_checksums: bool,
}

impl StoreOptions {
    #[must_use]
    pub const fn durable() -> Self {
        Self {
            max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
            sync_on_write: true,
            repair_torn_tail: true,
            segment_rotation_interval_secs: DEFAULT_SEGMENT_ROTATION_INTERVAL_SECS,
            segment_rotation_write_limit: DEFAULT_SEGMENT_ROTATION_WRITE_LIMIT,
            mirror_path: None,
            replica_paths: Vec::new(),
            durability_layout: None,
            fault_injection_config: None,
            reclaim_enabled: false,
            write_throttle_enabled: false,
            verify_read_checksums: true,
            background_scrub_interval_secs: DEFAULT_BACKGROUND_SCRUB_INTERVAL_SECS,
            segment_count: DEFAULT_SEGMENT_COUNT,
        }
    }

    #[must_use]
    pub const fn test_fast() -> Self {
        Self {
            max_segment_bytes: 4096,
            sync_on_write: false,
            repair_torn_tail: true,
            segment_rotation_interval_secs: u64::MAX,
            segment_rotation_write_limit: 0,
            mirror_path: None,
            replica_paths: Vec::new(),
            durability_layout: None,
            fault_injection_config: None,
            background_scrub_interval_secs: 0,
            segment_count: DEFAULT_SEGMENT_COUNT,
            reclaim_enabled: false,
            write_throttle_enabled: false,
            verify_read_checksums: false,
        }
    }

    /// Whether these options denote the local object-store fast harness.
    ///
    /// Directory/fixed-layout pool device shims are admitted only for this
    /// exact compatibility fixture, not for durable product pool admission.
    #[must_use]
    pub fn is_test_fast_harness_fixture(&self) -> bool {
        self.max_segment_bytes == 4096
            && !self.sync_on_write
            && self.repair_torn_tail
            && self.segment_rotation_interval_secs == u64::MAX
            && self.segment_rotation_write_limit == 0
            && self.background_scrub_interval_secs == 0
            && self.segment_count == DEFAULT_SEGMENT_COUNT
            && self.mirror_path.is_none()
            && self.replica_paths.is_empty()
            && self.durability_layout.is_none()
            && self.fault_injection_config.is_none()
            && !self.reclaim_enabled
            && !self.write_throttle_enabled
            && !self.verify_read_checksums
    }

    #[must_use]
    pub const fn max_object_bytes(&self) -> u64 {
        self.max_segment_bytes
            .saturating_sub(record_overhead_for_format(RECORD_FORMAT_VERSION))
    }

    fn validate(&self) -> Result<()> {
        if self.max_segment_bytes < MIN_SEGMENT_BYTES {
            return Err(StoreError::InvalidOptions {
                reason: "max_segment_bytes is below the minimum segment size",
            });
        }
        if self.segment_count == 0 {
            return Err(StoreError::InvalidOptions {
                reason: "segment_count must be greater than zero",
            });
        }
        if self.max_object_bytes() == 0 {
            return Err(StoreError::InvalidOptions {
                reason: "max_segment_bytes leaves no room for payload bytes",
            });
        }
        if let Some(ref mirror_path) = self.mirror_path {
            if mirror_path.as_os_str().is_empty() {
                return Err(StoreError::InvalidOptions {
                    reason: "mirror_path must not be empty",
                });
            }
        }
        for rp in &self.replica_paths {
            if rp.as_os_str().is_empty() {
                return Err(StoreError::InvalidOptions {
                    reason: "replica_paths must not contain empty paths",
                });
            }
        }
        if self.mirror_path.is_some()
            && !self.replica_paths.is_empty()
            && self
                .replica_paths
                .contains(self.mirror_path.as_ref().unwrap())
        {
            return Err(StoreError::InvalidOptions {
                reason: "mirror_path duplicates a path in replica_paths",
            });
        }
        // Validate durability layout compatibility:
        // If replica paths are configured, verify the layout's shard count
        // can be satisfied. When no replicas are configured, the layout
        // serves as advisory metadata for the single-device case.
        if let Some(ref layout) = self.durability_layout {
            let replica_count = self.replica_count();
            if replica_count > 0 {
                let shards = layout.policy.total_shards();
                if shards > replica_count + 1 {
                    return Err(StoreError::InvalidOptions {
                        reason: "durability layout requires more shards than available replicas",
                    });
                }
            }
        }
        Ok(())
    }

    /// Total number of replica devices (mirror + replica_paths).
    #[must_use]
    pub fn replica_count(&self) -> usize {
        let mirror = if self.mirror_path.is_some() { 1 } else { 0 };
        mirror + self.replica_paths.len()
    }

    /// Minimum number of acks (including primary) required for quorum.
    #[must_use]
    pub fn replica_quorum(&self) -> usize {
        let total = 1 + self.replica_count();
        (total / 2) + 1
    }
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self::durable()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct StoredObject {
    pub key: ObjectKey,
    pub sequence: u64,
    pub len: u64,
    pub checksum: IntegrityDigest64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct ObjectLocation {
    pub key: ObjectKey,
    pub segment_id: u64,
    pub record_offset: u64,
    pub payload_offset: u64,
    pub payload_len: u64,
    pub sequence: u64,
    pub payload_checksum: IntegrityDigest64,
}

/// Lightweight object metadata returned by [`crate::ObjectStore::get_attr`].
///
/// Provides size, creation timestamp, and the object key without
/// buffering or copying the full object payload.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]

pub struct ObjectAttr {
    /// Object payload size in bytes.
    pub size: u64,

    /// Best-effort creation time derived from the backing file.
    pub created: SystemTime,

    /// The content-addressed key for this object.
    pub key: ObjectKey,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReplayReport {
    pub segment_count: usize,
    pub records_seen: u64,
    pub v1_records_seen: u64,
    pub v2_records_seen: u64,
    pub v3_records_seen: u64,
    pub production_integrity_records_seen: u64,
    pub puts_seen: u64,
    pub deletes_seen: u64,
    pub highest_sequence: u64,
    pub repaired_tail_bytes: u64,
}

/// Statistics from a segment integrity chain verification pass.
///
/// Produced by [`SegmentChainVerifier`] when walking the hash chain
/// across segment footers.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SegmentChainStats {
    /// Total number of segments in the chain.
    pub segments_in_chain: usize,
    /// Byte length of the chain from oldest to newest footer.
    pub chain_length: u64,
    /// ID of the last (newest) segment verified.
    pub last_verified_segment: u64,
    /// Number of chain breaks detected during verification.
    pub chain_breaks_detected: u64,
}

/// Classification of a replicated write outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicatedWriteClass {
    /// All replicas acknowledged — full durability.
    Committed,
    /// Quorum reached but some replicas failed — degraded durability.
    DegradedCommitted,
    /// Fewer than quorum acknowledged — write refused (EIO).
    RefusedNoQuorum,
}

/// Result of a replicated write across primary + N replicas.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicatedWriteResult {
    pub class: ReplicatedWriteClass,
    pub acks: usize,
    pub total_replicas: usize,
    pub quorum: usize,
    pub healthy: Vec<bool>,
}

impl ReplicatedWriteResult {
    #[must_use]
    pub fn committed(total: usize, quorum: usize) -> Self {
        Self {
            class: ReplicatedWriteClass::Committed,
            acks: total + 1,
            total_replicas: total,
            quorum,
            healthy: vec![true; total],
        }
    }

    #[must_use]
    pub fn degraded(acks: usize, total: usize, quorum: usize, healthy: Vec<bool>) -> Self {
        Self {
            class: ReplicatedWriteClass::DegradedCommitted,
            acks,
            total_replicas: total,
            quorum,
            healthy,
        }
    }

    #[must_use]
    pub fn refused(total: usize, quorum: usize, healthy: Vec<bool>) -> Self {
        Self {
            class: ReplicatedWriteClass::RefusedNoQuorum,
            acks: 0,
            total_replicas: total,
            quorum,
            healthy,
        }
    }

    #[must_use]
    pub fn is_ok(&self) -> bool {
        !matches!(self.class, ReplicatedWriteClass::RefusedNoQuorum)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoreStats {
    pub live_objects: usize,
    pub live_bytes: u64,
    pub segment_count: usize,
    pub free_segments: u64,
    pub free_bytes: u64,
    pub next_sequence: u64,
    pub tombstone_count: u64,
    pub replay: ReplayReport,
    pub mirror_degraded: bool,
    pub mirror_live_objects: usize,
    pub mirror_live_bytes: u64,
    pub replica_healthy: Vec<bool>,
    pub replica_live_objects: Vec<usize>,
    pub last_scrub_secs: u64,
    pub committed_root_txg: u64,
    pub committed_root_generation: u64,
}

/// Result of a mirror scrub cycle.
///
/// A scrub compares every primary key against the mirror: keys present
/// only on the primary are resynced, and keys with digest mismatches
/// are repaired from the primary copy.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ScrubStats {
    /// Total keys examined in the primary index.
    pub keys_examined: u64,
    /// Keys that were present on the mirror and matched (healthy).
    pub keys_healthy: u64,
    /// Keys missing from the mirror that were resynced from primary.
    pub keys_resynced: u64,
    /// Keys with a digest mismatch that were repaired from primary.
    pub keys_repaired: u64,
    /// Keys where repair or resync failed.
    pub errors: u64,
    /// Duration of the scrub cycle in seconds (wall-clock, best-effort).
    pub duration_secs: f64,
}

impl ScrubStats {
    /// Total keys requiring intervention (resynced + repaired).
    #[must_use]
    pub fn keys_divergent(&self) -> u64 {
        self.keys_resynced.saturating_add(self.keys_repaired)
    }

    /// Whether the scrub found any issues.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.keys_divergent() == 0 && self.errors == 0
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoreRetentionCompactionReport {
    pub protected_key_count: usize,
    pub protected_exact_location_count: usize,
    pub copied_protected_objects: usize,
    pub tombstoned_unprotected_keys: usize,
    pub retired_segments: Vec<u64>,
    pub retained_segments: Vec<u64>,
    pub live_objects_before: usize,
    pub live_objects_after: usize,
    pub segment_count_before: usize,
    pub segment_count_after: usize,
    pub exact_locations_preserved: bool,
    pub production_fsck_required: bool,
}

pub mod device_manager;
pub mod device_removal;
pub use device_removal::{
    run_device_evacuation, DeviceEvacuator, EvacuationError, EvacuationPhase, EvacuationResult,
    EvacuationState,
};
pub mod error;
pub mod io_scheduler;
pub mod pool;
pub mod pool_exporter;
pub mod scrub;
pub mod scrub_core;
pub mod segment_builder;

pub mod pool_importer;
pub use io_scheduler::IoClass;
pub use pool::{
    PlacementReceipt, PlacementReceiptTarget, PlacementTargetRole, Pool, PoolConfig,
    PoolProperties, PoolRedundancyPolicy,
};
pub mod device;
pub mod device_health;
pub mod parity_raid;
pub mod pool_label;

pub use device::{DeviceBacking, DeviceClass, DeviceConfig, DeviceKind, IoClass as DeviceIoClass};
pub use device_layout::{
    recommend_segment_size, DeviceClassPolicy, DeviceLayoutStats, DeviceMediaClass, WriteAllocator,
};
pub use encrypt::{decrypt_object, encrypt_object, EncryptionConfig, StoreEncryptionKey};
pub use error::*;

pub mod store;
pub mod xattr;
pub use scrub::{ScrubCursor, ScrubOutcome, ScrubReport, SegmentIntegrityScrubber};
pub use scrub_core::{scrub_checksum_tree, ChecksumTreeScrubReport, LeafScrubResult};
pub use store::*;

/// Human alias namespace. Prefer `human::local_object_store::*` in new examples.
pub mod human {
    /// Durable local object-store API with human-readable import paths.
    ///
    /// This module is an alias of [`crate::local_object_store`], so rustdoc
    /// examples can import from the same path application code should use.
    pub mod local_object_store {
        pub use crate::local_object_store::*;
    }
}
pub mod dead_segment_scan;
pub mod log_device;
pub mod read_verify;
pub mod reclaim_queue;
pub mod validation;

#[cfg(test)]
mod tests;
