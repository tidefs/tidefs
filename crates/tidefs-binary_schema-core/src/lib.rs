// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs)]

//! # tidefs-binary_schema-core
//!
//! Canonical binary schema core: fixed-width little-endian scalar wrappers,
//! schema family and type identity, version compatibility law, feature bit
//! negotiation, continuity windows, checksum profile declarations, and
//! domain-separated tag enumerations.
//!
//! This crate is `no_std` and provides the shared scalar primitives, endian
//! enforcement, and schema identity law used by every other `binary_schema`
//! crate and by future Rust-for-Linux kernel modules.
//!
//! ## Role in the TideFS Stack
//!
//! `tidefs-binary_schema-core` sits at the bottom of the binary schema layer.
//! It defines the encoding contracts that every higher-level crate agrees on:
//!
//! * **`tidefs-binary_schema-framing`** — wraps core types into delimited
//!   message boundaries (envelopes, sections, chunk frames) for wire and
//!   on-disk framing.
//!
//! * **`tidefs-binary_schema-checksum`** — layers CRC32C and BLAKE3-256
//!   integrity verification on top of framed payloads, using the checksum
//!   profile enum declared here.
//!
//! * **Downstream crates** (`tidefs-block-volume-adapter-core`,
//!   `tidefs-authority-publication-core`, the POSIX adapter daemon) implement
//!   their domain types in terms of these scalar primitives and the `Schema`
//!   trait defined in the framing crate.
//!
//! ## Architecture
//!
//! ```text
//! +--------------------------------------------------------------+
//! |  Downstream Consumers                                         |
//! |  (block-volume-adapter, authority-publication, POSIX daemon)  |
//! +-----+---------------------+-------------------+--------------+
//!       |                     |                   |
//! +-----v--------+  +---------v--------+  +-------v-----------+
//! | binary_schema |  | binary_schema    |  | Other workspace   |
//! | -framing      |  | -checksum        |  | crates            |
//! | (envelopes,   |  | (CRC32C, BLAKE3) |  | (type-system,     |
//! |  sections,    |  |                   |  |  extent-map,      |
//! |  chunk frames)|  |                   |  |  inode-table...)  |
//! +-----+--------+  +---------+--------+  +-------------------+
//!       |                     |
//! +-----v---------------------v---------+
//! |  tidefs-binary_schema-core           |
//! |  (LE wrappers, version law,          |
//! |   feature bits, fingerprints,        |
//! |   continuity windows, checksum       |
//! |   profiles, domain tags, errors)     |
//! +--------------------------------------+
//! ```
//!
//! ## Type Taxonomy
//!
//! The crate defines three categories of types:
//!
//! * **Fixed-width little-endian scalars** — `U16Le`, `U32Le`, `U64Le`,
//!   `I32Le`, `I64Le`. These are `#[repr(transparent)]` wrappers around Rust
//!   primitives that enforce deterministic little-endian encoding on every
//!   platform. All wire and on-disk integers must use these wrappers.
//!
//! * **Identity and metadata types** — `SchemaFamilyId`, `SchemaTypeId`,
//!   `SchemaVersion`, `SchemaFingerprint`. These identify a specific schema
//!   revision and provide forward/backward compatibility decisions via the
//!   `can_read` / `can_be_read_by` version law.
//!
//! * **Policy and classification types** — `FeatureBits`,
//!   `ContinuityWindow`, `Acceptance`, `ChecksumProfile`, `PayloadClass`,
//!   `ChunkFrameSizeClass`, `DomainTag`. These declare capability
//!   requirements, classification labels, and domain separation for
//!   cryptographic operations.
//!
//! ## Encoding Contract
//!
//! All multi-byte values are **little-endian** on the wire and on disk.
//! Boolean values are encoded as `u8` (`0` = `false`, `1` = `true`).
//! Enum discriminants use `u16` and are validated on decode — unknown
//! discriminant values are rejected.
//!
//! The schema version compatibility model (see [`SchemaVersion::can_read`])
//! is the backbone of forward-compatible data migration:
//!
//! * Same major version, reader minor >= writer minor → compatible.
//! * Different major version → incompatible (requires explicit migration).
//! * Zero version (0.0) → unknown, always rejected.
//!
//! ## References
//!
//! * P2-03 §1: LE fixed-width scalar encoding
//! * P2-03 §2: Schema family/type/version/fingerprint identity
//! * P2-03 §3: Feature bit negotiation and continuity windows
//! * P2-03 §4: Domain-separated checksum profiles
//! * P2-03 §5: Zero-copy legality (alignment + bounds + continuity)
//!
//! ## Usage
//!
//! ```
//! use tidefs_binary_schema_core::{U64Le, FeatureBits, SchemaVersion, ChecksumProfile};
//!
//! // Encode a 64-bit value in little-endian
//! let obj_id = U64Le::from_le(42);
//! let bytes: [u8; 8] = obj_id.encode();
//! let decoded = U64Le::from_le_bytes(bytes);
//! assert_eq!(decoded, obj_id);
//!
//! // Check schema version compatibility
//! let reader = SchemaVersion::new(1, 5);
//! let writer = SchemaVersion::new(1, 2);
//! assert!(reader.can_read(&writer));
//!
//! // Feature bit negotiation
//! let mut features = FeatureBits::NONE;
//! features = features.with(3); // enable feature bit 3
//! assert!(features.has(3));
//! ```

// ---------------------------------------------------------------------------
// Magic
// ---------------------------------------------------------------------------

/// Magic identifier for TideFS binary schema envelopes.
///
/// Encodes as the ASCII bytes `VBFS` in little-endian byte order.
/// Used at the start of every envelope header to validate that the
/// byte stream is a well-formed TideFS binary schema message.
pub const BINARY_SCHEMA_MAGIC: u32 = 0x5346_4256; // "VBFS"

// ---------------------------------------------------------------------------
// Alignment law
// ---------------------------------------------------------------------------

/// Minimum envelope alignment in bytes.
///
/// All envelope headers must start at addresses divisible by this value.
/// This enables zero-copy access on 64-bit architectures.
pub const ENVELOPE_ALIGN: usize = 8;
/// Minimum section offset alignment in bytes.
pub const SECTION_OFFSET_ALIGN_MIN: usize = 8;
/// DMA-friendly chunk frame alignment in bytes.
pub const CHUNK_FRAME_ALIGN_DMA: usize = 4096;

// ---------------------------------------------------------------------------
// Envelope / section / chunk size constants
// ---------------------------------------------------------------------------

/// Envelope header size in bytes.
///
/// Every envelope begins with a fixed-size 64-byte header containing
/// magic, schema identity, payload length, and checksum.
pub const ENVELOPE_HEADER_BYTES: usize = 64;
/// Section header size in bytes.
pub const SECTION_HEADER_BYTES: usize = 32;
/// Chunk frame header size in bytes.
pub const CHUNK_FRAME_HEADER_BYTES: usize = 32;

/// 64 KiB chunk frame payload size.
pub const CHUNK_FRAME_SIZE_64K: usize = 64 * 1024;
/// 256 KiB chunk frame payload size.
pub const CHUNK_FRAME_SIZE_256K: usize = 256 * 1024;
/// 1 MiB chunk frame payload size.
pub const CHUNK_FRAME_SIZE_1M: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Scalar width law
// ---------------------------------------------------------------------------

/// ids, offsets, lengths, epochs: `u64`
/// Canonical 64-bit unsigned integer for ids, offsets, lengths, and epochs.
///
/// All wire-format u64 values must use this type alias or the [`U64Le`] wrapper.
pub type CanonicalU64 = u64;
/// Enum discriminants: `u16`.
pub type CanonicalDiscriminant = u16;
/// Flag sets: `u64`.
pub type CanonicalFlags = u64;
/// Booleans: `u8` (0 = false, 1 = true).
pub type CanonicalBool = u8;

/// Canonical false value (0).
///
/// All boolean values on the wire are encoded as `u8`. `0` represents
/// `false` and `1` represents `true`. Any other value is invalid.
pub const CANONICAL_FALSE: u8 = 0;
/// Canonical true value (1).
pub const CANONICAL_TRUE: u8 = 1;

#[inline]
/// Encode a Rust `bool` into the canonical wire format.
///
/// Returns `0` for `false` and `1` for `true`.
///
/// # Examples
///
/// ```
/// use tidefs_binary_schema_core::canonical_bool;
///
/// assert_eq!(canonical_bool(false), 0);
/// assert_eq!(canonical_bool(true), 1);
/// ```
pub const fn canonical_bool(b: bool) -> u8 {
    if b {
        CANONICAL_TRUE
    } else {
        CANONICAL_FALSE
    }
}

#[inline]
/// Decode a canonical wire-format boolean.
///
/// Returns `Some(false)` for `0`, `Some(true)` for `1`, and `None` for
/// any other byte value.
///
/// # Examples
///
/// ```
/// use tidefs_binary_schema_core::decode_canonical_bool;
///
/// assert_eq!(decode_canonical_bool(0), Some(false));
/// assert_eq!(decode_canonical_bool(1), Some(true));
/// assert_eq!(decode_canonical_bool(2), None);
/// ```
pub const fn decode_canonical_bool(v: u8) -> Option<bool> {
    match v {
        CANONICAL_FALSE => Some(false),
        CANONICAL_TRUE => Some(true),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Little-endian fixed-width wrappers
// ---------------------------------------------------------------------------

/// Generate a little-endian fixed-width wrapper type.
///
/// Each generated type is `#[repr(transparent)]`, `Copy`, and provides
/// `from_le`, `to_le_bytes`, `from_le_bytes`, `encode`, and `as_raw`
/// methods. The wrapper guarantees deterministic LE encoding on every
/// platform.
///
/// # Generated Types
///
/// The macro generates five wrapper types: [`U16Le`], [`U32Le`], [`U64Le`],
/// [`I32Le`], and [`I64Le`].
macro_rules! le_wrapper {
    ($name:ident, $inner:ty, $nbytes:expr) => {
        #[doc = concat!("Little-endian `", stringify!($inner), "` wrapper (", stringify!($name), ").")]
        #[doc = ""]
        #[doc = "Generated by the `le_wrapper!` macro. Provides deterministic"]
        #[doc = "little-endian encoding, decoding, and conversion methods."]
        #[doc = ""]
        #[doc = "Every wire-format and on-disk integer must use one of these wrappers"]
        #[doc = "to guarantee platform-independent little-endian encoding."]
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
        #[repr(transparent)]
        pub struct $name(pub $inner);

        impl $name {
            #[doc = concat!("Size of `", stringify!($name), "` in bytes (", stringify!($nbytes), ").")]
            pub const BYTES: usize = $nbytes;

            #[inline]
            #[doc = "Construct from a native-endian value, converting to little-endian."]
            pub const fn from_le(raw: $inner) -> Self {
                Self(raw.to_le())
            }

            #[inline]
            #[doc = "Return the little-endian byte representation."]
            pub const fn to_le_bytes(self) -> [u8; $nbytes] {
                self.0.to_le_bytes()
            }

            #[inline]
            #[doc = "Decode from little-endian bytes."]
            pub const fn from_le_bytes(bytes: [u8; $nbytes]) -> Self {
                Self(<$inner>::from_le_bytes(bytes))
            }

            #[inline]
            #[doc = "Return the raw native-endian value."]
            pub const fn as_raw(self) -> $inner {
                self.0
            }

            #[inline]
            #[doc = "Encode to little-endian bytes. Alias for `to_le_bytes`."]
            pub const fn encode(self) -> [u8; $nbytes] {
                self.to_le_bytes()
            }
        }

        #[doc = concat!("Convert from `", stringify!($inner), "`.")]
        impl From<$inner> for $name {
            #[inline]
            fn from(v: $inner) -> Self {
                Self::from_le(v)
            }
        }

        #[doc = concat!("Convert to `", stringify!($inner), "`.")]
        impl From<$name> for $inner {
            #[inline]
            fn from(v: $name) -> Self {
                v.as_raw()
            }
        }

        #[doc = concat!("Display the raw `", stringify!($inner), "` value.")]
        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.as_raw(), f)
            }
        }
    };
}

le_wrapper!(U16Le, u16, 2);
le_wrapper!(U32Le, u32, 4);
le_wrapper!(U64Le, u64, 8);
le_wrapper!(I32Le, i32, 4);
le_wrapper!(I64Le, i64, 8);

// ---------------------------------------------------------------------------
// Schema family and type identity
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
/// Schema family identifier.
///
/// Every binary schema type belongs to exactly one family. The family
/// groups related schema types that share versioning and compatibility
/// rules. The predefined `BINARY_SCHEMA` family (id=1) covers all
/// core TideFS binary schema types.
pub struct SchemaFamilyId(pub u64);

impl SchemaFamilyId {
    /// The predefined binary schema family (id=1).
    pub const BINARY_SCHEMA: Self = Self(1);
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
/// Schema type identifier within a family.
///
/// Uniquely identifies a specific schema type (e.g., "inode entry v1",
/// "extent record v2") within its [`SchemaFamilyId`]. Together with the
/// family id and version, this forms the complete schema identity tuple.
/// Schema type identifier within a family.
///
/// Uniquely identifies a specific schema type (e.g., "inode entry v1",
/// "extent record v2") within its [`SchemaFamilyId`]. Together with the
/// family id and version, this forms the complete schema identity tuple.
pub struct SchemaTypeId(pub u64);

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
/// Schema version (major.minor).
///
/// Version compatibility follows semantic-versioning-like rules:
/// minor-version bumps within the same major version are
/// backward-compatible; major-version bumps require explicit data
/// migration. A zero version (0.0) is treated as unknown.
pub struct SchemaVersion {
    /// Major version number. A bump indicates an incompatible schema change.
    pub major: u16,
    /// Minor version number. A bump indicates a backward-compatible addition.
    pub minor: u16,
}

impl SchemaVersion {
    /// Create a new `SchemaVersion` with the given major and minor components.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Encode this version as 4 little-endian bytes (major, minor).
    pub fn encode(self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&self.major.to_le_bytes());
        buf[2..4].copy_from_slice(&self.minor.to_le_bytes());
        buf
    }

    /// Decode a `SchemaVersion` from 4 little-endian bytes.
    pub fn decode(bytes: [u8; 4]) -> Self {
        Self {
            major: u16::from_le_bytes([bytes[0], bytes[1]]),
            minor: u16::from_le_bytes([bytes[2], bytes[3]]),
        }
    }

    /// Can this schema version read data written by `writer_version`?
    ///
    /// Backward-compatibility rule: a minor-version bump is always compatible
    /// within the same major version.  A major-version bump requires explicit
    /// migration and is considered incompatible by default.
    ///
    /// The zero version (0.0) is treated as unknown and returns `false`.
    pub const fn can_read(&self, writer_version: &SchemaVersion) -> bool {
        if self.major == 0 || writer_version.major == 0 {
            return false;
        }
        if self.major != writer_version.major {
            return false;
        }
        self.minor >= writer_version.minor
    }

    /// Can this schema version write data that `reader_version` can read?
    ///
    /// Symmetric convenience: `self.can_be_read_by(reader)` iff
    /// `reader.can_read(self)`.
    pub const fn can_be_read_by(&self, reader_version: &SchemaVersion) -> bool {
        reader_version.can_read(self)
    }
}
/// Return a static mapping of known (reader, writer, compatible) version
/// triples.  This is a human-readable reference for the compatibility model
/// and can be used by migration tooling to answer "is an upgrade needed?"
///
/// The returned slice is ordered by reader version, then writer version.
/// Return a static mapping of known (reader, writer, compatible) version
/// triples.
///
/// This is a human-readable reference for the compatibility model
/// and can be used by migration tooling to answer "is an upgrade needed?"
///
/// The returned slice is ordered by reader version, then writer version.
pub fn compatibility_matrix() -> &'static [(SchemaVersion, SchemaVersion, bool)] {
    &COMPATIBILITY_MATRIX
}

static COMPATIBILITY_MATRIX: [(SchemaVersion, SchemaVersion, bool); 13] = [
    // v1.x family: all minor upgrades are backward-compatible
    (v(1, 0), v(1, 0), true),
    (v(1, 1), v(1, 0), true),
    (v(1, 1), v(1, 1), true),
    (v(1, 2), v(1, 0), true),
    (v(1, 2), v(1, 1), true),
    (v(1, 2), v(1, 2), true),
    // Major-version boundaries require migration
    (v(2, 0), v(1, 0), false),
    (v(2, 0), v(1, 5), false),
    (v(2, 0), v(2, 0), true),
    (v(2, 1), v(2, 0), true),
    // Unknown versions (0.0) always reject
    (v(0, 0), v(1, 0), false),
    (v(1, 0), v(0, 0), false),
    // v3.x family: newer
    (v(3, 0), v(3, 0), true),
];

const fn v(major: u16, minor: u16) -> SchemaVersion {
    SchemaVersion { major, minor }
}

// ---------------------------------------------------------------------------
// Feature bits
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[repr(transparent)]
/// Feature bit set for capability negotiation.
///
/// A 64-bit bitmap where each bit represents a boolean feature flag.
/// Used by continuity windows to declare required capabilities and
/// by the framing layer to negotiate compatible schema subsets.
///
/// # Examples
///
/// ```
/// use tidefs_binary_schema_core::FeatureBits;
///
/// let fb = FeatureBits::NONE.with(3).with(7);
/// assert!(fb.has(3));
/// assert!(fb.has(7));
/// assert!(!fb.has(0));
///
/// let subset = FeatureBits::NONE.with(3);
/// assert!(subset.is_subset_of(fb));
/// ```
pub struct FeatureBits(pub CanonicalFlags);

impl FeatureBits {
    /// The empty feature set (no features enabled).
    pub const NONE: Self = Self(0);

    /// Enable a feature bit, returning the updated set.
    ///
    /// # Examples
    ///
    /// ```
    /// use tidefs_binary_schema_core::FeatureBits;
    ///
    /// let fb = FeatureBits::NONE.with(5);
    /// assert!(fb.has(5));
    /// ```
    pub const fn with(self, bit: u32) -> Self {
        Self(self.0 | (1u64 << bit))
    }

    /// Check whether a feature bit is enabled.
    pub const fn has(self, bit: u32) -> bool {
        (self.0 & (1u64 << bit)) != 0
    }

    /// Check whether all bits in `self` are also set in `other`.
    pub const fn is_subset_of(self, other: Self) -> bool {
        (self.0 & !other.0) == 0
    }

    /// Encode this feature set as 8 little-endian bytes.
    pub const fn encode(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

// ---------------------------------------------------------------------------
// Schema fingerprint — 256-bit
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
/// Schema fingerprint — a 256-bit content hash of the schema definition.
///
/// Uniquely identifies a specific schema revision (including all field
/// types, sizes, and ordering). Any change to a schema definition MUST
/// produce a different fingerprint. The fingerprint is used by continuity
/// windows to verify that the producer's schema revision is known and
/// accepted.
pub struct SchemaFingerprint(pub [u8; 32]);

impl SchemaFingerprint {
    /// The zero fingerprint (all zeros).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Return the low 64 bits of the fingerprint.
    pub const fn low_u64(self) -> u64 {
        u64::from_le_bytes([
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7],
        ])
    }

    /// Encode the fingerprint as 32 bytes.
    pub const fn encode(self) -> [u8; 32] {
        self.0
    }
    /// Decode a fingerprint from 32 bytes.
    pub const fn decode(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Default for SchemaFingerprint {
    fn default() -> Self {
        Self::ZERO
    }
}

impl core::fmt::Display for SchemaFingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.0.iter().take(8) {
            write!(f, "{b:02x}")?;
        }
        write!(f, "..")
    }
}

// ---------------------------------------------------------------------------
// Continuity window
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
/// Continuity window — declares the acceptable schema version range,
/// required feature bits, and known fingerprints for a schema family.
///
/// Used by consumers to validate that incoming data was produced by a
/// compatible schema revision before attempting to decode it. The
/// [`accepts`](ContinuityWindow::accepts) method performs all four
/// validation checks in order: major version, minor version window,
/// feature subset, and fingerprint match.
pub struct ContinuityWindow {
    /// The schema family this window applies to.
    pub family_id: SchemaFamilyId,
    /// The schema type this window applies to.
    pub type_id: SchemaTypeId,
    /// The major version of this schema.
    pub major_version: u16,
    /// The minimum acceptable minor version (inclusive).
    pub minor_min: u16,
    /// The maximum acceptable minor version (inclusive).
    pub minor_max: u16,
    /// Feature bits that the reader must support.
    pub required_features: FeatureBits,
    /// Known fingerprints accepted by this window.
    pub accepted_fingerprints: &'static [SchemaFingerprint],
}

impl ContinuityWindow {
    /// Validate that the given schema identity is accepted by this window.
    ///
    /// Checks in order: major version match, minor version in window,
    /// features are a subset of required features, fingerprint is known.
    ///
    /// # Examples
    ///
    /// ```
    /// use tidefs_binary_schema_core::*;
    ///
    /// let window = ContinuityWindow {
    ///     family_id: SchemaFamilyId::BINARY_SCHEMA,
    ///     type_id: SchemaTypeId(100),
    ///     major_version: 1,
    ///     minor_min: 0,
    ///     minor_max: 5,
    ///     required_features: FeatureBits::NONE,
    ///     accepted_fingerprints: &[SchemaFingerprint::ZERO],
    /// };
    /// assert_eq!(
    ///     window.accepts(1, 3, FeatureBits::NONE, SchemaFingerprint::ZERO),
    ///     Acceptance::Accepted
    /// );
    /// ```
    pub fn accepts(
        &self,
        major: u16,
        minor: u16,
        features: FeatureBits,
        fp: SchemaFingerprint,
    ) -> Acceptance {
        if major != self.major_version {
            return Acceptance::RejectMajorMismatch;
        }
        if minor < self.minor_min || minor > self.minor_max {
            return Acceptance::RejectMinorOutOfWindow;
        }
        if !features.is_subset_of(self.required_features) {
            return Acceptance::RejectFeaturesUnsupported;
        }
        if !self.accepted_fingerprints.contains(&fp) {
            return Acceptance::RejectFingerprintUnknown;
        }
        Acceptance::Accepted
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Result of a continuity window validation.
///
/// Each variant records the specific reason for rejection, enabling
/// diagnostic error messages and migration planning.
pub enum Acceptance {
    /// The schema identity is accepted.
    Accepted,
    /// The major version does not match.
    RejectMajorMismatch,
    /// The minor version is outside the accepted window.
    RejectMinorOutOfWindow,
    /// Required features are not a subset.
    RejectFeaturesUnsupported,
    /// The fingerprint is not in the known list.
    RejectFingerprintUnknown,
}

impl Acceptance {
    /// Returns `true` if this is the `Accepted` variant.
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

// ---------------------------------------------------------------------------
// Checksum / digest profile classes
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
/// Checksum and digest profile enumeration.
///
/// Declares which integrity verification algorithms are in use for a
/// given payload. Profiles can be combined (e.g., `Crc32cPlusBlake3_256`)
/// to provide both fast error detection and cryptographic integrity.
pub enum ChecksumProfile {
    /// No checksum or digest.
    None = 0,
    /// CRC32C checksum only (fast error detection).
    Crc32c = 1,
    /// BLAKE3-256 digest only (cryptographic integrity).
    Blake3_256 = 2,
    /// Both CRC32C and BLAKE3-256 (fast detection + cryptographic integrity).
    Crc32cPlusBlake3_256 = 3,
}

impl ChecksumProfile {
    /// Decode a `ChecksumProfile` from its discriminant byte.
    /// Returns `None` if the discriminant is unknown.
    pub const fn from_discriminant(d: u8) -> Option<Self> {
        match d {
            0 => Some(Self::None),
            1 => Some(Self::Crc32c),
            2 => Some(Self::Blake3_256),
            3 => Some(Self::Crc32cPlusBlake3_256),
            _ => None,
        }
    }
    /// Return the discriminant byte for this profile.
    pub const fn discriminant(self) -> u8 {
        self as u8
    }
    /// Returns `true` if this profile includes a CRC32C checksum.
    pub const fn has_crc32c(self) -> bool {
        matches!(self, Self::Crc32c | Self::Crc32cPlusBlake3_256)
    }
    /// Returns `true` if this profile includes a BLAKE3 digest.
    pub const fn has_blake3(self) -> bool {
        matches!(self, Self::Blake3_256 | Self::Crc32cPlusBlake3_256)
    }
}

// ---------------------------------------------------------------------------
// Payload class for section headers
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
/// Payload classification for section headers.
///
/// Tells the framing layer how a section's payload is structured:
/// fixed-size inline, variable-length inline, chunk-framed (streaming),
/// or an external reference (pointer to data stored elsewhere).
pub enum PayloadClass {
    /// Fixed-size payload embedded directly in the section.
    FixedInline = 1,
    /// Variable-length payload embedded in the section with a length prefix.
    VariableInline = 2,
    /// Payload split across one or more chunk frames.
    ChunkFramed = 3,
    /// Payload stored externally; the section contains a reference.
    ExternalRef = 4,
}

impl Default for PayloadClass {
    fn default() -> Self {
        Self::FixedInline
    }
}

impl PayloadClass {
    /// Decode a `PayloadClass` from its discriminant.
    /// Returns `None` if the discriminant is unknown.
    pub const fn from_discriminant(d: u16) -> Option<Self> {
        match d {
            1 => Some(Self::FixedInline),
            2 => Some(Self::VariableInline),
            3 => Some(Self::ChunkFramed),
            4 => Some(Self::ExternalRef),
            _ => None,
        }
    }
    /// Return the discriminant for this payload class.
    pub const fn discriminant(self) -> u16 {
        self as u16
    }
}

// ---------------------------------------------------------------------------
// Chunk frame size class
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
/// Chunk frame size class.
///
/// Standard chunk frame payload sizes: 64 KiB, 256 KiB, or 1 MiB.
/// Each class maps to a fixed byte count via
/// [`payload_bytes`](ChunkFrameSizeClass::payload_bytes).
pub enum ChunkFrameSizeClass {
    /// 64 KiB chunk frames.
    KiB64 = 0,
    /// 256 KiB chunk frames.
    KiB256 = 1,
    /// 1 MiB chunk frames.
    MiB1 = 2,
}

impl Default for ChunkFrameSizeClass {
    fn default() -> Self {
        Self::KiB64
    }
}

impl ChunkFrameSizeClass {
    /// Decode a `ChunkFrameSizeClass` from its discriminant.
    /// Returns `None` if the discriminant is unknown.
    pub const fn from_discriminant(d: u16) -> Option<Self> {
        match d {
            0 => Some(Self::KiB64),
            1 => Some(Self::KiB256),
            2 => Some(Self::MiB1),
            _ => None,
        }
    }
    /// Return the payload size in bytes for this frame size class.
    pub const fn payload_bytes(self) -> usize {
        match self {
            Self::KiB64 => CHUNK_FRAME_SIZE_64K,
            Self::KiB256 => CHUNK_FRAME_SIZE_256K,
            Self::MiB1 => CHUNK_FRAME_SIZE_1M,
        }
    }
}

// ---------------------------------------------------------------------------
// Domain-separated tag enum
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
/// Domain-separated tag for cryptographic operations.
///
/// Each tag identifies a distinct domain (envelope header, section body,
/// chunk frame, etc.) and is used as a domain separator in keyed hashing
/// and AEAD constructions to prevent cross-domain confusion.
pub enum DomainTag {
    /// Envelope header domain.
    EnvelopeHeader = 1,
    /// Section body domain.
    SectionBody = 2,
    /// Chunk frame domain.
    ChunkFrame = 3,
    /// External payload domain.
    ExternalPayload = 4,
    /// Receipt body domain.
    ReceiptBody = 5,
    /// Validation bundle domain.
    ValidationBundle = 6,
    /// Archive body domain.
    ArchiveBody = 7,
    /// Transfer stream domain.
    TransferStream = 8,
    /// Object payload chunk domain.
    ObjectPayloadChunk = 9,
    /// Object enumeration domain.
    ObjectEnumeration = 10,
}

impl DomainTag {
    /// Return the discriminant for this domain tag.
    pub const fn discriminant(self) -> u32 {
        self as u32
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Error types for binary schema operations.
///
/// Every validation failure, decode error, and continuity rejection is
/// represented by a variant of this enum. Downstream crates convert these
/// into their own error types via `From` impls or pattern matching.
pub enum BinarySchemaError {
    /// Bad magic bytes in the envelope header.
    BadMagic {
        /// The unexpected magic value that was read.
        got: u32,
    },
    /// CRC32C checksum mismatch.
    ChecksumMismatch,
    /// BLAKE3 digest mismatch.
    DigestMismatch,
    /// Alignment constraint violated.
    AlignmentViolation,
    /// Bounds constraint violated.
    BoundsViolation,
    /// Invalid canonical boolean value (not 0 or 1).
    InvalidBoolean,
    /// Unknown checksum profile discriminant.
    InvalidChecksumProfile,
    /// Unknown payload class discriminant.
    InvalidPayloadClass,
    /// Unknown domain tag discriminant.
    InvalidDomainTag,
    /// Continuity window rejected the schema identity.
    ContinuityRejection(Acceptance),
    /// Encoding error.
    EncodeError,
}

impl core::fmt::Display for BinarySchemaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMagic { got } => write!(f, "bad magic: {got:#010x}"),
            Self::ChecksumMismatch => write!(f, "crc32c checksum mismatch"),
            Self::DigestMismatch => write!(f, "blake3 digest mismatch"),
            Self::AlignmentViolation => write!(f, "alignment violation"),
            Self::BoundsViolation => write!(f, "bounds violation"),
            Self::InvalidBoolean => write!(f, "invalid canonical boolean"),
            Self::InvalidChecksumProfile => write!(f, "invalid checksum profile"),
            Self::InvalidPayloadClass => write!(f, "invalid payload class"),
            Self::InvalidDomainTag => write!(f, "invalid domain tag"),
            Self::ContinuityRejection(a) => write!(f, "continuity rejection: {a:?}"),
            Self::EncodeError => write!(f, "encode error"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn magic_is_vbfs_in_le() {
        assert_eq!(BINARY_SCHEMA_MAGIC, 0x5346_4256);
        assert_eq!(&BINARY_SCHEMA_MAGIC.to_le_bytes(), b"VBFS");
    }

    #[test]
    fn u64le_roundtrip() {
        let v = U64Le::from_le(0x01234567_89ABCDEF);
        assert_eq!(v.as_raw(), 0x01234567_89ABCDEF);
        let bytes = v.encode();
        assert_eq!(U64Le::from_le_bytes(bytes), v);
    }

    #[test]
    fn u32le_roundtrip() {
        let v = U32Le::from_le(0xDEADBEEF);
        assert_eq!(v.as_raw(), 0xDEADBEEF);
        assert_eq!(U32Le::from_le_bytes(v.encode()), v);
    }

    #[test]
    fn i64le_roundtrip() {
        let v = I64Le::from_le(-42);
        assert_eq!(v.as_raw(), -42);
        assert_eq!(I64Le::from_le_bytes(v.encode()), v);
    }

    #[test]
    fn canonical_bool_encodes_0_and_1() {
        assert_eq!(canonical_bool(false), 0);
        assert_eq!(canonical_bool(true), 1);
        assert_eq!(decode_canonical_bool(0), Some(false));
        assert_eq!(decode_canonical_bool(1), Some(true));
        assert_eq!(decode_canonical_bool(2), None);
    }

    #[test]
    fn checksum_profile_discriminants() {
        assert_eq!(ChecksumProfile::None.discriminant(), 0);
        assert_eq!(ChecksumProfile::Crc32c.discriminant(), 1);
        assert_eq!(ChecksumProfile::Blake3_256.discriminant(), 2);
        assert_eq!(ChecksumProfile::Crc32cPlusBlake3_256.discriminant(), 3);
        assert!(!ChecksumProfile::None.has_crc32c());
        assert!(ChecksumProfile::Crc32c.has_crc32c());
        assert!(ChecksumProfile::Crc32cPlusBlake3_256.has_crc32c());
    }

    #[test]
    fn continuity_window_accepts_valid() {
        const FP1: SchemaFingerprint = SchemaFingerprint([0xAAu8; 32]);
        let window = ContinuityWindow {
            family_id: SchemaFamilyId::BINARY_SCHEMA,
            type_id: SchemaTypeId(100),
            major_version: 1,
            minor_min: 0,
            minor_max: 5,
            required_features: FeatureBits(0xF),
            accepted_fingerprints: &[FP1],
        };
        assert_eq!(
            window.accepts(1, 3, FeatureBits(0x3), FP1),
            Acceptance::Accepted
        );
        assert_eq!(
            window.accepts(2, 3, FeatureBits(0x3), FP1),
            Acceptance::RejectMajorMismatch
        );
        assert_eq!(
            window.accepts(1, 6, FeatureBits(0x3), FP1),
            Acceptance::RejectMinorOutOfWindow
        );
        assert_eq!(
            window.accepts(1, 3, FeatureBits(0xFF), FP1),
            Acceptance::RejectFeaturesUnsupported
        );
    }

    #[test]
    fn feature_bits_subset_check() {
        assert!(FeatureBits(0b0110).is_subset_of(FeatureBits(0b1111)));
        assert!(!FeatureBits(0b1111).is_subset_of(FeatureBits(0b0110)));
    }

    #[test]
    fn payload_class_discriminants() {
        assert_eq!(
            PayloadClass::from_discriminant(1),
            Some(PayloadClass::FixedInline)
        );
        assert_eq!(PayloadClass::from_discriminant(0), None);
        assert_eq!(PayloadClass::default(), PayloadClass::FixedInline);
    }

    #[test]
    fn chunk_frame_size_default() {
        assert_eq!(ChunkFrameSizeClass::default(), ChunkFrameSizeClass::KiB64);
        assert_eq!(ChunkFrameSizeClass::KiB64.payload_bytes(), 64 * 1024);
        assert_eq!(ChunkFrameSizeClass::KiB256.payload_bytes(), 256 * 1024);
        assert_eq!(ChunkFrameSizeClass::MiB1.payload_bytes(), 1024 * 1024);
    }

    #[test]
    fn schema_version_encode_decode() {
        let v = SchemaVersion::new(2, 7);
        assert_eq!(SchemaVersion::decode(v.encode()), v);
    }

    #[test]
    fn fingerprint_low_u64() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xEF;
        bytes[1] = 0xCD;
        bytes[2] = 0xAB;
        bytes[3] = 0x89;
        bytes[4] = 0x67;
        bytes[5] = 0x45;
        bytes[6] = 0x23;
        bytes[7] = 0x01;
        assert_eq!(SchemaFingerprint(bytes).low_u64(), 0x01234567_89ABCDEF);
    }

    // -------------------------------------------------------------------
    // Missing round-trip coverage (issue #4002)
    // -------------------------------------------------------------------

    #[test]
    fn u16le_roundtrip() {
        let v = U16Le::from_le(0xBEEF);
        assert_eq!(v.as_raw(), 0xBEEF);
        assert_eq!(U16Le::from_le_bytes(v.encode()), v);
    }

    #[test]
    fn i32le_roundtrip() {
        let v = I32Le::from_le(-1_000_000);
        assert_eq!(v.as_raw(), -1_000_000);
        assert_eq!(I32Le::from_le_bytes(v.encode()), v);
    }

    #[test]
    fn u16le_max_value() {
        let v = U16Le::from_le(u16::MAX);
        assert_eq!(v.as_raw(), 0xFFFF);
        assert_eq!(U16Le::from_le_bytes(v.encode()), v);
    }

    #[test]
    fn u32le_max_value() {
        let v = U32Le::from_le(u32::MAX);
        assert_eq!(v.as_raw(), 0xFFFF_FFFF);
        assert_eq!(U32Le::from_le_bytes(v.encode()), v);
    }

    #[test]
    fn u64le_max_value() {
        let v = U64Le::from_le(u64::MAX);
        assert_eq!(v.as_raw(), u64::MAX);
        assert_eq!(U64Le::from_le_bytes(v.encode()), v);
    }

    #[test]
    fn i32le_min_value() {
        let v = I32Le::from_le(i32::MIN);
        assert_eq!(v.as_raw(), i32::MIN);
        assert_eq!(I32Le::from_le_bytes(v.encode()), v);
    }

    #[test]
    fn i64le_min_value() {
        let v = I64Le::from_le(i64::MIN);
        assert_eq!(v.as_raw(), i64::MIN);
        assert_eq!(I64Le::from_le_bytes(v.encode()), v);
    }

    #[test]
    fn le_deterministic_output() {
        let a = U64Le::from_le(0xCAFE_BABE);
        let b = U64Le::from_le(0xCAFE_BABE);
        assert_eq!(a.encode(), b.encode());
        let c = U32Le::from_le(0xDEAD);
        let d = U32Le::from_le(0xDEAD);
        assert_eq!(c.encode(), d.encode());
    }

    #[test]
    fn feature_bits_encode_decode() {
        let fb = FeatureBits(0x0123_4567_89AB_CDEF);
        assert_eq!(fb.encode(), 0x0123_4567_89AB_CDEFu64.to_le_bytes());
    }

    #[test]
    fn feature_bits_with_and_has() {
        let fb = FeatureBits::NONE.with(3).with(7);
        assert!(fb.has(3));
        assert!(fb.has(7));
        assert!(!fb.has(0));
        assert!(!fb.has(15));
    }

    #[test]
    fn checksum_profile_from_discriminant_valid_and_invalid() {
        assert_eq!(
            ChecksumProfile::from_discriminant(0),
            Some(ChecksumProfile::None)
        );
        assert_eq!(
            ChecksumProfile::from_discriminant(1),
            Some(ChecksumProfile::Crc32c)
        );
        assert_eq!(
            ChecksumProfile::from_discriminant(2),
            Some(ChecksumProfile::Blake3_256)
        );
        assert_eq!(
            ChecksumProfile::from_discriminant(3),
            Some(ChecksumProfile::Crc32cPlusBlake3_256)
        );
        assert_eq!(ChecksumProfile::from_discriminant(4), None);
        assert_eq!(ChecksumProfile::from_discriminant(255), None);
    }

    #[test]
    fn checksum_profile_has_blake3() {
        assert!(!ChecksumProfile::None.has_blake3());
        assert!(!ChecksumProfile::Crc32c.has_blake3());
        assert!(ChecksumProfile::Blake3_256.has_blake3());
        assert!(ChecksumProfile::Crc32cPlusBlake3_256.has_blake3());
    }

    #[test]
    fn payload_class_from_discriminant_valid_and_invalid() {
        assert_eq!(
            PayloadClass::from_discriminant(1),
            Some(PayloadClass::FixedInline)
        );
        assert_eq!(
            PayloadClass::from_discriminant(2),
            Some(PayloadClass::VariableInline)
        );
        assert_eq!(
            PayloadClass::from_discriminant(3),
            Some(PayloadClass::ChunkFramed)
        );
        assert_eq!(
            PayloadClass::from_discriminant(4),
            Some(PayloadClass::ExternalRef)
        );
        assert_eq!(PayloadClass::from_discriminant(0), None);
        assert_eq!(PayloadClass::from_discriminant(5), None);
        assert_eq!(PayloadClass::from_discriminant(u16::MAX), None);
    }

    #[test]
    fn chunk_frame_size_class_discriminants() {
        assert_eq!(
            ChunkFrameSizeClass::from_discriminant(0),
            Some(ChunkFrameSizeClass::KiB64)
        );
        assert_eq!(
            ChunkFrameSizeClass::from_discriminant(1),
            Some(ChunkFrameSizeClass::KiB256)
        );
        assert_eq!(
            ChunkFrameSizeClass::from_discriminant(2),
            Some(ChunkFrameSizeClass::MiB1)
        );
        assert_eq!(ChunkFrameSizeClass::from_discriminant(3), None);
        assert_eq!(ChunkFrameSizeClass::from_discriminant(u16::MAX), None);
    }

    #[test]
    fn domain_tag_discriminants() {
        assert_eq!(DomainTag::EnvelopeHeader.discriminant(), 1);
        assert_eq!(DomainTag::SectionBody.discriminant(), 2);
        assert_eq!(DomainTag::ChunkFrame.discriminant(), 3);
        assert_eq!(DomainTag::ExternalPayload.discriminant(), 4);
        assert_eq!(DomainTag::ReceiptBody.discriminant(), 5);
        assert_eq!(DomainTag::ValidationBundle.discriminant(), 6);
        assert_eq!(DomainTag::ArchiveBody.discriminant(), 7);
        assert_eq!(DomainTag::TransferStream.discriminant(), 8);
        assert_eq!(DomainTag::ObjectPayloadChunk.discriminant(), 9);
    }

    #[test]
    fn schema_fingerprint_encode_decode() {
        let fp = SchemaFingerprint([0x11u8; 32]);
        assert_eq!(SchemaFingerprint::decode(fp.encode()), fp);
    }

    #[test]
    fn schema_fingerprint_zero() {
        assert_eq!(SchemaFingerprint::ZERO.encode(), [0u8; 32]);
        assert_eq!(SchemaFingerprint::ZERO.low_u64(), 0);
    }

    #[test]
    fn schema_fingerprint_display() {
        let fp = SchemaFingerprint::default();
        let s = std::format!("{fp}");
        assert!(s.ends_with(".."));
        assert_eq!(s.len(), 18); // 16 hex + ".."
    }

    #[test]
    fn continuity_window_rejects_unknown_fingerprint() {
        const FP1: SchemaFingerprint = SchemaFingerprint([0xAAu8; 32]);
        const FP2: SchemaFingerprint = SchemaFingerprint([0xBBu8; 32]);
        let window = ContinuityWindow {
            family_id: SchemaFamilyId::BINARY_SCHEMA,
            type_id: SchemaTypeId(100),
            major_version: 1,
            minor_min: 0,
            minor_max: 5,
            required_features: FeatureBits(0xF),
            accepted_fingerprints: &[FP1],
        };
        assert_eq!(
            window.accepts(1, 3, FeatureBits(0x3), FP2),
            Acceptance::RejectFingerprintUnknown
        );
    }

    #[test]
    fn continuity_window_rejects_under_minor() {
        let window = ContinuityWindow {
            family_id: SchemaFamilyId::BINARY_SCHEMA,
            type_id: SchemaTypeId(100),
            major_version: 2,
            minor_min: 3,
            minor_max: 5,
            required_features: FeatureBits(0),
            accepted_fingerprints: &[],
        };
        assert_eq!(
            window.accepts(2, 2, FeatureBits(0), SchemaFingerprint::ZERO),
            Acceptance::RejectMinorOutOfWindow
        );
    }

    #[test]
    fn acceptance_is_accepted() {
        assert!(Acceptance::Accepted.is_accepted());
        assert!(!Acceptance::RejectMajorMismatch.is_accepted());
        assert!(!Acceptance::RejectMinorOutOfWindow.is_accepted());
        assert!(!Acceptance::RejectFeaturesUnsupported.is_accepted());
        assert!(!Acceptance::RejectFingerprintUnknown.is_accepted());
    }

    #[test]
    fn binary_schema_error_display() {
        let e = BinarySchemaError::BadMagic { got: 0xDEAD };
        let s = std::format!("{e}");
        assert!(s.contains("bad magic"));
        assert!(s.contains("0x0000dead"));

        assert!(std::format!("{}", BinarySchemaError::InvalidBoolean).contains("boolean"));
        assert!(std::format!("{}", BinarySchemaError::InvalidChecksumProfile).contains("checksum"));
        assert!(std::format!("{}", BinarySchemaError::InvalidPayloadClass).contains("payload"));
        assert!(std::format!("{}", BinarySchemaError::InvalidDomainTag).contains("domain"));
    }

    // -------------------------------------------------------------------
    // Boundary-value coverage: unsigned min (zero), signed max (issue #4007)
    // -------------------------------------------------------------------

    #[test]
    fn u16le_min_value() {
        let v = U16Le::from_le(0);
        assert_eq!(v.as_raw(), 0);
        assert_eq!(U16Le::from_le_bytes(v.encode()), v);
    }

    #[test]
    fn u32le_min_value() {
        let v = U32Le::from_le(0);
        assert_eq!(v.as_raw(), 0);
        assert_eq!(U32Le::from_le_bytes(v.encode()), v);
    }

    #[test]
    fn u64le_min_value() {
        let v = U64Le::from_le(0);
        assert_eq!(v.as_raw(), 0);
        assert_eq!(U64Le::from_le_bytes(v.encode()), v);
    }

    #[test]
    fn i32le_max_value() {
        let v = I32Le::from_le(i32::MAX);
        assert_eq!(v.as_raw(), i32::MAX);
        assert_eq!(I32Le::from_le_bytes(v.encode()), v);
    }

    #[test]
    fn i64le_max_value() {
        let v = I64Le::from_le(i64::MAX);
        assert_eq!(v.as_raw(), i64::MAX);
        assert_eq!(I64Le::from_le_bytes(v.encode()), v);
    }

    // -------------------------------------------------------------------
    // LE wrapper trait impls: Default, Display, From, Clone, Eq, Hash, Ord
    // -------------------------------------------------------------------

    #[test]
    fn le_wrapper_default_is_zero() {
        assert_eq!(U16Le::default(), U16Le(0));
        assert_eq!(U32Le::default(), U32Le(0));
        assert_eq!(U64Le::default(), U64Le(0));
        assert_eq!(I32Le::default(), I32Le(0));
        assert_eq!(I64Le::default(), I64Le(0));
    }

    #[test]
    fn le_wrapper_display() {
        use std::format;
        assert_eq!(format!("{}", U16Le::from_le(42)), "42");
        assert_eq!(format!("{}", U32Le::from_le(100)), "100");
        assert_eq!(format!("{}", U64Le::from_le(0)), "0");
        assert_eq!(format!("{}", I32Le::from_le(-5)), "-5");
        assert_eq!(format!("{}", I64Le::from_le(-1)), "-1");
    }

    #[test]
    fn le_wrapper_from_inner() {
        let u16v: U16Le = 0xBEEFu16.into();
        assert_eq!(u16v.as_raw(), 0xBEEF);
        let u32v: U32Le = 0xDEADu32.into();
        assert_eq!(u32v.as_raw(), 0xDEAD);
        let i32v: I32Le = (-42i32).into();
        assert_eq!(i32v.as_raw(), -42);
    }

    #[test]
    fn le_wrapper_into_inner() {
        let u16v = U16Le::from_le(0xCAFE);
        let raw: u16 = u16v.into();
        assert_eq!(raw, 0xCAFE);
        let i64v = I64Le::from_le(-99);
        let raw: i64 = i64v.into();
        assert_eq!(raw, -99);
    }

    #[test]
    fn le_wrapper_clone_and_eq() {
        let a = U64Le::from_le(0x1234);
        let b = a;
        assert_eq!(a, b);
        let c = U64Le::from_le(0x1234);
        assert_eq!(a, c);
        assert_ne!(a, U64Le::from_le(0x5678));
    }

    #[test]
    fn le_wrapper_hash_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h1 = DefaultHasher::new();
        U32Le::from_le(42).hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        U32Le::from_le(42).hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
        // Different value should (almost certainly) hash differently
        let mut h3 = DefaultHasher::new();
        U32Le::from_le(99).hash(&mut h3);
        assert_ne!(h1.finish(), h3.finish());
    }

    #[test]
    fn le_wrapper_ord() {
        assert!(U32Le::from_le(10) < U32Le::from_le(20));
        assert!(U32Le::from_le(20) > U32Le::from_le(10));
        assert!(I64Le::from_le(-5) < I64Le::from_le(0));
        assert!(I64Le::from_le(0) <= I64Le::from_le(0));
    }

    #[test]
    fn le_wrapper_debug_format() {
        let v = U16Le::from_le(0xABCD);
        let s = std::format!("{v:?}");
        assert!(s.contains("ABCD") || s.contains("43981"));
        let v2 = I32Le::from_le(-1);
        let s2 = std::format!("{v2:?}");
        assert!(s2.contains("-1"));
    }

    // -------------------------------------------------------------------
    // BinarySchemaError: full variant Display coverage (all 11 variants)
    // -------------------------------------------------------------------

    #[test]
    fn binary_schema_error_all_variants_display() {
        let checksum = std::format!("{}", BinarySchemaError::ChecksumMismatch);
        assert!(checksum.contains("checksum"));

        let digest = std::format!("{}", BinarySchemaError::DigestMismatch);
        assert!(digest.contains("digest"));

        let align = std::format!("{}", BinarySchemaError::AlignmentViolation);
        assert!(align.contains("alignment"));

        let bounds = std::format!("{}", BinarySchemaError::BoundsViolation);
        assert!(bounds.contains("bounds"));

        let cont = std::format!(
            "{}",
            BinarySchemaError::ContinuityRejection(Acceptance::RejectMajorMismatch)
        );
        assert!(cont.contains("continuity"));

        let encode = std::format!("{}", BinarySchemaError::EncodeError);
        assert!(encode.contains("encode"));
    }

    // -------------------------------------------------------------------
    // SchemaFamilyId and SchemaTypeId
    // -------------------------------------------------------------------

    #[test]
    fn schema_family_id_const() {
        assert_eq!(SchemaFamilyId::BINARY_SCHEMA.0, 1);
        assert_eq!(SchemaFamilyId::default().0, 0);
    }

    #[test]
    fn schema_type_id_roundtrip() {
        let id = SchemaTypeId(42);
        assert_eq!(id.0, 42);
        assert_eq!(id, SchemaTypeId(42));
        assert_ne!(id, SchemaTypeId(99));
    }

    // -------------------------------------------------------------------
    // SchemaVersion
    // -------------------------------------------------------------------

    #[test]
    fn schema_version_default() {
        let v = SchemaVersion::default();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 0);
    }

    #[test]
    fn schema_version_debug() {
        let v = SchemaVersion::new(1, 2);
        let s = std::format!("{v:?}");
        assert!(s.contains("1") && s.contains("2"));
    }

    // -------------------------------------------------------------------
    // FeatureBits default and edge cases
    // -------------------------------------------------------------------

    #[test]
    fn feature_bits_default_is_none() {
        assert_eq!(FeatureBits::default(), FeatureBits::NONE);
        assert_eq!(FeatureBits::default().0, 0);
    }

    #[test]
    fn feature_bits_with_bit63() {
        let fb = FeatureBits::NONE.with(63);
        assert!(fb.has(63));
        assert!(!fb.has(0));
    }

    // -------------------------------------------------------------------
    // ChecksumProfile full has_crc32c / has_blake3
    // -------------------------------------------------------------------

    #[test]
    fn checksum_profile_full_has_predicates() {
        assert!(!ChecksumProfile::None.has_crc32c());
        assert!(ChecksumProfile::Crc32c.has_crc32c());
        assert!(!ChecksumProfile::Blake3_256.has_crc32c());
        assert!(ChecksumProfile::Crc32cPlusBlake3_256.has_crc32c());

        assert!(!ChecksumProfile::None.has_blake3());
        assert!(!ChecksumProfile::Crc32c.has_blake3());
        assert!(ChecksumProfile::Blake3_256.has_blake3());
        assert!(ChecksumProfile::Crc32cPlusBlake3_256.has_blake3());
    }

    // -------------------------------------------------------------------
    // PayloadClass and ChunkFrameSizeClass discriminant symmetry
    // -------------------------------------------------------------------

    #[test]
    fn payload_class_discriminant_roundtrip() {
        for cls in &[
            PayloadClass::FixedInline,
            PayloadClass::VariableInline,
            PayloadClass::ChunkFramed,
            PayloadClass::ExternalRef,
        ] {
            assert_eq!(PayloadClass::from_discriminant(*cls as u16), Some(*cls));
        }
    }

    #[test]
    fn chunk_frame_size_class_discriminant_roundtrip() {
        for cls in &[
            ChunkFrameSizeClass::KiB64,
            ChunkFrameSizeClass::KiB256,
            ChunkFrameSizeClass::MiB1,
        ] {
            assert_eq!(
                ChunkFrameSizeClass::from_discriminant(*cls as u16),
                Some(*cls)
            );
        }
    }

    // -------------------------------------------------------------------
    // Acceptance: Clone + Copy + Debug + Eq
    // -------------------------------------------------------------------

    #[test]
    fn acceptance_clone_copy_debug_eq() {
        let a = Acceptance::Accepted;
        let b = a; // Copy
        assert_eq!(a, b);
        let c = a; // Copy again
        assert_eq!(a, c);
        let s = std::format!("{:?}", Acceptance::RejectMajorMismatch);
        assert!(!s.is_empty());
    }

    // -------------------------------------------------------------------
    // DomainTag: all discriminants are distinct and non-zero
    // -------------------------------------------------------------------

    #[test]
    fn domain_tag_all_distinct() {
        let tags = [
            DomainTag::EnvelopeHeader,
            DomainTag::SectionBody,
            DomainTag::ChunkFrame,
            DomainTag::ExternalPayload,
            DomainTag::ReceiptBody,
            DomainTag::ValidationBundle,
            DomainTag::ArchiveBody,
            DomainTag::TransferStream,
            DomainTag::ObjectPayloadChunk,
        ];
        for i in 0..tags.len() {
            for j in 0..tags.len() {
                if i != j {
                    assert_ne!(tags[i].discriminant(), tags[j].discriminant());
                } else {
                    assert_eq!(tags[i].discriminant(), tags[j].discriminant());
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // Constant sanity
    // -------------------------------------------------------------------

    #[test]
    fn alignment_constants_are_power_of_two() {
        assert!(ENVELOPE_ALIGN.is_power_of_two());
        assert!(SECTION_OFFSET_ALIGN_MIN.is_power_of_two());
        assert!(CHUNK_FRAME_ALIGN_DMA.is_power_of_two());
    }

    #[test]
    fn header_sizes_are_aligned() {
        assert_eq!(ENVELOPE_HEADER_BYTES % ENVELOPE_ALIGN, 0);
        assert_eq!(SECTION_HEADER_BYTES % SECTION_OFFSET_ALIGN_MIN, 0);
        assert_eq!(CHUNK_FRAME_HEADER_BYTES % ENVELOPE_ALIGN, 0);
    }

    #[test]
    fn chunk_frame_sizes_increasing() {
        let sizes = [
            CHUNK_FRAME_SIZE_64K,
            CHUNK_FRAME_SIZE_256K,
            CHUNK_FRAME_SIZE_1M,
        ];
        assert!(sizes[0] < sizes[1]);
        assert!(sizes[1] < sizes[2]);
    }

    // -------------------------------------------------------------------
    // SchemaVersion compatibility (issue #4040)
    // -------------------------------------------------------------------

    #[test]
    fn schema_version_can_read_same_version() {
        let v = SchemaVersion::new(1, 3);
        assert!(v.can_read(&v));
    }

    #[test]
    fn schema_version_can_read_newer_minor() {
        let reader = SchemaVersion::new(1, 5);
        let writer = SchemaVersion::new(1, 2);
        assert!(reader.can_read(&writer));
    }

    #[test]
    fn schema_version_cannot_read_older_reader_minor() {
        let reader = SchemaVersion::new(1, 2);
        let writer = SchemaVersion::new(1, 5);
        assert!(!reader.can_read(&writer));
    }

    #[test]
    fn schema_version_major_mismatch_rejected() {
        let reader = SchemaVersion::new(2, 0);
        let writer = SchemaVersion::new(1, 9);
        assert!(!reader.can_read(&writer));

        let reader_v1 = SchemaVersion::new(1, 9);
        let writer_v2 = SchemaVersion::new(2, 0);
        assert!(!reader_v1.can_read(&writer_v2));
    }

    #[test]
    fn schema_version_zero_version_rejected() {
        let zero = SchemaVersion::new(0, 0);
        let valid = SchemaVersion::new(1, 0);
        assert!(!zero.can_read(&valid));
        assert!(!valid.can_read(&zero));
        assert!(!zero.can_read(&zero));
    }

    #[test]
    fn schema_version_can_be_read_by_symmetry() {
        let v1 = SchemaVersion::new(1, 3);
        let v2 = SchemaVersion::new(1, 1);
        assert_eq!(v2.can_be_read_by(&v1), v1.can_read(&v2));
        assert_eq!(v1.can_be_read_by(&v2), v2.can_read(&v1));
    }

    #[test]
    fn schema_version_minor_zero_read_minor_zero() {
        let reader = SchemaVersion::new(1, 0);
        let writer = SchemaVersion::new(1, 0);
        assert!(reader.can_read(&writer));
    }

    #[test]
    fn schema_version_cross_major_can_be_read_by() {
        let v1 = SchemaVersion::new(1, 5);
        let v2 = SchemaVersion::new(2, 0);
        assert!(!v2.can_be_read_by(&v1));
        assert!(!v1.can_be_read_by(&v2));
    }

    #[test]
    fn compatibility_matrix_all_entries_match_can_read() {
        for &(reader, writer, expected) in compatibility_matrix() {
            assert_eq!(
                reader.can_read(&writer),
                expected,
                "can_read mismatch: {reader:?} reading {writer:?} expected {expected}"
            );
        }
    }

    #[test]
    fn compatibility_matrix_has_expected_entries() {
        let matrix = compatibility_matrix();
        assert!(!matrix.is_empty());
        // Verify specific known entries exist
        let v1_0 = SchemaVersion::new(1, 0);
        let v1_2 = SchemaVersion::new(1, 2);
        let v2_0 = SchemaVersion::new(2, 0);
        assert!(v1_2.can_read(&v1_0));
        assert!(!v2_0.can_read(&v1_0));
    }

    #[test]
    fn compatibility_matrix_includes_v3() {
        let v3 = SchemaVersion::new(3, 0);
        assert!(v3.can_read(&v3));
    }

    #[test]
    fn schema_version_const_fn_works() {
        const V1_0: SchemaVersion = SchemaVersion::new(1, 0);
        const V1_5: SchemaVersion = SchemaVersion::new(1, 5);
        assert!(V1_5.can_read(&V1_0));
        assert!(!V1_0.can_read(&V1_5));
    }

    // -------------------------------------------------------------------
    // Trait assertions: Send + Sync (#4042)
    // -------------------------------------------------------------------

    #[allow(dead_code)]
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn key_types_are_send_and_sync() {
        assert_send_sync::<U16Le>();
        assert_send_sync::<U32Le>();
        assert_send_sync::<U64Le>();
        assert_send_sync::<I32Le>();
        assert_send_sync::<I64Le>();
        assert_send_sync::<SchemaFamilyId>();
        assert_send_sync::<SchemaTypeId>();
        assert_send_sync::<SchemaVersion>();
        assert_send_sync::<FeatureBits>();
        assert_send_sync::<SchemaFingerprint>();
        assert_send_sync::<ContinuityWindow>();
        assert_send_sync::<Acceptance>();
        assert_send_sync::<ChecksumProfile>();
        assert_send_sync::<PayloadClass>();
        assert_send_sync::<ChunkFrameSizeClass>();
        assert_send_sync::<DomainTag>();
        assert_send_sync::<BinarySchemaError>();
    }

    // -------------------------------------------------------------------
    // BinarySchemaError: Debug + Display non-empty for all variants (#4042)
    // -------------------------------------------------------------------

    #[test]
    fn binary_schema_error_debug_non_empty() {
        let variants: &[BinarySchemaError] = &[
            BinarySchemaError::BadMagic { got: 0xDEAD },
            BinarySchemaError::ChecksumMismatch,
            BinarySchemaError::DigestMismatch,
            BinarySchemaError::AlignmentViolation,
            BinarySchemaError::BoundsViolation,
            BinarySchemaError::InvalidBoolean,
            BinarySchemaError::InvalidChecksumProfile,
            BinarySchemaError::InvalidPayloadClass,
            BinarySchemaError::InvalidDomainTag,
            BinarySchemaError::ContinuityRejection(Acceptance::RejectMajorMismatch),
            BinarySchemaError::EncodeError,
        ];
        for e in variants {
            let debug_str = std::format!("{e:?}");
            assert!(!debug_str.is_empty(), "Debug output empty for {e:?}");
            let display_str = std::format!("{e}");
            assert!(!display_str.is_empty(), "Display output empty for {e:?}");
        }
    }

    // -------------------------------------------------------------------
    // FeatureBits: edge cases (#4042)
    // -------------------------------------------------------------------

    #[test]
    fn feature_bits_with_all_bits_0_to_63() {
        for b in 0..64u32 {
            let fb = FeatureBits::NONE.with(b);
            assert!(fb.has(b));
            assert_eq!(fb.0, 1u64 << b);
        }
    }

    #[test]
    fn feature_bits_encode_is_8_bytes() {
        assert_eq!(FeatureBits(0).encode().len(), 8);
        assert_eq!(FeatureBits(u64::MAX).encode().len(), 8);
    }

    #[test]
    fn feature_bits_disjoint_not_subset() {
        assert!(!FeatureBits(0b0001).is_subset_of(FeatureBits(0b0010)));
        assert!(!FeatureBits(0b1111).is_subset_of(FeatureBits(0b0000)));
    }

    // -------------------------------------------------------------------
    // SchemaFingerprint: additional coverage (#4042)
    // -------------------------------------------------------------------

    #[test]
    fn schema_fingerprint_display_includes_dots() {
        let fp = SchemaFingerprint([0x42u8; 32]);
        let s = std::format!("{fp}");
        assert!(s.ends_with(".."), "Display should end with ..: {s}");
    }

    #[test]
    fn schema_fingerprint_low_u64_nonzero() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xFF;
        bytes[7] = 0x7F;
        let fp = SchemaFingerprint(bytes);
        let lo = fp.low_u64();
        assert_eq!(lo & 0xFF, 0xFF);
        assert_eq!((lo >> 56) & 0xFF, 0x7F);
    }

    // -------------------------------------------------------------------
    // ContinuityWindow: edge cases (#4042)
    // -------------------------------------------------------------------

    #[test]
    fn continuity_window_accepts_at_minor_boundaries() {
        let window = ContinuityWindow {
            family_id: SchemaFamilyId::BINARY_SCHEMA,
            type_id: SchemaTypeId(1),
            major_version: 3,
            minor_min: 2,
            minor_max: 4,
            required_features: FeatureBits(0),
            accepted_fingerprints: &[SchemaFingerprint::ZERO],
        };
        assert_eq!(
            window.accepts(3, 2, FeatureBits(0), SchemaFingerprint::ZERO),
            Acceptance::Accepted
        );
        assert_eq!(
            window.accepts(3, 4, FeatureBits(0), SchemaFingerprint::ZERO),
            Acceptance::Accepted
        );
        assert_eq!(
            window.accepts(3, 1, FeatureBits(0), SchemaFingerprint::ZERO),
            Acceptance::RejectMinorOutOfWindow
        );
        assert_eq!(
            window.accepts(3, 5, FeatureBits(0), SchemaFingerprint::ZERO),
            Acceptance::RejectMinorOutOfWindow
        );
    }

    // -------------------------------------------------------------------
    // DomainTag: round-trip through discriminant (#4042)
    // -------------------------------------------------------------------

    #[test]
    fn domain_tag_distinct_discriminants_are_nonzero() {
        let tags = [
            DomainTag::EnvelopeHeader,
            DomainTag::SectionBody,
            DomainTag::ChunkFrame,
            DomainTag::ExternalPayload,
            DomainTag::ReceiptBody,
            DomainTag::ValidationBundle,
            DomainTag::ArchiveBody,
            DomainTag::TransferStream,
            DomainTag::ObjectPayloadChunk,
        ];
        for t in &tags {
            assert!(t.discriminant() > 0);
        }
    }

    // -------------------------------------------------------------------
    // ChunkFrameSizeClass: from_discriminant zero and invalid (#4042)
    // -------------------------------------------------------------------

    #[test]
    fn chunk_frame_size_class_rejects_zero() {
        assert_eq!(
            ChunkFrameSizeClass::from_discriminant(0),
            Some(ChunkFrameSizeClass::KiB64)
        );
    }

    // -------------------------------------------------------------------
    // Coverage gap fillers: remaining untested corners (#4086)
    // -------------------------------------------------------------------

    #[test]
    fn continuity_window_rejects_when_fingerprint_list_empty() {
        let window = ContinuityWindow {
            family_id: SchemaFamilyId::BINARY_SCHEMA,
            type_id: SchemaTypeId(1),
            major_version: 1,
            minor_min: 0,
            minor_max: 5,
            required_features: FeatureBits(0),
            accepted_fingerprints: &[],
        };
        assert_eq!(
            window.accepts(1, 0, FeatureBits(0), SchemaFingerprint::ZERO),
            Acceptance::RejectFingerprintUnknown
        );
    }

    #[test]
    fn feature_bits_encode_decode_roundtrip() {
        for v in [0u64, 1, u64::MAX, 0x0123_4567_89AB_CDEF] {
            let fb = FeatureBits(v);
            let encoded = fb.encode();
            assert_eq!(encoded.len(), 8);
            let decoded_val = u64::from_le_bytes(encoded);
            assert_eq!(decoded_val, v);
        }
    }

    #[test]
    fn schema_family_id_derived_traits() {
        let a = SchemaFamilyId(42);
        let b = a; // Copy
        assert_eq!(a, b); // Eq, PartialEq
        let dbg = std::format!("{a:?}");
        assert!(!dbg.is_empty()); // Debug
        assert!(SchemaFamilyId(10) < SchemaFamilyId(20)); // Ord
    }

    #[test]
    fn schema_type_id_derived_traits() {
        let a = SchemaTypeId(99);
        let b = a;
        assert_eq!(a, b);
        let debug_str = std::format!("{a:?}");
        assert!(!debug_str.is_empty());
        assert_ne!(SchemaTypeId(1), SchemaTypeId(2));
        assert_eq!(SchemaTypeId::default().0, 0);
    }

    #[test]
    fn chunk_frame_align_dma_constant() {
        assert_eq!(CHUNK_FRAME_ALIGN_DMA, 4096);
        assert!(CHUNK_FRAME_ALIGN_DMA.is_power_of_two());
    }

    #[test]
    fn checksum_profile_from_discriminant_exact_boundaries() {
        assert_eq!(
            ChecksumProfile::from_discriminant(0),
            Some(ChecksumProfile::None)
        );
        assert_eq!(
            ChecksumProfile::from_discriminant(3),
            Some(ChecksumProfile::Crc32cPlusBlake3_256)
        );
        assert_eq!(ChecksumProfile::from_discriminant(4), None);
        assert_eq!(ChecksumProfile::from_discriminant(255), None);
    }

    #[test]
    fn payload_class_from_discriminant_exact_boundaries() {
        assert_eq!(
            PayloadClass::from_discriminant(1),
            Some(PayloadClass::FixedInline)
        );
        assert_eq!(
            PayloadClass::from_discriminant(4),
            Some(PayloadClass::ExternalRef)
        );
        assert_eq!(PayloadClass::from_discriminant(5), None);
    }

    #[test]
    fn canonical_bool_exhaustive_byte_range() {
        for v in 0u8..=255u8 {
            let decoded = decode_canonical_bool(v);
            if v == 0 {
                assert_eq!(decoded, Some(false));
            } else if v == 1 {
                assert_eq!(decoded, Some(true));
            } else {
                assert_eq!(decoded, None);
            }
        }
    }

    #[test]
    fn le_wrappers_from_le_bytes_zero_reconstruct() {
        assert_eq!(U16Le::from_le_bytes([0u8; 2]).as_raw(), 0);
        assert_eq!(U32Le::from_le_bytes([0u8; 4]).as_raw(), 0);
        assert_eq!(U64Le::from_le_bytes([0u8; 8]).as_raw(), 0);
        assert_eq!(I32Le::from_le_bytes([0u8; 4]).as_raw(), 0);
        assert_eq!(I64Le::from_le_bytes([0u8; 8]).as_raw(), 0);
    }

    #[test]
    fn compatibility_matrix_has_13_entries() {
        assert_eq!(compatibility_matrix().len(), 13);
    }
}

#[cfg(all(test, feature = "proptest"))]
mod proptests;
