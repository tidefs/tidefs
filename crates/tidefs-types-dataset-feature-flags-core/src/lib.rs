// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Authority types and persisted record encoding for per-dataset feature flags.
//!
//! This crate owns the `compat`, `ro_compat`, and `incompat` classes, the
//! reverse-DNS feature-name registry, canonical V1 class assignments, and the
//! fixed-width feature-tree root record. Runtime callers own mount admission
//! and feature-tree resolution; these types do not by themselves establish a
//! public on-disk compatibility or mounted-feature support promise.

use core::fmt;
use core::str::FromStr;

#[cfg(all(not(test), feature = "alloc"))]
extern crate alloc;

// ---------------------------------------------------------------------------
// FeatureClass — three compatibility classes with ordering
// ---------------------------------------------------------------------------

/// Compatibility class for a feature flag.
///
/// The classes are ordered: `Compat < RoCompat < Incompat`. An unknown
/// `Incompat` feature refuses mount; an unknown `RoCompat` feature forces
/// read-only mount; an unknown `Compat` feature is silently ignored.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum FeatureClass {
    /// Feature may be safely ignored by older code.
    Compat = 0,
    /// Writes without understanding may corrupt; read-only mount allowed.
    RoCompat = 1,
    /// Data cannot be interpreted without understanding; mount refused.
    Incompat = 2,
}

impl FeatureClass {
    /// Returns `true` if an unknown feature of this class forces read-only.
    #[must_use]
    pub const fn forces_read_only(self) -> bool {
        matches!(self, FeatureClass::RoCompat)
    }

    /// Returns `true` if an unknown feature of this class refuses mount.
    #[must_use]
    pub const fn refuses_mount(self) -> bool {
        matches!(self, FeatureClass::Incompat)
    }

    /// Encode this class as a wire byte (0=Compat, 1=RoCompat, 2=Incompat).
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            FeatureClass::Compat => 0,
            FeatureClass::RoCompat => 1,
            FeatureClass::Incompat => 2,
        }
    }

    /// Decode a class from a wire byte.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(FeatureClass::Compat),
            1 => Some(FeatureClass::RoCompat),
            2 => Some(FeatureClass::Incompat),
            _ => None,
        }
    }
}

impl fmt::Display for FeatureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FeatureClass::Compat => f.write_str("compat"),
            FeatureClass::RoCompat => f.write_str("ro_compat"),
            FeatureClass::Incompat => f.write_str("incompat"),
        }
    }
}

// ---------------------------------------------------------------------------
// FeatureFlagValueV1 — per-feature state in the B-tree
// ---------------------------------------------------------------------------

/// State of a feature flag in a dataset's feature B-tree.
///
/// V1 only uses `Enabled`. `EnabledActive` is reserved for future refcount
/// semantics (tracking how many objects depend on a feature).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FeatureFlagValueV1 {
    /// Feature is active in this dataset.
    Enabled = 0x01,
    /// Feature is enabled AND has active on-disk state (deferred to V2).
    EnabledActive = 0x02,
}

impl FeatureFlagValueV1 {
    /// Raw wire byte for `Enabled`.
    pub const ENABLED_BYTE: u8 = 0x01;

    /// Raw wire byte for `EnabledActive`.
    pub const ENABLED_ACTIVE_BYTE: u8 = 0x02;

    /// Decode from a wire byte.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(FeatureFlagValueV1::Enabled),
            0x02 => Some(FeatureFlagValueV1::EnabledActive),
            _ => None,
        }
    }

    /// Encode to a wire byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            FeatureFlagValueV1::Enabled => 0x01,
            FeatureFlagValueV1::EnabledActive => 0x02,
        }
    }

    /// Returns `true` if the feature is enabled (in any state).
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(
            self,
            FeatureFlagValueV1::Enabled | FeatureFlagValueV1::EnabledActive
        )
    }
}

// ---------------------------------------------------------------------------
// FeatureName — validated reverse-DNS feature name (max 127 bytes)
// ---------------------------------------------------------------------------

/// Maximum length of a feature name in bytes.
pub const FEATURE_NAME_MAX_LEN: usize = 127;

/// A validated feature name in reverse-DNS form (`org.tidefs:feature_name`).
///
/// Validation rules:
/// - ASCII lowercase alphanumeric, hyphens, underscores, and dots before the colon
/// - Single colon separating domain from feature name
/// - Feature name part: lowercase alphanumeric + underscores
/// - Total length ≤ 127 bytes
///
/// Construction is fallible via [`FeatureName::new`] or [`FromStr`].
#[derive(Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct FeatureName {
    /// The raw byte representation, always valid UTF-8.
    bytes: [u8; FEATURE_NAME_MAX_LEN],
    /// Actual length (1..=FEATURE_NAME_MAX_LEN).
    len: u8,
}

impl FeatureName {
    /// Create a new `FeatureName` from a byte slice.
    ///
    /// Returns `None` if the name fails validation.
    #[must_use]
    pub const fn new(name: &[u8]) -> Option<Self> {
        let n = name.len();
        if n == 0 || n > FEATURE_NAME_MAX_LEN {
            return None;
        }
        // Manual const validation
        let mut bytes = [0u8; FEATURE_NAME_MAX_LEN];
        let mut i = 0;
        let mut colon_seen = false;
        let mut colon_idx = FEATURE_NAME_MAX_LEN; // sentinel
        while i < n {
            let b = name[i];
            bytes[i] = b;
            match b {
                b'.' | b'-' => {
                    // dots and hyphens only in domain part
                    if colon_seen {
                        return None;
                    }
                }
                b'_' => {
                    // underscores allowed anywhere
                }
                b':' => {
                    if colon_seen {
                        return None; // only one colon
                    }
                    colon_seen = true;
                    colon_idx = i;
                }
                b'a'..=b'z' | b'0'..=b'9' => {
                    // alphanumeric always OK
                }
                _ => return None,
            }
            i += 1;
        }
        // Must have a colon
        if !colon_seen {
            return None;
        }
        // Domain part must not be empty, feature name part must not be empty
        if colon_idx == 0 || colon_idx + 1 >= n {
            return None;
        }
        Some(FeatureName {
            bytes,
            len: n as u8,
        })
    }

    /// Create a `FeatureName` from a `&str`.
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        FeatureName::new(s.as_bytes())
    }

    /// Returns the feature name as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_bytes_inner()
    }

    /// Returns the feature name as a `&str` (always valid UTF-8).
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Safe: all valid feature names are ASCII (validated on construction),
        // therefore the bytes are always valid UTF-8.
        core::str::from_utf8(self.as_bytes_inner()).expect("FeatureName must be valid UTF-8")
    }

    /// Returns the length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `true` if the name is empty (never true for valid names).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    // Internal: get the actual bytes slice
    fn as_bytes_inner(&self) -> &[u8] {
        let end = self.len as usize;
        &self.bytes[..end]
    }
}

impl fmt::Debug for FeatureName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FeatureName").field(&self.as_str()).finish()
    }
}

impl fmt::Display for FeatureName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FeatureName {
    type Err = InvalidFeatureName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FeatureName::from_str(s).ok_or(InvalidFeatureName)
    }
}

/// Error returned when a feature name fails validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidFeatureName;

impl fmt::Display for InvalidFeatureName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid feature name: must be reverse-DNS (org.tidefs:name), ASCII lowercase, max 127 bytes")
    }
}

// ---------------------------------------------------------------------------
// DatasetFeatureFlagsV1 — on-media struct (three logical object-key roots)
// ---------------------------------------------------------------------------

/// Logical object key for one persisted feature-tree root.
///
/// All 32 bytes are part of the V1 address. The all-zero value is reserved as
/// the empty-tree sentinel; every other value is a required object-store key.
#[derive(Clone, Copy, Default, Eq, PartialEq, Hash)]
pub struct FeatureTreeRootKeyV1([u8; 32]);

impl FeatureTreeRootKeyV1 {
    pub const WIRE_SIZE: usize = 32;
    pub const EMPTY: Self = Self([0_u8; Self::WIRE_SIZE]);

    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::WIRE_SIZE]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn new_required(bytes: [u8; Self::WIRE_SIZE]) -> Option<Self> {
        let root = Self(bytes);
        if root.is_empty() {
            None
        } else {
            Some(root)
        }
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; Self::WIRE_SIZE] {
        self.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        let mut index = 0;
        while index < Self::WIRE_SIZE {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }

    #[must_use]
    pub const fn is_required(self) -> bool {
        !self.is_empty()
    }

    #[must_use]
    pub const fn required(self) -> Option<Self> {
        if self.is_required() {
            Some(self)
        } else {
            None
        }
    }

    #[must_use]
    pub fn encode(self) -> [u8; Self::WIRE_SIZE] {
        self.0
    }

    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::WIRE_SIZE {
            return None;
        }
        let mut key = [0_u8; Self::WIRE_SIZE];
        key.copy_from_slice(bytes);
        Some(Self(key))
    }
}

impl fmt::Display for FeatureTreeRootKeyV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("FeatureTreeRootKeyV1(EMPTY)");
        }
        f.write_str("FeatureTreeRootKeyV1(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

impl fmt::Debug for FeatureTreeRootKeyV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatasetFeatureFlagsDecodeError {
    InvalidSize { actual: usize },
    InvalidMagic,
    UnsupportedVersion { version: u16 },
    NonzeroReserved { value: u16 },
}

impl fmt::Display for DatasetFeatureFlagsDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSize { actual } => write!(
                f,
                "invalid dataset feature-root record size {actual}, expected {}",
                DatasetFeatureFlagsV1::WIRE_SIZE
            ),
            Self::InvalidMagic => f.write_str("invalid dataset feature-root record magic"),
            Self::UnsupportedVersion { version } => {
                write!(
                    f,
                    "unsupported dataset feature-root record version {version}"
                )
            }
            Self::NonzeroReserved { value } => write!(
                f,
                "dataset feature-root record reserved field is nonzero ({value})"
            ),
        }
    }
}

/// Per-dataset feature flag storage — three logical-keyed trees, one per class.
///
/// The encoded record starts with an explicit magic/version header followed by
/// the exact 32-byte object key for each class. Unknown versions, nonzero
/// reserved fields, and retired record widths are rejected instead of being
/// reinterpreted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct DatasetFeatureFlagsV1 {
    /// B-tree root for `compat` features.
    pub compat_root: FeatureTreeRootKeyV1,
    /// B-tree root for `ro_compat` features.
    pub ro_compat_root: FeatureTreeRootKeyV1,
    /// B-tree root for `incompat` features.
    pub incompat_root: FeatureTreeRootKeyV1,
}

impl DatasetFeatureFlagsV1 {
    pub const MAGIC: [u8; 4] = *b"TFFR";
    pub const FORMAT_VERSION: u16 = 1;
    const HEADER_SIZE: usize = 8;
    const VERSION_OFFSET: usize = 4;
    const RESERVED_OFFSET: usize = 6;
    const COMPAT_ROOT_OFFSET: usize = Self::HEADER_SIZE;
    const RO_COMPAT_ROOT_OFFSET: usize = Self::COMPAT_ROOT_OFFSET + FeatureTreeRootKeyV1::WIRE_SIZE;
    const INCOMPAT_ROOT_OFFSET: usize =
        Self::RO_COMPAT_ROOT_OFFSET + FeatureTreeRootKeyV1::WIRE_SIZE;
    pub const WIRE_SIZE: usize = Self::INCOMPAT_ROOT_OFFSET + FeatureTreeRootKeyV1::WIRE_SIZE;

    /// Returns the logical object-key root for the given class.
    #[must_use]
    pub const fn root_for(&self, class: FeatureClass) -> FeatureTreeRootKeyV1 {
        match class {
            FeatureClass::Compat => self.compat_root,
            FeatureClass::RoCompat => self.ro_compat_root,
            FeatureClass::Incompat => self.incompat_root,
        }
    }

    #[must_use]
    pub const fn required_root_for(&self, class: FeatureClass) -> Option<FeatureTreeRootKeyV1> {
        self.root_for(class).required()
    }

    /// Returns `true` if all three B-trees are empty (no features enabled).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.compat_root.is_empty()
            && self.ro_compat_root.is_empty()
            && self.incompat_root.is_empty()
    }

    #[must_use]
    pub fn encode(self) -> [u8; Self::WIRE_SIZE] {
        let mut bytes = [0_u8; Self::WIRE_SIZE];
        bytes[..Self::MAGIC.len()].copy_from_slice(&Self::MAGIC);
        bytes[Self::VERSION_OFFSET..Self::RESERVED_OFFSET]
            .copy_from_slice(&Self::FORMAT_VERSION.to_le_bytes());
        bytes[Self::COMPAT_ROOT_OFFSET..Self::RO_COMPAT_ROOT_OFFSET]
            .copy_from_slice(&self.compat_root.encode());
        bytes[Self::RO_COMPAT_ROOT_OFFSET..Self::INCOMPAT_ROOT_OFFSET]
            .copy_from_slice(&self.ro_compat_root.encode());
        bytes[Self::INCOMPAT_ROOT_OFFSET..Self::WIRE_SIZE]
            .copy_from_slice(&self.incompat_root.encode());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DatasetFeatureFlagsDecodeError> {
        if bytes.len() != Self::WIRE_SIZE {
            return Err(DatasetFeatureFlagsDecodeError::InvalidSize {
                actual: bytes.len(),
            });
        }
        if bytes[..Self::MAGIC.len()] != Self::MAGIC {
            return Err(DatasetFeatureFlagsDecodeError::InvalidMagic);
        }
        let version =
            u16::from_le_bytes([bytes[Self::VERSION_OFFSET], bytes[Self::VERSION_OFFSET + 1]]);
        if version != Self::FORMAT_VERSION {
            return Err(DatasetFeatureFlagsDecodeError::UnsupportedVersion { version });
        }
        let reserved = u16::from_le_bytes([
            bytes[Self::RESERVED_OFFSET],
            bytes[Self::RESERVED_OFFSET + 1],
        ]);
        if reserved != 0 {
            return Err(DatasetFeatureFlagsDecodeError::NonzeroReserved { value: reserved });
        }
        Ok(Self {
            compat_root: FeatureTreeRootKeyV1::decode(
                &bytes[Self::COMPAT_ROOT_OFFSET..Self::RO_COMPAT_ROOT_OFFSET],
            )
            .expect("fixed feature-root slice"),
            ro_compat_root: FeatureTreeRootKeyV1::decode(
                &bytes[Self::RO_COMPAT_ROOT_OFFSET..Self::INCOMPAT_ROOT_OFFSET],
            )
            .expect("fixed feature-root slice"),
            incompat_root: FeatureTreeRootKeyV1::decode(
                &bytes[Self::INCOMPAT_ROOT_OFFSET..Self::WIRE_SIZE],
            )
            .expect("fixed feature-root slice"),
        })
    }
}

// ---------------------------------------------------------------------------
// Canonical feature name constants (initial V1 set)
// ---------------------------------------------------------------------------

/// Macro to define a canonical feature name constant.
///
/// Panics at compile time if the string is invalid (caught by tests).
macro_rules! canonical_feature {
    ($const_name:ident, $name:literal) => {
        #[doc = concat!("Canonical feature name: `", $name, "`")]
        #[allow(non_upper_case_globals)]
        pub const $const_name: &str = $name;
    };
}

// Force a const assertion at compile time via a static that's checked when this
// crate is compiled. The test suite also validates each constant.

canonical_feature!(FEATURE_POSIX_ACL, "org.tidefs:posix_acl");
canonical_feature!(FEATURE_POLYMORPHIC_XATTR, "org.tidefs:polymorphic_xattr");
canonical_feature!(
    FEATURE_POLYMORPHIC_DIR_INDEX,
    "org.tidefs:polymorphic_dir_index"
);
canonical_feature!(FEATURE_COMPRESSION_LZ4, "org.tidefs:compression_lz4");
canonical_feature!(FEATURE_COMPRESSION_ZSTD, "org.tidefs:compression_zstd");
canonical_feature!(
    FEATURE_ENCRYPTION_CHACHA20,
    "org.tidefs:encryption_chacha20"
);
canonical_feature!(
    FEATURE_INTENT_LOG_LOG_DEVICE,
    "org.tidefs:intent_log_log_device"
);
canonical_feature!(
    FEATURE_COMMIT_GROUP_STATE_MACHINE,
    "org.tidefs:commit_group_state_machine"
);
canonical_feature!(FEATURE_LOCATOR_TABLE, "org.tidefs:locator_table");
canonical_feature!(FEATURE_CHECKSUM_BLAKE3, "org.tidefs:checksum_blake3");
canonical_feature!(
    FEATURE_CHUNKED_FILE_LAYOUT,
    "org.tidefs:chunked_file_layout"
);
canonical_feature!(FEATURE_EXTENT_MAP_V2, "org.tidefs:extent_map_v2");
canonical_feature!(FEATURE_SNAPSHOT_V2, "org.tidefs:snapshot_v2");
canonical_feature!(FEATURE_SEND_RECV_V2, "org.tidefs:send_recv_v2");
canonical_feature!(FEATURE_ACL_SUPPORT, "org.tidefs:acl_support");
canonical_feature!(FEATURE_XATTR_SUPPORT, "org.tidefs:xattr_support");
canonical_feature!(FEATURE_DEDUP, "org.tidefs:dedup");

/// All canonical V1 feature names in registry order.
pub const CANONICAL_V1_FEATURES: &[&str] = &[
    FEATURE_POSIX_ACL,
    FEATURE_POLYMORPHIC_XATTR,
    FEATURE_POLYMORPHIC_DIR_INDEX,
    FEATURE_COMPRESSION_LZ4,
    FEATURE_COMPRESSION_ZSTD,
    FEATURE_ENCRYPTION_CHACHA20,
    FEATURE_INTENT_LOG_LOG_DEVICE,
    FEATURE_COMMIT_GROUP_STATE_MACHINE,
    FEATURE_LOCATOR_TABLE,
    FEATURE_CHECKSUM_BLAKE3,
    FEATURE_CHUNKED_FILE_LAYOUT,
    FEATURE_EXTENT_MAP_V2,
    FEATURE_SNAPSHOT_V2,
    FEATURE_SEND_RECV_V2,
    FEATURE_ACL_SUPPORT,
    FEATURE_XATTR_SUPPORT,
    FEATURE_DEDUP,
];

// ---------------------------------------------------------------------------
// Feature class lookup — canonical class assignment
// ---------------------------------------------------------------------------

/// Maps each canonical feature name to its required [`FeatureClass`].
///
/// The source-owned assignments use these bounds:
///
/// - `Incompat`: new on-disk record layout or changes how existing records
///   must be interpreted (e.g. extent_map_v2, encryption).
/// - `RoCompat`: writes unsafe without understanding, reads remain safe
///   (e.g. compression, checksums).
/// - `Compat`: purely additive metadata that can be safely ignored (e.g.
///   ACL, xattr support).
pub const CANONICAL_FEATURE_CLASSES: &[(&str, FeatureClass)] = &[
    // -- Incompat (new record layout / format change) --
    (FEATURE_CHUNKED_FILE_LAYOUT, FeatureClass::Incompat),
    (FEATURE_EXTENT_MAP_V2, FeatureClass::Incompat),
    (FEATURE_SNAPSHOT_V2, FeatureClass::Incompat),
    (FEATURE_SEND_RECV_V2, FeatureClass::Incompat),
    (FEATURE_ENCRYPTION_CHACHA20, FeatureClass::Incompat),
    (FEATURE_INTENT_LOG_LOG_DEVICE, FeatureClass::Incompat),
    // -- RoCompat (unsafe to write without understanding) --
    (FEATURE_COMPRESSION_LZ4, FeatureClass::RoCompat),
    (FEATURE_COMPRESSION_ZSTD, FeatureClass::RoCompat),
    (FEATURE_CHECKSUM_BLAKE3, FeatureClass::RoCompat),
    (FEATURE_DEDUP, FeatureClass::RoCompat),
    (FEATURE_LOCATOR_TABLE, FeatureClass::RoCompat),
    (FEATURE_COMMIT_GROUP_STATE_MACHINE, FeatureClass::RoCompat),
    // -- Compat (purely additive) --
    (FEATURE_POSIX_ACL, FeatureClass::Compat),
    (FEATURE_POLYMORPHIC_XATTR, FeatureClass::Compat),
    (FEATURE_POLYMORPHIC_DIR_INDEX, FeatureClass::Compat),
    (FEATURE_ACL_SUPPORT, FeatureClass::Compat),
    (FEATURE_XATTR_SUPPORT, FeatureClass::Compat),
];

/// Returns the canonical [`FeatureClass`] for a feature name.
///
/// Returns `None` if the feature is unknown (not in the canonical registry).
#[must_use]
pub fn get_feature_class(name: &FeatureName) -> Option<FeatureClass> {
    let name_str = name.as_str();
    for &(feature, class) in CANONICAL_FEATURE_CLASSES {
        if feature == name_str {
            return Some(class);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Feature prerequisites — dependency graph
// ---------------------------------------------------------------------------

/// Maps a feature name to its required prerequisites (if any).
///
/// Each entry is `(feature, &[prerequisites...])`. When enabling a feature,
/// all of its prerequisites must already be enabled. The upgrade tool should
/// auto-enable prerequisites before enabling the requested feature.
pub const FEATURE_PREREQUISITES: &[(&str, &[&str])] = &[
    (FEATURE_ENCRYPTION_CHACHA20, &[FEATURE_CHECKSUM_BLAKE3]),
    (FEATURE_SNAPSHOT_V2, &[FEATURE_COMMIT_GROUP_STATE_MACHINE]),
    (
        FEATURE_SEND_RECV_V2,
        &[FEATURE_SNAPSHOT_V2, FEATURE_CHECKSUM_BLAKE3],
    ),
    (FEATURE_EXTENT_MAP_V2, &[FEATURE_CHUNKED_FILE_LAYOUT]),
    (FEATURE_ACL_SUPPORT, &[FEATURE_POSIX_ACL]),
];

/// Returns the prerequisite feature name strings for `name`, or `None` if the
/// feature has no prerequisites or is not in the dependency graph.
#[must_use]
pub fn get_feature_prerequisites(name: &FeatureName) -> Option<&'static [&'static str]> {
    let name_str = name.as_str();
    for &(feature, prereqs) in FEATURE_PREREQUISITES {
        if feature == name_str {
            return Some(prereqs);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- FeatureClass -------------------------------------------------------

    #[test]
    fn feature_class_ordering() {
        assert!(FeatureClass::Compat < FeatureClass::RoCompat);
        assert!(FeatureClass::RoCompat < FeatureClass::Incompat);
        assert!(FeatureClass::Compat < FeatureClass::Incompat);
    }

    #[test]
    fn feature_class_display() {
        assert_eq!(FeatureClass::Compat.to_string(), "compat");
        assert_eq!(FeatureClass::RoCompat.to_string(), "ro_compat");
        assert_eq!(FeatureClass::Incompat.to_string(), "incompat");
    }

    #[test]
    fn feature_class_forces_read_only() {
        assert!(!FeatureClass::Compat.forces_read_only());
        assert!(FeatureClass::RoCompat.forces_read_only());
        assert!(!FeatureClass::Incompat.forces_read_only());
    }

    #[test]
    fn feature_class_refuses_mount() {
        assert!(!FeatureClass::Compat.refuses_mount());
        assert!(!FeatureClass::RoCompat.refuses_mount());
        assert!(FeatureClass::Incompat.refuses_mount());
    }

    // -- FeatureFlagValueV1 -------------------------------------------------

    #[test]
    fn feature_flag_value_roundtrip() {
        for v in [
            FeatureFlagValueV1::Enabled,
            FeatureFlagValueV1::EnabledActive,
        ] {
            let byte = v.to_u8();
            let decoded = FeatureFlagValueV1::from_u8(byte);
            assert_eq!(decoded, Some(v));
        }
    }

    #[test]
    fn feature_flag_value_invalid_byte() {
        assert_eq!(FeatureFlagValueV1::from_u8(0x00), None);
        assert_eq!(FeatureFlagValueV1::from_u8(0x03), None);
        assert_eq!(FeatureFlagValueV1::from_u8(0xFF), None);
    }

    #[test]
    fn feature_flag_value_is_enabled() {
        assert!(FeatureFlagValueV1::Enabled.is_enabled());
        assert!(FeatureFlagValueV1::EnabledActive.is_enabled());
    }

    // -- FeatureName --------------------------------------------------------

    #[test]
    fn valid_feature_names() {
        assert!(FeatureName::from_str("org.tidefs:posix_acl").is_some());
        assert!(FeatureName::from_str("org.tidefs:a").is_some());
        assert!(FeatureName::from_str("com.example:my_feature").is_some());
        assert!(FeatureName::from_str("a.b:c").is_some());
        assert!(FeatureName::from_str("org.tidefs:extent_map_tristate").is_some());
    }

    #[test]
    fn valid_underscore_in_domain() {
        // Per spec §4.1: underscores allowed in both domain and feature parts.
        let n = FeatureName::from_str("org.tidefs_storage:my_feature").unwrap();
        assert_eq!(n.as_str(), "org.tidefs_storage:my_feature");
    }

    #[test]
    fn invalid_feature_names_no_colon() {
        assert!(FeatureName::from_str("org.tidefs_posix_acl").is_none());
    }

    #[test]
    fn invalid_feature_names_multiple_colons() {
        assert!(FeatureName::from_str("org:tidefs:posix_acl").is_none());
    }

    #[test]
    fn invalid_feature_names_empty_domain() {
        assert!(FeatureName::from_str(":posix_acl").is_none());
    }

    #[test]
    fn invalid_feature_names_empty_feature() {
        assert!(FeatureName::from_str("org.tidefs:").is_none());
    }

    #[test]
    fn invalid_feature_names_uppercase() {
        assert!(FeatureName::from_str("org.tidefs:POSIX_ACL").is_none());
    }

    #[test]
    fn invalid_feature_names_special_chars() {
        assert!(FeatureName::from_str("org.tidefs:posix acl").is_none());
        assert!(FeatureName::from_str("org.tidefs:posix@acl").is_none());
    }

    #[test]
    fn feature_name_max_length() {
        // 127-byte name: domain part 118 + colon + 8-char feature = 127
        let long_domain = "a".repeat(118);
        let name = format!("{long_domain}:abcdefgh");
        assert_eq!(name.len(), 127);
        assert!(FeatureName::from_str(&name).is_some());

        // 128 bytes should fail
        let too_long = format!("{long_domain}:abcdefghi");
        assert_eq!(too_long.len(), 128);
        assert!(FeatureName::from_str(&too_long).is_none());
    }

    #[test]
    fn feature_name_display_debug() {
        let n = FeatureName::from_str("org.tidefs:posix_acl").unwrap();
        assert_eq!(n.to_string(), "org.tidefs:posix_acl");
        assert_eq!(format!("{n:?}"), r#"FeatureName("org.tidefs:posix_acl")"#);
    }

    #[test]
    fn feature_name_fromstr_trait() {
        let n: FeatureName = "org.tidefs:posix_acl".parse().unwrap();
        assert_eq!(n.as_str(), "org.tidefs:posix_acl");
    }

    // -- Canonical constants ------------------------------------------------

    #[test]
    fn all_canonical_names_parse() {
        for name in CANONICAL_V1_FEATURES {
            let n = FeatureName::from_str(name);
            assert!(n.is_some(), "canonical name '{name}' should parse");
            let n = n.unwrap();
            assert_eq!(n.as_str(), *name);
        }
    }

    #[test]
    fn canonical_names_are_unique() {
        let mut seen: [Option<FeatureName>; CANONICAL_V1_FEATURES.len()] = [const { None }; 17];
        for (i, name) in CANONICAL_V1_FEATURES.iter().enumerate() {
            let n = FeatureName::from_str(name).unwrap();
            for previous in seen.iter().take(i).flatten() {
                assert_ne!(&n, previous, "duplicate canonical name: {name}");
            }
            seen[i] = Some(n);
        }
    }

    // -- DatasetFeatureFlagsV1 ----------------------------------------------

    fn feature_root(byte: u8) -> FeatureTreeRootKeyV1 {
        FeatureTreeRootKeyV1::new_required([byte; FeatureTreeRootKeyV1::WIRE_SIZE])
            .expect("nonzero feature root")
    }

    #[test]
    fn empty_dataset_flags() {
        let flags = DatasetFeatureFlagsV1::default();
        assert!(flags.is_empty());
        assert!(flags.compat_root.is_empty());
        assert!(flags.ro_compat_root.is_empty());
        assert!(flags.incompat_root.is_empty());
        assert_eq!(
            flags.required_root_for(FeatureClass::Compat),
            None,
            "empty roots are not resolvable object keys"
        );

        let encoded = flags.encode();
        assert_eq!(&encoded[..4], &DatasetFeatureFlagsV1::MAGIC);
        assert_eq!(
            DatasetFeatureFlagsV1::decode(&encoded),
            Ok(DatasetFeatureFlagsV1::default())
        );
    }

    #[test]
    fn root_for_returns_correct_root() {
        let flags = DatasetFeatureFlagsV1 {
            compat_root: feature_root(1),
            ro_compat_root: feature_root(2),
            incompat_root: feature_root(3),
        };
        assert_eq!(flags.root_for(FeatureClass::Compat), feature_root(1));
        assert_eq!(flags.root_for(FeatureClass::RoCompat), feature_root(2));
        assert_eq!(flags.root_for(FeatureClass::Incompat), feature_root(3));
        assert_eq!(
            flags.required_root_for(FeatureClass::Compat),
            Some(feature_root(1))
        );
    }

    #[test]
    fn feature_tree_root_key_preserves_full_object_key() {
        let mut bytes = [0_u8; FeatureTreeRootKeyV1::WIRE_SIZE];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index as u8 + 1;
        }
        let root = FeatureTreeRootKeyV1::new_required(bytes).expect("required root");
        assert_eq!(root.as_bytes(), bytes);
        assert_eq!(root.encode(), bytes);
        assert_eq!(FeatureTreeRootKeyV1::decode(&bytes), Some(root));
        assert!(FeatureTreeRootKeyV1::decode(&bytes[..31]).is_none());
        assert_eq!(
            root.to_string(),
            "FeatureTreeRootKeyV1(0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20)"
        );
        assert_eq!(format!("{root:?}"), root.to_string());
        assert_eq!(
            FeatureTreeRootKeyV1::EMPTY.to_string(),
            "FeatureTreeRootKeyV1(EMPTY)"
        );
        assert!(FeatureTreeRootKeyV1::new_required([0_u8; 32]).is_none());
    }

    #[test]
    fn dataset_feature_flags_v1_roundtrip_preserves_all_roots() {
        let flags = DatasetFeatureFlagsV1 {
            compat_root: feature_root(0x11),
            ro_compat_root: FeatureTreeRootKeyV1::EMPTY,
            incompat_root: feature_root(0x33),
        };
        let encoded = flags.encode();
        assert_eq!(encoded.len(), DatasetFeatureFlagsV1::WIRE_SIZE);
        assert_eq!(&encoded[..4], &DatasetFeatureFlagsV1::MAGIC);
        assert_eq!(
            &encoded[DatasetFeatureFlagsV1::VERSION_OFFSET..DatasetFeatureFlagsV1::RESERVED_OFFSET],
            &DatasetFeatureFlagsV1::FORMAT_VERSION.to_le_bytes()
        );
        assert_eq!(
            &encoded[DatasetFeatureFlagsV1::COMPAT_ROOT_OFFSET
                ..DatasetFeatureFlagsV1::RO_COMPAT_ROOT_OFFSET],
            &[0x11; FeatureTreeRootKeyV1::WIRE_SIZE]
        );
        assert_eq!(DatasetFeatureFlagsV1::decode(&encoded), Ok(flags));
    }

    #[test]
    fn dataset_feature_flags_v1_rejects_noncurrent_records() {
        assert_eq!(
            DatasetFeatureFlagsV1::decode(&[0_u8; 24]),
            Err(DatasetFeatureFlagsDecodeError::InvalidSize { actual: 24 })
        );

        let mut encoded = DatasetFeatureFlagsV1::default().encode();
        encoded[0] ^= 0xff;
        assert_eq!(
            DatasetFeatureFlagsV1::decode(&encoded),
            Err(DatasetFeatureFlagsDecodeError::InvalidMagic)
        );

        let mut encoded = DatasetFeatureFlagsV1::default().encode();
        encoded[DatasetFeatureFlagsV1::VERSION_OFFSET..DatasetFeatureFlagsV1::RESERVED_OFFSET]
            .copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            DatasetFeatureFlagsV1::decode(&encoded),
            Err(DatasetFeatureFlagsDecodeError::UnsupportedVersion { version: 2 })
        );

        let mut encoded = DatasetFeatureFlagsV1::default().encode();
        encoded[DatasetFeatureFlagsV1::RESERVED_OFFSET..DatasetFeatureFlagsV1::COMPAT_ROOT_OFFSET]
            .copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(
            DatasetFeatureFlagsV1::decode(&encoded),
            Err(DatasetFeatureFlagsDecodeError::NonzeroReserved { value: 1 })
        );
    }
    // -- Feature prerequisites  ---------------------------------------------

    #[test]
    fn encryption_requires_checksum() {
        let enc = FeatureName::from_str(FEATURE_ENCRYPTION_CHACHA20).unwrap();
        let prereqs = get_feature_prerequisites(&enc);
        assert!(prereqs.is_some());
        assert_eq!(prereqs.unwrap(), &[FEATURE_CHECKSUM_BLAKE3]);
    }

    #[test]
    fn snapshot_requires_commit_group() {
        let snap = FeatureName::from_str(FEATURE_SNAPSHOT_V2).unwrap();
        let prereqs = get_feature_prerequisites(&snap);
        assert!(prereqs.is_some());
        assert_eq!(prereqs.unwrap(), &[FEATURE_COMMIT_GROUP_STATE_MACHINE]);
    }

    #[test]
    fn send_recv_requires_snapshot_and_checksum() {
        let send = FeatureName::from_str(FEATURE_SEND_RECV_V2).unwrap();
        let prereqs = get_feature_prerequisites(&send);
        assert!(prereqs.is_some());
        let p = prereqs.unwrap();
        assert!(p.contains(&FEATURE_SNAPSHOT_V2));
        assert!(p.contains(&FEATURE_CHECKSUM_BLAKE3));
    }

    #[test]
    fn posix_acl_has_no_prerequisites() {
        let acl = FeatureName::from_str(FEATURE_POSIX_ACL).unwrap();
        assert!(get_feature_prerequisites(&acl).is_none());
    }

    #[test]
    fn unknown_feature_has_no_prerequisites() {
        let unknown = FeatureName::from_str("com.example:custom").unwrap();
        assert!(get_feature_prerequisites(&unknown).is_none());
    }

    #[test]
    fn all_17_canonical_names_parse() {
        assert_eq!(CANONICAL_V1_FEATURES.len(), 17);
        for name in CANONICAL_V1_FEATURES {
            let n = FeatureName::from_str(name);
            assert!(n.is_some(), "canonical name '{name}' should parse");
            assert_eq!(n.unwrap().as_str(), *name);
        }
    }

    #[test]
    fn all_17_canonical_names_are_unique() {
        let mut seen: Vec<FeatureName> = Vec::new();
        for name in CANONICAL_V1_FEATURES {
            let n = FeatureName::from_str(name).unwrap();
            assert!(!seen.contains(&n), "duplicate canonical name: {name}");
            seen.push(n);
        }
    }

    // -- Feature class lookup -------------------------------------------------

    #[test]
    fn all_17_features_have_class() {
        assert_eq!(CANONICAL_FEATURE_CLASSES.len(), 17);
        for name in CANONICAL_V1_FEATURES {
            let n = FeatureName::from_str(name).unwrap();
            let class = get_feature_class(&n);
            assert!(
                class.is_some(),
                "canonical feature '{name}' must have a class"
            );
        }
    }

    #[test]
    fn feature_classes_match_rules() {
        // Incompat features
        assert_eq!(
            get_feature_class(&FeatureName::from_str(FEATURE_ENCRYPTION_CHACHA20).unwrap()),
            Some(FeatureClass::Incompat)
        );
        assert_eq!(
            get_feature_class(&FeatureName::from_str(FEATURE_EXTENT_MAP_V2).unwrap()),
            Some(FeatureClass::Incompat)
        );
        assert_eq!(
            get_feature_class(&FeatureName::from_str(FEATURE_SNAPSHOT_V2).unwrap()),
            Some(FeatureClass::Incompat)
        );
        // RoCompat features
        assert_eq!(
            get_feature_class(&FeatureName::from_str(FEATURE_COMPRESSION_ZSTD).unwrap()),
            Some(FeatureClass::RoCompat)
        );
        assert_eq!(
            get_feature_class(&FeatureName::from_str(FEATURE_CHECKSUM_BLAKE3).unwrap()),
            Some(FeatureClass::RoCompat)
        );
        assert_eq!(
            get_feature_class(&FeatureName::from_str(FEATURE_DEDUP).unwrap()),
            Some(FeatureClass::RoCompat)
        );
        // Compat features
        assert_eq!(
            get_feature_class(&FeatureName::from_str(FEATURE_POSIX_ACL).unwrap()),
            Some(FeatureClass::Compat)
        );
        assert_eq!(
            get_feature_class(&FeatureName::from_str(FEATURE_XATTR_SUPPORT).unwrap()),
            Some(FeatureClass::Compat)
        );
    }

    #[test]
    fn unknown_feature_has_no_class() {
        let unknown = FeatureName::from_str("com.example:custom").unwrap();
        assert_eq!(get_feature_class(&unknown), None);
    }

    #[test]
    fn every_canonical_name_has_a_class() {
        for name in CANONICAL_V1_FEATURES {
            let n = FeatureName::from_str(name).unwrap();
            let class = get_feature_class(&n);
            assert!(class.is_some(), "missing class for '{name}'");
        }
    }
}
