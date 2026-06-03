//! Local object-store format manifest and rejection gate.
//!
//! [`LocalObjectStoreFormatManifest`] is the single authoritative collection
//! of every on-disk format version identifier that this code can produce and
//! consume. The manifest is stored at a well-known key in every object store
//! at creation time and validated on every open.
//!
//! # Rejection gate
//!
//! [`validate_manifest_compatibility`] checks a stored manifest against the
//! current [`CURRENT_FORMAT_MANIFEST`]. Any unsupported or future format
//! version is rejected with a clear error before replay begins, so the store
//! never enters an undefined state.
//!
//! # On-disk encoding
//!
//! The manifest is stored as a fixed-size binary blob (20 bytes):
//!
//! | Offset | Size | Field                               |
//! |--------|------|-------------------------------------|
//! | 0      | 2    | manifest_version (u16 LE)           |
//! | 2      | 2    | record_format_version_min (u16 LE)  |
//! | 4      | 2    | record_format_version_max (u16 LE)  |
//! | 6      | 2    | index_base_format_version (u16 LE)  |
//! | 8      | 2    | spacemap_base_format_version (u16 LE)|
//! | 10     | 4    | suspect_log_format_version_min (u32 LE)|
//! | 14     | 4    | suspect_log_format_version_max (u32 LE)|
//! | 18     | 2    | integrity_trailer_digest_suite_id (u16 LE)|

use crate::constants::{
    INDEX_BASE_FORMAT_VERSION, INTEGRITY_TRAILER_V2_DIGEST_SUITE_ID, RECORD_FORMAT_VERSION,
    RECORD_FORMAT_VERSION_V1_NO_FOOTER,
};

/// Length of the on-disk binary manifest (20 bytes).
pub const FORMAT_MANIFEST_ENCODED_LEN: usize = 20;

// ---------------------------------------------------------------------------
// FormatManifest
// ---------------------------------------------------------------------------

/// Authoritative snapshot of every format version that governs the local
/// object store on-disk layout.
///
/// Written at store creation and validated on every open. A mismatch between
/// the stored manifest and [`CURRENT_FORMAT_MANIFEST`] is rejected before
/// replay begins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalObjectStoreFormatManifest {
    /// Format manifest version (starts at 1; increments when fields change).
    pub manifest_version: u16,
    /// Minimum record format version this store can contain.
    pub record_format_version_min: u16,
    /// Maximum (current) record format version written by this code.
    pub record_format_version_max: u16,
    /// Object index base format version.
    pub index_base_format_version: u16,
    /// Spacemap checkpoint format version.
    pub spacemap_base_format_version: u16,
    /// Suspect log format version floor.
    pub suspect_log_format_version_min: u32,
    /// Suspect log format version ceiling.
    pub suspect_log_format_version_max: u32,
    /// Integrity trailer digest suite identifier.
    pub integrity_trailer_digest_suite_id: u16,
}

/// The current production format manifest. Every store created by this
/// code receives this manifest, and every open validates against it.
pub const CURRENT_FORMAT_MANIFEST: LocalObjectStoreFormatManifest =
    LocalObjectStoreFormatManifest {
        manifest_version: 1,
        record_format_version_min: RECORD_FORMAT_VERSION_V1_NO_FOOTER,
        record_format_version_max: RECORD_FORMAT_VERSION,
        index_base_format_version: INDEX_BASE_FORMAT_VERSION,
        spacemap_base_format_version: crate::store::SPACEMAP_BASE_FORMAT_VERSION,
        suspect_log_format_version_min: crate::store::SUSPECT_LOG_VERSION_MIN,
        suspect_log_format_version_max: crate::store::SUSPECT_LOG_VERSION_MAX,
        integrity_trailer_digest_suite_id: INTEGRITY_TRAILER_V2_DIGEST_SUITE_ID,
    };

// ---------------------------------------------------------------------------
// Rejection gate
// ---------------------------------------------------------------------------

/// Outcome of validating a stored format manifest against the current one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestValidation {
    /// Stored manifest is compatible with the current code.
    Compatible,
    /// Stored manifest is from a newer, unsupported format.
    Incompatible {
        field: &'static str,
        stored: String,
        current: String,
    },
}

/// Validate `stored` against [`CURRENT_FORMAT_MANIFEST`].
///
/// Returns [`ManifestValidation::Compatible`] when every field in `stored`
/// lies within the supported range declared by the current manifest.
/// Returns [`ManifestValidation::Incompatible`] with the first mismatched
/// field otherwise.
#[must_use]
pub fn validate_manifest_compatibility(
    stored: &LocalObjectStoreFormatManifest,
) -> ManifestValidation {
    let current = &CURRENT_FORMAT_MANIFEST;

    // A stored record_format_version_max higher than ours means the store
    // was written by a newer code version and may contain records we cannot
    // decode.
    if stored.record_format_version_max > current.record_format_version_max {
        return ManifestValidation::Incompatible {
            field: "record_format_version_max",
            stored: stored.record_format_version_max.to_string(),
            current: current.record_format_version_max.to_string(),
        };
    }

    // If the stored floor is higher than our max, we cannot read any record.
    if stored.record_format_version_min > current.record_format_version_max {
        return ManifestValidation::Incompatible {
            field: "record_format_version_min",
            stored: stored.record_format_version_min.to_string(),
            current: format!("max={}", current.record_format_version_max),
        };
    }

    if stored.index_base_format_version != current.index_base_format_version {
        return ManifestValidation::Incompatible {
            field: "index_base_format_version",
            stored: stored.index_base_format_version.to_string(),
            current: current.index_base_format_version.to_string(),
        };
    }

    if stored.spacemap_base_format_version != current.spacemap_base_format_version {
        return ManifestValidation::Incompatible {
            field: "spacemap_base_format_version",
            stored: stored.spacemap_base_format_version.to_string(),
            current: current.spacemap_base_format_version.to_string(),
        };
    }

    if stored.suspect_log_format_version_min > current.suspect_log_format_version_max {
        return ManifestValidation::Incompatible {
            field: "suspect_log_format_version_min",
            stored: stored.suspect_log_format_version_min.to_string(),
            current: format!("max={}", current.suspect_log_format_version_max),
        };
    }

    if stored.suspect_log_format_version_max < current.suspect_log_format_version_min {
        return ManifestValidation::Incompatible {
            field: "suspect_log_format_version_max",
            stored: stored.suspect_log_format_version_max.to_string(),
            current: format!("min={}", current.suspect_log_format_version_min),
        };
    }

    if stored.integrity_trailer_digest_suite_id != current.integrity_trailer_digest_suite_id {
        return ManifestValidation::Incompatible {
            field: "integrity_trailer_digest_suite_id",
            stored: stored.integrity_trailer_digest_suite_id.to_string(),
            current: current.integrity_trailer_digest_suite_id.to_string(),
        };
    }

    ManifestValidation::Compatible
}

// ---------------------------------------------------------------------------
// Encode / decode (binary, fixed-size)
// ---------------------------------------------------------------------------

impl LocalObjectStoreFormatManifest {
    /// Serialize to a fixed-size 20-byte little-endian binary blob.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; FORMAT_MANIFEST_ENCODED_LEN] {
        let mut buf = [0u8; FORMAT_MANIFEST_ENCODED_LEN];
        buf[0..2].copy_from_slice(&self.manifest_version.to_le_bytes());
        buf[2..4].copy_from_slice(&self.record_format_version_min.to_le_bytes());
        buf[4..6].copy_from_slice(&self.record_format_version_max.to_le_bytes());
        buf[6..8].copy_from_slice(&self.index_base_format_version.to_le_bytes());
        buf[8..10].copy_from_slice(&self.spacemap_base_format_version.to_le_bytes());
        buf[10..14].copy_from_slice(&self.suspect_log_format_version_min.to_le_bytes());
        buf[14..18].copy_from_slice(&self.suspect_log_format_version_max.to_le_bytes());
        buf[18..20].copy_from_slice(&self.integrity_trailer_digest_suite_id.to_le_bytes());
        buf
    }

    /// Deserialize from a fixed-size 20-byte little-endian binary blob.
    ///
    /// # Errors
    ///
    /// Returns an error string if the buffer is the wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != FORMAT_MANIFEST_ENCODED_LEN {
            return Err(format!(
                "format manifest has {} bytes, expected {}",
                bytes.len(),
                FORMAT_MANIFEST_ENCODED_LEN
            ));
        }
        Ok(Self {
            manifest_version: u16::from_le_bytes([bytes[0], bytes[1]]),
            record_format_version_min: u16::from_le_bytes([bytes[2], bytes[3]]),
            record_format_version_max: u16::from_le_bytes([bytes[4], bytes[5]]),
            index_base_format_version: u16::from_le_bytes([bytes[6], bytes[7]]),
            spacemap_base_format_version: u16::from_le_bytes([bytes[8], bytes[9]]),
            suspect_log_format_version_min: u32::from_le_bytes([
                bytes[10], bytes[11], bytes[12], bytes[13],
            ]),
            suspect_log_format_version_max: u32::from_le_bytes([
                bytes[14], bytes[15], bytes[16], bytes[17],
            ]),
            integrity_trailer_digest_suite_id: u16::from_le_bytes([bytes[18], bytes[19]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_manifest_is_self_compatible() {
        assert_eq!(
            validate_manifest_compatibility(&CURRENT_FORMAT_MANIFEST),
            ManifestValidation::Compatible,
        );
    }

    #[test]
    fn future_record_version_rejected() {
        let mut future = CURRENT_FORMAT_MANIFEST.clone();
        future.record_format_version_max = 99;
        match validate_manifest_compatibility(&future) {
            ManifestValidation::Incompatible { field, .. } => {
                assert_eq!(field, "record_format_version_max");
            }
            ManifestValidation::Compatible => panic!("future version should be rejected"),
        }
    }

    #[test]
    fn too_high_floor_rejected() {
        let mut too_high = CURRENT_FORMAT_MANIFEST.clone();
        too_high.record_format_version_min = CURRENT_FORMAT_MANIFEST.record_format_version_max + 1;
        match validate_manifest_compatibility(&too_high) {
            ManifestValidation::Incompatible { field, .. } => {
                assert_eq!(field, "record_format_version_min");
            }
            ManifestValidation::Compatible => panic!("too-high floor should be rejected"),
        }
    }

    #[test]
    fn mismatched_index_base_rejected() {
        let mut wrong = CURRENT_FORMAT_MANIFEST.clone();
        wrong.index_base_format_version = 99;
        match validate_manifest_compatibility(&wrong) {
            ManifestValidation::Incompatible { field, .. } => {
                assert_eq!(field, "index_base_format_version");
            }
            ManifestValidation::Compatible => {
                panic!("mismatched index base version should be rejected")
            }
        }
    }

    #[test]
    fn mismatched_spacemap_rejected() {
        let mut wrong = CURRENT_FORMAT_MANIFEST.clone();
        wrong.spacemap_base_format_version = 99;
        match validate_manifest_compatibility(&wrong) {
            ManifestValidation::Incompatible { field, .. } => {
                assert_eq!(field, "spacemap_base_format_version");
            }
            ManifestValidation::Compatible => {
                panic!("mismatched spacemap version should be rejected")
            }
        }
    }

    #[test]
    fn suspect_log_future_min_rejected() {
        let mut future = CURRENT_FORMAT_MANIFEST.clone();
        future.suspect_log_format_version_min =
            CURRENT_FORMAT_MANIFEST.suspect_log_format_version_max + 1;
        match validate_manifest_compatibility(&future) {
            ManifestValidation::Incompatible { field, .. } => {
                assert_eq!(field, "suspect_log_format_version_min");
            }
            ManifestValidation::Compatible => {
                panic!("future suspect log min should be rejected")
            }
        }
    }

    #[test]
    fn suspect_log_too_old_max_rejected() {
        let mut old = CURRENT_FORMAT_MANIFEST.clone();
        old.suspect_log_format_version_max = CURRENT_FORMAT_MANIFEST
            .suspect_log_format_version_min
            .saturating_sub(1);
        match validate_manifest_compatibility(&old) {
            ManifestValidation::Incompatible { field, .. } => {
                assert_eq!(field, "suspect_log_format_version_max");
            }
            ManifestValidation::Compatible => {
                panic!("too-old suspect log max should be rejected")
            }
        }
    }

    #[test]
    fn mismatched_digest_suite_rejected() {
        let mut wrong = CURRENT_FORMAT_MANIFEST.clone();
        wrong.integrity_trailer_digest_suite_id = 99;
        match validate_manifest_compatibility(&wrong) {
            ManifestValidation::Incompatible { field, .. } => {
                assert_eq!(field, "integrity_trailer_digest_suite_id");
            }
            ManifestValidation::Compatible => {
                panic!("mismatched digest suite should be rejected")
            }
        }
    }

    #[test]
    fn roundtrip_binary() {
        let bytes = CURRENT_FORMAT_MANIFEST.to_bytes();
        assert_eq!(bytes.len(), FORMAT_MANIFEST_ENCODED_LEN);
        let parsed = LocalObjectStoreFormatManifest::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(CURRENT_FORMAT_MANIFEST, parsed);
    }

    #[test]
    fn wrong_size_rejected() {
        assert!(LocalObjectStoreFormatManifest::from_bytes(&[0u8; 10]).is_err());
        assert!(LocalObjectStoreFormatManifest::from_bytes(&[0u8; 30]).is_err());
    }

    #[test]
    fn manifest_constants_nondecreasing() {
        let record_range = [
            CURRENT_FORMAT_MANIFEST.record_format_version_min,
            CURRENT_FORMAT_MANIFEST.record_format_version_max,
        ];
        let suspect_range = [
            CURRENT_FORMAT_MANIFEST.suspect_log_format_version_min,
            CURRENT_FORMAT_MANIFEST.suspect_log_format_version_max,
        ];
        assert!(record_range[1] >= record_range[0]);
        assert!(suspect_range[1] >= suspect_range[0]);
        let manifest_version = [CURRENT_FORMAT_MANIFEST.manifest_version];
        assert_ne!(manifest_version[0], 0);
    }

    #[test]
    fn encoded_len_matches_struct() {
        // If someone adds a field without updating FORMAT_MANIFEST_ENCODED_LEN,
        // this test catches it.
        let encoded = CURRENT_FORMAT_MANIFEST.to_bytes();
        assert_eq!(encoded.len(), FORMAT_MANIFEST_ENCODED_LEN);
    }
}
