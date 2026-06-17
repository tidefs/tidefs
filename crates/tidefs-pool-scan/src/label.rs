//! Pool device label reader with configurable label region offsets and
//! explicit BLAKE3-256 checksum verification.
//!
//! Provides [`PoolScanConfig`] for scan configuration, [`LabelReadOutcome`]
//! for detailed label-read results, and [`LabelReader`] for reading and
//! validating TideFS pool labels from block devices.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use tidefs_types_pool_label_core::{
    decode_label, verify_label_checksum, LabelError, PoolLabelV1, POOL_LABEL_MAGIC,
    POOL_LABEL_SIZE, POOL_LABEL_V1_EXT_WIRE_SIZE,
};

// ---------------------------------------------------------------------------
// PoolScanConfig
// ---------------------------------------------------------------------------

/// Configuration for a pool device scan.
///
/// Specifies which devices to scan, where to look for labels on each
/// device, and how to handle errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolScanConfig {
    /// Block device paths to scan.
    pub device_paths: Vec<PathBuf>,
    /// Byte offset of label copy 0 (primary).  Default: 0.
    pub label0_offset: u64,
    /// Byte offset of label copy 1 (backup).
    ///
    /// When `None`, the reader calculates `device_size - label_area_bytes`
    /// at runtime for each device.  When `Some(offset)`, that offset is
    /// used for every device (useful for testing or fixed-layout pools).
    pub label1_offset: Option<u64>,
    /// Size in bytes of each label region.  Default: [`POOL_LABEL_SIZE`]
    /// (256 KiB).
    pub label_area_bytes: u64,
}

impl PoolScanConfig {
    /// Create a configuration that scans `device_paths` using
    /// standard label locations (offset 0 and end-of-device).
    #[must_use]
    pub fn new(device_paths: Vec<PathBuf>) -> Self {
        Self {
            device_paths,
            label0_offset: 0,
            label1_offset: None,
            label_area_bytes: POOL_LABEL_SIZE as u64,
        }
    }

    /// Set explicit offsets for both label copies.
    #[must_use]
    pub fn with_label_offsets(mut self, label0: u64, label1: u64) -> Self {
        self.label0_offset = label0;
        self.label1_offset = Some(label1);
        self
    }

    /// Set the label area size (default 256 KiB).
    #[must_use]
    pub fn with_label_area(mut self, bytes: u64) -> Self {
        self.label_area_bytes = bytes;
        self
    }

    /// Returns `true` if the config has at least one device path.
    #[must_use]
    pub fn has_devices(&self) -> bool {
        !self.device_paths.is_empty()
    }
}

impl Default for PoolScanConfig {
    fn default() -> Self {
        Self {
            device_paths: Vec::new(),
            label0_offset: 0,
            label1_offset: None,
            label_area_bytes: POOL_LABEL_SIZE as u64,
        }
    }
}

// ---------------------------------------------------------------------------
// LabelReadOutcome
// ---------------------------------------------------------------------------

/// The result of attempting to read and validate a pool label from a
/// single label region on a device.
#[derive(Clone, Debug)]
pub enum LabelReadOutcome {
    /// A valid TideFS pool label was found, decoded, and passed BLAKE3
    /// checksum verification.
    Valid(Box<PoolLabelV1>),
    /// No TideFS label is present at this location (magic bytes do not
    /// match).
    NoLabel,
    /// A label was found (magic bytes match) but the label is corrupt:
    /// BLAKE3 checksum mismatch, invalid field values, or unreadable.
    Corrupted {
        /// Human-readable reason describing what failed.
        reason: String,
        /// The underlying error kind, if available.
        error_kind: LabelErrorKind,
    },
}

/// Categorisation of a label corruption error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelErrorKind {
    /// BLAKE3-256 checksum did not match the computed hash.
    ChecksumMismatch,
    /// One or more fields were out of range (e.g. bad pool state or device
    /// class).
    BadField,
    /// Unsupported label format version.
    UnsupportedVersion,
    /// Other decode error not covered above.
    Other,
}

impl std::fmt::Display for LabelErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChecksumMismatch => f.write_str("checksum-mismatch"),
            Self::BadField => f.write_str("bad-field"),
            Self::UnsupportedVersion => f.write_str("unsupported-version"),
            Self::Other => f.write_str("other"),
        }
    }
}

impl From<&LabelError> for LabelErrorKind {
    fn from(e: &LabelError) -> Self {
        match e {
            LabelError::ChecksumMismatch => Self::ChecksumMismatch,
            LabelError::BadMagic => Self::Other,
            LabelError::BufferTooSmall => Self::Other,
            LabelError::UnsupportedVersion(_) => Self::UnsupportedVersion,
            LabelError::BadPoolState(_)
            | LabelError::BadDeviceClass(_)
            | LabelError::BadRedundancyPolicy { .. } => Self::BadField,
            LabelError::NameTooLong => Self::BadField,
            LabelError::LastDevice => Self::Other,
        }
    }
}

impl LabelReadOutcome {
    /// Returns `true` if a valid label was found.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_))
    }

    /// Returns the parsed label if valid, otherwise `None`.
    #[must_use]
    pub fn label(&self) -> Option<&PoolLabelV1> {
        match self {
            Self::Valid(l) => Some(l),
            _ => None,
        }
    }

    /// Returns the pool GUID if a valid label was found.
    #[must_use]
    pub fn pool_guid(&self) -> Option<[u8; 16]> {
        self.label().map(|l| l.pool_guid)
    }

    /// Returns the device GUID if a valid label was found.
    #[must_use]
    pub fn device_guid(&self) -> Option<[u8; 16]> {
        self.label().map(|l| l.device_guid)
    }
}

impl std::fmt::Display for LabelReadOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid(l) => write!(
                f,
                "valid label: pool='{}' device_index={}",
                l.pool_name_str(),
                l.device_index
            ),
            Self::NoLabel => f.write_str("no label"),
            Self::Corrupted { reason, .. } => write!(f, "corrupted: {reason}"),
        }
    }
}

// ---------------------------------------------------------------------------
// LabelReader
// ---------------------------------------------------------------------------

/// Reads and validates TideFS pool labels from block devices according to
/// a [`PoolScanConfig`].
///
/// Tries label copy 0 at the configured offset, then label copy 1.  For
/// each candidate region, the reader:
///
/// 1. Seeks to the offset and reads the wire-format bytes.
/// 2. Checks for [`POOL_LABEL_MAGIC`].
/// 3. Decodes the label (field validation).
/// 4. Verifies the BLAKE3-256 checksum over the label payload.
///
/// The outcome is reported as a [`LabelReadOutcome`] that distinguishes
/// missing labels from corrupted ones.
#[derive(Clone, Debug)]
pub struct LabelReader {
    config: PoolScanConfig,
}

impl LabelReader {
    /// Create a new reader from scan configuration.
    #[must_use]
    pub fn new(config: PoolScanConfig) -> Self {
        Self { config }
    }

    /// Return a reference to the configuration.
    #[must_use]
    pub fn config(&self) -> &PoolScanConfig {
        &self.config
    }

    // ------------------------------------------------------------------
    // Public read API
    // ------------------------------------------------------------------

    /// Read and validate the pool label from `device_path`.
    ///
    /// Returns [`LabelReadOutcome::Valid`] when both magic and BLAKE3
    /// checksum pass, [`LabelReadOutcome::NoLabel`] when no TideFS label
    /// is present, or [`LabelReadOutcome::Corrupted`] when a label is
    /// found but fails validation.
    pub fn read_label(&self, device_path: &Path) -> LabelReadOutcome {
        let file = match std::fs::File::open(device_path) {
            Ok(f) => f,
            Err(e) => {
                return LabelReadOutcome::Corrupted {
                    reason: format!("cannot open device: {e}"),
                    error_kind: LabelErrorKind::Other,
                };
            }
        };

        self.read_label_from_file(file, device_path)
    }

    /// Scan all device paths in the config and return per-device results.
    ///
    /// Devices that cannot be opened are reported as
    /// [`LabelReadOutcome::Corrupted`].
    #[must_use]
    pub fn scan_all(&self) -> Vec<(PathBuf, LabelReadOutcome)> {
        self.config
            .device_paths
            .iter()
            .map(|p| (p.clone(), self.read_label(p)))
            .collect()
    }

    /// Scan all devices and return only valid labels paired with their
    /// device paths.
    #[must_use]
    pub fn scan_valid_labels(&self) -> Vec<(PathBuf, PoolLabelV1)> {
        self.scan_all()
            .into_iter()
            .filter_map(|(path, outcome)| match outcome {
                LabelReadOutcome::Valid(label) => Some((path, *label)),
                _ => None,
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // Explicit BLAKE3 checksum validation
    // ------------------------------------------------------------------

    /// Verify the BLAKE3-256 checksum of an already-decoded label.
    ///
    /// Returns `true` if the label's stored checksum matches a freshly
    /// computed BLAKE3 hash over the label fields.
    #[must_use]
    pub fn validate_checksum(label: &PoolLabelV1) -> bool {
        verify_label_checksum(label)
    }

    /// Compute a standalone BLAKE3-256 checksum over raw label bytes
    /// and compare against the bytes at `checksum_offset`.
    ///
    /// `buf` must be at least `checksum_end` bytes long.  The checksum
    /// is computed over `buf[0..checksum_offset]`.  Returns `true` when
    /// the stored checksum at `buf[checksum_offset..checksum_end]`
    /// matches the computed hash.
    #[must_use]
    pub fn verify_raw_checksum(buf: &[u8], checksum_offset: usize, checksum_end: usize) -> bool {
        if buf.len() < checksum_end || checksum_offset > checksum_end {
            return false;
        }
        let stored: &[u8; 32] = match buf[checksum_offset..checksum_end].try_into() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let mut hasher = blake3::Hasher::new();
        hasher.update(&buf[0..checksum_offset]);
        let computed = hasher.finalize();
        computed.as_bytes() == stored
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn read_label_from_file(
        &self,
        mut file: std::fs::File,
        _device_path: &Path,
    ) -> LabelReadOutcome {
        let size = match file.seek(SeekFrom::End(0)) {
            Ok(s) => s,
            Err(e) => {
                return LabelReadOutcome::Corrupted {
                    reason: format!("seek to end failed: {e}"),
                    error_kind: LabelErrorKind::Other,
                };
            }
        };

        // Try label copy 0.
        let outcome0 = self.try_read_at(&mut file, self.config.label0_offset);
        if !matches!(outcome0, LabelReadOutcome::NoLabel) {
            return outcome0;
        }

        // Try label copy 1.
        let label1_offset = self
            .config
            .label1_offset
            .unwrap_or_else(|| size.saturating_sub(self.config.label_area_bytes));

        if label1_offset > 0 && label1_offset != self.config.label0_offset {
            return self.try_read_at(&mut file, label1_offset);
        }

        outcome0
    }

    fn try_read_at(&self, file: &mut std::fs::File, offset: u64) -> LabelReadOutcome {
        if file.seek(SeekFrom::Start(offset)).is_err() {
            return LabelReadOutcome::NoLabel;
        }

        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        if file.read_exact(&mut buf).is_err() {
            return LabelReadOutcome::NoLabel;
        }

        // Quick magic check.
        let magic: [u8; 4] = match buf[0..4].try_into() {
            Ok(m) => m,
            Err(_) => return LabelReadOutcome::NoLabel,
        };

        if magic != POOL_LABEL_MAGIC {
            return LabelReadOutcome::NoLabel;
        }

        // Attempt full decode (includes BLAKE3 checksum verification).
        match decode_label(&buf) {
            Ok(label) => {
                // Double-check with standalone BLAKE3 verification.
                // The decode_label function already verified, but we
                // provide a second explicit check for callers that want
                // to be certain.
                if !Self::validate_checksum(&label) {
                    return LabelReadOutcome::Corrupted {
                        reason: "BLAKE3 checksum mismatch (post-decode verification)".into(),
                        error_kind: LabelErrorKind::ChecksumMismatch,
                    };
                }
                LabelReadOutcome::Valid(Box::new(label))
            }
            Err(e) => {
                let reason = e.to_string();
                let error_kind = LabelErrorKind::from(&e);
                LabelReadOutcome::Corrupted { reason, error_kind }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience: validate pool membership across devices
// ---------------------------------------------------------------------------

/// Which pool member identity field was duplicated across devices.
///
/// Used by [`MembershipError::DuplicateMemberIdentity`] to distinguish
/// duplicate device GUIDs from duplicate device indices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DuplicateIdentityKind {
    /// Duplicate device GUID — two distinct physical devices claim the
    /// same `device_guid`.
    DeviceGuid,
    /// Duplicate device index — two distinct physical devices claim the
    /// same `device_index` within the pool topology.
    DeviceIndex,
}

impl std::fmt::Display for DuplicateIdentityKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeviceGuid => f.write_str("device GUID"),
            Self::DeviceIndex => f.write_str("device index"),
        }
    }
}

/// Error returned when pool membership validation fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MembershipError {
    /// No valid labels were found on any device.
    NoValidLabels,
    /// Devices belong to different pools.
    PoolGuidMismatch {
        /// The expected pool GUID (first valid label encountered).
        expected: [u8; 16],
        /// The conflicting pool GUID found on another device.
        found: [u8; 16],
        /// Path of the device with the conflicting GUID.
        device_path: PathBuf,
    },
    /// Two or more distinct physical devices claim the same pool member
    /// identity.  This is a hard import block: a pool must not assemble
    /// topology from ambiguous members because duplicate identity can
    /// hide stale replicas, wrong-device imports, or a split view of the
    /// same physical media.
    DuplicateMemberIdentity {
        /// Which identity was duplicated.
        kind: DuplicateIdentityKind,
        /// Human-readable representation of the duplicate value (GUID hex
        /// string for device GUID, decimal integer for device index).
        identity_value: String,
        /// Every observation of the duplicate identity, as
        /// `(canonical_device_path, label_detail)` pairs.
        observations: Vec<(PathBuf, String)>,
    },
    /// A device has a label that failed BLAKE3 checksum verification.
    CorruptedLabel {
        device_path: PathBuf,
        reason: String,
    },
}

impl std::fmt::Display for MembershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoValidLabels => f.write_str("no valid TideFS labels found on any device"),
            Self::PoolGuidMismatch {
                expected,
                found,
                device_path,
            } => write!(
                f,
                "pool GUID mismatch on {}: expected {}, found {}",
                device_path.display(),
                hex_fmt(expected),
                hex_fmt(found),
            ),
            Self::DuplicateMemberIdentity {
                kind,
                identity_value,
                observations,
            } => {
                write!(
                    f,
                    "duplicate {} identity \"{}\" observed on {} distinct device(s): ",
                    kind,
                    identity_value,
                    observations.len()
                )?;
                for (i, (path, detail)) in observations.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{} ({})", path.display(), detail)?;
                }
                Ok(())
            }
            Self::CorruptedLabel {
                device_path,
                reason,
            } => write!(f, "corrupted label on {}: {reason}", device_path.display()),
        }
    }
}

fn hex_fmt(bytes: &[u8; 16]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

/// Validate that all scanned devices belong to the same pool.
///
/// Reads labels from all devices in `config`, checks that each valid
/// label shares the same `pool_guid`, rejects duplicate member
/// identities (same `device_guid` or `device_index` on distinct
/// physical devices), and reports any corrupted labels.
///
/// A repeated scan of the same canonical device path is tolerated
/// (benign duplicate); two different paths with the same authority
/// identity are treated as a hard import block.
///
/// Returns the common pool GUID on success.  Fails with
/// [`MembershipError::DuplicateMemberIdentity`] when distinct
/// physical devices claim the same member identity.
pub fn validate_pool_membership(reader: &LabelReader) -> Result<[u8; 16], MembershipError> {
    use std::collections::BTreeMap;

    let results = reader.scan_all();

    let mut pool_guid: Option<[u8; 16]> = None;
    // Track observations of each device GUID / index for duplicate
    // detection.  Keyed by identity value; each entry is a list of
    // `(canonical_path, label_detail)` pairs.
    let mut seen_guids: BTreeMap<[u8; 16], Vec<(PathBuf, String)>> = BTreeMap::new();
    let mut seen_indices: BTreeMap<u32, Vec<(PathBuf, String)>> = BTreeMap::new();

    for (device_path, outcome) in &results {
        match outcome {
            LabelReadOutcome::Valid(label) => {
                // Resolve a canonical filesystem path so that repeated
                // scans of the same device node (e.g. /dev/sda vs
                // /dev/disk/by-id/...) are not misclassified as
                // duplicates.  Fall back to the raw path when
                // canonicalization fails (e.g. test fixtures on
                // synthetic filesystems).
                let canonical = canonicalize_or_identity(device_path);

                match pool_guid {
                    None => pool_guid = Some(label.pool_guid),
                    Some(expected) => {
                        if label.pool_guid != expected {
                            return Err(MembershipError::PoolGuidMismatch {
                                expected,
                                found: label.pool_guid,
                                device_path: device_path.clone(),
                            });
                        }
                    }
                }

                seen_guids.entry(label.device_guid).or_default().push((
                    canonical.clone(),
                    format!("device_index={}", label.device_index),
                ));
                seen_indices.entry(label.device_index).or_default().push((
                    canonical,
                    format!("device_guid={}", hex_fmt(&label.device_guid)),
                ));
            }
            LabelReadOutcome::Corrupted { reason, .. } => {
                return Err(MembershipError::CorruptedLabel {
                    device_path: device_path.clone(),
                    reason: reason.clone(),
                });
            }
            LabelReadOutcome::NoLabel => {
                // Devices without labels are skipped (they may be
                // uninitialized spares).
            }
        }
    }

    // Reject duplicate device GUIDs observed on distinct canonical paths.
    for (guid, observations) in &seen_guids {
        if distinct_canonical_paths(observations) {
            return Err(MembershipError::DuplicateMemberIdentity {
                kind: DuplicateIdentityKind::DeviceGuid,
                identity_value: hex_fmt(guid),
                observations: observations.clone(),
            });
        }
    }

    // Reject duplicate device indices observed on distinct canonical paths.
    for (index, observations) in &seen_indices {
        if distinct_canonical_paths(observations) {
            return Err(MembershipError::DuplicateMemberIdentity {
                kind: DuplicateIdentityKind::DeviceIndex,
                identity_value: index.to_string(),
                observations: observations.clone(),
            });
        }
    }

    pool_guid.ok_or(MembershipError::NoValidLabels)
}

/// Resolve `path` to a canonical, absolute path.
///
/// Returns the raw `path` unchanged when canonicalization fails (e.g.
/// synthetic test fixtures or missing device nodes).
fn canonicalize_or_identity(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// Returns `true` when `observations` refers to more than one distinct
/// canonical device path (i.e. the same identity was seen on at least
/// two different physical devices).
fn distinct_canonical_paths(observations: &[(PathBuf, String)]) -> bool {
    let paths: std::collections::BTreeSet<&PathBuf> =
        observations.iter().map(|(p, _)| p).collect();
    paths.len() > 1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};
    use tidefs_types_pool_label_core::{
        encode_label, seal_label, DeviceClass, PoolState, POOL_LABEL_V1_CHECKSUM_OFFSET,
    };

    // -- Helpers --

    /// Build a valid, sealed test label for the given pool name.
    fn make_label(pool_name: &str) -> PoolLabelV1 {
        let pool_guid = [0xABu8; 16];
        let device_guid = [0xCDu8; 16];
        let label = PoolLabelV1::new(pool_guid, device_guid, pool_name);
        seal_label(label).unwrap()
    }

    /// Write `label` at offset 0 of a new file in `dir`.
    fn write_label_file(dir: &tempfile::TempDir, name: &str, label: &PoolLabelV1) -> PathBuf {
        let path = dir.path().join(name);
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(label, &mut buf).unwrap();
        std::fs::write(&path, buf).unwrap();
        path
    }

    /// Write `label` at `offset` in a file, extending the file as needed.
    fn write_label_at(
        dir: &tempfile::TempDir,
        name: &str,
        label: &PoolLabelV1,
        offset: u64,
    ) -> PathBuf {
        let path = dir.path().join(name);
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(label, &mut buf).unwrap();
        let end = offset + POOL_LABEL_SIZE as u64;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.set_len(end).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&buf).unwrap();
        path
    }

    // -- PoolScanConfig tests --

    #[test]
    fn config_defaults() {
        let cfg = PoolScanConfig::default();
        assert!(cfg.device_paths.is_empty());
        assert_eq!(cfg.label0_offset, 0);
        assert!(cfg.label1_offset.is_none());
        assert_eq!(cfg.label_area_bytes, POOL_LABEL_SIZE as u64);
        assert!(!cfg.has_devices());
    }

    #[test]
    fn config_with_devices() {
        let paths = vec![PathBuf::from("/dev/sda"), PathBuf::from("/dev/sdb")];
        let cfg = PoolScanConfig::new(paths);
        assert!(cfg.has_devices());
        assert_eq!(cfg.device_paths.len(), 2);
    }

    #[test]
    fn config_custom_offsets() {
        let cfg = PoolScanConfig::new(vec![])
            .with_label_offsets(4096, 8192)
            .with_label_area(128 * 1024);
        assert_eq!(cfg.label0_offset, 4096);
        assert_eq!(cfg.label1_offset, Some(8192));
        assert_eq!(cfg.label_area_bytes, 128 * 1024);
    }

    // -- LabelReadOutcome tests --

    #[test]
    fn outcome_is_valid() {
        let label = make_label("test");
        let outcome = LabelReadOutcome::Valid(Box::new(label));
        assert!(outcome.is_valid());
        assert!(outcome.label().is_some());
    }

    #[test]
    fn outcome_no_label() {
        let outcome = LabelReadOutcome::NoLabel;
        assert!(!outcome.is_valid());
        assert!(outcome.label().is_none());
    }

    #[test]
    fn outcome_corrupted() {
        let outcome = LabelReadOutcome::Corrupted {
            reason: "test failure".into(),
            error_kind: LabelErrorKind::ChecksumMismatch,
        };
        assert!(!outcome.is_valid());
        assert!(outcome.label().is_none());
        assert_eq!(format!("{outcome}"), "corrupted: test failure");
    }

    #[test]
    fn outcome_pool_guid() {
        let label = make_label("mypool");
        let outcome = LabelReadOutcome::Valid(Box::new(label.clone()));
        assert_eq!(outcome.pool_guid(), Some([0xABu8; 16]));
        assert_eq!(outcome.device_guid(), Some([0xCDu8; 16]));
    }

    // -- LabelReadOutcome Display --

    #[test]
    fn outcome_display_valid() {
        let label = make_label("displaypool");
        let outcome = LabelReadOutcome::Valid(Box::new(label));
        assert!(format!("{outcome}").starts_with("valid label"));
    }

    #[test]
    fn outcome_display_no_label() {
        assert_eq!(format!("{}", LabelReadOutcome::NoLabel), "no label");
    }

    // -- LabelErrorKind Display --

    #[test]
    fn error_kind_display() {
        assert_eq!(
            format!("{}", LabelErrorKind::ChecksumMismatch),
            "checksum-mismatch"
        );
        assert_eq!(format!("{}", LabelErrorKind::BadField), "bad-field");
        assert_eq!(
            format!("{}", LabelErrorKind::UnsupportedVersion),
            "unsupported-version"
        );
        assert_eq!(format!("{}", LabelErrorKind::Other), "other");
    }

    // -- LabelReader: valid label --

    #[test]
    fn read_valid_label() {
        let dir = tempfile::tempdir().unwrap();
        let label = make_label("validpool");
        let path = write_label_file(&dir, "dev0", &label);

        let cfg = PoolScanConfig::new(vec![path.clone()]);
        let reader = LabelReader::new(cfg);

        let outcome = reader.read_label(&path);
        assert!(outcome.is_valid(), "expected valid label, got {outcome:?}");
        let parsed = outcome.label().unwrap();
        assert_eq!(parsed.pool_guid, [0xABu8; 16]);
        assert_eq!(parsed.device_guid, [0xCDu8; 16]);
        assert_eq!(parsed.pool_name_str(), "validpool");
    }

    // -- LabelReader: no label (missing magic) --

    #[test]
    fn read_no_label() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain");
        std::fs::write(&path, b"not a TideFS label").unwrap();

        let cfg = PoolScanConfig::new(vec![path.clone()]);
        let reader = LabelReader::new(cfg);

        let outcome = reader.read_label(&path);
        assert!(matches!(outcome, LabelReadOutcome::NoLabel));
    }

    // -- LabelReader: corrupted checksum --

    #[test]
    fn read_corrupted_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let label = make_label("corrupt");
        let path = write_label_file(&dir, "bad", &label);

        // Bit-flip a byte in the data region (not the magic).
        let mut data = std::fs::read(&path).unwrap();
        data[42] ^= 0xFF; // Flip a bit in the pool_name area.
        std::fs::write(&path, &data).unwrap();

        let cfg = PoolScanConfig::new(vec![path.clone()]);
        let reader = LabelReader::new(cfg);

        let outcome = reader.read_label(&path);
        match &outcome {
            LabelReadOutcome::Corrupted { error_kind, .. } => {
                assert_eq!(*error_kind, LabelErrorKind::ChecksumMismatch);
            }
            other => panic!("expected Corrupted, got {other:?}"),
        }
        assert!(!outcome.is_valid());
    }

    // -- LabelReader: reads from label copy 1 at end of device --

    #[test]
    fn read_label_copy1_at_end() {
        let dir = tempfile::tempdir().unwrap();
        let label = make_label("copy1pool");

        // Write a file that's 512 KiB; label at end (size - 256 KiB).
        let path = write_label_at(&dir, "bigdev", &label, 512 * 1024 - POOL_LABEL_SIZE as u64);

        let cfg = PoolScanConfig::new(vec![path.clone()]);
        let reader = LabelReader::new(cfg);

        let outcome = reader.read_label(&path);
        assert!(outcome.is_valid(), "expected valid label, got {outcome:?}");
        assert_eq!(outcome.label().unwrap().pool_name_str(), "copy1pool");
    }

    // -- LabelReader: custom label offsets --

    #[test]
    fn read_with_custom_offsets() {
        let dir = tempfile::tempdir().unwrap();
        let label = make_label("customoff");

        // Write label at offset 8192 in a 2 MiB file.  The default
        // config reads offset 0 and end-of-device (2 MiB - 256 KiB),
        // neither of which hits offset 8192, so it returns NoLabel.
        let path = write_label_at(&dir, "offsetdev", &label, 8192);
        // Extend the file to 2 MiB so end-of-device is far from 8192.
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(2 * 1024 * 1024).unwrap();

        // Default config misses this (reads offset 0 and end-of-device).
        let default_cfg = PoolScanConfig::new(vec![path.clone()]);
        let default_reader = LabelReader::new(default_cfg);
        assert!(matches!(
            default_reader.read_label(&path),
            LabelReadOutcome::NoLabel
        ));

        // With custom offset, we find it.
        let cfg = PoolScanConfig::new(vec![path.clone()]).with_label_offsets(8192, 0);
        let reader = LabelReader::new(cfg);
        let outcome = reader.read_label(&path);
        assert!(outcome.is_valid(), "expected valid with custom offset");
        assert_eq!(outcome.label().unwrap().pool_name_str(), "customoff");
    }

    // -- LabelReader: explicit BLAKE3 validation --

    #[test]
    fn explicit_blake3_validation_passes() {
        let label = make_label("blake3pass");
        assert!(LabelReader::validate_checksum(&label));
    }

    #[test]
    fn explicit_blake3_validation_fails_on_corruption() {
        let mut label = make_label("blake3fail");
        // Tamper with a field but don't recompute checksum.
        label.pool_state = PoolState::Destroyed;
        assert!(!LabelReader::validate_checksum(&label));
    }

    #[test]
    fn raw_checksum_verification() {
        let label = make_label("rawcheck");
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&label, &mut buf).unwrap();

        let checksum_offset = POOL_LABEL_V1_CHECKSUM_OFFSET;
        let checksum_end = POOL_LABEL_V1_EXT_WIRE_SIZE;

        assert!(LabelReader::verify_raw_checksum(
            &buf,
            checksum_offset,
            checksum_end,
        ));

        // Corrupt a byte.
        buf[100] ^= 0x01;
        assert!(!LabelReader::verify_raw_checksum(
            &buf,
            checksum_offset,
            checksum_end,
        ));
    }

    // -- scan_all --

    #[test]
    fn scan_all_mixed_devices() {
        let dir = tempfile::tempdir().unwrap();
        let label = make_label("scantest");

        let dev0 = write_label_file(&dir, "dev0", &label);
        let dev1 = dir.path().join("dev1");
        std::fs::write(&dev1, b"not a label").unwrap();

        let cfg = PoolScanConfig::new(vec![dev0, dev1]);
        let reader = LabelReader::new(cfg);
        let results = reader.scan_all();

        assert_eq!(results.len(), 2);
        assert!(results[0].1.is_valid());
        assert!(matches!(results[1].1, LabelReadOutcome::NoLabel));
    }

    #[test]
    fn scan_valid_labels_only() {
        let dir = tempfile::tempdir().unwrap();
        let label = make_label("validonly");

        let dev0 = write_label_file(&dir, "d0", &label);
        let dev1 = dir.path().join("d1");
        std::fs::write(&dev1, b"junk").unwrap();
        let dev2 = write_label_file(&dir, "d2", &label);

        let cfg = PoolScanConfig::new(vec![dev0, dev1, dev2]);
        let reader = LabelReader::new(cfg);
        let valid = reader.scan_valid_labels();

        assert_eq!(valid.len(), 2);
    }

    // -- validate_pool_membership --

    #[test]
    fn membership_single_device() {
        let dir = tempfile::tempdir().unwrap();
        let label = make_label("single");
        let path = write_label_file(&dir, "dev", &label);

        let cfg = PoolScanConfig::new(vec![path]);
        let reader = LabelReader::new(cfg);
        let guid = validate_pool_membership(&reader).unwrap();
        assert_eq!(guid, [0xABu8; 16]);
    }

    #[test]
    fn membership_two_devices_same_pool() {
        let dir = tempfile::tempdir().unwrap();
        let label_a = make_label("samepool");
        let label_b = {
            // Same pool GUID, different device GUID, distinct device index.
            let pool_guid = [0xABu8; 16];
            let device_guid = [0xEFu8; 16];
            let mut l = PoolLabelV1::new(pool_guid, device_guid, "samepool");
            l.device_index = 1;
            seal_label(l).unwrap()
        };
        let dev0 = write_label_file(&dir, "dev0", &label_a);
        let dev1 = write_label_file(&dir, "dev1", &label_b);

        let cfg = PoolScanConfig::new(vec![dev0, dev1]);
        let reader = LabelReader::new(cfg);
        let guid = validate_pool_membership(&reader).unwrap();
        assert_eq!(guid, [0xABu8; 16]);
    }

    #[test]
    fn membership_foreign_pool_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let label_a = make_label("poolA");
        let label_b = {
            let pool_guid = [0xFFu8; 16];
            let device_guid = [0xEEu8; 16];
            let l = PoolLabelV1::new(pool_guid, device_guid, "poolB");
            seal_label(l).unwrap()
        };
        let dev0 = write_label_file(&dir, "devA", &label_a);
        let dev1 = write_label_file(&dir, "devB", &label_b);

        let cfg = PoolScanConfig::new(vec![dev0, dev1]);
        let reader = LabelReader::new(cfg);
        let result = validate_pool_membership(&reader);
        match result {
            Err(MembershipError::PoolGuidMismatch {
                expected,
                found,
                device_path: _,
            }) => {
                assert_eq!(expected, [0xABu8; 16]);
                assert_eq!(found, [0xFFu8; 16]);
            }
            other => panic!("expected PoolGuidMismatch, got {other:?}"),
        }
    }

    #[test]
    fn membership_corrupted_label_reported() {
        let dir = tempfile::tempdir().unwrap();
        let label = make_label("corruptmem");

        // First device: valid.
        let dev0 = write_label_file(&dir, "good", &label);

        // Second device: valid label but we'll corrupt it.
        let dev1_path = write_label_file(&dir, "bad", &label);
        let mut data = std::fs::read(&dev1_path).unwrap();
        data[42] ^= 0xFF;
        std::fs::write(&dev1_path, &data).unwrap();

        let cfg = PoolScanConfig::new(vec![dev0, dev1_path]);
        let reader = LabelReader::new(cfg);
        let result = validate_pool_membership(&reader);
        match result {
            Err(MembershipError::CorruptedLabel { .. }) => {}
            other => panic!("expected CorruptedLabel, got {other:?}"),
        }
    }

    #[test]
    fn membership_no_valid_labels() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = dir.path().join("plain1");
        let p2 = dir.path().join("plain2");
        std::fs::write(&p1, b"not a label").unwrap();
        std::fs::write(&p2, b"also not").unwrap();

        let cfg = PoolScanConfig::new(vec![p1, p2]);
        let reader = LabelReader::new(cfg);
        let result = validate_pool_membership(&reader);
        assert!(matches!(result, Err(MembershipError::NoValidLabels)));
    }

    // -- MembershipError Display --

    #[test]
    fn membership_error_display_no_labels() {
        assert_eq!(
            format!("{}", MembershipError::NoValidLabels),
            "no valid TideFS labels found on any device"
        );
    }

    #[test]
    fn membership_error_display_guid_mismatch() {
        let err = MembershipError::PoolGuidMismatch {
            expected: [0x11u8; 16],
            found: [0x22u8; 16],
            device_path: PathBuf::from("/dev/sdb"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("pool GUID mismatch"));
        assert!(msg.contains("/dev/sdb"));
    }

    #[test]
    fn membership_error_display_corrupted() {
        let err = MembershipError::CorruptedLabel {
            device_path: PathBuf::from("/dev/sdc"),
            reason: "BLAKE3 checksum mismatch".into(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("corrupted label"));
        assert!(msg.contains("/dev/sdc"));
    }

    // -- Label round-trip via LabelReader --

    #[test]
    fn label_roundtrip_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let original = make_label("roundtrip");
        let path = write_label_file(&dir, "rt", &original);

        let cfg = PoolScanConfig::new(vec![path.clone()]);
        let reader = LabelReader::new(cfg);
        let outcome = reader.read_label(&path);
        let parsed = outcome.label().unwrap();

        assert_eq!(parsed.magic, original.magic);
        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.pool_guid, original.pool_guid);
        assert_eq!(parsed.device_guid, original.device_guid);
        assert_eq!(parsed.pool_name_str(), original.pool_name_str());
        assert_eq!(parsed.pool_state, original.pool_state);
        assert_eq!(parsed.checksum, original.checksum);
    }

    // -- Multi-device label scenario --

    #[test]
    fn multi_device_pool_scan() {
        let dir = tempfile::tempdir().unwrap();
        let pool_guid = [0x77u8; 16];

        let label0 = {
            let l = PoolLabelV1 {
                pool_guid,
                device_guid: [0x01u8; 16],
                device_index: 0,
                device_count: 3,
                device_class: DeviceClass::Hdd,
                ..PoolLabelV1::new(pool_guid, [0x01u8; 16], "multipool")
            };
            seal_label(l).unwrap()
        };
        let label1 = {
            let l = PoolLabelV1 {
                pool_guid,
                device_guid: [0x02u8; 16],
                device_index: 1,
                device_count: 3,
                device_class: DeviceClass::Ssd,
                ..PoolLabelV1::new(pool_guid, [0x02u8; 16], "multipool")
            };
            seal_label(l).unwrap()
        };
        let label2 = {
            let l = PoolLabelV1 {
                pool_guid,
                device_guid: [0x03u8; 16],
                device_index: 2,
                device_count: 3,
                device_class: DeviceClass::Nvme,
                ..PoolLabelV1::new(pool_guid, [0x03u8; 16], "multipool")
            };
            seal_label(l).unwrap()
        };

        let paths = vec![
            write_label_file(&dir, "dev0", &label0),
            write_label_file(&dir, "dev1", &label1),
            write_label_file(&dir, "dev2", &label2),
        ];

        let cfg = PoolScanConfig::new(paths.clone());
        let reader = LabelReader::new(cfg);

        let results = reader.scan_all();
        assert_eq!(results.len(), 3);
        for (_path, outcome) in &results {
            assert!(outcome.is_valid(), "expected valid, got {outcome:?}");
        }

        let valid = reader.scan_valid_labels();
        assert_eq!(valid.len(), 3);

        // Verify membership.
        let guid = validate_pool_membership(&reader).unwrap();
        assert_eq!(guid, pool_guid);

        // Verify each device has the correct index.
        let mut indices: Vec<u32> = valid.iter().map(|(_, l)| l.device_index).collect();
        indices.sort_unstable();
        assert_eq!(indices, vec![0, 1, 2]);
    }
}
