// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel-portable pool superblock scanner.
//!
//! Reads and validates the TideFS pool label from a block device through
//! [`KernelStorageIo`], providing pool identity and the committed-root
//! ledger location needed for KernelPoolCore initialization.
//!
//! # Label layout
//!
//! The pool label (PoolLabelV1) sits at sector 0 of the block device.
//! It is 440 bytes (POOL_LABEL_V1_EXT_WIRE_SIZE) and carries a BLAKE3-256
//! checksum covering all preceding fields. The label identifies the pool
//! GUID, device GUID, pool name, commit_group recovery point, and the
//! pool-wide redundancy policy plus the system-area pointer where the
//! committed-root ledger lives.
//!
//! # no_std
//!
//! This module uses only `core` and `alloc`, matching the crate's
//! `#![no_std]` posture.

use core::fmt;

use tidefs_types_pool_label_core::{
    decode_label, LabelError, PoolLabelV1, PoolRedundancyPolicy, POOL_LABEL_MAGIC,
    POOL_LABEL_V1_EXT_WIRE_SIZE,
};
use tidefs_types_vfs_core::Errno;

use crate::traits::KernelStorageIo;

// ── KernelPoolSuperblock ───────────────────────────────────────────────

/// Pool identity and committed-root ledger location parsed from the
/// on-disk pool label via [`read_pool_superblock`].
///
/// This is the minimal mount-relevant subset of [`PoolLabelV1`]:
/// pool identity fields, the recovery commit_group, and the system-area
/// pointer that locates the committed-root ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelPoolSuperblock {
    /// Magic bytes: `b"VBFS"`.
    pub magic: [u8; 4],
    /// Unique pool identifier (UUID v4).
    pub pool_guid: [u8; 16],
    /// Unique device identifier (UUID v4).
    pub device_guid: [u8; 16],
    /// Human-readable pool name (UTF-8 bytes, not NUL-terminated).
    pub pool_name: [u8; 255],
    /// Actual length of the pool name in bytes.
    pub pool_name_len: u16,
    /// Operational state of the pool (Active=0, Exported=1, Destroyed=2).
    pub pool_state: u8,
    /// Last committed commit_group on this device (recovery reference).
    pub commit_group: u64,
    /// Device position in topology (0-based).
    pub device_index: u32,
    /// Incremented on each device add/remove.
    pub topology_generation: u64,
    /// Total devices in the pool topology.
    pub device_count: u32,
    /// Allocation class of this device.
    pub device_class: u8,
    /// Total device capacity in bytes.
    pub device_capacity_bytes: u64,
    /// Byte offset to the committed-root ledger (system area).
    pub system_area_pointer: u64,
    /// Size of the committed-root ledger in bytes.
    pub system_area_size: u64,
    /// Feature bitmask: incompatible features.
    pub features_incompat: u64,
    /// Feature bitmask: read-only-compatible features.
    pub features_ro_compat: u64,
    /// Feature bitmask: compatible features.
    pub features_compat: u64,
    /// Pool-wide redundancy policy identity from the label.
    pub redundancy_policy: PoolRedundancyPolicy,
    /// BLAKE3-256 checksum of all preceding fields (verified on read).
    pub checksum: [u8; 32],
}

impl KernelPoolSuperblock {
    /// Construct from a fully-decoded [`PoolLabelV1`] after checksum
    /// verification.
    #[must_use]
    pub fn from_label(label: &PoolLabelV1) -> Self {
        Self {
            magic: label.magic,
            pool_guid: label.pool_guid,
            device_guid: label.device_guid,
            pool_name: label.pool_name,
            pool_name_len: label.pool_name_len,
            pool_state: label.pool_state.to_u8(),
            commit_group: label.commit_group,
            device_index: label.device_index,
            topology_generation: label.topology_generation,
            device_count: label.device_count,
            device_class: label.device_class.to_u8(),
            device_capacity_bytes: label.device_capacity_bytes,
            system_area_pointer: label.system_area_pointer,
            system_area_size: label.system_area_size,
            features_incompat: label.features_incompat,
            features_ro_compat: label.features_ro_compat,
            features_compat: label.features_compat,
            redundancy_policy: label.redundancy_policy,
            checksum: label.checksum,
        }
    }

    /// Extract the pool name as a UTF-8 string.
    #[must_use]
    pub fn pool_name_str(&self) -> &str {
        let len = self.pool_name_len as usize;
        let len = len.min(255);
        core::str::from_utf8(&self.pool_name[..len]).unwrap_or("")
    }

    /// Returns `true` if the pool state permits import (Active or
    /// Exported).
    #[must_use]
    pub const fn is_importable(&self) -> bool {
        self.pool_state == 0 || self.pool_state == 1
    }
}

impl fmt::Display for KernelPoolSuperblock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KernelPoolSuperblock(pool={}, device_index={}, txg={}, system_area=0x{:x})",
            self.pool_name_str(),
            self.device_index,
            self.commit_group,
            self.system_area_pointer,
        )
    }
}

// ── PoolSuperblockError ────────────────────────────────────────────────

/// Errors returned by [`read_pool_superblock`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolSuperblockError {
    /// I/O error reading the superblock region from the block device.
    Io(Errno),
    /// The block device is too small to hold a pool label.
    DeviceTooSmall,
    /// Magic bytes do not match `VBFS` — not a TideFS device.
    BadMagic,
    /// Unrecognized label format version.
    UnsupportedVersion(u32),
    /// BLAKE3-256 checksum mismatch — label is corrupt.
    Corrupt,
    /// The pool name contains invalid UTF-8.
    InvalidPoolName,
}

impl fmt::Display for PoolSuperblockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error reading pool superblock: {e:?}"),
            Self::DeviceTooSmall => f.write_str("device too small for pool superblock"),
            Self::BadMagic => f.write_str("bad magic bytes — not a TideFS device"),
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported label version {v}")
            }
            Self::Corrupt => f.write_str("pool label is corrupt (checksum mismatch)"),
            Self::InvalidPoolName => f.write_str("pool name contains invalid UTF-8"),
        }
    }
}

impl From<LabelError> for PoolSuperblockError {
    fn from(e: LabelError) -> Self {
        match e {
            LabelError::BufferTooSmall => Self::DeviceTooSmall,
            LabelError::BadMagic => Self::BadMagic,
            LabelError::UnsupportedVersion(v) => Self::UnsupportedVersion(v),
            LabelError::ChecksumMismatch => Self::Corrupt,
            LabelError::BadPoolState(_)
            | LabelError::BadDeviceClass(_)
            | LabelError::BadRedundancyPolicy { .. }
            | LabelError::NameTooLong
            | LabelError::LastDevice => Self::Corrupt,
        }
    }
}

// ── Pool superblock import evidence ────────────────────────────────────

/// Claim anchor for pool-superblock import evidence receipts.
pub const POOL_SUPERBLOCK_IMPORT_EVIDENCE_CLAIM: &str =
    "kernel-storage-io.pool-superblock-import-evidence";

/// GitHub issue that introduced pool-superblock import evidence receipts.
pub const POOL_SUPERBLOCK_IMPORT_EVIDENCE_ISSUE: u32 = 537;

/// Evidence tier represented by a pool-superblock import receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolSuperblockImportValidationTier {
    /// Focused source/unit evidence only.
    FocusedUnit,
}

/// Pool label copy represented in an import evidence receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolSuperblockLabelCopy {
    /// Label copy at the head of the member device.
    Primary,
    /// Secondary label copy, normally read from the member-device tail.
    Secondary,
}

/// Fail-closed import decision captured by a pool-superblock evidence receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolSuperblockImportDecision {
    /// Both label copies agree on pool/member identity, generation, and digest.
    Accepted,
    /// Import evidence is incomplete or incoherent.
    Rejected(PoolSuperblockImportRejectReason),
}

impl PoolSuperblockImportDecision {
    /// Returns `true` only for a coherent accepted decision.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// Reason an import evidence receipt rejected the observed label evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolSuperblockImportRejectReason {
    /// No label evidence was supplied.
    UnknownEvidence,
    /// The primary label copy was not available.
    MissingPrimaryEvidence,
    /// The secondary label copy was not available.
    MissingSecondaryEvidence,
    /// Label copies describe different pools or member devices.
    MixedLabels,
    /// Label copies disagree on the superblock generation.
    StaleGeneration,
    /// Label copies have different verified label digests.
    LabelDigestMismatch,
}

/// Verified label-copy evidence used to decide whether import can proceed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolSuperblockLabelEvidence {
    copy: PoolSuperblockLabelCopy,
    pool_guid: [u8; 16],
    member_id: [u8; 16],
    superblock_generation: u64,
    label_digest: [u8; 32],
}

impl PoolSuperblockLabelEvidence {
    /// Build label-copy evidence from a decoded and checksum-verified
    /// pool superblock.
    #[must_use]
    pub const fn from_superblock(
        copy: PoolSuperblockLabelCopy,
        superblock: &KernelPoolSuperblock,
    ) -> Self {
        Self {
            copy,
            pool_guid: superblock.pool_guid,
            member_id: superblock.device_guid,
            superblock_generation: superblock.commit_group,
            label_digest: superblock.checksum,
        }
    }

    /// Label copy described by this evidence.
    #[must_use]
    pub const fn copy(&self) -> PoolSuperblockLabelCopy {
        self.copy
    }

    /// Pool identity from the label copy.
    #[must_use]
    pub const fn pool_guid(&self) -> [u8; 16] {
        self.pool_guid
    }

    /// Member identity from the label copy.
    #[must_use]
    pub const fn member_id(&self) -> [u8; 16] {
        self.member_id
    }

    /// Superblock generation represented by the label's recovery commit group.
    #[must_use]
    pub const fn superblock_generation(&self) -> u64 {
        self.superblock_generation
    }

    /// Verified BLAKE3-256 digest from the label copy.
    #[must_use]
    pub const fn label_digest(&self) -> [u8; 32] {
        self.label_digest
    }
}

/// Pool-superblock import evidence receipt for one member device.
///
/// The constructor is fail-closed: `Accepted` is produced only when both
/// primary and secondary label evidence are present and agree on pool/member
/// identity, superblock generation, and verified label digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolSuperblockImportEvidence {
    primary: Option<PoolSuperblockLabelEvidence>,
    secondary: Option<PoolSuperblockLabelEvidence>,
    member_id: Option<[u8; 16]>,
    superblock_generation: Option<u64>,
    label_digest: Option<[u8; 32]>,
    import_decision: PoolSuperblockImportDecision,
    validation_tier: PoolSuperblockImportValidationTier,
    claim_ref: &'static str,
    issue_ref: u32,
}

impl PoolSuperblockImportEvidence {
    /// Evaluate primary/secondary label evidence at the focused unit tier.
    #[must_use]
    pub fn focused_unit(
        primary: Option<PoolSuperblockLabelEvidence>,
        secondary: Option<PoolSuperblockLabelEvidence>,
    ) -> Self {
        Self::new(
            primary,
            secondary,
            PoolSuperblockImportValidationTier::FocusedUnit,
        )
    }

    /// Evaluate primary/secondary label evidence for a caller-selected tier.
    #[must_use]
    pub fn new(
        primary: Option<PoolSuperblockLabelEvidence>,
        secondary: Option<PoolSuperblockLabelEvidence>,
        validation_tier: PoolSuperblockImportValidationTier,
    ) -> Self {
        let (candidate, import_decision) = match (primary, secondary) {
            (None, None) => (
                None,
                PoolSuperblockImportDecision::Rejected(
                    PoolSuperblockImportRejectReason::UnknownEvidence,
                ),
            ),
            (None, Some(secondary)) => (
                Some(secondary),
                PoolSuperblockImportDecision::Rejected(
                    PoolSuperblockImportRejectReason::MissingPrimaryEvidence,
                ),
            ),
            (Some(primary), None) => (
                Some(primary),
                PoolSuperblockImportDecision::Rejected(
                    PoolSuperblockImportRejectReason::MissingSecondaryEvidence,
                ),
            ),
            (Some(primary), Some(secondary)) => {
                let decision = if primary.pool_guid != secondary.pool_guid
                    || primary.member_id != secondary.member_id
                {
                    PoolSuperblockImportDecision::Rejected(
                        PoolSuperblockImportRejectReason::MixedLabels,
                    )
                } else if primary.superblock_generation != secondary.superblock_generation {
                    PoolSuperblockImportDecision::Rejected(
                        PoolSuperblockImportRejectReason::StaleGeneration,
                    )
                } else if primary.label_digest != secondary.label_digest {
                    PoolSuperblockImportDecision::Rejected(
                        PoolSuperblockImportRejectReason::LabelDigestMismatch,
                    )
                } else {
                    PoolSuperblockImportDecision::Accepted
                };

                let candidate = if primary.superblock_generation >= secondary.superblock_generation
                {
                    primary
                } else {
                    secondary
                };
                (Some(candidate), decision)
            }
        };

        Self {
            primary,
            secondary,
            member_id: candidate.map(|evidence| evidence.member_id),
            superblock_generation: candidate.map(|evidence| evidence.superblock_generation),
            label_digest: candidate.map(|evidence| evidence.label_digest),
            import_decision,
            validation_tier,
            claim_ref: POOL_SUPERBLOCK_IMPORT_EVIDENCE_CLAIM,
            issue_ref: POOL_SUPERBLOCK_IMPORT_EVIDENCE_ISSUE,
        }
    }

    /// Primary label evidence, if it was observed.
    #[must_use]
    pub const fn primary(&self) -> Option<PoolSuperblockLabelEvidence> {
        self.primary
    }

    /// Secondary label evidence, if it was observed.
    #[must_use]
    pub const fn secondary(&self) -> Option<PoolSuperblockLabelEvidence> {
        self.secondary
    }

    /// Candidate member identity summarized by this receipt.
    #[must_use]
    pub const fn member_id(&self) -> Option<[u8; 16]> {
        self.member_id
    }

    /// Candidate superblock generation summarized by this receipt.
    #[must_use]
    pub const fn superblock_generation(&self) -> Option<u64> {
        self.superblock_generation
    }

    /// Candidate verified label digest summarized by this receipt.
    #[must_use]
    pub const fn label_digest(&self) -> Option<[u8; 32]> {
        self.label_digest
    }

    /// Import decision made from the supplied evidence.
    #[must_use]
    pub const fn import_decision(&self) -> PoolSuperblockImportDecision {
        self.import_decision
    }

    /// Validation tier represented by this receipt.
    #[must_use]
    pub const fn validation_tier(&self) -> PoolSuperblockImportValidationTier {
        self.validation_tier
    }

    /// Claim anchor this receipt can cite.
    #[must_use]
    pub const fn claim_ref(&self) -> &'static str {
        self.claim_ref
    }

    /// GitHub issue that introduced this receipt schema.
    #[must_use]
    pub const fn issue_ref(&self) -> u32 {
        self.issue_ref
    }

    /// Returns `true` only when the receipt contains a coherent accepted import.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        self.import_decision.is_accepted()
            && self.primary.is_some()
            && self.secondary.is_some()
            && self.member_id.is_some()
            && self.superblock_generation.is_some()
            && self.label_digest.is_some()
    }
}

// ── read_pool_superblock ───────────────────────────────────────────────

/// Read and validate the TideFS pool superblock from a block device.
///
/// Reads enough sectors from sector 0 to cover the pool label
/// (436 bytes), validates the magic bytes, decodes the label with
/// BLAKE3-256 checksum verification, and returns the mount-relevant
/// fields as a [`KernelPoolSuperblock`].
///
/// # Errors
///
/// - [`PoolSuperblockError::DeviceTooSmall`] when the device has
///   fewer sectors than needed for one pool label.
/// - [`PoolSuperblockError::BadMagic`] when the first four bytes are
///   not `b"VBFS"`.
/// - [`PoolSuperblockError::Corrupt`] when the BLAKE3-256 checksum
///   does not match or a field value is out of range.
/// - [`PoolSuperblockError::Io`] when the underlying
///   [`KernelStorageIo`] read returns an error.
pub fn read_pool_superblock(
    io: &dyn KernelStorageIo,
) -> Result<KernelPoolSuperblock, PoolSuperblockError> {
    let ss = io.sector_size() as usize;

    // Need at least POOL_LABEL_V1_EXT_WIRE_SIZE (436) bytes.
    // Read enough whole sectors to cover it.
    let sectors_needed = POOL_LABEL_V1_EXT_WIRE_SIZE.div_ceil(ss);
    let buf_len = sectors_needed * ss;

    if sectors_needed == 0 {
        return Err(PoolSuperblockError::DeviceTooSmall);
    }

    // Verify the device has enough sectors.
    if io.capacity_sectors() < sectors_needed as u64 {
        return Err(PoolSuperblockError::DeviceTooSmall);
    }

    let mut buf = alloc::vec![0u8; buf_len];

    let read_sectors = io
        .read_sectors(0, &mut buf)
        .map_err(PoolSuperblockError::Io)?;

    if read_sectors < sectors_needed as u32 {
        return Err(PoolSuperblockError::Io(Errno::EIO));
    }

    // Quick magic check before full decode.
    if buf.len() < 4 || buf[0..4] != POOL_LABEL_MAGIC {
        return Err(PoolSuperblockError::BadMagic);
    }

    // Decode and verify checksum.
    let label = decode_label(&buf)?;

    Ok(KernelPoolSuperblock::from_label(&label))
}

// ── read_pool_superblock_at ───────────────────────────────────────────

/// Read and validate the TideFS pool superblock from a specific start
/// sector on a block device.
///
/// Like [] but reads from  instead of
/// sector 0. Used to scan the tail label copy (label copy 1) at the end
/// of the device.
///
/// Returns  if  exceeds
/// the device capacity.
pub fn read_pool_superblock_at(
    io: &dyn KernelStorageIo,
    start_sector: u64,
) -> Result<KernelPoolSuperblock, PoolSuperblockError> {
    let ss = io.sector_size() as usize;

    let sectors_needed = POOL_LABEL_V1_EXT_WIRE_SIZE.div_ceil(ss);
    let buf_len = sectors_needed * ss;

    if sectors_needed == 0 {
        return Err(PoolSuperblockError::DeviceTooSmall);
    }

    // Verify range.
    let end = start_sector
        .checked_add(sectors_needed as u64)
        .ok_or(PoolSuperblockError::DeviceTooSmall)?;
    if end > io.capacity_sectors() {
        return Err(PoolSuperblockError::DeviceTooSmall);
    }

    let mut buf = alloc::vec![0u8; buf_len];

    let read_sectors = io
        .read_sectors(start_sector, &mut buf)
        .map_err(PoolSuperblockError::Io)?;

    if read_sectors < sectors_needed as u32 {
        return Err(PoolSuperblockError::Io(Errno::EIO));
    }

    if buf.len() < 4 || buf[0..4] != POOL_LABEL_MAGIC {
        return Err(PoolSuperblockError::BadMagic);
    }

    let label = decode_label(&buf)?;

    Ok(KernelPoolSuperblock::from_label(&label))
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::traits::KernelStorageIoCapabilities;
    use tidefs_types_pool_label_core::{
        encode_label, seal_label, PoolLabelV1, POOL_LABEL_V1_EXT_WIRE_SIZE,
    };
    use tidefs_types_vfs_core::Errno;

    /// Build a valid, sealed PoolLabelV1 and encode it into a buffer.
    fn make_test_label_bytes(pool_name: &str, sector_size: u32) -> alloc::vec::Vec<u8> {
        let pool_guid = [0xABu8; 16];
        let device_guid = [0xCDu8; 16];
        let label = PoolLabelV1::new(pool_guid, device_guid, pool_name);
        let sealed = seal_label(label).unwrap();
        let mut label_buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&sealed, &mut label_buf).unwrap();
        // Pad to a whole sector so capacity_sectors() reports the right value.
        let ss = sector_size as usize;
        let padded_len = POOL_LABEL_V1_EXT_WIRE_SIZE.div_ceil(ss) * ss;
        let mut buf = alloc::vec![0u8; padded_len];
        buf[..POOL_LABEL_V1_EXT_WIRE_SIZE].copy_from_slice(&label_buf);
        buf
    }

    fn make_test_superblock(
        pool_guid: [u8; 16],
        device_guid: [u8; 16],
        generation: u64,
        system_area_size: u64,
    ) -> KernelPoolSuperblock {
        let mut label = PoolLabelV1::new(pool_guid, device_guid, "evidence");
        label.commit_group = generation;
        label.system_area_size = system_area_size;
        let sealed = seal_label(label).unwrap();
        KernelPoolSuperblock::from_label(&sealed)
    }

    fn label_evidence(
        copy: PoolSuperblockLabelCopy,
        superblock: &KernelPoolSuperblock,
    ) -> PoolSuperblockLabelEvidence {
        PoolSuperblockLabelEvidence::from_superblock(copy, superblock)
    }

    /// In-memory KernelStorageIo backed by a Vec<u8>.
    use std::sync::Mutex;

    struct MemStorageIo {
        data: Mutex<alloc::vec::Vec<u8>>,
        sector_size: u32,
        fail_read: Mutex<bool>,
    }

    impl MemStorageIo {
        fn new(data: alloc::vec::Vec<u8>, sector_size: u32) -> Self {
            Self {
                data: Mutex::new(data),
                sector_size,
                fail_read: Mutex::new(false),
            }
        }

        fn set_fail_read(&self, fail: bool) {
            *self.fail_read.lock().unwrap() = fail;
        }
    }

    impl KernelStorageIo for MemStorageIo {
        fn capabilities(&self) -> KernelStorageIoCapabilities {
            KernelStorageIoCapabilities {
                read: true,
                write: false,
                flush: true,
                discard: false,
                write_zeroes: false,
                zero_range: false,
                teardown: true,
                sector_size: self.sector_size,
                capacity_sectors: self.capacity_sectors(),
            }
        }

        fn read_sectors(&self, start_sector: u64, buf: &mut [u8]) -> Result<u32, Errno> {
            if *self.fail_read.lock().unwrap() {
                return Err(Errno::EIO);
            }
            let ss = self.sector_size as u64;
            let offset = start_sector.checked_mul(ss).ok_or(Errno::EINVAL)? as usize;
            let data = self.data.lock().unwrap();
            if offset + buf.len() > data.len() {
                return Err(Errno::EINVAL);
            }
            let n = buf.len().min(data.len() - offset);
            buf[..n].copy_from_slice(&data[offset..offset + n]);
            Ok((n / self.sector_size as usize) as u32)
        }

        fn write_sectors(&self, _start_sector: u64, _data: &[u8]) -> Result<u32, Errno> {
            Err(Errno::ENOSYS)
        }

        fn flush(&self) -> Result<(), Errno> {
            Ok(())
        }

        fn sector_size(&self) -> u32 {
            self.sector_size
        }

        fn capacity_sectors(&self) -> u64 {
            let data = self.data.lock().unwrap();
            (data.len() as u64) / u64::from(self.sector_size)
        }

        fn teardown(&self) -> Result<(), Errno> {
            Ok(())
        }
    }

    // ── Successful read ────────────────────────────────────────────

    #[test]
    fn read_valid_superblock_512() {
        let label_bytes = make_test_label_bytes("testpool", 512);
        let io = MemStorageIo::new(label_bytes, 512);
        let sb = read_pool_superblock(&io).unwrap();

        assert_eq!(sb.magic, *b"VBFS");
        assert_eq!(sb.pool_guid, [0xABu8; 16]);
        assert_eq!(sb.device_guid, [0xCDu8; 16]);
        assert_eq!(sb.pool_name_str(), "testpool");
        assert!(sb.is_importable());
    }

    #[test]
    fn read_valid_superblock_4096() {
        let label_bytes = make_test_label_bytes("bigsector", 4096);
        let io = MemStorageIo::new(label_bytes, 4096);
        let sb = read_pool_superblock(&io).unwrap();
        assert_eq!(sb.pool_name_str(), "bigsector");
        assert!(sb.is_importable());
    }

    // ── Bad magic ─────────────────────────────────────────────────

    #[test]
    fn read_bad_magic() {
        let mut label_bytes = make_test_label_bytes("badmagic", 512);
        label_bytes[0] = b'X'; // corrupt magic
        let io = MemStorageIo::new(label_bytes, 512);
        let err = read_pool_superblock(&io).unwrap_err();
        assert_eq!(err, PoolSuperblockError::BadMagic);
    }

    // ── Corrupt checksum ──────────────────────────────────────────

    #[test]
    fn read_corrupt_checksum() {
        let mut label_bytes = make_test_label_bytes("corrupt", 512);
        // Flip a byte in the data region (not magic), don't re-checksum.
        label_bytes[8] ^= 0xFF;
        let io = MemStorageIo::new(label_bytes, 512);
        let err = read_pool_superblock(&io).unwrap_err();
        assert_eq!(err, PoolSuperblockError::Corrupt);
    }

    // ── I/O error propagation ──────────────────────────────────────

    #[test]
    fn read_io_error() {
        let label_bytes = make_test_label_bytes("ioerr", 512);
        let io = MemStorageIo::new(label_bytes, 512);
        io.set_fail_read(true);
        let err = read_pool_superblock(&io).unwrap_err();
        assert_eq!(err, PoolSuperblockError::Io(Errno::EIO));
    }

    // ── Device too small ──────────────────────────────────────────

    #[test]
    fn read_device_too_small() {
        let small_data = alloc::vec![0u8; 100];
        let io = MemStorageIo::new(small_data, 512);
        let err = read_pool_superblock(&io).unwrap_err();
        assert_eq!(err, PoolSuperblockError::DeviceTooSmall);
    }

    // ── KernelPoolSuperblock Display ──────────────────────────────

    #[test]
    fn superblock_display() {
        let label_bytes = make_test_label_bytes("display", 512);
        let io = MemStorageIo::new(label_bytes, 512);
        let sb = read_pool_superblock(&io).unwrap();
        let s = alloc::format!("{sb}");
        assert!(s.contains("display"));
        assert!(s.contains("KernelPoolSuperblock"));
    }

    // ── PoolSuperblockError Display ───────────────────────────────

    #[test]
    fn error_display() {
        assert_eq!(
            alloc::format!("{}", PoolSuperblockError::BadMagic),
            "bad magic bytes — not a TideFS device"
        );
        assert_eq!(
            alloc::format!("{}", PoolSuperblockError::Corrupt),
            "pool label is corrupt (checksum mismatch)"
        );
        assert_eq!(
            alloc::format!("{}", PoolSuperblockError::DeviceTooSmall),
            "device too small for pool superblock"
        );
        let io_err = PoolSuperblockError::Io(Errno::EIO);
        assert!(alloc::format!("{io_err}").contains("I/O error"));
    }

    // ── KernelPoolSuperblock field extraction ─────────────────────

    #[test]
    fn superblock_fields_from_label() {
        use tidefs_types_pool_label_core::DeviceClass;

        let pool_guid = [0x11u8; 16];
        let device_guid = [0x22u8; 16];
        let mut label = PoolLabelV1::new(pool_guid, device_guid, "fields");
        label.device_index = 3;
        label.device_count = 5;
        label.commit_group = 42;
        label.system_area_pointer = 0x100000;
        label.system_area_size = 65536;
        label.topology_generation = 7;
        label.device_class = DeviceClass::Ssd;
        label.features_incompat = 1;
        label.features_ro_compat = 2;
        label.features_compat = 4;
        let sealed = seal_label(label).unwrap();

        let sb = KernelPoolSuperblock::from_label(&sealed);
        assert_eq!(sb.pool_guid, [0x11u8; 16]);
        assert_eq!(sb.device_guid, [0x22u8; 16]);
        assert_eq!(sb.device_index, 3);
        assert_eq!(sb.device_count, 5);
        assert_eq!(sb.commit_group, 42);
        assert_eq!(sb.system_area_pointer, 0x100000);
        assert_eq!(sb.system_area_size, 65536);
        assert_eq!(sb.topology_generation, 7);
        assert_eq!(sb.device_class, DeviceClass::Ssd.to_u8());
        assert_eq!(sb.features_incompat, 1);
        assert_eq!(sb.features_ro_compat, 2);
        assert_eq!(sb.features_compat, 4);
        assert_ne!(sb.checksum, [0u8; 32]);
    }

    // ── Pool superblock import evidence ────────────────────────────

    #[test]
    fn import_evidence_accepts_coherent_labels() {
        let pool_guid = [0x11u8; 16];
        let member_id = [0x22u8; 16];
        let primary_sb = make_test_superblock(pool_guid, member_id, 42, 65536);
        let secondary_sb = primary_sb.clone();

        let receipt = PoolSuperblockImportEvidence::focused_unit(
            Some(label_evidence(
                PoolSuperblockLabelCopy::Primary,
                &primary_sb,
            )),
            Some(label_evidence(
                PoolSuperblockLabelCopy::Secondary,
                &secondary_sb,
            )),
        );

        assert!(receipt.is_accepted());
        assert_eq!(
            receipt.import_decision(),
            PoolSuperblockImportDecision::Accepted
        );
        assert_eq!(receipt.member_id(), Some(member_id));
        assert_eq!(receipt.superblock_generation(), Some(42));
        assert_eq!(receipt.label_digest(), Some(primary_sb.checksum));
        assert_eq!(
            receipt.validation_tier(),
            PoolSuperblockImportValidationTier::FocusedUnit
        );
        assert_eq!(receipt.claim_ref(), POOL_SUPERBLOCK_IMPORT_EVIDENCE_CLAIM);
        assert_eq!(receipt.issue_ref(), POOL_SUPERBLOCK_IMPORT_EVIDENCE_ISSUE);
        assert_eq!(
            receipt.primary().unwrap().copy(),
            PoolSuperblockLabelCopy::Primary
        );
        assert_eq!(
            receipt.secondary().unwrap().copy(),
            PoolSuperblockLabelCopy::Secondary
        );
    }

    #[test]
    fn import_evidence_rejects_mixed_labels() {
        let pool_guid = [0x33u8; 16];
        let primary_sb = make_test_superblock(pool_guid, [0x44u8; 16], 7, 4096);
        let secondary_sb = make_test_superblock(pool_guid, [0x45u8; 16], 7, 4096);

        let receipt = PoolSuperblockImportEvidence::focused_unit(
            Some(label_evidence(
                PoolSuperblockLabelCopy::Primary,
                &primary_sb,
            )),
            Some(label_evidence(
                PoolSuperblockLabelCopy::Secondary,
                &secondary_sb,
            )),
        );

        assert!(!receipt.is_accepted());
        assert_eq!(
            receipt.import_decision(),
            PoolSuperblockImportDecision::Rejected(PoolSuperblockImportRejectReason::MixedLabels)
        );
    }

    #[test]
    fn import_evidence_rejects_stale_generation() {
        let pool_guid = [0x55u8; 16];
        let member_id = [0x66u8; 16];
        let primary_sb = make_test_superblock(pool_guid, member_id, 9, 4096);
        let secondary_sb = make_test_superblock(pool_guid, member_id, 8, 4096);

        let receipt = PoolSuperblockImportEvidence::focused_unit(
            Some(label_evidence(
                PoolSuperblockLabelCopy::Primary,
                &primary_sb,
            )),
            Some(label_evidence(
                PoolSuperblockLabelCopy::Secondary,
                &secondary_sb,
            )),
        );

        assert!(!receipt.is_accepted());
        assert_eq!(
            receipt.import_decision(),
            PoolSuperblockImportDecision::Rejected(
                PoolSuperblockImportRejectReason::StaleGeneration
            )
        );
        assert_eq!(receipt.member_id(), Some(member_id));
        assert_eq!(receipt.superblock_generation(), Some(9));
    }

    #[test]
    fn import_evidence_rejects_missing_secondary() {
        let primary_sb = make_test_superblock([0x77u8; 16], [0x88u8; 16], 12, 4096);

        let receipt = PoolSuperblockImportEvidence::focused_unit(
            Some(label_evidence(
                PoolSuperblockLabelCopy::Primary,
                &primary_sb,
            )),
            None,
        );

        assert!(!receipt.is_accepted());
        assert_eq!(
            receipt.import_decision(),
            PoolSuperblockImportDecision::Rejected(
                PoolSuperblockImportRejectReason::MissingSecondaryEvidence
            )
        );
        assert!(receipt.secondary().is_none());
        assert_eq!(receipt.member_id(), Some([0x88u8; 16]));
    }

    #[test]
    fn import_evidence_rejects_digest_mismatch() {
        let pool_guid = [0x99u8; 16];
        let member_id = [0xAAu8; 16];
        let primary_sb = make_test_superblock(pool_guid, member_id, 15, 4096);
        let secondary_sb = make_test_superblock(pool_guid, member_id, 15, 8192);
        assert_ne!(primary_sb.checksum, secondary_sb.checksum);

        let receipt = PoolSuperblockImportEvidence::focused_unit(
            Some(label_evidence(
                PoolSuperblockLabelCopy::Primary,
                &primary_sb,
            )),
            Some(label_evidence(
                PoolSuperblockLabelCopy::Secondary,
                &secondary_sb,
            )),
        );

        assert!(!receipt.is_accepted());
        assert_eq!(
            receipt.import_decision(),
            PoolSuperblockImportDecision::Rejected(
                PoolSuperblockImportRejectReason::LabelDigestMismatch
            )
        );
    }

    #[test]
    fn import_evidence_rejects_unknown_evidence() {
        let receipt = PoolSuperblockImportEvidence::focused_unit(None, None);

        assert!(!receipt.is_accepted());
        assert_eq!(
            receipt.import_decision(),
            PoolSuperblockImportDecision::Rejected(
                PoolSuperblockImportRejectReason::UnknownEvidence
            )
        );
        assert_eq!(receipt.member_id(), None);
        assert_eq!(receipt.superblock_generation(), None);
        assert_eq!(receipt.label_digest(), None);
    }

    #[test]
    fn superblock_is_importable() {
        let label_bytes = make_test_label_bytes("importable", 512);
        let io = MemStorageIo::new(label_bytes, 512);
        let sb = read_pool_superblock(&io).unwrap();
        assert!(sb.is_importable());
    }

    #[test]
    fn read_valid_superblock_has_nonzero_checksum() {
        let label_bytes = make_test_label_bytes("cksum", 512);
        let io = MemStorageIo::new(label_bytes, 512);
        let sb = read_pool_superblock(&io).unwrap();
        assert_ne!(sb.checksum, [0u8; 32]);
    }

    // ── Object safety ─────────────────────────────────────────────

    #[test]
    fn kernel_storage_io_object_safe_for_superblock() {
        let label_bytes = make_test_label_bytes("objectsafe", 512);
        let io = MemStorageIo::new(label_bytes, 512);
        let io_dyn: &dyn KernelStorageIo = &io;
        let sb = read_pool_superblock(io_dyn).unwrap();
        assert_eq!(sb.pool_name_str(), "objectsafe");
    }

    // ── 4096-byte sector alignment ─────────────────────────────────

    #[test]
    fn read_4096_sector_alignment() {
        let label_bytes = make_test_label_bytes("align4096", 4096);
        let io = MemStorageIo::new(label_bytes, 4096);
        let sb = read_pool_superblock(&io).unwrap();
        assert_eq!(sb.pool_name_str(), "align4096");
    }

    // ── Unsupported version -> Corrupt ────────────────────────────

    #[test]
    fn read_unsupported_version() {
        let mut label_bytes = make_test_label_bytes("version", 512);
        // version is at offset 4..8, little-endian. Set to 99.
        label_bytes[4] = 99;
        // decode_label rejects version before checksum.
        let io = MemStorageIo::new(label_bytes, 512);
        let err = read_pool_superblock(&io).unwrap_err();
        assert!(matches!(
            err,
            PoolSuperblockError::Corrupt | PoolSuperblockError::UnsupportedVersion(_)
        ));
    }
}
