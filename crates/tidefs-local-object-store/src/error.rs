//! Error types for the local object store.
//!
//! The [`StoreError`] enum covers all failure modes in the store lifecycle:
//! I/O errors with path context, invalid configuration, read-only violations,
//! oversized payloads, corrupt on-disk records, unsupported format versions,
//! checksum mismatches (both legacy FNV and production BLAKE3), content-
//! address collisions and mismatches, out-of-space conditions, and I/O
//! scheduler pressure refusal.
//!
//! The [`ObjectReadError`] enum provides more specific error reporting for
//! read operations: key-not-found, I/O failures with path context, and
//! content-hash-mismatch indicating bit-rot or store corruption.
//!

use crate::io_scheduler::IoClass;
use crate::IntegrityDigest64;
use crate::ObjectKey;
use crate::ProductionIntegrityDigest;
use std::fmt;
use std::io;
use std::path::PathBuf;
use tidefs_checksum_tree::ObjectDigest;

#[derive(Debug)]
pub enum StoreError {
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidOptions {
        reason: &'static str,
    },
    /// The stored format manifest is incompatible with the running code.
    FormatIncompatible {
        field: &'static str,
        stored: String,
        current: String,
    },
    ReadOnly {
        operation: &'static str,
    },
    PayloadTooLarge {
        len: u64,
        max: u64,
    },
    CorruptHeader {
        segment_id: u64,
        offset: u64,
        reason: &'static str,
    },
    UnsupportedVersion {
        segment_id: u64,
        offset: u64,
        version: u16,
    },
    UnknownRecordKind {
        segment_id: u64,
        offset: u64,
        kind: u16,
    },
    ChecksumMismatch {
        segment_id: u64,
        offset: u64,
        expected: IntegrityDigest64,
        actual: IntegrityDigest64,
    },
    ProductionIntegrityMismatch {
        segment_id: u64,
        offset: u64,
        field: &'static str,
        expected: ProductionIntegrityDigest,
        actual: ProductionIntegrityDigest,
    },
    ContentAddressCollision {
        key: ObjectKey,
    },
    /// Stored content hash does not match the requested key,
    /// indicating bit-rot or store-level corruption.
    ContentAddressMismatch {
        expected: ObjectKey,
        actual: ObjectKey,
    },
    /// Stored per-object BLAKE3 checksum does not match the read payload,
    /// indicating bit-rot or store-level data corruption.
    ObjectChecksumMismatch {
        key: ObjectKey,
        expected: ObjectDigest,
        actual: ObjectDigest,
    },
    InvalidDeadObjectReceipt {
        reason: &'static str,
    },
    NoSpace,
    /// I/O scheduler refused an operation — the class token bucket was depleted.
    PressureRefused {
        class: IoClass,
    },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, path, source } => {
                write!(f, "{operation} {}: {source}", path.display())
            }
            Self::InvalidOptions { reason } => write!(f, "invalid store options: {reason}"),
            Self::FormatIncompatible { field, stored, current } => {
                write!(f, "format incompatible: {field} stored={stored} current={current}")
            }
            Self::ReadOnly { operation } => {
                write!(f, "cannot {operation} through a read-only object store")
            }
            Self::PayloadTooLarge { len, max } => {
                write!(f, "payload has {len} bytes but max object size is {max} bytes")
            }
            Self::CorruptHeader { segment_id, offset, reason } => write!(
                f, "corrupt local object-store header at segment {segment_id}, offset {offset}: {reason}"
            ),
            Self::UnsupportedVersion { segment_id, offset, version } => write!(
                f, "unsupported local object-store record version {version} at segment {segment_id}, offset {offset}"
            ),
            Self::UnknownRecordKind { segment_id, offset, kind } => write!(
                f, "unknown local object-store record kind {kind} at segment {segment_id}, offset {offset}"
            ),
            Self::ChecksumMismatch { segment_id, offset, expected, actual } => write!(
                f, "checksum mismatch at segment {segment_id}, offset {offset}: expected {expected}, actual {actual}"
            ),
            Self::ProductionIntegrityMismatch { segment_id, offset, field, expected, actual } => write!(
                f, "production integrity {field} mismatch at segment {segment_id}, offset {offset}: expected {expected}, actual {actual}"
            ),
            Self::ContentAddressCollision { key } => write!(
                f,
                "content-addressed object key {key} already references different bytes"
            ),
            Self::ContentAddressMismatch { expected, actual } => write!(
                f,
                "content address mismatch: expected key {expected}, actual key {actual} (bit-rot or corruption)"
            ),
            Self::ObjectChecksumMismatch { key, expected, actual } => write!(f, "object checksum mismatch for {key}: expected {expected}, actual {actual}"),
            Self::InvalidDeadObjectReceipt { reason } => {
                write!(f, "invalid dead-object replacement receipt: {reason}")
            }
            Self::NoSpace => write!(f, "no space left on device"),
            Self::PressureRefused { class } => write!(
                f, "I/O scheduler refused {} operation: token bucket depleted", class.label()
            ),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Error returned by object read and attribute operations.
#[derive(Debug)]
pub enum ObjectReadError {
    /// The requested object key is not present in the store.
    NotFound { key: ObjectKey },
    /// An underlying storage I/O failure occurred.
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    /// The stored content's hash does not match the requested key,
    /// indicating bit-rot or store-level corruption.
    ContentMismatch {
        expected: ObjectKey,
        actual: ObjectKey,
    },
}

impl fmt::Display for ObjectReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { key } => write!(f, "object key {key} not found"),
            Self::Io {
                operation,
                path,
                source,
            } => {
                write!(f, "{operation} {}: {source}", path.display())
            }
            Self::ContentMismatch { expected, actual } => write!(
                f,
                "content hash mismatch: expected {expected}, actual {actual}"
            ),
        }
    }
}

impl std::error::Error for ObjectReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<ObjectReadError> for StoreError {
    fn from(e: ObjectReadError) -> Self {
        match e {
            ObjectReadError::Io {
                operation,
                path,
                source,
            } => StoreError::Io {
                operation,
                path,
                source,
            },
            ObjectReadError::NotFound { key: _ } => StoreError::CorruptHeader {
                segment_id: 0,
                offset: 0,
                reason: "object not found during read",
            },
            ObjectReadError::ContentMismatch { expected, actual } => {
                StoreError::ContentAddressMismatch { expected, actual }
            }
        }
    }
}
