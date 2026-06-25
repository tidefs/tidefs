// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fmt;

use tidefs_local_object_store::StoreError;
use tidefs_storage_intent_read_serving::ReadServingDecisionRecord;
use tidefs_types_space_accounting_core::AdmissionResult;
use tidefs_types_vfs_core::{InodeId, NodeKind};

use crate::types::{
    CommittedRootSummary, CrashRecoveryExpectation, FilesystemCommitBoundary, LocalStorageResource,
};

pub const INCREMENTAL_RECEIVE_BASE_ROOT_CONFLICT_OPERATOR_ACTIONS: &str =
    "delete-and-re-receive into a fresh target; create a data-retaining base snapshot if the base content exists but is unprotected; or rollback to a shared ancestor snapshot matching from_root, then retry";

/// Identity fields from an incremental receive stream's `from_root`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IncrementalReceiveBaseRootIdentity {
    pub transaction_id: u64,
    pub generation: u64,
    pub superblock_checksum: u64,
}

impl IncrementalReceiveBaseRootIdentity {
    pub fn from_summary(summary: &CommittedRootSummary) -> Self {
        Self {
            transaction_id: summary.transaction_id,
            generation: summary.generation,
            superblock_checksum: summary.superblock_checksum.get(),
        }
    }
}

/// Unified error type for local filesystem operations.
///
/// `FileSystemError` covers three categories:
///
/// - **I/O errors** — wrapped [`StoreError`] from the object-store layer,
///   including pool-open failures, device faults, and checksum mismatches.
/// - **Integrity errors** — missing or invalid root authentication keys,
///   corrupt committed-root summaries, corrupt inode/directory records,
///   unexpected node kinds, and intent-log replay failures.
/// - **Semantic errors** — filesystem-level violations: `NotFound`,
///   `AlreadyExists`, `NotEmpty`, `QuotaExceeded`, `IsDirectory`,
///   `NotFile`, `FileTooLarge`, `PermissionDenied`, and unsupported
///   operations.
///
/// Most public methods return `crate::Result<T>` which is
/// `std::result::Result<T, FileSystemError>`.
#[derive(Debug)]
pub enum FileSystemError {
    Store(StoreError),
    MissingRootAuthenticationKey {
        env_var: &'static str,
    },
    InvalidRootAuthenticationKey {
        reason: &'static str,
    },
    PublishOutcomeUncertain {
        completed_boundary: FilesystemCommitBoundary,
        recovery_expectation: CrashRecoveryExpectation,
        live_state_reconciled: bool,
        source: StoreError,
    },
    InvalidPath {
        path: String,
        reason: &'static str,
    },
    InvalidName {
        name: Vec<u8>,
        reason: &'static str,
    },
    NotFound {
        path: String,
    },
    AlreadyExists {
        path: String,
    },
    NotDirectory {
        path: String,
    },
    IsDirectory {
        path: String,
    },
    NotFile {
        path: String,
        kind: NodeKind,
    },
    SnapshotAlreadyExists {
        name: String,
    },
    SnapshotNotFound {
        name: String,
    },
    BookmarkNotFound {
        name: String,
    },
    CloneOriginRequired {
        operation: &'static str,
    },
    HoldOnBookmark {
        name: String,
    },
    NotAClone {
        name: String,
    },
    SnapshotHeld {
        name: String,
        hold_count: u32,
        hold_tag: Option<String>,
    },

    DirectoryNotEmpty {
        path: String,
    },
    Unsupported {
        operation: &'static str,
        reason: &'static str,
    },
    IncrementalReceiveBaseRootConflict {
        from_root: IncrementalReceiveBaseRootIdentity,
        found_in_recovery_audit: bool,
        protected_by_data_retaining_snapshot_or_clone: bool,
        operator_action_guidance: &'static str,
    },
    NoSpace {
        resource: LocalStorageResource,
        requested: u64,
        available: u64,
        capacity: u64,
        allocated: u64,
    },
    RetentionDebt {
        required: usize,
        available: usize,
        missing: usize,
    },
    CorruptState {
        reason: &'static str,
    },
    /// Content on an inode has been detected as corrupt and could not
    /// be repaired automatically. Reads return EIO.
    CorruptContent {
        inode_id: InodeId,
    },
    Decode {
        object: &'static str,
        reason: &'static str,
    },
    QuotaExceeded {
        path: String,
        limit: u64,
        usage: u64,
        delta: u64,
        kind: QuotaExceededKind,
    },
    SizeOverflow {
        requested: u64,
    },
    /// Runtime read-serving refused a byte-serving path before content was
    /// fetched from cache, local storage, or a remote source.
    ReadServingRefused {
        decision: Box<ReadServingDecisionRecord>,
    },
    /// Claim rejected by the obligation ledger — authority scarcity gate.
    /// The request has been denied because the budget domain is exhausted
    /// after accounting for current claims and active reserves.
    ClaimRejected {
        budget_domain: String,
        reason: &'static str,
    },
    /// POSIX ACL xattr validation failed.
    AclValidationFailed {
        name: Vec<u8>,
        reason: &'static str,
    },
    /// Mount refused because the running code's format version is outside
    /// the filesystem's compatibility window.  This is the downgrade fence:
    /// older code cannot mount a filesystem written by newer code, and
    /// newer code may refuse a filesystem whose minimum version it cannot
    /// satisfy.
    FormatVersionIncompatible {
        running_version: u16,
        filesystem_min: u16,
        filesystem_max: u16,
    },
    /// Mount refused by the dataset lifecycle state machine (e.g. dataset
    /// is Destroying, Tombstone, or Poisoned).
    LifecycleError {
        reason: String,
    },
    /// Dataset import refused: the pool is encrypted and the encryption
    /// key was not provided.  The dataset is "locked" — its committed-root
    /// chain is valid but reads and writes are gated until the correct
    /// key is supplied (e.g. via `tidefsctl unlock` or operator key-load).
    DatasetLocked {
        reason: String,
    },
    /// Write admission rejected by the performance contract — dirty
    /// byte, op, age, or permit cap has been reached.  Writers must
    /// wait for a commit group SYNC to release dirty debt.
    DirtyAdmissionRejected {
        reason: String,
    },
    /// Distributed-stream sender authority fields are invalid or malformed
    /// (zero pool UUID, zero epoch, or zero membership generation).
    MalformedSenderAuthority {
        reason: &'static str,
    },
    /// A distributed receive stream carries cross-pool sender authority but
    /// no per-receive authorization was provided for that sender pool.
    CrossPoolReceiveUnauthorized {
        sender_pool_uuid: [u8; 16],
    },
    /// A cross-pool receive authorization was provided but one or more fields
    /// do not match the stream's declared sender authority.
    CrossPoolReceiveAuthorizationMismatch {
        field: &'static str,
    },
    /// The sender membership generation or pool epoch is older than the
    /// receiver can accept.
    StaleSenderGeneration {
        reason: &'static str,
    },
    /// Local readback or degraded-read source selection could not verify
    /// the pool placement receipt for an object key because the pool is
    /// unavailable (I/O error, device fault, or pool not open).
    ReceiptAuthorityUnavailable {
        object_key: tidefs_local_object_store::ObjectKey,
        expected_generation: u64,
    },
    /// No placement receipt exists in the pool for the referenced object
    /// key. The chunk ref carries a receipt generation that was never
    /// committed by the pool.
    ReceiptAuthorityMissing {
        object_key: tidefs_local_object_store::ObjectKey,
        expected_generation: u64,
    },
    /// The pool's placement receipt generation differs from the chunk
    /// ref's recorded generation. A replacement may have been written
    /// without a durable receipt, or the receipt was rotated too early.
    ReceiptAuthorityStale {
        object_key: tidefs_local_object_store::ObjectKey,
        expected_generation: u64,
        observed_generation: u64,
    },
    /// The pool receipt carries generation zero (synthetic/uncommitted)
    /// while the chunk ref expects a committed receipt.
    ReceiptAuthoritySynthetic {
        object_key: tidefs_local_object_store::ObjectKey,
        expected_generation: u64,
    },
    /// The pool receipt's redundancy policy is not well-formed (e.g.
    /// zero copies or zero data/parity shards).
    ReceiptAuthorityMalformedPolicy {
        object_key: tidefs_local_object_store::ObjectKey,
        generation: u64,
    },
    /// The pool receipt's target count is less than the policy's
    /// required placement width.
    ReceiptAuthorityUnderWidth {
        object_key: tidefs_local_object_store::ObjectKey,
        generation: u64,
        target_count: u16,
        required_width: u16,
    },
    /// The pool receipt's target count exceeds the policy's required
    /// placement width.
    ReceiptAuthorityOverWidth {
        object_key: tidefs_local_object_store::ObjectKey,
        generation: u64,
        target_count: u16,
        required_width: u16,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaExceededKind {
    HardBytes,
    HardInodes,
    Reservation,
}

impl fmt::Display for FileSystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(err) => write!(f, "local object-store error: {err}"),
            Self::MissingRootAuthenticationKey { env_var } => write!(
                f,
                "missing root authentication key: set {env_var} to a 32-byte hex key or use an explicit root authentication key API"
            ),
            Self::InvalidRootAuthenticationKey { reason } => {
                write!(f, "invalid root authentication key: {reason}")
            }
            Self::PublishOutcomeUncertain {
                completed_boundary,
                recovery_expectation,
                live_state_reconciled,
                source,
            } => write!(
                f,
                "publish outcome is uncertain after {}; recovery may select {}; live state reconciled: {live_state_reconciled}; source: {source}",
                completed_boundary.human_name(),
                recovery_expectation.human_name()
            ),
            Self::InvalidPath { path, reason } => write!(f, "invalid path `{path}`: {reason}"),
            Self::InvalidName { name, reason } => {
                write!(
                    f,
                    "invalid path component `{}`: {reason}",
                    String::from_utf8_lossy(name)
                )
            }
            Self::NotFound { path } => write!(f, "path not found: {path}"),
            Self::AlreadyExists { path } => write!(f, "path already exists: {path}"),
            Self::NotDirectory { path } => write!(f, "path is not a directory: {path}"),
            Self::IsDirectory { path } => write!(f, "path is a directory: {path}"),
            Self::NotFile { path, kind } => {
                write!(f, "path is not a file-like inode: {path} has kind {kind:?}")
            }
            Self::SnapshotAlreadyExists { name } => write!(f, "snapshot already exists: {name}"),
            Self::SnapshotNotFound { name } => write!(f, "snapshot not found: {name}"),
            Self::BookmarkNotFound { name } => write!(f, "bookmark not found: {name}"),
            Self::CloneOriginRequired { operation } => write!(f, "clone origin required for: {operation}"),
            Self::HoldOnBookmark { name } => write!(f, "cannot hold a bookmark: {name}"),
            Self::NotAClone { name } => write!(f, "not a clone: {name}"),
            Self::SnapshotHeld { name, hold_count, hold_tag } => {
                if let Some(ref tag) = hold_tag {
                    write!(f, "snapshot '{name}' is held by {tag} ({hold_count} active hold(s))")
                } else {
                    write!(f, "snapshot '{name}' is held ({hold_count} active hold(s))")
                }
            }
            Self::DirectoryNotEmpty { path } => write!(f, "directory is not empty: {path}"),
            Self::Unsupported { operation, reason } => {
                write!(f, "unsupported {operation}: {reason}")
            }
            Self::IncrementalReceiveBaseRootConflict {
                from_root,
                found_in_recovery_audit,
                protected_by_data_retaining_snapshot_or_clone,
                operator_action_guidance,
            } => write!(
                f,
                "incremental receive conflicts with non-empty target: from_root transaction_id={} generation={} superblock_checksum=0x{:016x}; recovery_audit_found={found_in_recovery_audit}; protection_found={protected_by_data_retaining_snapshot_or_clone}; operator actions: {operator_action_guidance}",
                from_root.transaction_id,
                from_root.generation,
                from_root.superblock_checksum,
            ),
            Self::NoSpace {
                resource,
                requested,
                available,
                capacity,
                allocated,
            } => write!(
                f,
                "no space left for {}: requested {requested}, available {available}, capacity {capacity}, allocated {allocated}",
                resource.human_name()
            ),
            Self::RetentionDebt {
                required,
                available,
                missing,
            } => write!(
                f,
                "cannot reclaim local storage while retention debt remains: required {required}, available {available}, missing {missing}"
            ),
            Self::CorruptContent { inode_id } => {
                write!(f, "content corrupt on inode {}: repair attempted, file truncated or marked corrupted", inode_id.get())
            }
            Self::CorruptState { reason } => write!(f, "corrupt local filesystem state: {reason}"),
            Self::Decode { object, reason } => write!(f, "could not decode {object}: {reason}"),
            Self::QuotaExceeded { path, limit, usage, delta, kind } => {
                write!(
                    f,
                    "quota exceeded on {path}: {kind:?} limit={limit}, usage={usage}, delta={delta}"
                )
            }
            Self::SizeOverflow { requested } => {
                write!(f, "file size or offset is too large: {requested}")
            }
            Self::ReadServingRefused { decision } => write!(
                f,
                "read-serving refused bytes: state={:?} requested_source={:?} refusal={:?} rejected=0x{:x}",
                decision.decision_state,
                decision.requested_source,
                decision.refusal,
                decision.rejected_reasons.0,
            ),
            Self::ClaimRejected {
                budget_domain,
                reason,
            } => write!(f, "claim rejected for budget domain `{budget_domain}`: {reason}"),
            Self::AclValidationFailed { name, reason } => {
                write!(
                    f,
                    "ACL xattr validation failed for `{}`: {reason}",
                    String::from_utf8_lossy(name)
                )
            }
            Self::FormatVersionIncompatible {
                running_version,
                filesystem_min,
                filesystem_max,
            } => write!(
                f,
                "format version incompatible: running code is v{running_version}, filesystem requires min=v{filesystem_min} max=v{filesystem_max}"
            ),
            Self::LifecycleError { reason } => write!(f, "mount refused by lifecycle: {reason}"),
            Self::DatasetLocked { reason } => write!(f, "dataset is locked: {reason}"),
            Self::DirtyAdmissionRejected { reason } => write!(f, "write admission rejected: {reason}"),
            Self::MalformedSenderAuthority { reason } => {
                write!(f, "malformed sender authority in receive stream: {reason}")
            }
            Self::CrossPoolReceiveUnauthorized { sender_pool_uuid } => {
                write!(f, "cross-pool receive not authorized: sender pool UUID ")?;
                for byte in sender_pool_uuid {
                    write!(f, "{byte:02x}")?;
                }
                write!(f, " is not the local pool and no exact authorization was provided")
            }
            Self::CrossPoolReceiveAuthorizationMismatch { field } => {
                write!(f, "cross-pool receive authorization mismatch: {field} does not match the stream sender authority")
            }
            Self::StaleSenderGeneration { reason } => {
                write!(f, "stale sender generation: {reason}")
            }
            Self::ReceiptAuthorityUnavailable { object_key, expected_generation } => {
                write!(f, "placement receipt authority unavailable for object key {object_key:?}: expected generation {expected_generation}")
            }
            Self::ReceiptAuthorityMissing { object_key, expected_generation } => {
                write!(f, "placement receipt missing for object key {object_key:?}: expected generation {expected_generation}")
            }
            Self::ReceiptAuthorityStale { object_key, expected_generation, observed_generation } => {
                write!(f, "placement receipt stale for object key {object_key:?}: expected generation {expected_generation}, observed {observed_generation}")
            }
            Self::ReceiptAuthoritySynthetic { object_key, expected_generation } => {
                write!(f, "placement receipt synthetic for object key {object_key:?}: expected generation {expected_generation}, pool receipt generation is zero")
            }
            Self::ReceiptAuthorityMalformedPolicy { object_key, generation } => {
                write!(f, "placement receipt malformed policy for object key {object_key:?} generation {generation}")
            }
            Self::ReceiptAuthorityUnderWidth { object_key, generation, target_count, required_width } => {
                write!(f, "placement receipt under-width for object key {object_key:?} generation {generation}: target_count {target_count} < required_width {required_width}")
            }
            Self::ReceiptAuthorityOverWidth { object_key, generation, target_count, required_width } => {
                write!(f, "placement receipt over-width for object key {object_key:?} generation {generation}: target_count {target_count} > required_width {required_width}")
            }
        }
    }
}

impl std::error::Error for FileSystemError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(err) | Self::PublishOutcomeUncertain { source: err, .. } => Some(err),
            _ => None,
        }
    }
}

impl FileSystemError {
    pub const fn keeps_live_state_on_error(&self) -> bool {
        matches!(
            self,
            Self::PublishOutcomeUncertain {
                live_state_reconciled: true,
                ..
            }
        )
    }
}

impl From<StoreError> for FileSystemError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<crate::quota::QuotaDecision> for FileSystemError {
    fn from(d: crate::quota::QuotaDecision) -> Self {
        match d {
            crate::quota::QuotaDecision::HardBytesExceeded {
                limit_bytes,
                current_bytes,
                delta_bytes,
            } => FileSystemError::QuotaExceeded {
                path: String::new(),
                limit: limit_bytes,
                usage: current_bytes,
                delta: delta_bytes,
                kind: QuotaExceededKind::HardBytes,
            },
            crate::quota::QuotaDecision::HardInodesExceeded {
                limit_inodes,
                current_inodes,
            } => FileSystemError::QuotaExceeded {
                path: String::new(),
                limit: limit_inodes,
                usage: current_inodes,
                delta: 0,
                kind: QuotaExceededKind::HardInodes,
            },
            crate::quota::QuotaDecision::ReservationViolation {
                reserved_bytes,
                free_bytes: _,
            } => FileSystemError::QuotaExceeded {
                path: String::new(),
                limit: reserved_bytes,
                usage: 0,
                delta: 0,
                kind: QuotaExceededKind::Reservation,
            },
            _ => panic!("called From<QuotaDecision> on a non-refusal decision"),
        }
    }
}

impl From<AdmissionResult> for FileSystemError {
    fn from(r: AdmissionResult) -> Self {
        match r {
            AdmissionResult::QuotaExceeded {
                quota_bytes,
                current_alloc_bytes,
                needed_bytes,
            } => FileSystemError::QuotaExceeded {
                path: String::new(),
                limit: quota_bytes,
                usage: current_alloc_bytes,
                delta: needed_bytes,
                kind: QuotaExceededKind::HardBytes,
            },
            AdmissionResult::PhysicalCapacityExceeded {
                phys_avail_bytes,
                needed_bytes,
            } => FileSystemError::NoSpace {
                resource: LocalStorageResource::ContentBytes,
                requested: needed_bytes,
                available: phys_avail_bytes,
                capacity: 0,
                allocated: 0,
            },
            AdmissionResult::Allowed => panic!("called From<AdmissionResult> on Allowed"),
        }
    }
}

impl From<tidefs_dataset_lifecycle::LifecycleError> for FileSystemError {
    fn from(e: tidefs_dataset_lifecycle::LifecycleError) -> Self {
        FileSystemError::LifecycleError {
            reason: format!("{e}"),
        }
    }
}

impl From<tidefs_performance_contract::AdmissionError> for FileSystemError {
    fn from(e: tidefs_performance_contract::AdmissionError) -> Self {
        FileSystemError::DirtyAdmissionRejected {
            reason: format!("{e:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CrashRecoveryExpectation, FilesystemCommitBoundary, LocalStorageResource};
    use std::error::Error;
    use tidefs_local_object_store::StoreError;
    use tidefs_types_vfs_core::{InodeId, NodeKind};

    // ── Error creation ──────────────────────────────────────────────────

    #[test]
    fn test_not_found_creation() {
        let err = FileSystemError::NotFound {
            path: "/tmp/missing".to_string(),
        };
        // Verify the path is accessible via matching
        match &err {
            FileSystemError::NotFound { path } => assert_eq!(path, "/tmp/missing"),
            _ => panic!("expected NotFound variant"),
        }
    }

    #[test]
    fn test_not_file_creation() {
        let err = FileSystemError::NotFile {
            path: "/tmp/not_a_file".to_string(),
            kind: NodeKind::Dir,
        };
        match &err {
            FileSystemError::NotFile { path, kind } => {
                assert_eq!(path, "/tmp/not_a_file");
                assert_eq!(*kind, NodeKind::Dir);
            }
            _ => panic!("expected NotFile variant"),
        }
    }

    #[test]
    fn test_no_space_creation() {
        let err = FileSystemError::NoSpace {
            resource: LocalStorageResource::ContentBytes,
            requested: 4096,
            available: 1024,
            capacity: 1048576,
            allocated: 1047552,
        };
        match &err {
            FileSystemError::NoSpace {
                resource,
                requested,
                available,
                capacity,
                allocated,
            } => {
                assert_eq!(*resource, LocalStorageResource::ContentBytes);
                assert_eq!(*requested, 4096);
                assert_eq!(*available, 1024);
                assert_eq!(*capacity, 1048576);
                assert_eq!(*allocated, 1047552);
            }
            _ => panic!("expected NoSpace variant"),
        }
    }

    #[test]
    fn test_quota_exceeded_creation() {
        let err = FileSystemError::QuotaExceeded {
            path: "/quota_dir".to_string(),
            limit: 100000,
            usage: 99999,
            delta: 2,
            kind: QuotaExceededKind::HardBytes,
        };
        match &err {
            FileSystemError::QuotaExceeded {
                path,
                limit,
                usage,
                delta,
                kind,
            } => {
                assert_eq!(path, "/quota_dir");
                assert_eq!(*limit, 100000);
                assert_eq!(*usage, 99999);
                assert_eq!(*delta, 2);
                assert_eq!(*kind, QuotaExceededKind::HardBytes);
            }
            _ => panic!("expected QuotaExceeded variant"),
        }
    }

    // ── Display / Debug formatting ──────────────────────────────────────

    #[test]
    fn test_display_output_non_empty() {
        let errors: Vec<FileSystemError> = vec![
            FileSystemError::NotFound {
                path: "/a".to_string(),
            },
            FileSystemError::AlreadyExists {
                path: "/b".to_string(),
            },
            FileSystemError::NotDirectory {
                path: "/c".to_string(),
            },
            FileSystemError::IsDirectory {
                path: "/d".to_string(),
            },
            FileSystemError::DirectoryNotEmpty {
                path: "/e".to_string(),
            },
            FileSystemError::Unsupported {
                operation: "test_op",
                reason: "not yet",
            },
            FileSystemError::CorruptState {
                reason: "bad state",
            },
            FileSystemError::SizeOverflow { requested: 999 },
            FileSystemError::FormatVersionIncompatible {
                running_version: 1,
                filesystem_min: 2,
                filesystem_max: 5,
            },
            FileSystemError::LifecycleError {
                reason: "destroying".to_string(),
            },
        ];

        for err in &errors {
            let display = format!("{err}");
            assert!(
                !display.is_empty(),
                "Display should be non-empty for {err:?}"
            );
        }
    }

    #[test]
    fn test_debug_output_non_empty() {
        let errors: Vec<FileSystemError> = vec![
            FileSystemError::NotFound {
                path: "/x".to_string(),
            },
            FileSystemError::Store(StoreError::NoSpace),
            FileSystemError::InvalidPath {
                path: "bad".to_string(),
                reason: "too short",
            },
            FileSystemError::CorruptContent {
                inode_id: InodeId::new(42),
            },
            FileSystemError::Decode {
                object: "inode",
                reason: "invalid tag",
            },
        ];

        for err in &errors {
            let debug = format!("{err:?}");
            assert!(!debug.is_empty(), "Debug should be non-empty for {err:?}");
        }
    }

    #[test]
    fn test_display_contains_path() {
        let err = FileSystemError::NotFound {
            path: "/unique/path/xyz".to_string(),
        };
        let display = format!("{err}");
        assert!(
            display.contains("/unique/path/xyz"),
            "Display should contain the path: got '{display}'"
        );

        let err2 = FileSystemError::AlreadyExists {
            path: "/another/path".to_string(),
        };
        let display2 = format!("{err2}");
        assert!(
            display2.contains("/another/path"),
            "Display should contain the path: got '{display2}'"
        );
    }

    // ── StoreError wrapping ────────────────────────────────────────────

    #[test]
    fn test_from_store_error() {
        let store_err = StoreError::NoSpace;
        let fs_err = FileSystemError::from(store_err);
        assert!(matches!(fs_err, FileSystemError::Store(..)));
    }

    #[test]
    fn test_store_error_source() {
        let store_err = StoreError::ReadOnly { operation: "write" };
        let fs_err = FileSystemError::Store(store_err);
        let source = fs_err.source();
        assert!(source.is_some(), "Store variant should have a source error");
        let source_msg = format!("{}", source.unwrap());
        assert!(
            source_msg.contains("write"),
            "source error should reference operation: got '{source_msg}'"
        );
    }

    // ── Error equivalence / matching ────────────────────────────────────

    #[test]
    fn test_match_not_file_extracts_path_and_kind() {
        let err = FileSystemError::NotFile {
            path: "/data/pipe".to_string(),
            kind: NodeKind::Fifo,
        };
        let (extracted_path, extracted_kind) = match err {
            FileSystemError::NotFile { path, kind } => (path, kind),
            _ => panic!("expected NotFile"),
        };
        assert_eq!(extracted_path, "/data/pipe");
        assert_eq!(extracted_kind, NodeKind::Fifo);
    }

    #[test]
    fn test_match_distinguishes_is_dir_from_not_dir() {
        let is_dir = FileSystemError::IsDirectory {
            path: "/tmp/dir".to_string(),
        };
        let not_dir = FileSystemError::NotDirectory {
            path: "/tmp/file".to_string(),
        };

        match &is_dir {
            FileSystemError::IsDirectory { path } => assert_eq!(path, "/tmp/dir"),
            _ => panic!("expected IsDirectory"),
        }
        match &not_dir {
            FileSystemError::NotDirectory { path } => assert_eq!(path, "/tmp/file"),
            _ => panic!("expected NotDirectory"),
        }
    }

    #[test]
    fn test_keeps_live_state_returns_true_when_reconciled() {
        let err = FileSystemError::PublishOutcomeUncertain {
            completed_boundary: FilesystemCommitBoundary::RootCommitSynced,
            recovery_expectation: CrashRecoveryExpectation::NewCommittedRoot,
            live_state_reconciled: true,
            source: StoreError::NoSpace,
        };
        assert!(
            err.keeps_live_state_on_error(),
            "keeps_live_state_on_error should return true when live_state_reconciled is true"
        );

        let err2 = FileSystemError::PublishOutcomeUncertain {
            completed_boundary: FilesystemCommitBoundary::TransactionObjectsWritten,
            recovery_expectation: CrashRecoveryExpectation::OldCommittedRoot,
            live_state_reconciled: false,
            source: StoreError::NoSpace,
        };
        assert!(
            !err2.keeps_live_state_on_error(),
            "keeps_live_state_on_error should return false when live_state_reconciled is false"
        );
    }

    // ── Edge cases ─────────────────────────────────────────────────────

    #[test]
    fn test_invalid_path_empty_string() {
        let err = FileSystemError::InvalidPath {
            path: String::new(),
            reason: "empty",
        };
        match &err {
            FileSystemError::InvalidPath { path, reason } => {
                assert!(path.is_empty());
                assert_eq!(*reason, "empty");
            }
            _ => panic!("expected InvalidPath"),
        }
        // Display should still work for empty path
        let display = format!("{err}");
        assert!(!display.is_empty());
    }

    #[test]
    fn test_invalid_name_non_utf8() {
        // 0xFF is never valid UTF-8
        let invalid_name: Vec<u8> = vec![0x48, 0x65, 0x6C, 0xFF, 0x6F]; // "Hel\xFFo"
        let err = FileSystemError::InvalidName {
            name: invalid_name.clone(),
            reason: "non-utf8",
        };
        match &err {
            FileSystemError::InvalidName { name, reason } => {
                assert_eq!(name, &invalid_name);
                assert_eq!(*reason, "non-utf8");
            }
            _ => panic!("expected InvalidName"),
        }
        // Display should use String::from_utf8_lossy
        let display = format!("{err}");
        assert!(!display.is_empty());
    }

    #[test]
    fn test_publish_outcome_uncertain_creation() {
        let err = FileSystemError::PublishOutcomeUncertain {
            completed_boundary: FilesystemCommitBoundary::TransactionObjectsSynced,
            recovery_expectation: CrashRecoveryExpectation::OldOrNewCommittedRoot,
            live_state_reconciled: false,
            source: StoreError::NoSpace,
        };
        match &err {
            FileSystemError::PublishOutcomeUncertain {
                completed_boundary,
                recovery_expectation,
                live_state_reconciled,
                source: _,
            } => {
                assert_eq!(
                    *completed_boundary,
                    FilesystemCommitBoundary::TransactionObjectsSynced
                );
                assert_eq!(
                    *recovery_expectation,
                    CrashRecoveryExpectation::OldOrNewCommittedRoot
                );
                assert!(!live_state_reconciled);
            }
            _ => panic!("expected PublishOutcomeUncertain"),
        }
        // Verify Display is non-empty
        let display = format!("{err}");
        assert!(!display.is_empty());
    }

    #[test]
    fn test_quota_exceeded_kind_discriminants() {
        let hard_bytes = QuotaExceededKind::HardBytes;
        let hard_inodes = QuotaExceededKind::HardInodes;
        let reservation = QuotaExceededKind::Reservation;

        // All three variants should be distinct
        assert_ne!(hard_bytes, hard_inodes);
        assert_ne!(hard_inodes, reservation);
        assert_ne!(hard_bytes, reservation);

        // Each should be equal to itself
        assert_eq!(hard_bytes, QuotaExceededKind::HardBytes);
        assert_eq!(hard_inodes, QuotaExceededKind::HardInodes);
        assert_eq!(reservation, QuotaExceededKind::Reservation);

        // Debug output should be non-empty for each
        assert!(!format!("{hard_bytes:?}").is_empty());
        assert!(!format!("{hard_inodes:?}").is_empty());
        assert!(!format!("{reservation:?}").is_empty());
    }

    #[test]
    fn test_acl_validation_failed_creation() {
        let err = FileSystemError::AclValidationFailed {
            name: b"system.posix_acl_access".to_vec(),
            reason: "malformed ACE",
        };
        match &err {
            FileSystemError::AclValidationFailed { name, reason } => {
                assert_eq!(name, b"system.posix_acl_access");
                assert_eq!(*reason, "malformed ACE");
            }
            _ => panic!("expected AclValidationFailed"),
        }
        let display = format!("{err}");
        assert!(!display.is_empty());
    }

    #[test]
    fn test_corrupt_content_creation() {
        let err = FileSystemError::CorruptContent {
            inode_id: InodeId::new(12345),
        };
        match &err {
            FileSystemError::CorruptContent { inode_id } => {
                assert_eq!(inode_id.get(), 12345);
            }
            _ => panic!("expected CorruptContent"),
        }
    }

    // ── Additional coverage (s12 #4226) ──────────────────────────────────

    #[test]
    fn construct_publish_outcome_uncertain() {
        let store_err = StoreError::InvalidOptions { reason: "test" };
        let err = FileSystemError::PublishOutcomeUncertain {
            completed_boundary: FilesystemCommitBoundary::TransactionObjectsWritten,
            recovery_expectation: CrashRecoveryExpectation::OldOrNewCommittedRoot,
            live_state_reconciled: true,
            source: store_err,
        };
        assert!(err.keeps_live_state_on_error());
    }

    #[test]
    fn construct_store_from_invalid_options() {
        let store_err = StoreError::InvalidOptions {
            reason: "test reason",
        };
        let err = FileSystemError::Store(store_err);
        match err {
            FileSystemError::Store(_) => {}
            _ => panic!("expected Store variant"),
        }
    }

    #[test]
    fn display_store_contains_object_store_error() {
        let store_err = StoreError::ReadOnly { operation: "write" };
        let err = FileSystemError::Store(store_err);
        let s = format!("{err}");
        assert!(s.contains("local object-store error"));
        assert!(s.contains("write"));
    }

    #[test]
    fn display_format_version_incompatible_contains_versions() {
        let err = FileSystemError::FormatVersionIncompatible {
            running_version: 1,
            filesystem_min: 2,
            filesystem_max: 5,
        };
        let s = format!("{err}");
        assert!(s.contains("v1"));
        assert!(s.contains("v2"));
        assert!(s.contains("v5"));
    }

    #[test]
    fn display_invalid_name_contains_name_bytes() {
        let err = FileSystemError::InvalidName {
            name: b"bad\x00name".to_vec(),
            reason: "null byte",
        };
        let s = format!("{err}");
        assert!(s.contains("bad"));
        assert!(s.contains("null byte"));
    }

    #[test]
    fn display_already_exists_contains_path() {
        let err = FileSystemError::AlreadyExists {
            path: "/tmp/dup".into(),
        };
        let s = format!("{err}");
        assert!(s.contains("already exists"));
        assert!(s.contains("/tmp/dup"));
    }

    #[test]
    fn display_no_space_reports_resource_and_counts() {
        let err = FileSystemError::NoSpace {
            resource: LocalStorageResource::ContentBytes,
            requested: 1024,
            available: 512,
            capacity: 4096,
            allocated: 3584,
        };
        let s = format!("{err}");
        assert!(s.contains("no space left"));
        assert!(s.contains("content bytes"));
        assert!(s.contains("1024"));
        assert!(s.contains("512"));
    }

    #[test]
    fn error_source_not_found_returns_none() {
        let err = FileSystemError::NotFound { path: "/x".into() };
        assert!(err.source().is_none());
    }

    #[test]
    fn error_source_publish_outcome_uncertain_returns_some() {
        let store_err = StoreError::InvalidOptions { reason: "test" };
        let err = FileSystemError::PublishOutcomeUncertain {
            completed_boundary: FilesystemCommitBoundary::TransactionObjectsWritten,
            recovery_expectation: CrashRecoveryExpectation::OldCommittedRoot,
            live_state_reconciled: false,
            source: store_err,
        };
        assert!(err.source().is_some());
    }

    #[test]
    fn keeps_live_state_false_when_not_reconciled() {
        let store_err = StoreError::InvalidOptions { reason: "x" };
        let err = FileSystemError::PublishOutcomeUncertain {
            completed_boundary: FilesystemCommitBoundary::TransactionObjectsSynced,
            recovery_expectation: CrashRecoveryExpectation::OldCommittedRoot,
            live_state_reconciled: false,
            source: store_err,
        };
        assert!(!err.keeps_live_state_on_error());
    }

    #[test]
    fn keeps_live_state_false_for_other_variants() {
        let err = FileSystemError::NotFound { path: "/".into() };
        assert!(!err.keeps_live_state_on_error());

        let err = FileSystemError::CorruptState { reason: "bad root" };
        assert!(!err.keeps_live_state_on_error());
    }

    #[test]
    fn from_admission_quota_exceeded_maps_to_quota_exceeded() {
        let ar = AdmissionResult::QuotaExceeded {
            quota_bytes: 1000,
            current_alloc_bytes: 900,
            needed_bytes: 200,
        };
        let err = FileSystemError::from(ar);
        match err {
            FileSystemError::QuotaExceeded {
                limit,
                usage,
                delta,
                kind,
                ..
            } => {
                assert_eq!(limit, 1000);
                assert_eq!(usage, 900);
                assert_eq!(delta, 200);
                assert_eq!(kind, QuotaExceededKind::HardBytes);
            }
            _ => panic!("expected QuotaExceeded variant"),
        }
    }

    #[test]
    fn from_admission_physical_capacity_maps_to_no_space() {
        let ar = AdmissionResult::PhysicalCapacityExceeded {
            phys_avail_bytes: 100,
            needed_bytes: 500,
        };
        let err = FileSystemError::from(ar);
        match err {
            FileSystemError::NoSpace {
                resource: _,
                requested,
                available,
                ..
            } => {
                assert_eq!(requested, 500);
                assert_eq!(available, 100);
            }
            _ => panic!("expected NoSpace variant"),
        }
    }

    #[test]
    fn debug_output_nonempty_for_representative_variants() {
        let variants: &[FileSystemError] = &[
            FileSystemError::CorruptState {
                reason: "bad state",
            },
            FileSystemError::Decode {
                object: "inode",
                reason: "bad magic",
            },
            FileSystemError::Unsupported {
                operation: "link",
                reason: "not yet",
            },
            FileSystemError::SizeOverflow {
                requested: u64::MAX,
            },
            FileSystemError::ClaimRejected {
                budget_domain: "default".into(),
                reason: "exhausted",
            },
            FileSystemError::DirectoryNotEmpty {
                path: "/full".into(),
            },
            FileSystemError::RetentionDebt {
                required: 10,
                available: 5,
                missing: 5,
            },
        ];
        for err in variants {
            let debug_str = format!("{err:?}");
            assert!(!debug_str.is_empty(), "Debug output empty for {err}");
        }
    }

    #[test]
    fn lifecycle_error_displays_reason() {
        let err = FileSystemError::LifecycleError {
            reason: "dataset is tombstoned".into(),
        };
        let s = format!("{err}");
        assert!(s.contains("tombstoned"));
    }
}
