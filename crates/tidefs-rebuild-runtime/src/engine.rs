//! DataMovementEngine: BLAKE3-verified chunk transfer between replicas.
//!
//! Copies object data from a healthy source replica to a target placement,
//! verifying source and destination checksums match the expected digest
//! before marking the transfer complete.

use crate::progress::BackfillProgress;
use crate::task::BackfillTask;
use std::error::Error;
use std::fmt;
use tidefs_membership_epoch::MemberId;
use tidefs_object_io::{ObjectKey, ObjectStore};
use tidefs_replication_model::PlacementReceiptRef;

/// Maximum bytes to report in a single progress tick.
pub const DEFAULT_CHUNK_SIZE: usize = 65536;

/// Errors produced by the data-movement engine.
#[derive(Debug)]
pub enum EngineError {
    /// The source store does not contain the requested object.
    ObjectNotFound(ObjectKey),
    /// BLAKE3 checksum of source data does not match expectations.
    SourceChecksumMismatch {
        expected_hex: String,
        actual_hex: String,
    },
    /// BLAKE3 checksum of destination data does not match the source.
    DestinationChecksumMismatch {
        source_hex: String,
        destination_hex: String,
    },
    /// An error from the underlying object store.
    StoreError(Box<dyn Error + Send + Sync>),
    /// Receipt-bound execution was asked to use a synthetic placeholder.
    SyntheticReceiptRef { object_id: u64 },
    /// The receiptless object-store executor was asked to run a real
    /// receipt-bound movement task.
    ReceiptBoundTaskRequiresReceiptSource { object_id: u64 },
    /// The receipt source could not fetch bytes from the selected member.
    ReceiptSourceError {
        source_member: MemberId,
        object_id: u64,
        message: String,
    },
    /// The task and receipt disagree about the payload length.
    ReceiptTaskLengthMismatch {
        object_id: u64,
        task_len: u64,
        receipt_len: u64,
    },
    /// The receipt-bound source returned fewer or more bytes than the receipt
    /// authorizes.
    ReceiptPayloadLengthMismatch {
        object_id: u64,
        expected_len: u64,
        actual_len: u64,
    },
    /// The receipt-bound source returned bytes that do not match the durable
    /// placement receipt digest.
    ReceiptPayloadDigestMismatch {
        object_id: u64,
        expected_hex: String,
        actual_hex: String,
    },
    /// The task has no payload (zero-length object).
    EmptyPayload,
    /// Invalid state transition during progress tracking.
    ProgressError(&'static str),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectNotFound(key) => write!(f, "source object not found: {key}"),
            Self::SourceChecksumMismatch {
                expected_hex,
                actual_hex,
            } => write!(
                f,
                "source checksum mismatch: expected {expected_hex}, got {actual_hex}"
            ),
            Self::DestinationChecksumMismatch {
                source_hex,
                destination_hex,
            } => write!(
                f,
                "destination checksum mismatch: source {source_hex}, destination {destination_hex}"
            ),
            Self::StoreError(err) => write!(f, "object store error: {err}"),
            Self::SyntheticReceiptRef { object_id } => write!(
                f,
                "receipt-bound rebuild fetch for object {object_id} requires non-synthetic placement receipt"
            ),
            Self::ReceiptBoundTaskRequiresReceiptSource { object_id } => write!(
                f,
                "receipt-bound rebuild task for object {object_id} must use execute_from_receipt_source"
            ),
            Self::ReceiptSourceError {
                source_member,
                object_id,
                message,
            } => write!(
                f,
                "receipt-bound source fetch from member {} for object {object_id} failed: {message}",
                source_member.0
            ),
            Self::ReceiptTaskLengthMismatch {
                object_id,
                task_len,
                receipt_len,
            } => write!(
                f,
                "receipt-bound task length mismatch for object {object_id}: task {task_len}, receipt {receipt_len}"
            ),
            Self::ReceiptPayloadLengthMismatch {
                object_id,
                expected_len,
                actual_len,
            } => write!(
                f,
                "receipt-bound payload length mismatch for object {object_id}: expected {expected_len}, got {actual_len}"
            ),
            Self::ReceiptPayloadDigestMismatch {
                object_id,
                expected_hex,
                actual_hex,
            } => write!(
                f,
                "receipt-bound payload digest mismatch for object {object_id}: expected {expected_hex}, got {actual_hex}"
            ),
            Self::EmptyPayload => f.write_str("empty payload, nothing to transfer"),
            Self::ProgressError(msg) => write!(f, "progress tracking error: {msg}"),
        }
    }
}

/// Source that can fetch rebuild/backfill bytes by durable placement receipt.
pub trait ReceiptSegmentSource {
    /// Backend error type.
    type Error: fmt::Display + Send + Sync + 'static;

    /// Fetch bytes from `source_member` using the exact placement receipt.
    fn fetch_segment_by_receipt(
        &mut self,
        source_member: MemberId,
        placement_receipt_ref: PlacementReceiptRef,
        segment_offset: u64,
        segment_length: u64,
    ) -> Result<Vec<u8>, Self::Error>;
}

impl Error for EngineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::StoreError(err) => Some(err.as_ref()),
            _ => None,
        }
    }
}

// ── Object key derivation ─────────────────────────────────────────

/// Compute the deterministic ObjectKey for a backfill task.
///
/// Real placement receipt refs carry the source object key that the local pool
/// made durable. Synthetic receipt refs fall back to the receiptless
/// subject+digest derivation used by existing tests and scaffolding callers.
///
/// For synthetic refs, the fallback key is the BLAKE3 hash of
/// (subject_ref.0 || payload_digest.0) as little-endian bytes.
pub fn task_object_key(task: &BackfillTask) -> ObjectKey {
    if !task.placement_receipt_ref.is_synthetic() {
        return ObjectKey::from_bytes32(task.placement_receipt_ref.object_key);
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(&task.subject_ref.0.to_le_bytes());
    hasher.update(&task.payload_digest.0.to_le_bytes());
    let hash = hasher.finalize();
    ObjectKey::from_bytes32(*hash.as_bytes())
}

/// Compute the BLAKE3 hex string for a slice of data.
pub fn blake3_hex(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    bytes_to_hex(hash.as_bytes())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('?'));
        s.push(char::from_digit((b & 0x0F) as u32, 16).unwrap_or('?'));
    }
    s
}

// ── DataMovementEngine ────────────────────────────────────────────

/// Engine that executes data-movement tasks by copying object data
/// from a healthy source replica to a target placement with BLAKE3
/// verification at both ends.
///
/// The engine is generic over the [`ObjectStore`] trait, so it works
/// with local stores, networked backends, and test mocks.
pub struct DataMovementEngine<S: ObjectStore> {
    /// Granularity for progress reporting ticks.
    chunk_size: usize,
    _marker: std::marker::PhantomData<S>,
}

impl<S: ObjectStore> DataMovementEngine<S> {
    /// Create a new engine with the default chunk size (64 KiB).
    #[must_use]
    pub fn new() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            _marker: std::marker::PhantomData,
        }
    }

    /// Create a new engine with a custom chunk size.
    ///
    /// A value of 0 is silently replaced with [`DEFAULT_CHUNK_SIZE`].
    #[must_use]
    pub fn with_chunk_size(chunk_size: usize) -> Self {
        Self {
            chunk_size: if chunk_size == 0 {
                DEFAULT_CHUNK_SIZE
            } else {
                chunk_size
            },
            _marker: std::marker::PhantomData,
        }
    }

    /// Execute a synthetic receiptless backfill task through object stores.
    ///
    /// This path is retained for local scaffolding that still uses synthetic
    /// receipt refs. Real receipt-bound rebuild/backfill movement must use
    /// [`Self::execute_from_receipt_source`] so source selection and payload
    /// verification remain tied to the durable placement receipt.
    ///
    /// 1. Read object data from `source_store` using the deterministic key.
    /// 2. Verify the BLAKE3 checksum.
    /// 3. Write the data to `target_store` in a single put, reporting
    ///    progress in `chunk_size` increments.
    /// 4. Read back from `target_store` and verify the BLAKE3 checksum.
    /// 5. Transition `progress` through Verified → Complete.
    pub fn execute(
        &self,
        task: &BackfillTask,
        source_store: &S,
        target_store: &mut S,
        progress: &mut BackfillProgress,
    ) -> Result<(), EngineError> {
        if !task.placement_receipt_ref.is_synthetic() {
            return Err(EngineError::ReceiptBoundTaskRequiresReceiptSource {
                object_id: task.placement_receipt_ref.object_id,
            });
        }
        if task.payload_len == 0 {
            return Err(EngineError::EmptyPayload);
        }

        let key = task_object_key(task);

        // ── 1. Read from source ──────────────────────────────────
        let object_data = source_store
            .get(&key)
            .map_err(|e| EngineError::StoreError(Box::new(e)))?
            .ok_or(EngineError::ObjectNotFound(key))?;

        // ── 2. Verify source checksum ────────────────────────────
        let expected_hex = blake3_hex(&object_data);
        let actual_hex = bytes_to_hex(blake3::hash(&object_data).as_bytes());
        if expected_hex != actual_hex {
            return Err(EngineError::SourceChecksumMismatch {
                expected_hex,
                actual_hex,
            });
        }

        self.write_target_and_complete(key, object_data, target_store, progress)
    }

    /// Execute a backfill task using receipt-bound source bytes.
    ///
    /// This is the distributed rebuild/backfill execution path. Unlike the
    /// receiptless local-store executor, it refuses synthetic receipt refs and
    /// asks the source to fetch by the exact `PlacementReceiptRef` carried by
    /// the admitted task.
    pub fn execute_from_receipt_source<R>(
        &self,
        task: &BackfillTask,
        source: &mut R,
        target_store: &mut S,
        progress: &mut BackfillProgress,
    ) -> Result<(), EngineError>
    where
        R: ReceiptSegmentSource,
    {
        if task.payload_len == 0 {
            return Err(EngineError::EmptyPayload);
        }
        if task.placement_receipt_ref.is_synthetic() {
            return Err(EngineError::SyntheticReceiptRef {
                object_id: task.placement_receipt_ref.object_id,
            });
        }
        if task.payload_len != task.placement_receipt_ref.payload_len {
            return Err(EngineError::ReceiptTaskLengthMismatch {
                object_id: task.placement_receipt_ref.object_id,
                task_len: task.payload_len,
                receipt_len: task.placement_receipt_ref.payload_len,
            });
        }

        let object_data = source
            .fetch_segment_by_receipt(
                task.source_member,
                task.placement_receipt_ref,
                0,
                task.placement_receipt_ref.payload_len,
            )
            .map_err(|err| EngineError::ReceiptSourceError {
                source_member: task.source_member,
                object_id: task.placement_receipt_ref.object_id,
                message: err.to_string(),
            })?;

        self.verify_receipt_payload(task.placement_receipt_ref, &object_data)?;

        let key = task_object_key(task);
        self.write_target_and_complete(key, object_data, target_store, progress)
    }

    fn verify_receipt_payload(
        &self,
        placement_receipt_ref: PlacementReceiptRef,
        object_data: &[u8],
    ) -> Result<(), EngineError> {
        let actual_len = object_data.len() as u64;
        if actual_len != placement_receipt_ref.payload_len {
            return Err(EngineError::ReceiptPayloadLengthMismatch {
                object_id: placement_receipt_ref.object_id,
                expected_len: placement_receipt_ref.payload_len,
                actual_len,
            });
        }

        let actual_digest = blake3::hash(object_data);
        if actual_digest.as_bytes() != &placement_receipt_ref.payload_digest {
            return Err(EngineError::ReceiptPayloadDigestMismatch {
                object_id: placement_receipt_ref.object_id,
                expected_hex: bytes_to_hex(&placement_receipt_ref.payload_digest),
                actual_hex: bytes_to_hex(actual_digest.as_bytes()),
            });
        }

        Ok(())
    }

    fn write_target_and_complete(
        &self,
        key: ObjectKey,
        object_data: Vec<u8>,
        target_store: &mut S,
        progress: &mut BackfillProgress,
    ) -> Result<(), EngineError> {
        let expected_hex = blake3_hex(&object_data);

        progress
            .start_transfer()
            .map_err(EngineError::ProgressError)?;

        // ── 3. Write to target, reporting progress in chunks ─────
        let total_len = object_data.len();
        let mut reported: u64 = 0;
        while reported < total_len as u64 {
            let tick = (self.chunk_size as u64).min(total_len as u64 - reported);
            reported += tick;
            progress
                .record_progress(tick)
                .map_err(EngineError::ProgressError)?;
        }

        // Single atomic put of the full object data.
        target_store
            .put(key, &object_data)
            .map_err(|e| EngineError::StoreError(Box::new(e)))?;

        // ── 4. Verify destination checksum ───────────────────────
        let target_data = target_store
            .get(&key)
            .map_err(|e| EngineError::StoreError(Box::new(e)))?
            .ok_or(EngineError::ObjectNotFound(key))?;
        let target_hex = bytes_to_hex(blake3::hash(&target_data).as_bytes());
        if target_hex != expected_hex {
            return Err(EngineError::DestinationChecksumMismatch {
                source_hex: expected_hex,
                destination_hex: target_hex,
            });
        }

        progress.verify().map_err(EngineError::ProgressError)?;
        progress.complete().map_err(EngineError::ProgressError)?;

        Ok(())
    }

    /// Return the chunk size in bytes.
    #[must_use]
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }
}

impl<S: ObjectStore> Default for DataMovementEngine<S> {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::{BackfillProgress, TaskState};
    use crate::task::BackfillTaskInit;
    use std::collections::HashMap;
    use tidefs_membership_epoch::MemberId;
    use tidefs_replication_model::{
        ObjectDigest, PlacementReceiptRef, ReplicaMovementClass, ReplicatedSubjectId,
    };

    /// In-memory object store for testing.
    #[derive(Clone, Debug, Default)]
    struct MemStore {
        objects: HashMap<ObjectKey, Vec<u8>>,
    }

    #[derive(Debug)]
    struct MemStoreError(String);

    impl fmt::Display for MemStoreError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "MemStoreError: {}", self.0)
        }
    }

    impl Error for MemStoreError {}

    impl ObjectStore for MemStore {
        type Error = MemStoreError;

        fn put(&mut self, key: ObjectKey, data: &[u8]) -> std::result::Result<(), Self::Error> {
            self.objects.insert(key, data.to_vec());
            Ok(())
        }

        fn get(&self, key: &ObjectKey) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.objects.get(key).cloned())
        }
    }

    fn test_task(payload_len: u64) -> BackfillTask {
        BackfillTask::new(BackfillTaskInit {
            subject_ref: ReplicatedSubjectId::new(1),
            placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(
                ReplicatedSubjectId::new(1),
            ),
            source_member: MemberId::new(10),
            target_member: MemberId::new(20),
            movement_class: ReplicaMovementClass::BackfillLaggedCopy,
            payload_digest: ObjectDigest::new(0xABCD),
            payload_len,
            created_at_ns: 1000,
            deadline_ns: 5000,
        })
    }

    fn populate_source(store: &mut MemStore, task: &BackfillTask, data: &[u8]) -> ObjectKey {
        let key = task_object_key(task);
        store.put(key, data).unwrap();
        key
    }

    // ── Tests ────────────────────────────────────────────────────

    #[test]
    fn successful_transfer_and_verification() {
        let data = b"hello backfill world";
        let task = test_task(data.len() as u64);
        let mut source = MemStore::default();
        let mut target = MemStore::default();
        let engine = DataMovementEngine::new();

        populate_source(&mut source, &task, data);

        let mut progress = BackfillProgress::new(task.payload_len, 3);
        progress.schedule().unwrap();

        engine
            .execute(&task, &source, &mut target, &mut progress)
            .unwrap();

        assert_eq!(progress.state, TaskState::Complete);
        assert_eq!(progress.bytes_transferred, task.payload_len);

        let key = task_object_key(&task);
        let target_data = target.get(&key).unwrap().unwrap();
        assert_eq!(target_data, data);
    }

    #[test]
    fn object_not_found_error() {
        let task = test_task(32);
        let source = MemStore::default(); // empty
        let mut target = MemStore::default();
        let engine = DataMovementEngine::new();

        let mut progress = BackfillProgress::new(task.payload_len, 3);
        progress.schedule().unwrap();

        let err = engine
            .execute(&task, &source, &mut target, &mut progress)
            .unwrap_err();
        assert!(matches!(err, EngineError::ObjectNotFound(_)));
    }

    #[test]
    fn empty_payload_rejected() {
        let task = test_task(0);
        let source = MemStore::default();
        let mut target = MemStore::default();
        let engine = DataMovementEngine::new();

        let mut progress = BackfillProgress::new(0, 3);
        progress.schedule().unwrap();

        let err = engine
            .execute(&task, &source, &mut target, &mut progress)
            .unwrap_err();
        assert!(matches!(err, EngineError::EmptyPayload));
    }

    #[test]
    fn receiptless_executor_rejects_real_receipt_ref() {
        let data = b"receipt-bound task must use receipt source";
        let receipt_key = ObjectKey::from_bytes32([0xA6; 32]);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(blake3::hash(data).as_bytes());
        let task = BackfillTask::new(BackfillTaskInit {
            subject_ref: ReplicatedSubjectId::new(7003),
            placement_receipt_ref: PlacementReceiptRef::replicated(
                7003,
                receipt_key.as_bytes32(),
                tidefs_membership_epoch::EpochId::new(7),
                1,
                2,
                data.len() as u64,
                digest,
            ),
            source_member: MemberId::new(10),
            target_member: MemberId::new(20),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            payload_digest: ObjectDigest::new(0xCAFE),
            payload_len: data.len() as u64,
            created_at_ns: 1000,
            deadline_ns: 5000,
        });
        let mut source = MemStore::default();
        let mut target = MemStore::default();
        let engine = DataMovementEngine::new();
        let mut progress = BackfillProgress::new(task.payload_len, 3);

        source.put(receipt_key, data).unwrap();
        progress.schedule().unwrap();

        let err = engine
            .execute(&task, &source, &mut target, &mut progress)
            .unwrap_err();

        assert!(matches!(
            err,
            EngineError::ReceiptBoundTaskRequiresReceiptSource { object_id: 7003 }
        ));
        assert!(target.objects.is_empty());
        assert_eq!(progress.state, TaskState::Scheduled);
        assert_eq!(progress.bytes_transferred, 0);
    }

    #[test]
    fn large_object_chunked_progress() {
        let data: Vec<u8> = (0..200_000u64).map(|i| (i % 251) as u8).collect();
        let task = test_task(data.len() as u64);
        let mut source = MemStore::default();
        let mut target = MemStore::default();
        let engine = DataMovementEngine::<MemStore>::with_chunk_size(8192);

        populate_source(&mut source, &task, &data);

        let mut progress = BackfillProgress::new(task.payload_len, 3);
        progress.schedule().unwrap();

        engine
            .execute(&task, &source, &mut target, &mut progress)
            .unwrap();

        assert_eq!(progress.state, TaskState::Complete);
        assert_eq!(progress.bytes_transferred, task.payload_len);

        let key = task_object_key(&task);
        let target_data = target.get(&key).unwrap().unwrap();
        assert_eq!(target_data, data);
    }

    #[test]
    fn zero_chunk_size_defaults_to_default() {
        let engine = DataMovementEngine::<MemStore>::with_chunk_size(0);
        assert_eq!(engine.chunk_size(), DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn task_object_key_is_deterministic() {
        let t1 = BackfillTask::new(BackfillTaskInit {
            subject_ref: ReplicatedSubjectId::new(42),
            placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(
                ReplicatedSubjectId::new(42),
            ),
            source_member: MemberId::new(10),
            target_member: MemberId::new(20),
            movement_class: ReplicaMovementClass::BackfillLaggedCopy,
            payload_digest: ObjectDigest::new(0xCAFE),
            payload_len: 4096,
            created_at_ns: 1000,
            deadline_ns: 5000,
        });
        let t2 = BackfillTask::new(BackfillTaskInit {
            subject_ref: ReplicatedSubjectId::new(42),
            placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(
                ReplicatedSubjectId::new(42),
            ),
            source_member: MemberId::new(10),
            target_member: MemberId::new(99),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            payload_digest: ObjectDigest::new(0xCAFE),
            payload_len: 4096,
            created_at_ns: 2000,
            deadline_ns: 6000,
        });
        assert_eq!(task_object_key(&t1), task_object_key(&t2));

        let t3 = BackfillTask::new(BackfillTaskInit {
            subject_ref: ReplicatedSubjectId::new(42),
            placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(
                ReplicatedSubjectId::new(42),
            ),
            source_member: MemberId::new(10),
            target_member: MemberId::new(20),
            movement_class: ReplicaMovementClass::BackfillLaggedCopy,
            payload_digest: ObjectDigest::new(0xBEEF),
            payload_len: 4096,
            created_at_ns: 1000,
            deadline_ns: 5000,
        });
        assert_ne!(task_object_key(&t1), task_object_key(&t3));
    }

    #[test]
    fn task_object_key_uses_real_placement_receipt_key() {
        let mut object_key = [0xA5; 32];
        object_key[..8].copy_from_slice(&42u64.to_le_bytes());
        let mut digest = [0x5A; 32];
        digest[..8].copy_from_slice(&42u64.to_le_bytes());

        let task = BackfillTask::new(BackfillTaskInit {
            subject_ref: ReplicatedSubjectId::new(42),
            placement_receipt_ref: PlacementReceiptRef::replicated(
                42,
                object_key,
                tidefs_membership_epoch::EpochId::new(7),
                1,
                2,
                4096,
                digest,
            ),
            source_member: MemberId::new(10),
            target_member: MemberId::new(20),
            movement_class: ReplicaMovementClass::BackfillLaggedCopy,
            payload_digest: ObjectDigest::new(0xCAFE),
            payload_len: 4096,
            created_at_ns: 1000,
            deadline_ns: 5000,
        });

        assert_eq!(task_object_key(&task), ObjectKey::from_bytes32(object_key));
    }

    #[test]
    fn engine_error_display() {
        let key = ObjectKey::from_bytes32([0xAB; 32]);
        let err = EngineError::ObjectNotFound(key);
        assert!(err.to_string().contains("source object not found"));

        let err = EngineError::SourceChecksumMismatch {
            expected_hex: "abc".into(),
            actual_hex: "def".into(),
        };
        assert!(err.to_string().contains("source checksum mismatch"));

        let err = EngineError::EmptyPayload;
        assert!(err.to_string().contains("empty payload"));

        let err = EngineError::ProgressError("bad state");
        assert!(err.to_string().contains("progress tracking error"));
    }

    #[test]
    fn default_engine_has_default_chunk_size() {
        let engine = DataMovementEngine::<MemStore>::default();
        assert_eq!(engine.chunk_size(), DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn destination_checksum_mismatch_detected() {
        let err = EngineError::DestinationChecksumMismatch {
            source_hex: "aaa".into(),
            destination_hex: "bbb".into(),
        };
        assert!(err.to_string().contains("destination checksum mismatch"));
        assert!(err.to_string().contains("aaa"));
        assert!(err.to_string().contains("bbb"));
    }
}
