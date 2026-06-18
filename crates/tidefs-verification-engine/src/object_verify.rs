// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Per-object BLAKE3-verified integrity checking.
//!
//! Low-level verification primitive consumed by background scrub
//! ([`tidefs_scrub_core`]), recovery-loop replay validation
//! ([`tidefs_recovery_loop`]), and rebuild integrity checking
//! ([`tidefs_rebuild_runtime`]).
//!
//! # Architecture
//!
//! Each object is read through the [`tidefs_object_io::ObjectStore`] trait,
//! hashed with BLAKE3-256, and compared against the expected hash. Results
//! are reported as [`ObjectVerificationOutcome`] values -- `Match`,
//! `Mismatch` with byte-offset and hash detail, or `IoError`.
//!
//! # Concurrency
//!
//! [`verify_batch`] distributes plans across available parallelism when the
//! store implements `Sync`. This is the entry point used by scrub, recovery,
//! and rebuild to verify many objects efficiently.

use tidefs_object_io::{ObjectKey, ObjectStore};

// ---------------------------------------------------------------------------
// VerificationPlan
// ---------------------------------------------------------------------------

/// A validated request to verify an object's data integrity.
///
/// Carries the object store key, the expected BLAKE3-256 hash, and an
/// optional byte range to restrict verification to a sub-range of the
/// object payload.
#[derive(Clone, Debug)]
pub struct VerificationPlan {
    /// Object store key identifying the object to verify.
    pub object_key: ObjectKey,
    /// Expected BLAKE3-256 hash of the object data (or sub-range).
    pub expected_hash: [u8; 32],
    /// Optional byte range `(start_offset, length)` to verify.
    /// When `None`, the full object payload is hashed and compared.
    pub byte_range: Option<(u64, u64)>,
}

impl VerificationPlan {
    /// Create a plan to verify the full object.
    #[must_use]
    pub fn new_full(object_key: ObjectKey, expected_hash: [u8; 32]) -> Self {
        Self {
            object_key,
            expected_hash,
            byte_range: None,
        }
    }

    /// Create a plan to verify a sub-range of the object.
    #[must_use]
    pub fn new_range(
        object_key: ObjectKey,
        expected_hash: [u8; 32],
        start: u64,
        length: u64,
    ) -> Self {
        Self {
            object_key,
            expected_hash,
            byte_range: Some((start, length)),
        }
    }
}

// ---------------------------------------------------------------------------
// ObjectVerificationOutcome
// ---------------------------------------------------------------------------

/// Result of verifying a single object against its expected BLAKE3 hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectVerificationOutcome {
    /// Object data matches the expected hash over the verified range.
    Match,
    /// Object data does not match. The `byte_offset` is the start of the
    /// verified range where the mismatch was detected.
    Mismatch {
        /// Start of the verified range where corruption was detected.
        byte_offset: u64,
        /// The expected BLAKE3-256 hash.
        expected_hash: [u8; 32],
        /// The actual BLAKE3-256 hash computed from the stored data.
        actual_hash: [u8; 32],
    },
    /// An I/O error prevented verification.
    IoError {
        /// Human-readable error description.
        error: String,
    },
}

impl ObjectVerificationOutcome {
    /// True when the outcome is [`Match`].
    #[must_use]
    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match)
    }

    /// True when the outcome indicates corruption or I/O failure.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        !self.is_match()
    }
}

impl std::fmt::Display for ObjectVerificationOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Match => write!(f, "object integrity verified: match"),
            Self::Mismatch {
                byte_offset,
                expected_hash,
                actual_hash,
            } => {
                write!(
                    f,
                    "integrity mismatch at byte offset {byte_offset}: \
                     expected {} actual {}",
                    hex_fmt(expected_hash),
                    hex_fmt(actual_hash),
                )
            }
            Self::IoError { error } => write!(f, "I/O error during verification: {error}"),
        }
    }
}

impl std::error::Error for ObjectVerificationOutcome {}

/// Format a 32-byte hash as a compact hex string (64 hex chars).
fn hex_fmt(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

// ---------------------------------------------------------------------------
// verify_object
// ---------------------------------------------------------------------------

/// Verify a single object against its expected BLAKE3-256 hash.
///
/// Reads the object data through `store`, restricts to the requested byte
/// range (or the full payload), computes the BLAKE3 hash, and compares it
/// against `plan.expected_hash`.
///
/// # Returns
///
/// - [`ObjectVerificationOutcome::Match`] when the hash matches.
/// - [`ObjectVerificationOutcome::Mismatch`] when the hash differs.
/// - [`ObjectVerificationOutcome::IoError`] when the object cannot be read.
pub fn verify_object<S: ObjectStore>(
    store: &S,
    plan: &VerificationPlan,
) -> ObjectVerificationOutcome {
    // Read the object payload.
    let data = match store.get(&plan.object_key) {
        Ok(Some(data)) => data,
        Ok(None) => {
            return ObjectVerificationOutcome::IoError {
                error: format!("object not found: {}", plan.object_key),
            };
        }
        Err(e) => {
            return ObjectVerificationOutcome::IoError {
                error: format!("I/O error reading object {}: {e}", plan.object_key),
            };
        }
    };

    // Select the byte slice to hash.
    let slice = match plan.byte_range {
        None => &data[..],
        Some((start, length)) => {
            let s = start as usize;
            let len = length as usize;
            if s >= data.len() {
                // Start is past end of object -- hash the empty slice.
                &data[..0]
            } else {
                let end = s.saturating_add(len).min(data.len());
                &data[s..end]
            }
        }
    };

    let actual_hash = blake3::hash(slice);
    let actual_bytes: [u8; 32] = *actual_hash.as_bytes();

    if actual_bytes == plan.expected_hash {
        ObjectVerificationOutcome::Match
    } else {
        ObjectVerificationOutcome::Mismatch {
            byte_offset: plan.byte_range.map(|(s, _)| s).unwrap_or(0),
            expected_hash: plan.expected_hash,
            actual_hash: actual_bytes,
        }
    }
}

// ---------------------------------------------------------------------------
// verify_batch
// ---------------------------------------------------------------------------

/// Verify multiple objects concurrently.
///
/// Distributes [`VerificationPlan`] entries across available CPU parallelism
/// when the store implements `Sync`. For small batches (<= 4 plans) or when
/// only one thread is available, verification proceeds sequentially.
///
/// Outcomes are returned in plan order (stable mapping from input plans to
/// output outcomes).
///
/// # Panics
///
/// Panics if a spawned thread panics during verification.
pub fn verify_batch<S: ObjectStore + Sync>(
    store: &S,
    plans: &[VerificationPlan],
) -> Vec<ObjectVerificationOutcome> {
    if plans.is_empty() {
        return Vec::new();
    }

    let parallelism = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // Small batches: sequential is faster than spawning overhead.
    if plans.len() <= 4 || parallelism <= 1 {
        return plans
            .iter()
            .map(|plan| verify_object(store, plan))
            .collect();
    }

    let n_threads = parallelism.min(plans.len());
    let chunk_size = plans.len().div_ceil(n_threads);

    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(n_threads);

        for chunk in plans.chunks(chunk_size) {
            let handle = s.spawn(move || {
                chunk
                    .iter()
                    .map(|plan| verify_object(store, plan))
                    .collect::<Vec<_>>()
            });
            handles.push(handle);
        }

        let mut results = Vec::with_capacity(plans.len());
        for handle in handles {
            results.extend(handle.join().expect("verification thread panicked"));
        }
        results
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    // A thread-safe in-memory ObjectStore for testing.
    struct MemStore {
        data: Mutex<BTreeMap<ObjectKey, Vec<u8>>>,
    }

    impl MemStore {
        fn new() -> Self {
            Self {
                data: Mutex::new(BTreeMap::new()),
            }
        }

        fn insert(&self, key: ObjectKey, value: Vec<u8>) {
            self.data.lock().unwrap().insert(key, value);
        }
    }

    impl ObjectStore for MemStore {
        type Error = std::io::Error;

        fn put(&mut self, key: ObjectKey, data: &[u8]) -> Result<(), Self::Error> {
            self.data.lock().unwrap().insert(key, data.to_vec());
            Ok(())
        }

        fn get(&self, key: &ObjectKey) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.data.lock().unwrap().get(key).cloned())
        }
    }

    fn make_key(id: u8) -> ObjectKey {
        let mut bytes = [0u8; 32];
        bytes[0] = id;
        ObjectKey::from_bytes32(bytes)
    }

    fn make_hash(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }

    // --- verify_object tests ---

    #[test]
    fn full_object_match() {
        let store = MemStore::new();
        let payload = b"hello world".to_vec();
        let key = make_key(1);
        let hash = make_hash(&payload);
        store.insert(key, payload);

        let plan = VerificationPlan::new_full(key, hash);
        let outcome = verify_object(&store, &plan);
        assert_eq!(outcome, ObjectVerificationOutcome::Match);
    }

    #[test]
    fn full_object_mismatch() {
        let store = MemStore::new();
        let payload = b"hello world".to_vec();
        let key = make_key(1);
        store.insert(key, payload);

        let wrong_hash = make_hash(b"goodbye");
        let plan = VerificationPlan::new_full(key, wrong_hash);
        let outcome = verify_object(&store, &plan);

        match &outcome {
            ObjectVerificationOutcome::Mismatch {
                byte_offset,
                expected_hash,
                actual_hash,
            } => {
                assert_eq!(*byte_offset, 0);
                assert_eq!(*expected_hash, wrong_hash);
                assert_eq!(*actual_hash, make_hash(b"hello world"));
            }
            _ => panic!("expected Mismatch, got {outcome:?}"),
        }
    }

    #[test]
    fn partial_range_match() {
        let store = MemStore::new();
        let payload = b"abcdefghij".to_vec();
        let key = make_key(1);
        store.insert(key, payload.clone());

        // Verify bytes 2..7 = "cdefg"
        let sub_slice = &payload[2..7];
        let sub_hash = make_hash(sub_slice);
        let plan = VerificationPlan::new_range(key, sub_hash, 2, 5);
        let outcome = verify_object(&store, &plan);

        assert_eq!(outcome, ObjectVerificationOutcome::Match);
    }

    #[test]
    fn partial_range_mismatch_with_offset() {
        let store = MemStore::new();
        let payload = b"abcdefghij".to_vec();
        let key = make_key(1);
        store.insert(key, payload.clone());

        let wrong_hash = make_hash(b"xxxxx");
        let plan = VerificationPlan::new_range(key, wrong_hash, 2, 5);
        let outcome = verify_object(&store, &plan);

        match &outcome {
            ObjectVerificationOutcome::Mismatch { byte_offset, .. } => {
                assert_eq!(*byte_offset, 2);
            }
            _ => panic!("expected Mismatch, got {outcome:?}"),
        }
    }

    #[test]
    fn empty_range_edge_case() {
        let store = MemStore::new();
        let payload = b"non-empty".to_vec();
        let key = make_key(1);
        store.insert(key, payload);

        let empty_hash = make_hash(b"");
        let plan = VerificationPlan::new_range(key, empty_hash, 0, 0);
        let outcome = verify_object(&store, &plan);

        assert_eq!(outcome, ObjectVerificationOutcome::Match);
    }

    #[test]
    fn range_past_end_hashes_empty() {
        let store = MemStore::new();
        let payload = b"abc".to_vec();
        let key = make_key(1);
        store.insert(key, payload);

        let empty_hash = make_hash(b"");
        let plan = VerificationPlan::new_range(key, empty_hash, 100, 10);
        let outcome = verify_object(&store, &plan);

        assert_eq!(outcome, ObjectVerificationOutcome::Match);
    }

    #[test]
    fn io_error_object_not_found() {
        let store = MemStore::new();
        let key = make_key(99);
        let hash = make_hash(b"irrelevant");

        let plan = VerificationPlan::new_full(key, hash);
        let outcome = verify_object(&store, &plan);

        match &outcome {
            ObjectVerificationOutcome::IoError { error } => {
                assert!(error.contains("not found"));
            }
            _ => panic!("expected IoError, got {outcome:?}"),
        }
    }

    #[test]
    fn outcome_display_match() {
        let o = ObjectVerificationOutcome::Match;
        assert!(o.to_string().contains("match"));
    }

    #[test]
    fn outcome_display_mismatch() {
        let h = [0xabu8; 32];
        let o = ObjectVerificationOutcome::Mismatch {
            byte_offset: 42,
            expected_hash: h,
            actual_hash: [0u8; 32],
        };
        let s = o.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("mismatch"));
    }

    #[test]
    fn outcome_display_io_error() {
        let o = ObjectVerificationOutcome::IoError {
            error: "disk on fire".into(),
        };
        assert!(o.to_string().contains("disk on fire"));
    }

    #[test]
    fn outcome_error_trait() {
        let o = ObjectVerificationOutcome::IoError {
            error: "test".into(),
        };
        let e: &dyn std::error::Error = &o;
        assert_eq!(e.to_string(), "I/O error during verification: test");
    }

    #[test]
    fn outcome_is_match_and_is_failure() {
        let m = ObjectVerificationOutcome::Match;
        assert!(m.is_match());
        assert!(!m.is_failure());

        let err = ObjectVerificationOutcome::IoError { error: "e".into() };
        assert!(!err.is_match());
        assert!(err.is_failure());

        let mismatch = ObjectVerificationOutcome::Mismatch {
            byte_offset: 0,
            expected_hash: [0u8; 32],
            actual_hash: [1u8; 32],
        };
        assert!(!mismatch.is_match());
        assert!(mismatch.is_failure());
    }

    // --- verify_batch tests ---

    #[test]
    fn batch_empty() {
        let store = MemStore::new();
        let results = verify_batch(&store, &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn batch_all_matches() {
        let store = MemStore::new();
        let mut plans = Vec::new();

        for i in 0u8..8 {
            let payload = vec![i; 16];
            let key = make_key(i);
            let hash = make_hash(&payload);
            store.insert(key, payload);
            plans.push(VerificationPlan::new_full(key, hash));
        }

        let results = verify_batch(&store, &plans);
        assert_eq!(results.len(), 8);
        assert!(results.iter().all(ObjectVerificationOutcome::is_match));
    }

    #[test]
    fn batch_mixed_outcomes() {
        let store = MemStore::new();
        let mut plans = Vec::new();

        // Object 0: correct hash -> Match.
        let payload0 = b"obj0-data".to_vec();
        let key0 = make_key(0);
        let hash0 = make_hash(&payload0);
        store.insert(key0, payload0);
        plans.push(VerificationPlan::new_full(key0, hash0));

        // Object 1: wrong hash -> Mismatch.
        let payload1 = b"obj1-data".to_vec();
        let key1 = make_key(1);
        store.insert(key1, payload1);
        plans.push(VerificationPlan::new_full(key1, make_hash(b"wrong")));

        // Object 2: not stored -> IoError.
        let key2 = make_key(2);
        plans.push(VerificationPlan::new_full(key2, make_hash(b"nope")));

        let results = verify_batch(&store, &plans);
        assert_eq!(results.len(), 3);
        assert!(results[0].is_match());
        assert!(matches!(
            results[1],
            ObjectVerificationOutcome::Mismatch { .. }
        ));
        assert!(matches!(
            results[2],
            ObjectVerificationOutcome::IoError { .. }
        ));
    }

    #[test]
    fn batch_outcomes_preserve_order() {
        let store = MemStore::new();
        let mut plans = Vec::new();

        for i in 0u8..10 {
            let payload = vec![i; 8];
            let key = make_key(i);
            let hash = make_hash(&payload);
            store.insert(key, payload);
            plans.push(VerificationPlan::new_full(key, hash));
        }

        let results = verify_batch(&store, &plans);
        assert_eq!(results.len(), 10);
        for (i, r) in results.iter().enumerate() {
            assert!(r.is_match(), "plan {i} should match");
        }
    }

    #[test]
    fn concurrent_batch_stress_test() {
        let store = MemStore::new();
        let mut plans = Vec::new();

        // 64 objects -- enough to trigger concurrent path when parallelism > 1.
        for i in 0u8..64 {
            let payload = vec![i; 64];
            let key = make_key(i);
            let hash = make_hash(&payload);
            store.insert(key, payload);
            plans.push(VerificationPlan::new_full(key, hash));
        }

        let results = verify_batch(&store, &plans);
        assert_eq!(results.len(), 64);
        assert!(results.iter().all(ObjectVerificationOutcome::is_match));
    }

    // --- VerificationPlan tests ---

    #[test]
    fn plan_new_full() {
        let key = make_key(1);
        let hash = [0x42u8; 32];
        let plan = VerificationPlan::new_full(key, hash);
        assert_eq!(plan.object_key, key);
        assert_eq!(plan.expected_hash, hash);
        assert!(plan.byte_range.is_none());
    }

    #[test]
    fn plan_new_range() {
        let key = make_key(1);
        let hash = [0xabu8; 32];
        let plan = VerificationPlan::new_range(key, hash, 100, 200);
        assert_eq!(plan.object_key, key);
        assert_eq!(plan.byte_range, Some((100, 200)));
    }

    #[test]
    fn object_key_display_roundtrip() {
        let key = make_key(0xab);
        let hex = format!("{key}");
        assert_eq!(hex.len(), 64);
    }

    // --- MemStore concurrent put and get test ---

    #[test]
    fn mem_store_concurrent_put_and_get() {
        let mut store = MemStore::new();
        let key = make_key(1);
        let payload = b"thread-safe".to_vec();

        store.put(key, &payload).unwrap();
        let got = store.get(&key).unwrap();
        assert_eq!(got, Some(payload));
    }
}
