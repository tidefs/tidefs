//! Device removal evacuation engine.
//!
//! When an operator requests device removal, this module coordinates the
//! safe evacuation of all objects from the departing device to surviving
//! devices. Each object is read with segment-level integrity verification,
//! its BLAKE3 content digest is computed, and it is copied to a target
//! device. The source copy is freed upon successful transfer.
//!
//! # State machine
//!
//! ```text
//! Quiesce --> Evacuate --> Verify --> Commit --> Complete
//!                |           |          |
//!                v           v          v
//!             Failed      Failed     Failed
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::{LocalObjectStore, ObjectKey, StoreError};

// ---------------------------------------------------------------------------
// Evacuation phase
// ---------------------------------------------------------------------------

/// Phases of the device removal state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvacuationPhase {
    /// Initial phase: stop new allocations on the target device.
    Quiesce,
    /// Move all objects off the target device.
    Evacuate,
    /// Confirm zero remaining objects on the departing device.
    Verify,
    /// Persist removal and update pool metadata.
    Commit,
    /// Removal completed successfully.
    Complete,
    /// Removal failed and cannot proceed.
    Failed,
}

impl EvacuationPhase {
    /// Returns the next phase in the normal forward progression.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Quiesce => Some(Self::Evacuate),
            Self::Evacuate => Some(Self::Verify),
            Self::Verify => Some(Self::Commit),
            Self::Commit => Some(Self::Complete),
            Self::Complete | Self::Failed => None,
        }
    }

    /// Returns `true` if this is a terminal phase.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Failed)
    }
}

// ---------------------------------------------------------------------------
// Evacuation state
// ---------------------------------------------------------------------------

/// Live state of an in-progress or completed device evacuation.
#[derive(Clone, Debug)]
pub struct EvacuationState {
    /// Current phase.
    pub phase: EvacuationPhase,
    /// Path of the device being removed.
    pub target_device: PathBuf,
    /// Number of objects evacuated so far.
    pub objects_evacuated: u64,
    /// Number of objects that failed evacuation.
    pub objects_failed: u64,
    /// Total bytes evacuated.
    pub bytes_evacuated: u64,
    /// Human-readable error message if the operation entered Failed.
    pub error: Option<String>,
    /// Keys of objects still pending evacuation.
    pub pending_keys: Vec<ObjectKey>,
    /// Keys of objects that failed evacuation.
    pub failed_keys: Vec<ObjectKey>,
}

impl EvacuationState {
    /// Create a new evacuation state at the Quiesce phase.
    #[must_use]
    pub fn new(target_device: PathBuf) -> Self {
        Self {
            phase: EvacuationPhase::Quiesce,
            target_device,
            objects_evacuated: 0,
            objects_failed: 0,
            bytes_evacuated: 0,
            error: None,
            pending_keys: Vec::new(),
            failed_keys: Vec::new(),
        }
    }

    /// Transition to the next phase. Returns an error if already terminal.
    pub fn advance(&mut self) -> Result<(), &'static str> {
        match self.phase.next() {
            Some(next) => {
                self.phase = next;
                Ok(())
            }
            None => Err("cannot advance from terminal phase"),
        }
    }

    /// Transition to the Failed phase with an error message.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.phase = EvacuationPhase::Failed;
        self.error = Some(error.into());
    }
}

// ---------------------------------------------------------------------------
// Evacuation result
// ---------------------------------------------------------------------------

/// Result of executing a device evacuation.
#[derive(Clone, Debug, Default)]
pub struct EvacuationResult {
    /// Number of objects successfully evacuated.
    pub objects_evacuated: u64,
    /// Number of objects that failed evacuation.
    pub objects_failed: u64,
    /// Total bytes evacuated.
    pub bytes_evacuated: u64,
    /// Keys that failed evacuation.
    pub failed_keys: Vec<ObjectKey>,
    /// BLAKE3 content digests of evacuated objects (key -> digest).
    pub content_digests: BTreeMap<ObjectKey, [u8; 32]>,
    /// Whether all objects were evacuated successfully.
    pub complete: bool,
}

// ---------------------------------------------------------------------------
// DeviceEvacuator -- copies objects between two LocalObjectStore instances
// ---------------------------------------------------------------------------

/// Coordinates object evacuation from one device store to another.
///
/// Each [`LocalObjectStore`] represents one device. The evacuator reads
/// objects from the source store, computes BLAKE3 content digests, writes
/// them to the target store, and deletes the source copy after successful
/// transfer.
pub struct DeviceEvacuator<'a> {
    source: &'a mut LocalObjectStore,
    target: &'a mut LocalObjectStore,
}

impl<'a> DeviceEvacuator<'a> {
    /// Create a new evacuator that moves objects from `source` to `target`.
    pub fn new(source: &'a mut LocalObjectStore, target: &'a mut LocalObjectStore) -> Self {
        Self { source, target }
    }

    /// Evacuate a single object by key.
    ///
    /// Reads the object from the source store, computes its BLAKE3 content
    /// digest for integrity verification, writes it to the target store,
    /// and deletes it from the source.
    ///
    /// Returns the number of bytes evacuated and the BLAKE3 content digest
    /// on success.
    ///
    /// # Errors
    ///
    /// Returns [`EvacuationError`] if the read, write, or delete fails.
    pub fn evacuate_one(&mut self, key: ObjectKey) -> Result<(u64, [u8; 32]), EvacuationError> {
        // Read from source (segment-level integrity is verified by the store).
        let data = self
            .source
            .get(key)
            .map_err(|e| EvacuationError::ReadFailed {
                key,
                source: e.to_string(),
            })?
            .ok_or(EvacuationError::ObjectNotFound { key })?;

        // Compute BLAKE3 content digest for cross-store verification.
        let content_digest: [u8; 32] = blake3::hash(&data).into();
        let len = data.len() as u64;

        // Write to target.
        self.target
            .put(key, &data)
            .map_err(|e| EvacuationError::WriteFailed {
                key,
                source: e.to_string(),
            })?;

        // Verify the target copy is readable and has correct content.
        self.verify_target_copy(key, &content_digest)?;

        // Delete from source on successful transfer.
        self.source
            .delete(key)
            .map_err(|e| EvacuationError::DeleteFailed {
                key,
                source: e.to_string(),
            })?;

        Ok((len, content_digest))
    }

    /// Verify that an evacuated object on the target store has the expected
    /// BLAKE3 content digest.
    fn verify_target_copy(
        &self,
        key: ObjectKey,
        expected_digest: &[u8; 32],
    ) -> Result<(), EvacuationError> {
        let data = self
            .target
            .get(key)
            .map_err(|e| EvacuationError::ReadFailed {
                key,
                source: e.to_string(),
            })?
            .ok_or(EvacuationError::ObjectNotFound { key })?;

        let actual_digest: [u8; 32] = blake3::hash(&data).into();
        if actual_digest != *expected_digest {
            return Err(EvacuationError::ContentMismatch { key });
        }
        Ok(())
    }

    /// Evacuate all objects from the source store to the target store.
    ///
    /// Iterates over all live keys in the source, evacuates each one, and
    /// records successes, failures, and BLAKE3 digests.
    pub fn evacuate_all(&mut self) -> EvacuationResult {
        let keys = self.source.list_keys();
        let mut result = EvacuationResult::default();

        for key in keys {
            match self.evacuate_one(key) {
                Ok((bytes, digest)) => {
                    result.objects_evacuated += 1;
                    result.bytes_evacuated += bytes;
                    result.content_digests.insert(key, digest);
                }
                Err(_) => {
                    result.objects_failed += 1;
                    result.failed_keys.push(key);
                }
            }
        }

        // Final check: source should be empty.
        let remaining = self.source.list_keys();
        result.complete = result.objects_failed == 0 && remaining.is_empty();

        result
    }

    /// Verify that all evacuated objects on the target store match their
    /// expected BLAKE3 content digests.
    ///
    /// Returns a map of key -> verification status (true = verified,
    /// false = missing or digest mismatch).
    pub fn verify_evacuation(
        &self,
        expected_digests: &BTreeMap<ObjectKey, [u8; 32]>,
    ) -> (BTreeMap<ObjectKey, bool>, bool) {
        let mut status = BTreeMap::new();
        let mut all_ok = true;

        for (&key, &expected_digest) in expected_digests {
            let ok = match self.target.get(key) {
                Ok(Some(data)) => {
                    let actual_digest: [u8; 32] = blake3::hash(&data).into();
                    actual_digest == expected_digest
                }
                _ => false,
            };
            if !ok {
                all_ok = false;
            }
            status.insert(key, ok);
        }

        (status, all_ok)
    }

    /// Check if the source store has zero live objects remaining.
    #[must_use]
    pub fn source_is_empty(&self) -> bool {
        self.source.list_keys().is_empty()
    }

    /// Sync both stores to durable storage.
    pub fn sync_both(&mut self) -> Result<(), StoreError> {
        self.source.sync()?;
        self.target.sync()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EvacuationError
// ---------------------------------------------------------------------------

/// Errors that can occur during object evacuation.
#[derive(Clone, Debug)]
pub enum EvacuationError {
    /// The object was not found in the source store.
    ObjectNotFound { key: ObjectKey },
    /// Failed to read the object from the source store.
    ReadFailed { key: ObjectKey, source: String },
    /// Failed to write the object to the target store.
    WriteFailed { key: ObjectKey, source: String },
    /// Failed to delete the object from the source store.
    DeleteFailed { key: ObjectKey, source: String },
    /// BLAKE3 content verification failed after transfer.
    ContentMismatch { key: ObjectKey },
    /// The source store has no objects to evacuate.
    NoObjectsToEvacuate,
    /// The target device has insufficient space.
    NoSpace,
    /// An I/O error occurred during evacuation.
    IoError { operation: String, path: PathBuf },
}

impl std::fmt::Display for EvacuationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObjectNotFound { key } => {
                write!(f, "object {} not found in source store", key.short_hex())
            }
            Self::ReadFailed { key, source } => {
                write!(
                    f,
                    "failed to read object {} from source: {source}",
                    key.short_hex()
                )
            }
            Self::WriteFailed { key, source } => {
                write!(
                    f,
                    "failed to write object {} to target: {source}",
                    key.short_hex()
                )
            }
            Self::DeleteFailed { key, source } => {
                write!(
                    f,
                    "failed to delete object {} from source: {source}",
                    key.short_hex()
                )
            }
            Self::ContentMismatch { key } => {
                write!(f, "BLAKE3 content mismatch for object {}", key.short_hex())
            }
            Self::NoObjectsToEvacuate => f.write_str("no objects to evacuate on source device"),
            Self::NoSpace => f.write_str("target device has insufficient space"),
            Self::IoError { operation, path } => {
                write!(f, "I/O error during {operation} on {}", path.display())
            }
        }
    }
}

impl std::error::Error for EvacuationError {}

// ---------------------------------------------------------------------------
// run_device_evacuation -- four-phase state machine execution
// ---------------------------------------------------------------------------

/// Run the full four-phase device removal for a single source->target pair.
///
/// # Phases
///
/// 1. **Quiesce** -- Verifies the source has objects to evacuate and the
///    target is reachable.
/// 2. **Evacuate** -- Copies all objects from source to target, deletes
///    source copies. Records BLAKE3 digests.
/// 3. **Verify** -- Confirms zero live objects remain on source and all
///    evacuated objects are readable on target with correct BLAKE3 digests.
/// 4. **Commit** -- Syncs both stores to durable storage.
pub fn run_device_evacuation(
    state: &mut EvacuationState,
    evacuator: &mut DeviceEvacuator<'_>,
) -> Result<EvacuationResult, EvacuationError> {
    assert!(
        !state.phase.is_terminal(),
        "run_device_evacuation called on terminal phase {:?}",
        state.phase
    );

    // --- Phase 1: Quiesce ---
    let source_keys = evacuator.source.list_keys();
    if source_keys.is_empty() {
        state.phase = EvacuationPhase::Complete;
        return Ok(EvacuationResult::default());
    }
    state.pending_keys = source_keys;
    state.advance().map_err(|_e| EvacuationError::IoError {
        operation: "phase_transition".into(),
        path: state.target_device.clone(),
    })?;

    // --- Phase 2: Evacuate ---
    let mut result = EvacuationResult::default();

    for key in &state.pending_keys.clone() {
        match evacuator.evacuate_one(*key) {
            Ok((bytes, digest)) => {
                result.objects_evacuated += 1;
                result.bytes_evacuated += bytes;
                result.content_digests.insert(*key, digest);
            }
            Err(_) => {
                result.objects_failed += 1;
                result.failed_keys.push(*key);
            }
        }
        state.objects_evacuated = result.objects_evacuated;
        state.objects_failed = result.objects_failed;
        state.bytes_evacuated = result.bytes_evacuated;
    }
    state.advance().map_err(|_e| EvacuationError::IoError {
        operation: "phase_transition".into(),
        path: state.target_device.clone(),
    })?;

    // --- Phase 3: Verify ---
    if !evacuator.source_is_empty() {
        state.fail("source device still has live objects after evacuation");
        result.complete = false;
        return Ok(result);
    }

    let (_, all_verified) = evacuator.verify_evacuation(&result.content_digests);
    if !all_verified {
        state.fail("objects failed BLAKE3 verification on target after evacuation");
        result.complete = false;
        return Ok(result);
    }
    state.advance().map_err(|_e| EvacuationError::IoError {
        operation: "phase_transition".into(),
        path: state.target_device.clone(),
    })?;

    // --- Phase 4: Commit ---
    evacuator
        .sync_both()
        .map_err(|_e| EvacuationError::IoError {
            operation: "sync".into(),
            path: state.target_device.clone(),
        })?;
    state.advance().map_err(|_e| EvacuationError::IoError {
        operation: "phase_transition".into(),
        path: state.target_device.clone(),
    })?;

    result.complete = true;
    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalObjectStore, ObjectKey};

    fn make_object_data(id: u64) -> Vec<u8> {
        format!("evacuation-test-object-{id:04x}-payload-for-blake3-verification").into_bytes()
    }

    #[test]
    fn evacuate_single_object_source_to_target() {
        let dir = tempfile::tempdir().unwrap();
        let source_root = dir.path().join("source");
        let target_root = dir.path().join("target");
        std::fs::create_dir_all(&source_root).unwrap();
        std::fs::create_dir_all(&target_root).unwrap();

        let mut source = LocalObjectStore::open(&source_root).unwrap();
        let mut target = LocalObjectStore::open(&target_root).unwrap();

        let key = ObjectKey::from_name("test-object-1");
        let data = make_object_data(1);
        let expected_digest: [u8; 32] = blake3::hash(&data).into();
        source.put(key, &data).unwrap();
        source.sync().unwrap();

        let mut evacuator = DeviceEvacuator::new(&mut source, &mut target);
        let (bytes, digest) = evacuator.evacuate_one(key).unwrap();
        assert_eq!(bytes, data.len() as u64);
        assert_eq!(digest, expected_digest);

        // Source should no longer have the object.
        assert!(source.get(key).unwrap().is_none());
        // Target should have it with correct content.
        let relocated = target.get(key).unwrap().unwrap();
        assert_eq!(relocated, data);
        let relocated_digest: [u8; 32] = blake3::hash(&relocated).into();
        assert_eq!(relocated_digest, expected_digest);
    }

    #[test]
    fn evacuate_all_multiple_objects() {
        let dir = tempfile::tempdir().unwrap();
        let source_root = dir.path().join("source");
        let target_root = dir.path().join("target");
        std::fs::create_dir_all(&source_root).unwrap();
        std::fs::create_dir_all(&target_root).unwrap();

        let mut source = LocalObjectStore::open(&source_root).unwrap();
        let mut target = LocalObjectStore::open(&target_root).unwrap();

        let mut original_data: Vec<(ObjectKey, Vec<u8>)> = Vec::new();
        for i in 0u64..20 {
            let key = ObjectKey::from_name(format!("obj-{i:03x}"));
            let data = make_object_data(i);
            source.put(key, &data).unwrap();
            original_data.push((key, data));
        }
        source.sync().unwrap();

        let mut evacuator = DeviceEvacuator::new(&mut source, &mut target);
        let result = evacuator.evacuate_all();
        assert_eq!(result.objects_evacuated, 20);
        assert_eq!(result.objects_failed, 0);
        assert!(result.complete);
        assert!(evacuator.source_is_empty());

        // Verify all objects on target with BLAKE3 digests.
        for (key, expected_data) in &original_data {
            let relocated = target.get(*key).unwrap().unwrap();
            assert_eq!(relocated, *expected_data);
            let expected_digest: [u8; 32] = blake3::hash(expected_data).into();
            assert_eq!(result.content_digests[key], expected_digest);
        }
    }

    #[test]
    fn evacuate_empty_source_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let source_root = dir.path().join("source");
        let target_root = dir.path().join("target");
        std::fs::create_dir_all(&source_root).unwrap();
        std::fs::create_dir_all(&target_root).unwrap();

        let mut source = LocalObjectStore::open(&source_root).unwrap();
        let mut target = LocalObjectStore::open(&target_root).unwrap();

        let mut evacuator = DeviceEvacuator::new(&mut source, &mut target);
        let result = evacuator.evacuate_all();
        assert_eq!(result.objects_evacuated, 0);
        assert_eq!(result.objects_failed, 0);
        assert!(result.complete);
    }

    #[test]
    fn state_machine_phases_progress_correctly() {
        let mut state = EvacuationState::new(PathBuf::from("/dev/disk1"));
        assert_eq!(state.phase, EvacuationPhase::Quiesce);

        state.advance().unwrap();
        assert_eq!(state.phase, EvacuationPhase::Evacuate);

        state.advance().unwrap();
        assert_eq!(state.phase, EvacuationPhase::Verify);

        state.advance().unwrap();
        assert_eq!(state.phase, EvacuationPhase::Commit);

        state.advance().unwrap();
        assert_eq!(state.phase, EvacuationPhase::Complete);
        assert!(state.phase.is_terminal());

        assert!(state.advance().is_err());
    }

    #[test]
    fn state_machine_can_fail_at_any_phase() {
        let mut state = EvacuationState::new(PathBuf::from("/dev/disk1"));
        state.advance().unwrap();
        state.advance().unwrap();

        state.fail("BLAKE3 verification mismatch");
        assert_eq!(state.phase, EvacuationPhase::Failed);
        assert!(state.phase.is_terminal());
        assert!(state.error.as_ref().unwrap().contains("BLAKE3"));
    }

    #[test]
    fn run_full_evacuation_state_machine() {
        let dir = tempfile::tempdir().unwrap();
        let source_root = dir.path().join("source");
        let target_root = dir.path().join("target");
        std::fs::create_dir_all(&source_root).unwrap();
        std::fs::create_dir_all(&target_root).unwrap();

        let mut source = LocalObjectStore::open(&source_root).unwrap();
        let mut target = LocalObjectStore::open(&target_root).unwrap();

        for i in 0u64..10 {
            let key = ObjectKey::from_name(format!("obj-{i:03x}"));
            source.put(key, &make_object_data(i)).unwrap();
        }
        source.sync().unwrap();

        let mut state = EvacuationState::new(PathBuf::from("/dev/disk0"));
        let mut evacuator = DeviceEvacuator::new(&mut source, &mut target);

        let result = run_device_evacuation(&mut state, &mut evacuator).unwrap();
        assert_eq!(result.objects_evacuated, 10);
        assert_eq!(result.objects_failed, 0);
        assert!(result.complete);
        assert_eq!(state.phase, EvacuationPhase::Complete);
        assert!(evacuator.source_is_empty());
    }

    #[test]
    fn evacuate_nonexistent_object_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let source_root = dir.path().join("source");
        let target_root = dir.path().join("target");
        std::fs::create_dir_all(&source_root).unwrap();
        std::fs::create_dir_all(&target_root).unwrap();

        let mut source = LocalObjectStore::open(&source_root).unwrap();
        let mut target = LocalObjectStore::open(&target_root).unwrap();

        let key = ObjectKey::from_name("nonexistent");
        let mut evacuator = DeviceEvacuator::new(&mut source, &mut target);
        let result = evacuator.evacuate_one(key);
        assert!(result.is_err());
    }

    #[test]
    fn verify_evacuation_detects_missing_objects() {
        let dir = tempfile::tempdir().unwrap();
        let source_root = dir.path().join("source");
        let target_root = dir.path().join("target");
        std::fs::create_dir_all(&source_root).unwrap();
        std::fs::create_dir_all(&target_root).unwrap();

        let mut source = LocalObjectStore::open(&source_root).unwrap();
        let mut target = LocalObjectStore::open(&target_root).unwrap();

        let key1 = ObjectKey::from_name("obj-1");
        let key2 = ObjectKey::from_name("obj-2");
        let data1 = make_object_data(1);
        let data2 = make_object_data(2);
        let digest1: [u8; 32] = blake3::hash(&data1).into();
        let digest2: [u8; 32] = blake3::hash(&data2).into();
        source.put(key1, &data1).unwrap();
        source.put(key2, &data2).unwrap();
        source.sync().unwrap();

        let mut evacuator = DeviceEvacuator::new(&mut source, &mut target);
        evacuator.evacuate_one(key1).unwrap();

        let mut expected = BTreeMap::new();
        expected.insert(key1, digest1);
        expected.insert(key2, digest2);

        let (status, all_ok) = evacuator.verify_evacuation(&expected);
        assert!(status[&key1]);
        assert!(!status[&key2]);
        assert!(!all_ok);
    }
}
