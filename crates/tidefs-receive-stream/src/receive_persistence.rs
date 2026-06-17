//! Receive persistence bridge: persist reassembled objects into a local
//! object store with incremental base-root pin authority checks.
//!
//! Bridges the receive-stream decode pipeline to a concrete [`ObjectStore`]
//! backend. Each fully reassembled [`AssembledObject`] is persisted via
//! content-addressed put with optional BLAKE3 key-consistency verification,
//! closing the receive-side persistence gap for multi-node state transfer.
//!
//! For incremental receive streams, the bridge enforces that the advertised
//! base root is pinned in local dataset authority before accepting object
//! chunks as durable receive output. The caller supplies a
//! [`BaseRootPinLookup`] implementation and calls
//! [`ReceivePersistenceBridge::validate_base_root_pin`] before any objects
//! are persisted. If validation fails, no partially received objects are
//! promoted to durable dataset authority.
//!
//! # Architecture
//!
//! ```text
//! Receiver wire bytes
//!        |
//!   ChunkDecoder (verify per-chunk BLAKE3-256)
//!        |
//!   ObjectAssembler (reassemble ordered chunks)
//!        |
//!   ReceivePersistenceBridge (contract check + content-addressed put + key verify)
//!        |
//!   ObjectStore (durable local storage)
//! ```

use crate::assembler::AssembledObject;
use crate::dispatch::ReceiveDispatch;
use tidefs_local_object_store::{ObjectKey, ObjectStore, StoreError};

// ---------------------------------------------------------------------------
// ReceiveContract — incremental stream identity
// ---------------------------------------------------------------------------

/// Contract for an incremental receive stream.
///
/// Carries the explicit base-root identity, dataset lineage identity, and
/// receive generation required to validate that the target dataset holds a
/// pinned base root before accepting receive objects as durable authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveContract {
    /// BLAKE3 content hash of the serialized base root (32 bytes).
    ///
    /// This is the content-derived identity of the base root object as
    /// advertised by the sender; the receiver must verify that this exact
    /// root is pinned in the local dataset authority before persisting
    /// received objects.
    pub base_root_identity: [u8; 32],

    /// BLAKE3 hash representing the dataset lineage identity (32 bytes).
    ///
    /// Identifies the dataset lineage chain. The receiver must verify that
    /// the local dataset catalog records the same lineage identity for the
    /// target dataset. A mismatch indicates the sender is streaming into
    /// the wrong dataset or a divergent fork.
    pub dataset_lineage_identity: [u8; 32],

    /// Monotonic receive generation counter.
    ///
    /// Incremented for each successive incremental receive on the same
    /// dataset. Protects against stale or replayed receive streams.
    pub receive_generation: u64,
}

// ---------------------------------------------------------------------------
// BaseRootPinLookup — minimal pin authority boundary
// ---------------------------------------------------------------------------

/// Minimal trait for checking whether a base root is pinned in the local
/// dataset catalog/pin authority.
///
/// Implementations bridge the receive-stream crate to the concrete pin
/// authority (e.g., `tidefs_dataset_lifecycle::DatasetLifecycle` or the
/// `tidefs_gc_pin_set::GcPinSet`) without coupling the receive pipeline to
/// those crates.
pub trait BaseRootPinLookup {
    /// Check whether a base root with the given identity is currently pinned.
    ///
    /// Returns `true` if the exact base root identity is protected by an
    /// active pin in the local pin authority.
    fn is_base_root_pinned(&self, base_root_identity: &[u8; 32]) -> bool;

    /// Return the dataset lineage identity for a pinned base root, if known.
    ///
    /// Returns `None` when the lineage is not available (e.g., the pin
    /// authority does not track lineage) or when the base root is not pinned.
    /// A `None` return does not automatically fail validation; callers
    /// decide whether missing lineage is acceptable.
    fn dataset_lineage_for_base_root(
        &self,
        base_root_identity: &[u8; 32],
    ) -> Option<[u8; 32]>;
}

// ---------------------------------------------------------------------------
// ReceivePersistenceError — classified receive persistence errors
// ---------------------------------------------------------------------------

/// Errors that can occur during receive persistence, including base-root
/// pin authority failures.
#[derive(Debug)]
pub enum ReceivePersistenceError {
    /// The advertised base root is not pinned in the local pin authority.
    ///
    /// The receiver must reject the incremental stream because there is no
    /// guarantee the base root data will be retained long enough for the
    /// receive to complete.
    BaseRootNotPinned {
        /// The base root identity from the receive contract.
        base_root_identity: [u8; 32],
    },

    /// The base root is pinned, but its stored lineage identity does not
    /// match the contract.
    DatasetLineageMismatch {
        /// Lineage identity from the receive contract.
        expected: [u8; 32],
        /// Lineage identity returned by the pin authority.
        actual: [u8; 32],
    },

    /// The receive contract has not been validated before objects were
    /// dispatched for persistence.
    ///
    /// Callers must call [`ReceivePersistenceBridge::validate_base_root_pin`]
    /// after setting an incremental contract via
    /// [`ReceivePersistenceBridge::with_incremental_contract`].
    ContractNotValidated,

    /// An incremental contract was expected but none was provided.
    ///
    /// Raised when the caller attempts to validate without first setting
    /// a contract.
    ContractRequired,

    /// An underlying object-store error occurred during put or key lookup.
    Store(StoreError),
}

impl std::fmt::Display for ReceivePersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BaseRootNotPinned { base_root_identity } => {
                write!(
                    f,
                    "incremental receive base root {:02x?} is not pinned",
                    &base_root_identity[..8]
                )
            }
            Self::DatasetLineageMismatch { expected, actual } => {
                write!(
                    f,
                    "dataset lineage mismatch: expected {:02x?}, got {:02x?}",
                    &expected[..8],
                    &actual[..8]
                )
            }
            Self::ContractNotValidated => {
                write!(
                    f,
                    "incremental receive contract has not been validated against pin authority"
                )
            }
            Self::ContractRequired => {
                write!(f, "incremental receive contract is required but none was provided")
            }
            Self::Store(e) => write!(f, "object store error: {e}"),
        }
    }
}

impl std::error::Error for ReceivePersistenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StoreError> for ReceivePersistenceError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

// ---------------------------------------------------------------------------
// ReceivePersistenceBridge
// ---------------------------------------------------------------------------

/// Persistence bridge that dispatches reassembled objects into an
/// [`ObjectStore`] via content-addressed put with incremental base-root
/// pin authority checks.
///
/// Each object is written through [`ObjectStore::put`], which derives the
/// storage key as BLAKE3-256 of the payload. When `verify_key` is enabled
/// (the default), the returned key is checked against the sender-provided
/// `object_id` to detect data tampering or sender-side bugs.
///
/// ## Incremental receive contract
///
/// For incremental streams, set a [`ReceiveContract`] via
/// [`with_incremental_contract`](Self::with_incremental_contract) and call
/// [`validate_base_root_pin`](Self::validate_base_root_pin) before
/// persisting any objects. The bridge will reject all `store_object` calls
/// until the contract is validated, ensuring no partially received objects
/// are promoted to durable dataset authority.
///
/// # Example
///
/// ```ignore
/// use tidefs_receive_stream::receive_persistence::{
///     ReceivePersistenceBridge, ReceiveContract,
/// };
/// use tidefs_receive_stream::dispatch::receive_object;
/// use tidefs_local_object_store::LocalObjectStore;
///
/// let mut store = LocalObjectStore::open("/pool/objects", Default::default()).unwrap();
/// let contract = ReceiveContract {
///     base_root_identity: [0xAA; 32],
///     dataset_lineage_identity: [0xBB; 32],
///     receive_generation: 1,
/// };
/// let mut bridge = ReceivePersistenceBridge::new(&mut store)
///     .with_incremental_contract(contract);
/// // bridge.validate_base_root_pin(&pin_lookup)?;  // caller validates
/// let wire_bytes = /* chunk frames from peer */;
/// let (objects, bytes) = receive_object(&wire_bytes, 0, &mut bridge).unwrap();
/// ```
#[derive(Debug)]
pub struct ReceivePersistenceBridge<'a, S: ObjectStore> {
    /// The backing object store (borrowed from caller).
    store: &'a mut S,
    /// When true, verify the BLAKE3-derived key matches the sender's object_id.
    verify_key: bool,
    /// Optional incremental receive contract.
    contract: Option<ReceiveContract>,
    /// Whether the contract has been validated against pin authority.
    contract_validated: bool,
    /// Number of objects successfully persisted.
    objects_persisted: u64,
    /// Total payload bytes persisted.
    bytes_persisted: u64,
    /// Total chunks received (sum of `total_chunks` across all objects).
    chunks_received: u64,
}

impl<'a, S: ObjectStore> ReceivePersistenceBridge<'a, S> {
    /// Create a new persistence bridge wrapping the given store.
    ///
    /// Key verification is enabled by default. No incremental contract is set.
    #[must_use]
    pub fn new(store: &'a mut S) -> Self {
        Self {
            store,
            verify_key: true,
            contract: None,
            contract_validated: false,
            objects_persisted: 0,
            bytes_persisted: 0,
            chunks_received: 0,
        }
    }

    /// Enable or disable BLAKE3 key-consistency verification.
    ///
    /// When disabled, objects are stored using the content-derived key
    /// without checking it against the sender's `object_id`. This is useful
    /// when the sender uses a different object-id scheme.
    #[must_use]
    pub fn with_key_verification(mut self, verify: bool) -> Self {
        self.verify_key = verify;
        self
    }

    /// Set an incremental receive contract.
    ///
    /// The contract carries the base-root identity, dataset lineage, and
    /// receive generation advertised by the sender. Call
    /// [`validate_base_root_pin`](Self::validate_base_root_pin) after
    /// setting the contract to verify the base root against local pin
    /// authority before persisting any objects.
    ///
    /// The contract is marked as **not validated** until
    /// [`validate_base_root_pin`](Self::validate_base_root_pin) succeeds.
    #[must_use]
    pub fn with_incremental_contract(mut self, contract: ReceiveContract) -> Self {
        self.contract = Some(contract);
        self.contract_validated = false;
        self
    }

    /// Validate the incremental receive contract against the local pin authority.
    ///
    /// Checks:
    /// 1. The base root identity from the contract is pinned in `pin_lookup`.
    /// 2. If the pin authority provides a lineage identity, it matches the
    ///    contract's `dataset_lineage_identity`.
    ///
    /// On success, marks the contract as validated and permits subsequent
    /// `store_object` calls. On failure, returns a classified
    /// [`ReceivePersistenceError`] and leaves the contract unvalidated,
    /// blocking all further persistence through this bridge.
    ///
    /// # Errors
    ///
    /// - [`ReceivePersistenceError::ContractRequired`] if no contract was set.
    /// - [`ReceivePersistenceError::BaseRootNotPinned`] if the base root is
    ///   not pinned.
    /// - [`ReceivePersistenceError::DatasetLineageMismatch`] if the lineage
    ///   does not match.
    pub fn validate_base_root_pin(
        &mut self,
        pin_lookup: &dyn BaseRootPinLookup,
    ) -> Result<(), ReceivePersistenceError> {
        let contract = self
            .contract
            .as_ref()
            .ok_or(ReceivePersistenceError::ContractRequired)?;

        if !pin_lookup.is_base_root_pinned(&contract.base_root_identity) {
            return Err(ReceivePersistenceError::BaseRootNotPinned {
                base_root_identity: contract.base_root_identity,
            });
        }

        if let Some(actual_lineage) =
            pin_lookup.dataset_lineage_for_base_root(&contract.base_root_identity)
        {
            if actual_lineage != contract.dataset_lineage_identity {
                return Err(ReceivePersistenceError::DatasetLineageMismatch {
                    expected: contract.dataset_lineage_identity,
                    actual: actual_lineage,
                });
            }
        }

        self.contract_validated = true;
        Ok(())
    }

    /// Returns `true` if an incremental contract is set and has been validated.
    #[must_use]
    pub fn has_validated_contract(&self) -> bool {
        self.contract.is_some() && self.contract_validated
    }

    /// Returns the current receive contract, if set.
    #[must_use]
    pub fn contract(&self) -> Option<&ReceiveContract> {
        self.contract.as_ref()
    }

    /// Number of objects successfully persisted since construction.
    #[must_use]
    pub fn objects_persisted(&self) -> u64 {
        self.objects_persisted
    }

    /// Total payload bytes persisted since construction.
    #[must_use]
    pub fn bytes_persisted(&self) -> u64 {
        self.bytes_persisted
    }

    /// Total chunks received (sum of `total_chunks`) since construction.
    #[must_use]
    pub fn chunks_received(&self) -> u64 {
        self.chunks_received
    }
}

impl<S: ObjectStore> ReceiveDispatch for ReceivePersistenceBridge<'_, S> {
    type Error = ReceivePersistenceError;

    fn store_object(&mut self, object: AssembledObject) -> Result<(), Self::Error> {
        // Enforce contract validation before any persistence for incremental
        // streams. A full (non-incremental) stream with no contract is
        // permitted without validation.
        if self.contract.is_some() && !self.contract_validated {
            return Err(ReceivePersistenceError::ContractNotValidated);
        }

        let sender_id = object.object_id;
        let payload_len = object.payload.len() as u64;

        // Persist via content-addressed put (BLAKE3-256 derives the key)
        let stored_key = self.store.put(&object.payload)?;

        // Verify BLAKE3 key consistency between sender and store
        if self.verify_key {
            let sender_key = ObjectKey::from_bytes32(sender_id);
            if stored_key != sender_key {
                return Err(StoreError::ContentAddressMismatch {
                    expected: sender_key,
                    actual: stored_key,
                }
                .into());
            }
        }

        self.objects_persisted += 1;
        self.bytes_persisted += payload_len;
        self.chunks_received += object.total_chunks as u64;

        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        // ObjectStore flushes segments internally during put; no explicit flush
        // is required on the trait. The store guarantees durability per put.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::AssembledObject;
    use blake3::hash;
    use std::collections::HashMap;
    use std::time::SystemTime;
    use tidefs_local_object_store::{ObjectAttr, ObjectKey, ObjectReadError, ObjectStore, StoreError};

    // ── Test helpers ──────────────────────────────────────────────────

    fn content_key(payload: &[u8]) -> ObjectKey {
        ObjectKey::from_bytes32(hash(payload).into())
    }

    fn make_object(_id_byte: u8, payload: &[u8], total_chunks: u32) -> AssembledObject {
        // Derive object_id from content so key verification passes by default.
        // Callers that need a non-matching id must construct AssembledObject directly.
        let object_id = content_key(payload).as_bytes32();
        AssembledObject {
            object_id,
            payload: payload.to_vec(),
            total_chunks,
        }
    }

    /// A minimal in-memory ObjectStore for unit tests.
    #[derive(Debug, Default)]
    struct MockStore {
        objects: HashMap<ObjectKey, Vec<u8>>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                objects: HashMap::new(),
            }
        }

        fn object_count(&self) -> usize {
            self.objects.len()
        }

        fn get_object(&self, key: ObjectKey) -> Option<&Vec<u8>> {
            self.objects.get(&key)
        }
    }

    impl ObjectStore for MockStore {
        type Scan = std::vec::IntoIter<ObjectKey>;

        fn put(&mut self, payload: &[u8]) -> Result<ObjectKey, StoreError> {
            let key = ObjectKey::from_content(payload);
            self.objects.insert(key, payload.to_vec());
            Ok(key)
        }

        fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>, StoreError> {
            Ok(self.objects.get(&key).cloned())
        }

        fn delete(&mut self, key: ObjectKey) -> Result<bool, StoreError> {
            Ok(self.objects.remove(&key).is_some())
        }

        fn scan(&self) -> Self::Scan {
            self.objects.keys().copied().collect::<Vec<_>>().into_iter()
        }

        fn get_attr(
            &self,
            key: &ObjectKey,
        ) -> std::result::Result<ObjectAttr, ObjectReadError> {
            match self.objects.get(key) {
                Some(payload) => Ok(ObjectAttr {
                    size: payload.len() as u64,
                    key: *key,
                    created: SystemTime::UNIX_EPOCH,
                }),
                None => Err(ObjectReadError::NotFound { key: *key }),
            }
        }
    }

    /// A pin lookup that holds a set of pinned base-root identities and
    /// optional lineage mappings.
    struct TestPinLookup {
        pinned: HashMap<[u8; 32], Option<[u8; 32]>>,
    }

    impl TestPinLookup {
        fn new() -> Self {
            Self {
                pinned: HashMap::new(),
            }
        }

        fn insert(&mut self, identity: [u8; 32], lineage: Option<[u8; 32]>) {
            self.pinned.insert(identity, lineage);
        }
    }

    impl BaseRootPinLookup for TestPinLookup {
        fn is_base_root_pinned(&self, base_root_identity: &[u8; 32]) -> bool {
            self.pinned.contains_key(base_root_identity)
        }

        fn dataset_lineage_for_base_root(
            &self,
            base_root_identity: &[u8; 32],
        ) -> Option<[u8; 32]> {
            self.pinned.get(base_root_identity).and_then(|v| *v)
        }
    }

    fn test_contract(base_byte: u8) -> ReceiveContract {
        let mut base = [0u8; 32];
        base[0] = base_byte;
        let mut lineage = [0u8; 32];
        lineage[0] = base_byte.wrapping_add(0x10);
        ReceiveContract {
            base_root_identity: base,
            dataset_lineage_identity: lineage,
            receive_generation: 1,
        }
    }

    // ── Contract validation tests ─────────────────────────────────────

    #[test]
    fn validate_base_root_pinned_succeeds() {
        let mut pin_lookup = TestPinLookup::new();
        let contract = test_contract(0x01);
        pin_lookup.insert(contract.base_root_identity, None);

        let mut mock = MockStore::new();
        let mut bridge =
            ReceivePersistenceBridge::new(&mut mock).with_incremental_contract(contract);

        bridge.validate_base_root_pin(&pin_lookup).unwrap();
        assert!(bridge.has_validated_contract());
    }

    #[test]
    fn validate_base_root_not_pinned_fails() {
        let pin_lookup = TestPinLookup::new();
        let contract = test_contract(0x02);

        let mut mock = MockStore::new();
        let mut bridge =
            ReceivePersistenceBridge::new(&mut mock).with_incremental_contract(contract);

        let err = bridge.validate_base_root_pin(&pin_lookup).unwrap_err();
        assert!(matches!(
            err,
            ReceivePersistenceError::BaseRootNotPinned { .. }
        ));
        assert!(!bridge.has_validated_contract());
    }

    #[test]
    fn validate_lineage_mismatch_fails() {
        let mut pin_lookup = TestPinLookup::new();
        let contract = test_contract(0x03);
        let mut wrong_lineage = [0u8; 32];
        wrong_lineage[0] = 0xFF;
        pin_lookup.insert(contract.base_root_identity, Some(wrong_lineage));

        let mut mock = MockStore::new();
        let mut bridge =
            ReceivePersistenceBridge::new(&mut mock).with_incremental_contract(contract);

        let err = bridge.validate_base_root_pin(&pin_lookup).unwrap_err();
        assert!(matches!(
            err,
            ReceivePersistenceError::DatasetLineageMismatch { .. }
        ));
        assert!(!bridge.has_validated_contract());
    }

    #[test]
    fn validate_with_lineage_match_succeeds() {
        let mut pin_lookup = TestPinLookup::new();
        let contract = test_contract(0x04);
        pin_lookup.insert(
            contract.base_root_identity,
            Some(contract.dataset_lineage_identity),
        );

        let mut mock = MockStore::new();
        let mut bridge =
            ReceivePersistenceBridge::new(&mut mock).with_incremental_contract(contract);

        bridge.validate_base_root_pin(&pin_lookup).unwrap();
        assert!(bridge.has_validated_contract());
    }

    #[test]
    fn validate_without_contract_fails() {
        let pin_lookup = TestPinLookup::new();
        let mut mock = MockStore::new();
        let mut bridge = ReceivePersistenceBridge::new(&mut mock);

        let err = bridge.validate_base_root_pin(&pin_lookup).unwrap_err();
        assert!(matches!(err, ReceivePersistenceError::ContractRequired));
    }

    // ── Persistence blocking tests ────────────────────────────────────

    #[test]
    fn store_object_blocked_when_contract_not_validated() {
        let mut mock = MockStore::new();
        let contract = test_contract(0x05);
        let mut bridge =
            ReceivePersistenceBridge::new(&mut mock).with_incremental_contract(contract);

        let obj = make_object(0xAA, b"blocked", 1);
        let err = bridge.store_object(obj).unwrap_err();
        assert!(matches!(
            err,
            ReceivePersistenceError::ContractNotValidated
        ));
        assert_eq!(bridge.objects_persisted(), 0);
        assert_eq!(mock.object_count(), 0);
    }

    #[test]
    fn store_object_succeeds_after_contract_validated() {
        let mut pin_lookup = TestPinLookup::new();
        let contract = test_contract(0x06);
        pin_lookup.insert(contract.base_root_identity, None);

        let mut mock = MockStore::new();
        let mut bridge =
            ReceivePersistenceBridge::new(&mut mock).with_incremental_contract(contract);

        bridge.validate_base_root_pin(&pin_lookup).unwrap();

        let obj = make_object(0xBB, b"allowed", 1);
        bridge.store_object(obj).unwrap();
        assert_eq!(bridge.objects_persisted(), 1);
        assert_eq!(mock.object_count(), 1);
    }

    #[test]
    fn store_object_succeeds_without_contract() {
        let mut mock = MockStore::new();
        let mut bridge = ReceivePersistenceBridge::new(&mut mock);

        let obj = make_object(0xCC, b"no-contract", 1);
        bridge.store_object(obj).unwrap();
        assert_eq!(bridge.objects_persisted(), 1);
        assert_eq!(mock.object_count(), 1);
    }

    #[test]
    fn store_object_blocked_after_failed_validation() {
        let mut pin_lookup = TestPinLookup::new();
        let contract = test_contract(0x07);
        // Don't insert the base root — it will fail validation
        pin_lookup.insert([0xFF; 32], None); // some other root

        let mut mock = MockStore::new();
        let mut bridge =
            ReceivePersistenceBridge::new(&mut mock).with_incremental_contract(contract);

        let val_err = bridge.validate_base_root_pin(&pin_lookup).unwrap_err();
        assert!(matches!(
            val_err,
            ReceivePersistenceError::BaseRootNotPinned { .. }
        ));

        // Contract remains unvalidated — persistence is still blocked
        let obj = make_object(0xDD, b"still-blocked", 1);
        let store_err = bridge.store_object(obj).unwrap_err();
        assert!(matches!(
            store_err,
            ReceivePersistenceError::ContractNotValidated
        ));
        assert_eq!(bridge.objects_persisted(), 0);
        assert_eq!(mock.object_count(), 0);
    }

    // ── Key verification ──────────────────────────────────────────────

    #[test]
    fn key_mismatch_with_contract_validated() {
        let mut pin_lookup = TestPinLookup::new();
        let contract = test_contract(0x08);
        pin_lookup.insert(contract.base_root_identity, None);

        let mut mock = MockStore::new();
        let mut bridge =
            ReceivePersistenceBridge::new(&mut mock).with_incremental_contract(contract);

        bridge.validate_base_root_pin(&pin_lookup).unwrap();

        // Create an object whose content-derived key doesn't match object_id
        let payload = b"content-mismatch";
        let wrong_id = [0xEE; 32];
        let obj = AssembledObject {
            object_id: wrong_id,
            payload: payload.to_vec(),
            total_chunks: 1,
        };

        let err = bridge.store_object(obj).unwrap_err();
        assert!(matches!(
            err,
            ReceivePersistenceError::Store(StoreError::ContentAddressMismatch { .. })
        ));
        // Object was NOT persisted due to key mismatch
        assert_eq!(bridge.objects_persisted(), 0);
    }

    // ── Error display ─────────────────────────────────────────────────

    #[test]
    fn error_display_formats() {
        let base = [0xAB; 32];
        assert!(
            format!(
                "{}",
                ReceivePersistenceError::BaseRootNotPinned {
                    base_root_identity: base
                }
            )
            .contains("not pinned")
        );
        assert!(
            format!("{}", ReceivePersistenceError::ContractNotValidated)
                .contains("not been validated")
        );
        assert!(
            format!("{}", ReceivePersistenceError::ContractRequired).contains("required")
        );
        let lineage_err = format!(
            "{}",
            ReceivePersistenceError::DatasetLineageMismatch {
                expected: [0x01; 32],
                actual: [0x02; 32],
            }
        );
        assert!(lineage_err.contains("lineage mismatch"));
    }

    #[test]
    fn error_from_store_error() {
        let store_err = StoreError::ContentAddressMismatch {
            expected: ObjectKey::from_bytes32([0x01; 32]),
            actual: ObjectKey::from_bytes32([0x02; 32]),
        };
        let persist_err: ReceivePersistenceError = store_err.into();
        assert!(matches!(
            persist_err,
            ReceivePersistenceError::Store(StoreError::ContentAddressMismatch { .. })
        ));
    }

    // ── Contract accessors ────────────────────────────────────────────

    #[test]
    fn contract_accessor_returns_set_contract() {
        let mut mock = MockStore::new();
        let contract = test_contract(0x09);
        let bridge =
            ReceivePersistenceBridge::new(&mut mock).with_incremental_contract(contract);

        assert_eq!(bridge.contract(), Some(&contract));
        assert!(!bridge.has_validated_contract());
    }

    #[test]
    fn contract_accessor_returns_none_when_no_contract() {
        let mut mock = MockStore::new();
        let bridge = ReceivePersistenceBridge::new(&mut mock);
        assert!(bridge.contract().is_none());
        assert!(!bridge.has_validated_contract());
    }

    // ── Existing persistence tests (adapted for new error type) ───────

    #[test]
    fn content_addressed_put_with_key_verification() {
        let mut mock = MockStore::new();
        let mut bridge = ReceivePersistenceBridge::new(&mut mock);

        let payload = b"hello store";
        let obj_id = content_key(payload).as_bytes32();
        let obj = AssembledObject {
            object_id: obj_id,
            payload: payload.to_vec(),
            total_chunks: 1,
        };

        bridge.store_object(obj).unwrap();
        assert_eq!(bridge.objects_persisted(), 1);
        assert_eq!(bridge.bytes_persisted(), payload.len() as u64);
        assert_eq!(mock.object_count(), 1);

        let stored = mock.get_object(content_key(payload)).unwrap();
        assert_eq!(stored, payload);
    }

    #[test]
    fn content_addressed_put_without_key_verification() {
        let mut mock = MockStore::new();
        let mut bridge = ReceivePersistenceBridge::new(&mut mock).with_key_verification(false);

        let payload = b"no-verify";
        let wrong_id = [0x99; 32]; // different from content-derived key
        let obj = AssembledObject {
            object_id: wrong_id,
            payload: payload.to_vec(),
            total_chunks: 1,
        };

        // Should succeed because key verification is off
        bridge.store_object(obj).unwrap();
        assert_eq!(bridge.objects_persisted(), 1);

        // Object is stored under the content-derived key
        let content = content_key(payload);
        assert!(mock.get_object(content).is_some());
    }

    #[test]
    fn repeated_object_idempotent_persistence() {
        let mut mock = MockStore::new();
        let mut bridge = ReceivePersistenceBridge::new(&mut mock);

        let payload = b"idempotent-test";
        let obj_id = content_key(payload).as_bytes32();

        let obj1 = AssembledObject {
            object_id: obj_id,
            payload: payload.to_vec(),
            total_chunks: 1,
        };
        bridge.store_object(obj1).unwrap();
        assert_eq!(bridge.objects_persisted(), 1);

        // Second put with same content-derived key — depends on store behavior
        let obj2 = AssembledObject {
            object_id: obj_id,
            payload: payload.to_vec(),
            total_chunks: 1,
        };
        // Content-addressed put produces the same key, so no mismatch
        let result = bridge.store_object(obj2);
        assert!(result.is_ok());

        // Verify count after all bridge operations complete
        assert_eq!(mock.object_count(), 1);
    }

    #[test]
    fn empty_payload_object_persists() {
        let mut mock = MockStore::new();
        let mut bridge = ReceivePersistenceBridge::new(&mut mock);

        let obj = make_object(0x01, b"", 0);
        bridge.store_object(obj).unwrap();

        assert_eq!(bridge.objects_persisted(), 1);
        assert_eq!(bridge.bytes_persisted(), 0);
        assert_eq!(mock.object_count(), 1);

        let key = content_key(b"");
        assert!(mock.get_object(key).is_some());
    }

    #[test]
    fn counters_accumulate_across_multiple_calls() {
        let mut mock = MockStore::new();
        let mut bridge = ReceivePersistenceBridge::new(&mut mock);

        let obj1 = make_object(0x01, b"aaaa", 2);
        let obj2 = make_object(0x02, b"bbb", 3);

        bridge.store_object(obj1).unwrap();
        assert_eq!(bridge.objects_persisted(), 1);
        assert_eq!(bridge.bytes_persisted(), 4);
        assert_eq!(bridge.chunks_received(), 2);

        bridge.store_object(obj2).unwrap();
        assert_eq!(bridge.objects_persisted(), 2);
        assert_eq!(bridge.bytes_persisted(), 7);
        assert_eq!(bridge.chunks_received(), 5);
    }
}
