//! Replication dispatch engine.
//!
//! Consumes a [`ReplicationIntent`] (Mirror or ErasureCoded) and fans out
//! object writes to placement-selected target devices through registered
//! object-store backends. Layout validation runs as a pre-condition before
//! any write is attempted.
//!
//! # Architecture
//!
//! ```text
//! ReplicationIntent  --  PlacementResolver  --  PlacementEntry[]
//!                                                 |
//!                               LayoutValidator::validate()
//!                                                 |
//!                               ObjectStoreRegistry -- fan-out writes
//!                                                 |
//!                               ReplicationOutcome (per-target digests)
//! ```

use tidefs_replication_model::{
    LayoutValidationError, LayoutValidator, PlacementEntry, ReplicationIntent,
};

// ---------------------------------------------------------------------------
// ReplicationTargetResult
// ---------------------------------------------------------------------------

/// Per-target result within a replication dispatch.
///
/// Captures the placement entry, BLAKE3 digest, and success/failure
/// status for a single replica or erasure-coded shard write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicationTargetResult {
    /// The placement entry identifying the target device/node/rack.
    pub entry: PlacementEntry,
    /// BLAKE3-256 digest of the written payload (32 bytes).
    pub digest: [u8; 32],
    /// Whether the write succeeded on this target.
    pub success: bool,
    /// Error description if the write failed.
    pub error: Option<String>,
}

impl ReplicationTargetResult {
    /// Build a successful result.
    #[must_use]
    pub fn success(entry: PlacementEntry, digest: [u8; 32]) -> Self {
        Self {
            entry,
            digest,
            success: true,
            error: None,
        }
    }

    /// Build a failed result.
    #[must_use]
    pub fn failure(entry: PlacementEntry, error: String) -> Self {
        Self {
            entry,
            digest: [0u8; 32],
            success: false,
            error: Some(error),
        }
    }
}

// ---------------------------------------------------------------------------
// ReplicationOutcome
// ---------------------------------------------------------------------------

/// Full outcome of a replication dispatch operation.
///
/// Aggregates per-target results, success/failure counts, layout
/// validation status, and cross-replica digest consistency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicationOutcome {
    /// Per-target write results, one per placement entry.
    pub targets: Vec<ReplicationTargetResult>,
    /// Number of targets that acknowledged the write.
    pub succeeded: usize,
    /// Number of targets that failed the write.
    pub failed: usize,
    /// Whether the layout passed validation.
    pub layout_valid: bool,
    /// Layout validation error, when validation failed.
    pub layout_error: Option<LayoutValidationError>,
    /// BLAKE3 digests from all successful targets.
    pub successful_digests: Vec<[u8; 32]>,
    /// Whether all successful targets produced the same digest.
    pub digests_consistent: bool,
}

impl ReplicationOutcome {
    /// Build an outcome from per-target results and optional layout error.
    #[must_use]
    pub fn new(
        targets: Vec<ReplicationTargetResult>,
        layout_error: Option<LayoutValidationError>,
    ) -> Self {
        let succeeded = targets.iter().filter(|t| t.success).count();
        let failed = targets.len() - succeeded;
        let layout_valid = layout_error.is_none();

        let successful_digests: Vec<[u8; 32]> = targets
            .iter()
            .filter(|t| t.success)
            .map(|t| t.digest)
            .collect();

        let digests_consistent = if successful_digests.is_empty() {
            true
        } else {
            let first = successful_digests[0];
            successful_digests.iter().all(|d| *d == first)
        };

        Self {
            targets,
            succeeded,
            failed,
            layout_valid,
            layout_error,
            successful_digests,
            digests_consistent,
        }
    }

    /// Returns `true` if at least one target succeeded.
    #[must_use]
    pub fn any_succeeded(&self) -> bool {
        self.succeeded > 0
    }

    /// Returns `true` if all targets succeeded.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.failed == 0 && self.succeeded > 0
    }

    /// Returns `true` if quorum (simple majority of total targets) was
    /// reached.
    #[must_use]
    pub fn quorum_reached(&self) -> bool {
        let total = self.targets.len();
        if total == 0 {
            return false;
        }
        self.succeeded >= (total / 2 + 1)
    }
}

// ---------------------------------------------------------------------------
// PlacementResolver trait
// ---------------------------------------------------------------------------

/// Resolves a [`ReplicationIntent`] into concrete placement entries.
///
/// Implementations bridge the intent model to the placement subsystem
/// (e.g. `tidefs-placement-runtime`) to select target devices that satisfy
/// the failure-domain constraints.
pub trait PlacementResolver {
    /// Given a replication intent, produce the set of placement entries
    /// that satisfy its target count and failure-domain requirements.
    ///
    /// Returns an error if insufficient devices or failure domains are
    /// available to meet the intent.
    fn resolve(&self, intent: &ReplicationIntent) -> Result<Vec<PlacementEntry>, String>;
}

// ---------------------------------------------------------------------------
// ObjectWriteTarget trait
// ---------------------------------------------------------------------------

/// A target capable of receiving an object write and returning a BLAKE3
/// digest.
///
/// Implementations may wrap a local-object-store instance, a transport
/// session to a remote node, or a mock for testing.
pub trait ObjectWriteTarget {
    /// Write `payload` identified by `key` to the device with the given
    /// `device_id`. Returns the BLAKE3-256 digest of the payload on success.
    fn put_object(
        &mut self,
        device_id: u64,
        key: &[u8],
        payload: &[u8],
    ) -> Result<[u8; 32], String>;
}

// ---------------------------------------------------------------------------
// ObjectStoreRegistry trait
// ---------------------------------------------------------------------------

/// Registry mapping device identifiers to [`ObjectWriteTarget`] backends.
///
/// The dispatcher uses this to fan out writes. In production this might
/// maintain local-object-store handles per device; in tests it serves
/// mock stores.
pub trait ObjectStoreRegistry {
    /// Return a mutable reference to the write target for the given device,
    /// or `None` if the device is unknown.
    fn get_target_mut(&mut self, device_id: u64) -> Option<&mut dyn ObjectWriteTarget>;
}

// ---------------------------------------------------------------------------
// ReplicationDispatcher
// ---------------------------------------------------------------------------

/// Replication dispatch engine.
///
/// Consumes a [`ReplicationIntent`] together with placement-resolved
/// targets and fans out object writes through registered backends.
/// Layout validation runs as a pre-condition before any write is
/// attempted.
///
/// # Type parameters
///
/// * `P` - placement resolver producing [`PlacementEntry`] targets.
/// * `R` - registry providing per-device [`ObjectWriteTarget`] backends.
pub struct ReplicationDispatcher<P: PlacementResolver, R: ObjectStoreRegistry> {
    placement: P,
    registry: R,
}

impl<P: PlacementResolver, R: ObjectStoreRegistry> ReplicationDispatcher<P, R> {
    /// Create a new dispatcher with the given placement resolver and
    /// object-store registry.
    #[must_use]
    pub const fn new(placement: P, registry: R) -> Self {
        Self {
            placement,
            registry,
        }
    }

    /// Dispatch an object write according to the replication intent.
    ///
    /// # Flow
    ///
    /// 1. Resolve placement entries from the intent via [`PlacementResolver`].
    /// 2. Validate the placement against the intent via
    ///    [`LayoutValidator::validate`].
    /// 3. Fan out the payload to each target device through the
    ///    [`ObjectStoreRegistry`].
    /// 4. Collect per-target BLAKE3 digests and aggregate into a
    ///    [`ReplicationOutcome`].
    ///
    /// If placement resolution fails, the outcome is empty with the error
    /// recorded. If layout validation fails, the error is captured but
    /// writes still proceed (degraded dispatch). Individual write failures
    /// are captured per-target.
    pub fn dispatch(
        &mut self,
        intent: &ReplicationIntent,
        object_key: &[u8],
        payload: &[u8],
    ) -> ReplicationOutcome {
        // 1. Resolve placement.
        let entries = match self.placement.resolve(intent) {
            Ok(entries) => entries,
            Err(_e) => {
                return ReplicationOutcome::new(
                    Vec::new(),
                    Some(LayoutValidationError::InsufficientEntries {
                        intent: intent.to_string(),
                        required: intent.total_targets(),
                        actual: 0,
                    }),
                );
            }
        };

        // 2. Layout validation (pre-condition).
        let layout_error = LayoutValidator::validate(intent, &entries).err();

        // 3. Fan-out writes.
        let mut results = Vec::with_capacity(entries.len());

        for entry in &entries {
            let device_id = entry.device_id;

            let result = match self.registry.get_target_mut(device_id) {
                Some(target) => match target.put_object(device_id, object_key, payload) {
                    Ok(digest) => ReplicationTargetResult::success(entry.clone(), digest),
                    Err(e) => ReplicationTargetResult::failure(entry.clone(), e),
                },
                None => ReplicationTargetResult::failure(
                    entry.clone(),
                    format!("no object-store backend registered for device {device_id}"),
                ),
            };

            results.push(result);
        }

        ReplicationOutcome::new(results, layout_error)
    }

    /// Return a shared reference to the placement resolver.
    #[must_use]
    pub fn placement(&self) -> &P {
        &self.placement
    }

    /// Return a shared reference to the object-store registry.
    #[must_use]
    pub fn registry(&self) -> &R {
        &self.registry
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tidefs_replication_model::{FailureDomain, PlacementEntry, ReplicationIntent};

    // -- Mock placement resolver --------------------------------------------

    /// A placement resolver that returns pre-configured entries.
    struct MockPlacementResolver {
        entries: Vec<PlacementEntry>,
    }

    impl MockPlacementResolver {
        fn new(entries: Vec<PlacementEntry>) -> Self {
            Self { entries }
        }
    }

    impl PlacementResolver for MockPlacementResolver {
        fn resolve(&self, _intent: &ReplicationIntent) -> Result<Vec<PlacementEntry>, String> {
            Ok(self.entries.clone())
        }
    }

    /// A placement resolver that always fails.
    struct FailingPlacementResolver {
        reason: String,
    }

    impl PlacementResolver for FailingPlacementResolver {
        fn resolve(&self, _intent: &ReplicationIntent) -> Result<Vec<PlacementEntry>, String> {
            Err(self.reason.clone())
        }
    }

    // -- Mock object-store registry -----------------------------------------

    /// In-memory registry mapping device_id to mock store.
    struct MockObjectStoreRegistry {
        stores: HashMap<u64, MockObjectStore>,
    }

    impl MockObjectStoreRegistry {
        fn new() -> Self {
            Self {
                stores: HashMap::new(),
            }
        }

        fn with_store(mut self, device_id: u64, store: MockObjectStore) -> Self {
            self.stores.insert(device_id, store);
            self
        }
    }

    impl ObjectStoreRegistry for MockObjectStoreRegistry {
        fn get_target_mut(&mut self, device_id: u64) -> Option<&mut dyn ObjectWriteTarget> {
            self.stores
                .get_mut(&device_id)
                .map(|s| s as &mut dyn ObjectWriteTarget)
        }
    }

    /// A mock store that records writes and optionally returns errors.
    #[derive(Default)]
    struct MockObjectStore {
        pub writes: Vec<(Vec<u8>, Vec<u8>, [u8; 32])>,
        pub fail_next: Option<String>,
        pub out_of_space: bool,
    }

    impl MockObjectStore {
        fn new() -> Self {
            Self::default()
        }

        fn with_failure(mut self, msg: impl Into<String>) -> Self {
            self.fail_next = Some(msg.into());
            self
        }
    }

    impl ObjectWriteTarget for MockObjectStore {
        fn put_object(
            &mut self,
            _device_id: u64,
            key: &[u8],
            payload: &[u8],
        ) -> Result<[u8; 32], String> {
            if let Some(msg) = self.fail_next.take() {
                return Err(msg);
            }
            if self.out_of_space {
                return Err("ENOSPC".into());
            }
            let digest = blake3::hash(payload);
            let digest_bytes: [u8; 32] = digest.into();
            self.writes
                .push((key.to_vec(), payload.to_vec(), digest_bytes));
            Ok(digest_bytes)
        }
    }

    // -- Helpers ------------------------------------------------------------

    fn make_entry(shard: u16, device: u64, node: u64, rack: u64) -> PlacementEntry {
        PlacementEntry::new(shard, device, node, rack)
    }

    fn mirror_2_intent() -> ReplicationIntent {
        ReplicationIntent::new_mirror(2, FailureDomain::Node).unwrap()
    }

    fn mirror_3_intent() -> ReplicationIntent {
        ReplicationIntent::new_mirror(3, FailureDomain::Node).unwrap()
    }

    fn ec_4_2_intent() -> ReplicationIntent {
        ReplicationIntent::new_erasure_coded(4, 2, FailureDomain::Rack).unwrap()
    }

    fn make_dispatcher(
        entries: Vec<PlacementEntry>,
        registry: MockObjectStoreRegistry,
    ) -> ReplicationDispatcher<MockPlacementResolver, MockObjectStoreRegistry> {
        ReplicationDispatcher::new(MockPlacementResolver::new(entries), registry)
    }

    // -- Mirror-2 dispatch across distinct devices --------------------------

    #[test]
    fn mirror_2_distinct_devices_all_succeed() {
        let entries = vec![make_entry(0, 1, 10, 100), make_entry(1, 2, 20, 200)];
        let registry = MockObjectStoreRegistry::new()
            .with_store(1, MockObjectStore::new())
            .with_store(2, MockObjectStore::new());
        let mut dispatcher = make_dispatcher(entries, registry);

        let intent = mirror_2_intent();
        let outcome = dispatcher.dispatch(&intent, b"obj-001", b"hello mirror");

        assert!(outcome.layout_valid);
        assert_eq!(outcome.succeeded, 2);
        assert_eq!(outcome.failed, 0);
        assert!(outcome.all_succeeded());
        assert!(outcome.quorum_reached());
        assert!(outcome.digests_consistent);
        assert_eq!(outcome.successful_digests.len(), 2);
        assert_eq!(outcome.successful_digests[0], outcome.successful_digests[1]);
    }

    #[test]
    fn mirror_2_distinct_devices_one_failure() {
        let entries = vec![make_entry(0, 1, 10, 100), make_entry(1, 2, 20, 200)];
        let registry = MockObjectStoreRegistry::new()
            .with_store(1, MockObjectStore::new().with_failure("device offline"))
            .with_store(2, MockObjectStore::new());
        let mut dispatcher = make_dispatcher(entries, registry);

        let intent = mirror_2_intent();
        let outcome = dispatcher.dispatch(&intent, b"obj-002", b"partial write");

        assert_eq!(outcome.succeeded, 1);
        assert_eq!(outcome.failed, 1);
        assert!(outcome.any_succeeded());
        assert!(!outcome.all_succeeded());
        // For 2 targets, quorum needs 2/2+1 = 2, so 1 is not enough.
        assert!(!outcome.quorum_reached());
        assert!(outcome.digests_consistent);
        assert!(outcome.targets[0].error.is_some());
    }

    // -- Mirror-3 with single-device failure domain rejection ---------------

    #[test]
    fn mirror_3_single_device_failure_domain_rejected() {
        // All three entries share device_id=1 -- violates Device-level
        // failure domain separation for a Mirror-3 with Device domain.
        let entries = vec![
            make_entry(0, 1, 10, 100),
            make_entry(1, 1, 20, 200),
            make_entry(2, 1, 30, 300),
        ];
        let registry = MockObjectStoreRegistry::new().with_store(1, MockObjectStore::new());
        let mut dispatcher = make_dispatcher(entries, registry);

        let intent = ReplicationIntent::new_mirror(3, FailureDomain::Device).unwrap();
        let outcome = dispatcher.dispatch(&intent, b"obj-003", b"should fail layout");

        assert!(!outcome.layout_valid);
        assert!(outcome.layout_error.is_some());
        match &outcome.layout_error {
            Some(LayoutValidationError::DomainCollision {
                domain,
                colliding_id,
                ..
            }) => {
                assert_eq!(*domain, FailureDomain::Device);
                assert_eq!(*colliding_id, 1);
            }
            other => panic!("expected DomainCollision, got {other:?}"),
        }
        // Writes still proceed despite layout failure (degraded dispatch).
        assert_eq!(outcome.succeeded, 3);
    }

    // -- ErasureCoded(4+2) dispatch -----------------------------------------

    #[test]
    fn ec_4_2_six_distinct_racks_all_succeed() {
        let entries = vec![
            make_entry(0, 1, 10, 100),
            make_entry(1, 2, 20, 200),
            make_entry(2, 3, 30, 300),
            make_entry(3, 4, 40, 400),
            make_entry(4, 5, 50, 500),
            make_entry(5, 6, 60, 600),
        ];
        let mut registry = MockObjectStoreRegistry::new();
        for i in 1..=6 {
            registry = registry.with_store(i, MockObjectStore::new());
        }
        let mut dispatcher = make_dispatcher(entries, registry);

        let intent = ec_4_2_intent();
        let outcome = dispatcher.dispatch(&intent, b"obj-ec", b"erasure coded payload");

        assert!(outcome.layout_valid);
        assert_eq!(outcome.succeeded, 6);
        assert_eq!(outcome.failed, 0);
        assert!(outcome.all_succeeded());
        assert!(outcome.digests_consistent);
    }

    #[test]
    fn ec_4_2_rack_collision_detected() {
        // Shards 0 and 3 share rack_id=100 -- violates rack-level separation.
        let entries = vec![
            make_entry(0, 1, 10, 100),
            make_entry(1, 2, 20, 200),
            make_entry(2, 3, 30, 300),
            make_entry(3, 4, 40, 100), // collision on rack=100
            make_entry(4, 5, 50, 500),
            make_entry(5, 6, 60, 600),
        ];
        let mut registry = MockObjectStoreRegistry::new();
        for i in 1..=6 {
            registry = registry.with_store(i, MockObjectStore::new());
        }
        let mut dispatcher = make_dispatcher(entries, registry);

        let intent = ec_4_2_intent();
        let outcome = dispatcher.dispatch(&intent, b"obj-ec-bad", b"bad layout");

        assert!(!outcome.layout_valid);
        match &outcome.layout_error {
            Some(LayoutValidationError::DomainCollision {
                domain,
                colliding_id,
                ..
            }) => {
                assert_eq!(*domain, FailureDomain::Rack);
                assert_eq!(*colliding_id, 100);
            }
            other => panic!("expected DomainCollision, got {other:?}"),
        }
        assert_eq!(outcome.succeeded, 6);
    }

    // -- Placement exhaustion -----------------------------------------------

    #[test]
    fn mirror_3_insufficient_entries() {
        // Only 2 entries for a Mirror-3 intent.
        let entries = vec![make_entry(0, 1, 10, 100), make_entry(1, 2, 20, 200)];
        let registry = MockObjectStoreRegistry::new()
            .with_store(1, MockObjectStore::new())
            .with_store(2, MockObjectStore::new());
        let mut dispatcher = make_dispatcher(entries, registry);

        let intent = mirror_3_intent();
        let outcome = dispatcher.dispatch(&intent, b"obj-004", b"not enough targets");

        assert!(!outcome.layout_valid);
        match &outcome.layout_error {
            Some(LayoutValidationError::InsufficientEntries {
                required, actual, ..
            }) => {
                assert_eq!(*required, 3);
                assert_eq!(*actual, 2);
            }
            other => panic!("expected InsufficientEntries, got {other:?}"),
        }
        // The 2 available targets still get the write.
        assert_eq!(outcome.succeeded, 2);
    }

    #[test]
    fn ec_4_2_insufficient_entries() {
        let entries = vec![
            make_entry(0, 1, 10, 100),
            make_entry(1, 2, 20, 200),
            make_entry(2, 3, 30, 300),
        ]; // Only 3, need 6
        let mut registry = MockObjectStoreRegistry::new();
        for i in 1..=3 {
            registry = registry.with_store(i, MockObjectStore::new());
        }
        let mut dispatcher = make_dispatcher(entries, registry);

        let intent = ec_4_2_intent();
        let outcome = dispatcher.dispatch(&intent, b"obj-ec-few", b"too few");

        assert!(!outcome.layout_valid);
        match &outcome.layout_error {
            Some(LayoutValidationError::InsufficientEntries {
                required, actual, ..
            }) => {
                assert_eq!(*required, 6);
                assert_eq!(*actual, 3);
            }
            other => panic!("expected InsufficientEntries, got {other:?}"),
        }
        assert_eq!(outcome.succeeded, 3);
    }

    // -- Placement resolver failure -----------------------------------------

    #[test]
    fn placement_resolver_failure_returns_empty_outcome() {
        let registry = MockObjectStoreRegistry::new();
        let resolver = FailingPlacementResolver {
            reason: "no devices available".into(),
        };
        let mut dispatcher = ReplicationDispatcher::new(resolver, registry);

        let intent = mirror_2_intent();
        let outcome = dispatcher.dispatch(&intent, b"obj-005", b"no targets");

        assert!(outcome.targets.is_empty());
        assert_eq!(outcome.succeeded, 0);
        assert_eq!(outcome.failed, 0);
        assert!(!outcome.layout_valid);
        assert!(!outcome.any_succeeded());
        assert!(!outcome.quorum_reached());
    }

    // -- Missing device in registry -----------------------------------------

    #[test]
    fn missing_device_in_registry_reported_as_failure() {
        let entries = vec![
            make_entry(0, 1, 10, 100),
            make_entry(1, 99, 20, 200), // device 99 not in registry
        ];
        let registry = MockObjectStoreRegistry::new().with_store(1, MockObjectStore::new());
        let mut dispatcher = make_dispatcher(entries, registry);

        let intent = mirror_2_intent();
        let outcome = dispatcher.dispatch(&intent, b"obj-006", b"missing device");

        assert_eq!(outcome.succeeded, 1);
        assert_eq!(outcome.failed, 1);
        assert!(outcome.targets[0].success);
        assert!(!outcome.targets[1].success);
        assert!(outcome.targets[1]
            .error
            .as_deref()
            .unwrap()
            .contains("no object-store"));
    }

    // -- Digest consistency checking ----------------------------------------

    #[test]
    fn cross_replica_digest_mismatch_detected() {
        // A store that returns a different digest per call to simulate
        // divergence.
        struct DivergentStore {
            tag: u8,
        }
        impl ObjectWriteTarget for DivergentStore {
            fn put_object(
                &mut self,
                _device_id: u64,
                _key: &[u8],
                payload: &[u8],
            ) -> Result<[u8; 32], String> {
                let mut hasher = blake3::Hasher::new();
                hasher.update(payload);
                hasher.update(&[self.tag]);
                Ok(hasher.finalize().into())
            }
        }

        struct DivergeRegistry {
            store1: DivergentStore,
            store2: DivergentStore,
        }

        impl DivergeRegistry {
            fn new() -> Self {
                Self {
                    store1: DivergentStore { tag: 1 },
                    store2: DivergentStore { tag: 2 },
                }
            }
        }
        impl ObjectStoreRegistry for DivergeRegistry {
            fn get_target_mut(&mut self, device_id: u64) -> Option<&mut dyn ObjectWriteTarget> {
                match device_id {
                    1 => Some(&mut self.store1),
                    2 => Some(&mut self.store2),
                    _ => None,
                }
            }
        }

        let entries = vec![make_entry(0, 1, 10, 100), make_entry(1, 2, 20, 200)];
        let registry = DivergeRegistry::new();
        let mut dispatcher =
            ReplicationDispatcher::new(MockPlacementResolver::new(entries), registry);

        let intent = mirror_2_intent();
        let outcome = dispatcher.dispatch(&intent, b"obj-div", b"divergent payload");

        assert!(outcome.layout_valid);
        assert_eq!(outcome.succeeded, 2);
        assert!(!outcome.digests_consistent);
    }

    // -- Mirror-1 (no redundancy) -------------------------------------------

    #[test]
    fn mirror_1_single_target_dispatch() {
        let entries = vec![make_entry(0, 1, 10, 100)];
        let registry = MockObjectStoreRegistry::new().with_store(1, MockObjectStore::new());
        let mut dispatcher = make_dispatcher(entries, registry);

        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();
        let outcome = dispatcher.dispatch(&intent, b"obj-solo", b"single copy");

        assert!(outcome.layout_valid);
        assert_eq!(outcome.succeeded, 1);
        assert_eq!(outcome.failed, 0);
        assert!(outcome.all_succeeded());
        assert!(outcome.quorum_reached());
        assert!(outcome.digests_consistent);
    }

    // -- Distinct payloads produce distinct digests -------------------------

    #[test]
    fn distinct_payloads_produce_distinct_digests() {
        let entries = vec![make_entry(0, 1, 10, 100)];
        let registry = MockObjectStoreRegistry::new().with_store(1, MockObjectStore::new());
        let mut dispatcher = make_dispatcher(entries, registry);

        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();
        let outcome_a = dispatcher.dispatch(&intent, b"k", b"payload A");
        let outcome_b = dispatcher.dispatch(&intent, b"k", b"payload B");

        assert_ne!(
            outcome_a.successful_digests[0],
            outcome_b.successful_digests[0]
        );
    }

    // -- Empty payload ------------------------------------------------------

    #[test]
    fn empty_payload_dispatch_succeeds() {
        let entries = vec![make_entry(0, 1, 10, 100)];
        let registry = MockObjectStoreRegistry::new().with_store(1, MockObjectStore::new());
        let mut dispatcher = make_dispatcher(entries, registry);

        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();
        let outcome = dispatcher.dispatch(&intent, b"obj-empty", b"");

        assert!(outcome.layout_valid);
        assert_eq!(outcome.succeeded, 1);
        let empty_digest: [u8; 32] = blake3::hash(b"").into();
        assert_eq!(outcome.successful_digests[0], empty_digest);
    }

    // -- Accessor tests -----------------------------------------------------

    #[test]
    fn dispatcher_accessors() {
        let entries = vec![make_entry(0, 1, 10, 100)];
        let registry = MockObjectStoreRegistry::new().with_store(1, MockObjectStore::new());
        let dispatcher = make_dispatcher(entries, registry);

        let _ = dispatcher.placement();
        let _ = dispatcher.registry();
    }

    // -- Outcome builder edge cases -----------------------------------------

    #[test]
    fn outcome_new_empty_targets() {
        let outcome = ReplicationOutcome::new(vec![], None);
        assert!(outcome.targets.is_empty());
        assert_eq!(outcome.succeeded, 0);
        assert_eq!(outcome.failed, 0);
        assert!(outcome.layout_valid);
        assert!(!outcome.any_succeeded());
        assert!(!outcome.all_succeeded());
        assert!(!outcome.quorum_reached());
        assert!(outcome.digests_consistent);
    }

    #[test]
    fn outcome_quorum_majority() {
        let entry = make_entry(0, 1, 10, 100);
        let digest = blake3::hash(b"x").into();
        let targets = vec![
            ReplicationTargetResult::success(entry.clone(), digest),
            ReplicationTargetResult::success(entry.clone(), digest),
            ReplicationTargetResult::failure(entry.clone(), "fail".into()),
        ];
        let outcome = ReplicationOutcome::new(targets, None);
        assert!(outcome.quorum_reached());
        assert!(outcome.any_succeeded());
        assert!(!outcome.all_succeeded());
    }

    #[test]
    fn outcome_no_quorum_on_tie() {
        let entry = make_entry(0, 1, 10, 100);
        let digest = blake3::hash(b"x").into();
        let targets = vec![
            ReplicationTargetResult::success(entry.clone(), digest),
            ReplicationTargetResult::failure(entry.clone(), "a".into()),
            ReplicationTargetResult::failure(entry.clone(), "b".into()),
        ];
        let outcome = ReplicationOutcome::new(targets, None);
        // 1/3 < 2 needed for majority
        assert!(!outcome.quorum_reached());
    }

    // -- ENOSPC handling ----------------------------------------------------

    #[test]
    fn enospc_reported_as_failure() {
        let entries = vec![make_entry(0, 1, 10, 100)];
        let store = MockObjectStore {
            out_of_space: true,
            ..MockObjectStore::new()
        };
        let registry = MockObjectStoreRegistry::new().with_store(1, store);
        let mut dispatcher = make_dispatcher(entries, registry);

        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();
        let outcome = dispatcher.dispatch(&intent, b"obj-enospc", b"no room");

        assert_eq!(outcome.succeeded, 0);
        assert_eq!(outcome.failed, 1);
        assert_eq!(outcome.targets[0].error.as_deref(), Some("ENOSPC"));
    }
}
