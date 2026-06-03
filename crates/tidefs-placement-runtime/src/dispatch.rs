//! Placement-driven write and read dispatch.
//!
//! Bridges the placement planner's [`PlacementPlan`] and `assign_devices()`
//! output into concrete object write fan-out and read dispatch to target
//! nodes. The caller implements [`ObjectWriteTarget`] and/or
//! [`ObjectReadTarget`] so that the runtime can invoke per-node put/get
//! operations without depending on any specific storage-node or harness crate.
//!
//! ## Write dispatch design
//!
//! 1. Compute [`ShardAssignment`] set via [`PlacementPlan::assign_devices`].
//! 2. For each assigned device, call [`ObjectWriteTarget::put_object`] on the
//!    corresponding target node.
//! 3. Collect results per target.
//!
//! The caller owns the mapping from `device_id` to concrete node/writer
//! handle.
//!
//! ## Read dispatch design
//!
//! 1. Compute [`ShardAssignment`] set via [`PlacementPlan::assign_devices`].
//! 2. For each assigned device, call [`ObjectReadTarget::get_object`].
//! 3. Return the first successful payload plus per-target outcomes.
//! 4. Detect cross-mirror inconsistency when payloads differ across devices.

use tidefs_placement_planner::placement_plan::{
    DeviceCandidate, PlacementPlan, PlacementPlanError, ShardAssignment,
};

// ---------------------------------------------------------------------------
// ObjectWriteTarget trait
// ---------------------------------------------------------------------------

/// Something that can receive an object write on behalf of a target node.
///
/// The placement runtime calls `put_object` once per assigned shard. The
/// implementor is responsible for mapping `device_id` (from
/// [`ShardAssignment`]) to the correct node and performing the actual write.
pub trait ObjectWriteTarget {
    /// Write an object identified by `key` with the given `payload` to the
    /// node hosting `device_id`.
    ///
    /// Returns `Ok(())` on success or an error message on failure.
    fn put_object(&mut self, device_id: u64, key: &[u8], payload: &[u8]) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// ObjectReadTarget trait
// ---------------------------------------------------------------------------

/// Something that can serve an object read on behalf of a target node.
///
/// The placement runtime calls `get_object` once per assigned shard. The
/// implementor is responsible for mapping `device_id` (from
/// [`ShardAssignment`]) to the correct node and performing the actual read.
pub trait ObjectReadTarget {
    /// Retrieve an object identified by `key` from the node hosting
    /// `device_id`. Returns `None` if the object is not present.
    fn get_object(&self, device_id: u64, key: &[u8]) -> Option<Vec<u8>>;
}

// ---------------------------------------------------------------------------
// Dispatch result
// ---------------------------------------------------------------------------

/// Outcome of a single shard-target write within a dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardWriteOutcome {
    /// The shard assignment that was attempted.
    pub assignment: ShardAssignment,
    /// The target device that was written to.
    pub device_id: u64,
    /// Whether the write succeeded.
    pub ok: bool,
    /// Error message if the write failed.
    pub error: Option<String>,
}

/// Summary after fanning out a write across all assigned targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchWriteResult {
    /// Per-target outcomes, one per assigned shard.
    pub outcomes: Vec<ShardWriteOutcome>,
    /// Number of targets that acknowledged the write.
    pub acknowledged: usize,
    /// Whether quorum (simple majority) was reached.
    pub quorum_reached: bool,
}

/// Outcome of a single shard-target read within a dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardReadOutcome {
    /// The shard assignment that was attempted.
    pub assignment: ShardAssignment,
    /// The target device that was read from.
    pub device_id: u64,
    /// Whether the object was found on this device.
    pub found: bool,
    /// The retrieved payload, if found.
    pub payload: Option<Vec<u8>>,
    /// Error message if the read failed or object was not found.
    pub error: Option<String>,
}

/// Summary after dispatching a read across all assigned targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchReadResult {
    /// Per-target outcomes, one per assigned shard.
    pub outcomes: Vec<ShardReadOutcome>,
    /// The object payload from the first mirror that had it.
    /// `None` if no mirror returned the object.
    pub payload: Option<Vec<u8>>,
    /// The device_id of the primary (first successful) mirror.
    pub primary_device: u64,
    /// Whether all mirrors that returned data returned identical payloads.
    /// When `true`, cross-node data integrity is confirmed.
    /// When `false`, at least one mirror diverged — possible corruption.
    pub mirrors_consistent: bool,
}

// ---------------------------------------------------------------------------
// dispatch_write
// ---------------------------------------------------------------------------

/// Compute placement targets for `key` / `payload` via the given
/// [`PlacementPlan`] and candidate device set, then fan out writes to each
/// target through `writer`.
///
/// Quorum is simple majority of assigned shards (`acknowledged >= n/2 + 1`).
/// A failed device assignment (e.g. not enough domains) is propagated as
/// an error, and no writes are attempted.
pub fn dispatch_write(
    plan: &PlacementPlan,
    candidates: &[DeviceCandidate],
    key: &[u8],
    payload: &[u8],
    writer: &mut dyn ObjectWriteTarget,
) -> Result<DispatchWriteResult, PlacementPlanError> {
    let assignments = plan.assign_devices(candidates)?;

    let n = assignments.len();
    let mut outcomes = Vec::with_capacity(n);
    let mut acknowledged = 0usize;

    for assignment in &assignments {
        let device_id = assignment.device_id;
        match writer.put_object(device_id, key, payload) {
            Ok(()) => {
                acknowledged += 1;
                outcomes.push(ShardWriteOutcome {
                    assignment: assignment.clone(),
                    device_id,
                    ok: true,
                    error: None,
                });
            }
            Err(e) => {
                outcomes.push(ShardWriteOutcome {
                    assignment: assignment.clone(),
                    device_id,
                    ok: false,
                    error: Some(e),
                });
            }
        }
    }

    let quorum = (n / 2) + 1;
    Ok(DispatchWriteResult {
        outcomes,
        acknowledged,
        quorum_reached: acknowledged >= quorum,
    })
}

// ---------------------------------------------------------------------------
// dispatch_read
// ---------------------------------------------------------------------------

/// Compute placement targets for `key` via the given [`PlacementPlan`] and
/// candidate device set, then read from each target through `reader` until
/// a payload is found.
///
/// Returns the first successful payload and per-target outcomes. Cross-mirror
/// consistency is checked: if two mirrors return different payloads for the
/// same key, `mirrors_consistent` is set to `false` to signal potential
/// silent corruption.
///
/// A failed device assignment (e.g. not enough domains) is propagated as
/// an error, and no reads are attempted.
pub fn dispatch_read(
    plan: &PlacementPlan,
    candidates: &[DeviceCandidate],
    key: &[u8],
    reader: &dyn ObjectReadTarget,
) -> Result<DispatchReadResult, PlacementPlanError> {
    let assignments = plan.assign_devices(candidates)?;

    let mut outcomes = Vec::with_capacity(assignments.len());
    let mut primary_payload: Option<Vec<u8>> = None;
    let mut primary_device: u64 = 0;
    let mut mirrors_consistent = true;

    for assignment in &assignments {
        let device_id = assignment.device_id;
        match reader.get_object(device_id, key) {
            Some(payload) => {
                // First mirror with data becomes the primary.
                if primary_payload.is_none() {
                    primary_payload = Some(payload.clone());
                    primary_device = device_id;
                } else if primary_payload.as_ref() != Some(&payload) {
                    // Mismatch: cross-mirror inconsistency detected.
                    mirrors_consistent = false;
                }
                outcomes.push(ShardReadOutcome {
                    assignment: assignment.clone(),
                    device_id,
                    found: true,
                    payload: Some(payload),
                    error: None,
                });
            }
            None => {
                outcomes.push(ShardReadOutcome {
                    assignment: assignment.clone(),
                    device_id,
                    found: false,
                    payload: None,
                    error: Some("object not found on this device".into()),
                });
            }
        }
    }

    Ok(DispatchReadResult {
        outcomes,
        payload: primary_payload,
        primary_device,
        mirrors_consistent,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_durability_layout::{DurabilityLayoutV1, FailureDomainLevel, FailureDomainV1};
    use tidefs_placement_planner::placement_plan::DeviceCandidate;

    // -- Mock writer --------------------------------------------------------

    /// Collects written (device_id, key, payload) tuples for test inspection.
    #[derive(Default)]
    struct MockWriter {
        pub writes: Vec<(u64, Vec<u8>, Vec<u8>)>,
        pub fail_next: Option<String>,
    }

    impl ObjectWriteTarget for MockWriter {
        fn put_object(&mut self, device_id: u64, key: &[u8], payload: &[u8]) -> Result<(), String> {
            if let Some(msg) = self.fail_next.take() {
                return Err(msg);
            }
            self.writes
                .push((device_id, key.to_vec(), payload.to_vec()));
            Ok(())
        }
    }

    /// Succeeds for `success_count` writes, then returns errors.
    struct CountingMockWriter {
        remaining_ok: usize,
        pub writes: Vec<(u64, Vec<u8>, Vec<u8>)>,
    }

    impl CountingMockWriter {
        fn new(success_count: usize) -> Self {
            Self {
                remaining_ok: success_count,
                writes: Vec::new(),
            }
        }
    }

    impl ObjectWriteTarget for CountingMockWriter {
        fn put_object(&mut self, device_id: u64, key: &[u8], payload: &[u8]) -> Result<(), String> {
            if self.remaining_ok > 0 {
                self.remaining_ok -= 1;
                self.writes
                    .push((device_id, key.to_vec(), payload.to_vec()));
                Ok(())
            } else {
                Err("injected write failure".into())
            }
        }
    }

    // -- Helpers ------------------------------------------------------------

    fn dev_node(id: u64, node: u64) -> DeviceCandidate {
        DeviceCandidate {
            device_id: id,
            node_id: Some(node),
            rack_id: None,
            datacenter_id: None,
        }
    }

    // -- 2-node Host failure domain fan-out --------------------------------

    #[test]
    fn two_node_host_domain_fans_out_to_both_nodes() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 2).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_node(1, 1), dev_node(2, 2)];

        let mut writer = MockWriter::default();
        let key = b"obj-42";
        let payload = b"placement-driven write payload";

        let result = dispatch_write(&plan, &candidates, key, payload, &mut writer)
            .expect("dispatch_write should succeed");

        assert_eq!(result.outcomes.len(), 2);
        assert_eq!(result.acknowledged, 2);
        assert!(result.quorum_reached);

        let mut device_ids: Vec<u64> = writer.writes.iter().map(|(d, _, _)| *d).collect();
        device_ids.sort();
        assert_eq!(device_ids, vec![1, 2]);

        for (_dev, _k, p) in &writer.writes {
            assert_eq!(p, payload);
        }
    }

    #[test]
    fn two_node_host_domain_single_failure_partial_quorum() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 2).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_node(1, 1), dev_node(2, 2)];

        let mut writer = CountingMockWriter::new(1);
        let result = dispatch_write(&plan, &candidates, b"k", b"v", &mut writer)
            .expect("dispatch_write should succeed");

        assert_eq!(result.acknowledged, 1);
        assert_eq!(result.outcomes.len(), 2);
        assert!(!result.quorum_reached);
        assert!(result.outcomes.iter().any(|o| o.ok));
        assert!(result.outcomes.iter().any(|o| !o.ok));
    }

    #[test]
    fn not_enough_devices_error_propagated() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 3).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_node(1, 1), dev_node(2, 2)];

        let mut writer = MockWriter::default();
        let err = dispatch_write(&plan, &candidates, b"k", b"v", &mut writer).unwrap_err();

        assert!(
            matches!(err, PlacementPlanError::NotEnoughDevices { .. }),
            "expected NotEnoughDevices, got {err:?}"
        );
        assert!(writer.writes.is_empty());
    }

    #[test]
    fn not_enough_failure_domains_error_propagated() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 3).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_node(1, 1), dev_node(2, 1), dev_node(3, 1)];

        let mut writer = MockWriter::default();
        let err = dispatch_write(&plan, &candidates, b"k", b"v", &mut writer).unwrap_err();

        assert!(
            matches!(err, PlacementPlanError::NotEnoughFailureDomains { .. }),
            "expected NotEnoughFailureDomains, got {err:?}"
        );
        assert!(writer.writes.is_empty());
    }

    #[test]
    fn three_node_mirror_quorum_with_majority() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 3).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_node(1, 1), dev_node(2, 2), dev_node(3, 3)];

        let mut writer = CountingMockWriter::new(2);
        let result = dispatch_write(&plan, &candidates, b"k", b"v", &mut writer)
            .expect("dispatch_write should succeed");

        assert_eq!(result.acknowledged, 2);
        assert!(result.quorum_reached);
        assert_eq!(result.outcomes.len(), 3);
    }

    // -- Mock reader --------------------------------------------------------

    /// Serves stored (key, payload) lookups keyed by device_id for test
    /// inspection.
    struct MockReader {
        pub store: std::collections::BTreeMap<(u64, Vec<u8>), Vec<u8>>,
    }

    impl MockReader {
        fn new() -> Self {
            Self {
                store: std::collections::BTreeMap::new(),
            }
        }

        fn put(&mut self, device_id: u64, key: &[u8], payload: &[u8]) {
            self.store
                .insert((device_id, key.to_vec()), payload.to_vec());
        }
    }

    impl ObjectReadTarget for MockReader {
        fn get_object(&self, device_id: u64, key: &[u8]) -> Option<Vec<u8>> {
            self.store.get(&(device_id, key.to_vec())).cloned()
        }
    }

    impl ObjectWriteTarget for MockReader {
        fn put_object(&mut self, device_id: u64, key: &[u8], payload: &[u8]) -> Result<(), String> {
            self.put(device_id, key, payload);
            Ok(())
        }
    }

    // -- Read dispatch tests -----------------------------------------------

    #[test]
    fn read_dispatch_two_node_mirror_both_have_data() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 2).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_node(1, 1), dev_node(2, 2)];

        let mut reader = MockReader::new();
        reader.put(1, b"obj-1", b"hello payload");
        reader.put(2, b"obj-1", b"hello payload");

        let result = dispatch_read(&plan, &candidates, b"obj-1", &reader)
            .expect("dispatch_read should succeed");

        assert!(result.payload.is_some());
        assert_eq!(result.payload.as_deref(), Some(b"hello payload".as_ref()));
        assert_eq!(result.outcomes.len(), 2);
        assert!(result.outcomes.iter().all(|o| o.found));
        assert!(result.mirrors_consistent);
    }

    #[test]
    fn read_dispatch_two_node_mirror_one_missing() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 2).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_node(1, 1), dev_node(2, 2)];

        let reader = MockReader::new();
        let result = dispatch_read(&plan, &candidates, b"no-such-obj", &reader)
            .expect("dispatch_read should succeed");

        assert!(result.payload.is_none());
        assert_eq!(result.outcomes.len(), 2);
        assert!(result.outcomes.iter().all(|o| !o.found));
        assert!(result.mirrors_consistent);
    }

    #[test]
    fn read_dispatch_two_node_mirror_only_primary_has_data() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 2).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_node(1, 1), dev_node(2, 2)];

        let mut reader = MockReader::new();
        reader.put(1, b"obj-7", b"primary only");

        let result = dispatch_read(&plan, &candidates, b"obj-7", &reader)
            .expect("dispatch_read should succeed");

        assert!(result.payload.is_some());
        assert_eq!(result.payload.as_deref(), Some(b"primary only".as_ref()));
        assert_eq!(result.primary_device, 1);
        assert!(result.mirrors_consistent);

        let found_count = result.outcomes.iter().filter(|o| o.found).count();
        assert_eq!(found_count, 1);
    }

    #[test]
    fn read_dispatch_detects_cross_mirror_divergence() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 2).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_node(1, 1), dev_node(2, 2)];

        let mut reader = MockReader::new();
        reader.put(1, b"obj-c", b"correct data");
        reader.put(2, b"obj-c", b"corrupted!!!");

        let result = dispatch_read(&plan, &candidates, b"obj-c", &reader)
            .expect("dispatch_read should succeed");

        assert!(result.payload.is_some());
        assert_eq!(result.payload.as_deref(), Some(b"correct data".as_ref()));
        assert_eq!(result.outcomes.len(), 2);
        assert!(
            !result.mirrors_consistent,
            "cross-mirror divergence must be detected"
        );
    }

    #[test]
    fn read_dispatch_three_node_mirror_majority_consistent() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 3).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_node(1, 1), dev_node(2, 2), dev_node(3, 3)];

        let mut reader = MockReader::new();
        reader.put(1, b"obj-m", b"majority");
        reader.put(2, b"obj-m", b"majority");
        reader.put(3, b"obj-m", b"majority");

        let result = dispatch_read(&plan, &candidates, b"obj-m", &reader)
            .expect("dispatch_read should succeed");

        assert!(result.payload.is_some());
        assert!(result.mirrors_consistent);
        assert_eq!(result.outcomes.len(), 3);
    }

    #[test]
    fn read_dispatch_three_node_mirror_one_divergent() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 3).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_node(1, 1), dev_node(2, 2), dev_node(3, 3)];

        let mut reader = MockReader::new();
        reader.put(1, b"obj-d", b"good");
        reader.put(2, b"obj-d", b"good");
        reader.put(3, b"obj-d", b"bad");

        let result = dispatch_read(&plan, &candidates, b"obj-d", &reader)
            .expect("dispatch_read should succeed");

        assert!(result.payload.is_some());
        assert_eq!(result.payload.as_deref(), Some(b"good".as_ref()));
        assert!(
            !result.mirrors_consistent,
            "single divergent mirror must be detected"
        );
    }

    #[test]
    fn read_dispatch_not_enough_devices_error() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 3).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_node(1, 1), dev_node(2, 2)];

        let reader = MockReader::new();
        let err = dispatch_read(&plan, &candidates, b"k", &reader).unwrap_err();
        assert!(matches!(err, PlacementPlanError::NotEnoughDevices { .. }));
    }

    #[test]
    fn read_dispatch_not_enough_failure_domains_error() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 3).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_node(1, 1), dev_node(2, 1), dev_node(3, 1)];

        let reader = MockReader::new();
        let err = dispatch_read(&plan, &candidates, b"k", &reader).unwrap_err();
        assert!(
            matches!(err, PlacementPlanError::NotEnoughFailureDomains { .. }),
            "expected NotEnoughFailureDomains, got {err:?}"
        );
    }
}
