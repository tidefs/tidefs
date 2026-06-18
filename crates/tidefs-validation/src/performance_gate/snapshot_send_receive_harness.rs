// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Snapshot send/receive performance benchmark harness.
//!
//! Measures VFSSEND2 stream encode/decode throughput and space metrics:
//!
//! - Full-stream encode throughput (objects/sec, bytes/sec)
//! - Full-stream decode throughput (objects/sec, bytes/sec)
//! - Incremental/delta stream encode throughput
//! - Wire-format space efficiency (payload bytes vs wire bytes)
//!
//! Uses tidefs_send_stream SendBuilder and ReceiveBuilder for
//! deterministic in-process measurements without transport overhead.
//! All measurements are cargo/unit tier (Tier 1) — they exercise the
//! production send/receive code paths against in-memory data.

use super::benchmark_harness::BenchmarkResult;
use super::gate_entry::MeasuredKpi;
use super::validation_tier::ValidationTier;

use std::collections::BTreeMap;
use std::time::Instant;

use tidefs_send_stream::{
    Bytes32, DeltaObject, Id128, ObjectKind, ReceiveBuilder, SendBuilder, SendStreamHeader,
    SnapshotDelta,
};

/// Harness that measures snapshot send/receive performance using the
/// VFSSEND2 encode/decode pipeline.
pub struct SnapshotSendReceiveHarness {
    pool_id: Id128,
    dataset_id: Id128,
}

impl SnapshotSendReceiveHarness {
    pub fn new() -> Self {
        Self {
            pool_id: [0xA1; 16],
            dataset_id: [0xB2; 16],
        }
    }

    // ------------------------------------------------------------------
    // Full stream throughput
    // ------------------------------------------------------------------

    /// Build a full send stream with `object_count` objects of `object_size`
    /// bytes each, measure encode and decode wall time, and report KPIs.
    pub fn measure_full_stream(&self, object_count: u64, object_size: usize) -> BenchmarkResult {
        let subject = "send-recv-full-stream";
        let desc = format!(
            "full stream: {} objects x {} bytes",
            object_count, object_size
        );

        let snapshots = build_snapshots(1, object_count, object_size, 1);

        // --- Encode ---
        let header = SendStreamHeader::new(self.pool_id, self.dataset_id, [0x01; 16]);
        let builder = match SendBuilder::full(header, snapshots.clone()) {
            Ok(b) => b,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("SendBuilder::full failed: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };

        let t0 = Instant::now();
        let wire_bytes = match builder.encode() {
            Ok(b) => b,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("encode failed: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };
        let encode_secs = t0.elapsed().as_secs_f64();

        let total_payload: u64 = snapshots
            .iter()
            .flat_map(|s| s.objects.iter())
            .map(|o| o.payload.len() as u64)
            .sum();

        // --- Decode ---
        let t1 = Instant::now();
        let receiver = match ReceiveBuilder::new(self.dataset_id, &wire_bytes) {
            Ok(r) => r,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("ReceiveBuilder::new failed: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };
        let received = match receiver.finish_all() {
            Ok(r) => r,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("finish_all failed: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };
        let decode_secs = t1.elapsed().as_secs_f64();

        let total_secs = encode_secs + decode_secs;
        let objects_per_sec = if total_secs > 0.0 {
            object_count as f64 / total_secs
        } else {
            0.0
        };
        let payload_bytes_per_sec = if total_secs > 0.0 {
            total_payload as f64 / total_secs
        } else {
            0.0
        };
        let wire_bytes_per_sec = if total_secs > 0.0 {
            wire_bytes.len() as f64 / total_secs
        } else {
            0.0
        };
        let space_overhead = if total_payload > 0 {
            (wire_bytes.len() as f64 - total_payload as f64) / total_payload as f64
        } else {
            0.0
        };
        let recv_object_count = received.objects.len() as u64;

        BenchmarkResult {
            subject: subject.to_string(),
            description: desc,
            executed: true,
            exit_code: Some(0),
            duration_secs: total_secs,
            kpis: vec![
                MeasuredKpi {
                    ref_id: "send-recv.encode-secs".into(),
                    name: "encode_secs".into(),
                    value: encode_secs,
                    unit: "s".into(),
                    passed: Some(encode_secs < 60.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv.decode-secs".into(),
                    name: "decode_secs".into(),
                    value: decode_secs,
                    unit: "s".into(),
                    passed: Some(decode_secs < 60.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv.objects-per-sec".into(),
                    name: "objects_per_sec".into(),
                    value: objects_per_sec,
                    unit: "objects/s".into(),
                    passed: Some(objects_per_sec > 0.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv.payload-bytes-per-sec".into(),
                    name: "payload_bytes_per_sec".into(),
                    value: payload_bytes_per_sec,
                    unit: "bytes/s".into(),
                    passed: Some(payload_bytes_per_sec > 0.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv.wire-bytes-per-sec".into(),
                    name: "wire_bytes_per_sec".into(),
                    value: wire_bytes_per_sec,
                    unit: "bytes/s".into(),
                    passed: Some(wire_bytes_per_sec > 0.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv.space-overhead".into(),
                    name: "space_overhead_ratio".into(),
                    value: space_overhead,
                    unit: "ratio".into(),
                    passed: Some(space_overhead < 2.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv.payload-bytes".into(),
                    name: "payload_bytes".into(),
                    value: total_payload as f64,
                    unit: "bytes".into(),
                    passed: Some(total_payload > 0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv.wire-bytes".into(),
                    name: "wire_bytes".into(),
                    value: wire_bytes.len() as f64,
                    unit: "bytes".into(),
                    passed: Some(!wire_bytes.is_empty()),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv.received-objects".into(),
                    name: "received_objects".into(),
                    value: recv_object_count as f64,
                    unit: "objects".into(),
                    passed: Some(recv_object_count == object_count),
                    percentile: None,
                },
            ],
            validation_tier: ValidationTier::CargoUnit,
            stdout_tail: format!(
                "full stream: {} objects, {} payload bytes, {} wire bytes, enc={:.6}s dec={:.6}s",
                object_count,
                total_payload,
                wire_bytes.len(),
                encode_secs,
                decode_secs
            ),
            stderr_tail: String::new(),
        }
    }

    // ------------------------------------------------------------------
    // Incremental stream throughput
    // ------------------------------------------------------------------

    /// Build a base full stream with `base_object_count` objects, then an
    /// incremental stream adding `delta_object_count` more objects.  Measure
    /// incremental encode and full decode throughput.
    pub fn measure_incremental_stream(
        &self,
        base_object_count: u64,
        delta_object_count: u64,
        object_size: usize,
    ) -> BenchmarkResult {
        let subject = "send-recv-incremental-stream";
        let desc = format!(
            "incremental: base {} + delta {} objects x {} bytes",
            base_object_count, delta_object_count, object_size
        );

        let base_snaps = build_snapshots(1, base_object_count, object_size, 1);
        let delta_snaps = build_snapshots(1, delta_object_count, object_size, 2);

        // --- Encode full stream from base ---
        let header = SendStreamHeader::new(self.pool_id, self.dataset_id, [0x01; 16]);
        let full_builder = match SendBuilder::full(header.clone(), base_snaps) {
            Ok(b) => b,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("full SendBuilder failed: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };
        let _full_wire = match full_builder.encode() {
            Ok(b) => b,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("full encode failed: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };

        // --- Encode incremental stream with from_snapshot_id ---
        let inc_header = SendStreamHeader::new(self.pool_id, self.dataset_id, [0x02; 16])
            .incremental_from([0x01; 16]);

        let t0 = Instant::now();
        let inc_builder =
            match SendBuilder::incremental(inc_header, delta_snaps.clone(), BTreeMap::new()) {
                Ok(b) => b,
                Err(e) => {
                    return BenchmarkResult::refused(
                        subject,
                        format!("incremental SendBuilder failed: {e:?}"),
                        ValidationTier::CargoUnit,
                    );
                }
            };
        let inc_wire = match inc_builder.encode() {
            Ok(b) => b,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("incremental encode failed: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };
        let inc_encode_secs = t0.elapsed().as_secs_f64();

        let delta_payload: u64 = delta_snaps
            .iter()
            .flat_map(|s| s.objects.iter())
            .map(|o| o.payload.len() as u64)
            .sum();

        // --- Decode the incremental stream ---
        let t1 = Instant::now();
        let receiver = match ReceiveBuilder::new(self.dataset_id, &inc_wire) {
            Ok(r) => r,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("incremental ReceiveBuilder failed: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };
        let received = match receiver.finish_all() {
            Ok(r) => r,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("incremental finish_all failed: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };
        let decode_secs = t1.elapsed().as_secs_f64();

        let total_secs = inc_encode_secs + decode_secs;
        let objects_per_sec = if total_secs > 0.0 {
            delta_object_count as f64 / total_secs
        } else {
            0.0
        };
        let bytes_per_sec = if total_secs > 0.0 {
            delta_payload as f64 / total_secs
        } else {
            0.0
        };
        let space_overhead = if delta_payload > 0 {
            (inc_wire.len() as f64 - delta_payload as f64) / delta_payload as f64
        } else {
            0.0
        };

        BenchmarkResult {
            subject: subject.to_string(),
            description: desc,
            executed: true,
            exit_code: Some(0),
            duration_secs: total_secs,
            kpis: vec![
                MeasuredKpi {
                    ref_id: "send-recv-inc.encode-secs".into(),
                    name: "inc_encode_secs".into(),
                    value: inc_encode_secs,
                    unit: "s".into(),
                    passed: Some(inc_encode_secs < 60.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv-inc.decode-secs".into(),
                    name: "inc_decode_secs".into(),
                    value: decode_secs,
                    unit: "s".into(),
                    passed: Some(decode_secs < 60.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv-inc.objects-per-sec".into(),
                    name: "inc_objects_per_sec".into(),
                    value: objects_per_sec,
                    unit: "objects/s".into(),
                    passed: Some(objects_per_sec > 0.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv-inc.bytes-per-sec".into(),
                    name: "inc_bytes_per_sec".into(),
                    value: bytes_per_sec,
                    unit: "bytes/s".into(),
                    passed: Some(bytes_per_sec > 0.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv-inc.wire-bytes".into(),
                    name: "inc_wire_bytes".into(),
                    value: inc_wire.len() as f64,
                    unit: "bytes".into(),
                    passed: Some(!inc_wire.is_empty()),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv-inc.space-overhead".into(),
                    name: "inc_space_overhead".into(),
                    value: space_overhead,
                    unit: "ratio".into(),
                    passed: Some(space_overhead < 2.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv-inc.received-objects".into(),
                    name: "inc_received_objects".into(),
                    value: received.objects.len() as f64,
                    unit: "objects".into(),
                    passed: Some(!received.objects.is_empty()),
                    percentile: None,
                },
            ],
            validation_tier: ValidationTier::CargoUnit,
            stdout_tail: format!(
                "incremental: {} delta objects, {} payload bytes, {} wire bytes, enc={:.6}s dec={:.6}s",
                delta_object_count, delta_payload, inc_wire.len(), inc_encode_secs, decode_secs
            ),
            stderr_tail: String::new(),
        }
    }

    // ------------------------------------------------------------------
    // Large-object throughput
    // ------------------------------------------------------------------

    /// Measure throughput with objects large enough to exercise the
    /// multi-record object encoding path (object_size > DEFAULT_MAX_RECORD_PAYLOAD).
    pub fn measure_large_objects(&self, object_count: u64, object_size: usize) -> BenchmarkResult {
        let subject = "send-recv-large-objects";
        let desc = format!(
            "large objects: {} objects x {} bytes",
            object_count, object_size
        );

        let snapshots = build_snapshots(1, object_count, object_size, 1);
        let header = SendStreamHeader::new(self.pool_id, self.dataset_id, [0x01; 16]);

        let builder = match SendBuilder::full(header, snapshots.clone()) {
            Ok(b) => b,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("SendBuilder::full: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };

        let t0 = Instant::now();
        let wire_bytes = match builder.encode() {
            Ok(b) => b,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("encode: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };
        let encode_secs = t0.elapsed().as_secs_f64();

        let t1 = Instant::now();
        let receiver = match ReceiveBuilder::new(self.dataset_id, &wire_bytes) {
            Ok(r) => r,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("ReceiveBuilder: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };
        let received = match receiver.finish_all() {
            Ok(r) => r,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("finish_all: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };
        let decode_secs = t1.elapsed().as_secs_f64();

        let total_bytes = object_count as u64 * object_size as u64;
        let total_secs = encode_secs + decode_secs;
        let bytes_per_sec = if total_secs > 0.0 {
            total_bytes as f64 / total_secs
        } else {
            0.0
        };
        let recv_ok = received.objects.len() == object_count as usize;

        BenchmarkResult {
            subject: subject.to_string(),
            description: desc,
            executed: true,
            exit_code: Some(0),
            duration_secs: total_secs,
            kpis: vec![
                MeasuredKpi {
                    ref_id: "send-recv-large.encode-secs".into(),
                    name: "large_encode_secs".into(),
                    value: encode_secs,
                    unit: "s".into(),
                    passed: Some(encode_secs < 60.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv-large.decode-secs".into(),
                    name: "large_decode_secs".into(),
                    value: decode_secs,
                    unit: "s".into(),
                    passed: Some(decode_secs < 60.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv-large.bytes-per-sec".into(),
                    name: "large_bytes_per_sec".into(),
                    value: bytes_per_sec,
                    unit: "bytes/s".into(),
                    passed: Some(bytes_per_sec > 0.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv-large.wire-bytes".into(),
                    name: "large_wire_bytes".into(),
                    value: wire_bytes.len() as f64,
                    unit: "bytes".into(),
                    passed: Some(!wire_bytes.is_empty()),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv-large.objects-ok".into(),
                    name: "large_objects_ok".into(),
                    value: if recv_ok { 1.0 } else { 0.0 },
                    unit: "bool".into(),
                    passed: Some(recv_ok),
                    percentile: None,
                },
            ],
            validation_tier: ValidationTier::CargoUnit,
            stdout_tail: format!(
                "large objects: {} x {}B, wire {}B, enc={:.6}s dec={:.6}s",
                object_count,
                object_size,
                wire_bytes.len(),
                encode_secs,
                decode_secs
            ),
            stderr_tail: String::new(),
        }
    }

    // ------------------------------------------------------------------
    // Many-small-objects throughput
    // ------------------------------------------------------------------

    /// Measure throughput with many small objects to exercise per-object
    /// record overhead.
    pub fn measure_many_small_objects(&self, object_count: u64) -> BenchmarkResult {
        let object_size = 64;
        let subject = "send-recv-many-small";
        let desc = format!(
            "many small objects: {} objects x {} bytes",
            object_count, object_size
        );

        let snapshots = build_snapshots(1, object_count, object_size, 1);
        let header = SendStreamHeader::new(self.pool_id, self.dataset_id, [0x01; 16]);

        let builder = match SendBuilder::full(header, snapshots.clone()) {
            Ok(b) => b,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("SendBuilder::full: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };

        let t0 = Instant::now();
        let wire_bytes = match builder.encode() {
            Ok(b) => b,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("encode: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };
        let encode_secs = t0.elapsed().as_secs_f64();

        let t1 = Instant::now();
        let receiver = match ReceiveBuilder::new(self.dataset_id, &wire_bytes) {
            Ok(r) => r,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("ReceiveBuilder: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };
        let received = match receiver.finish_all() {
            Ok(r) => r,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("finish_all: {e:?}"),
                    ValidationTier::CargoUnit,
                );
            }
        };
        let decode_secs = t1.elapsed().as_secs_f64();

        let total_bytes = object_count as u64 * object_size as u64;
        let total_secs = encode_secs + decode_secs;
        let objects_per_sec = if total_secs > 0.0 {
            object_count as f64 / total_secs
        } else {
            0.0
        };
        let bytes_per_sec = if total_secs > 0.0 {
            total_bytes as f64 / total_secs
        } else {
            0.0
        };
        let recv_ok = received.objects.len() == object_count as usize;

        BenchmarkResult {
            subject: subject.to_string(),
            description: desc,
            executed: true,
            exit_code: Some(0),
            duration_secs: total_secs,
            kpis: vec![
                MeasuredKpi {
                    ref_id: "send-recv-small.encode-secs".into(),
                    name: "small_encode_secs".into(),
                    value: encode_secs,
                    unit: "s".into(),
                    passed: Some(encode_secs < 60.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv-small.decode-secs".into(),
                    name: "small_decode_secs".into(),
                    value: decode_secs,
                    unit: "s".into(),
                    passed: Some(decode_secs < 60.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv-small.objects-per-sec".into(),
                    name: "small_objects_per_sec".into(),
                    value: objects_per_sec,
                    unit: "objects/s".into(),
                    passed: Some(objects_per_sec > 0.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv-small.bytes-per-sec".into(),
                    name: "small_bytes_per_sec".into(),
                    value: bytes_per_sec,
                    unit: "bytes/s".into(),
                    passed: Some(bytes_per_sec > 0.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "send-recv-small.objects-ok".into(),
                    name: "small_objects_ok".into(),
                    value: if recv_ok { 1.0 } else { 0.0 },
                    unit: "bool".into(),
                    passed: Some(recv_ok),
                    percentile: None,
                },
            ],
            validation_tier: ValidationTier::CargoUnit,
            stdout_tail: format!(
                "small objects: {} x {}B, wire {}B, enc={:.6}s dec={:.6}s",
                object_count,
                object_size,
                wire_bytes.len(),
                encode_secs,
                decode_secs
            ),
            stderr_tail: String::new(),
        }
    }
}

impl Default for SnapshotSendReceiveHarness {
    fn default() -> Self {
        Self::new()
    }
}

// --- Helpers ----------------------------------------------------------------

fn obj_id(byte: u8, index: u64) -> Bytes32 {
    let mut id = [byte; 32];
    id[24..32].copy_from_slice(&index.to_le_bytes());
    id
}

fn build_snapshots(
    snapshot_count: u64,
    objects_per_snapshot: u64,
    object_size: usize,
    base_byte: u8,
) -> Vec<SnapshotDelta> {
    let mut snaps = Vec::with_capacity(snapshot_count as usize);
    for s in 0..snapshot_count {
        let mut snap = SnapshotDelta::new([base_byte + s as u8; 16], format!("snap-{s}"), s + 1);
        let payload: Vec<u8> = (0..object_size).map(|i| (i % 251) as u8).collect();
        for i in 0..objects_per_snapshot {
            let object = DeltaObject::new(
                obj_id(base_byte + s as u8, i),
                ObjectKind::Extent,
                payload.clone(),
            );
            snap.objects.push(object);
        }
        snaps.push(snap);
    }
    snaps
}

// --- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_stream_small() {
        let harness = SnapshotSendReceiveHarness::new();
        let result = harness.measure_full_stream(10, 256);
        assert!(result.executed);
        assert_eq!(result.exit_code, Some(0));
        let kpi = result
            .kpis
            .iter()
            .find(|k| k.name == "received_objects")
            .unwrap();
        assert_eq!(kpi.value, 10.0);
        assert_eq!(kpi.passed, Some(true));
    }

    #[test]
    fn full_stream_medium() {
        let harness = SnapshotSendReceiveHarness::new();
        let result = harness.measure_full_stream(100, 1024);
        assert!(result.executed);
        let kpi = result
            .kpis
            .iter()
            .find(|k| k.name == "received_objects")
            .unwrap();
        assert_eq!(kpi.value, 100.0);
        let bps = result
            .kpis
            .iter()
            .find(|k| k.name == "payload_bytes_per_sec")
            .unwrap();
        assert!(bps.value > 0.0);
    }

    #[test]
    fn incremental_stream_basic() {
        let harness = SnapshotSendReceiveHarness::new();
        let result = harness.measure_incremental_stream(50, 25, 512);
        assert!(result.executed);
        assert_eq!(result.exit_code, Some(0));
        let kpi = result
            .kpis
            .iter()
            .find(|k| k.name == "inc_received_objects")
            .unwrap();
        assert!(kpi.value > 0.0);
    }

    #[test]
    fn large_objects_multi_record() {
        // 2MB objects force multi-record encoding (DEFAULT_MAX_RECORD_PAYLOAD = 1MiB)
        let harness = SnapshotSendReceiveHarness::new();
        let result = harness.measure_large_objects(5, 2 * 1024 * 1024);
        assert!(result.executed);
        assert_eq!(result.exit_code, Some(0));
        let kpi = result
            .kpis
            .iter()
            .find(|k| k.name == "large_objects_ok")
            .unwrap();
        assert_eq!(kpi.value, 1.0);
        let bps = result
            .kpis
            .iter()
            .find(|k| k.name == "large_bytes_per_sec")
            .unwrap();
        assert!(bps.value > 0.0);
    }

    #[test]
    fn many_small_objects() {
        let harness = SnapshotSendReceiveHarness::new();
        let result = harness.measure_many_small_objects(500);
        assert!(result.executed);
        assert_eq!(result.exit_code, Some(0));
        let kpi = result
            .kpis
            .iter()
            .find(|k| k.name == "small_objects_ok")
            .unwrap();
        assert_eq!(kpi.value, 1.0);
    }

    #[test]
    fn full_stream_space_overhead_reported() {
        let harness = SnapshotSendReceiveHarness::new();
        let result = harness.measure_full_stream(50, 4096);
        assert!(result.executed);
        let kpi = result
            .kpis
            .iter()
            .find(|k| k.name == "space_overhead_ratio")
            .unwrap();
        // Wire bytes always >= payload bytes due to framing overhead
        assert!(kpi.value >= 0.0);
        assert!(
            kpi.value < 2.0,
            "space overhead {:.4} should be reasonable",
            kpi.value
        );
    }

    #[test]
    fn roundtrip_data_integrity() {
        let harness = SnapshotSendReceiveHarness::new();

        let payload = b"verify roundtrip data integrity in send-receive harness".to_vec();
        let mut snap = SnapshotDelta::new([0xCA; 16], "integrity-snap", 1);
        snap.objects.push(DeltaObject::new(
            [0xFE; 32],
            ObjectKind::Extent,
            payload.clone(),
        ));

        let header = SendStreamHeader::new(harness.pool_id, harness.dataset_id, [0x01; 16]);
        let builder = SendBuilder::full(header, vec![snap]).expect("build send stream");
        let wire = builder.encode().expect("encode");

        let receiver = ReceiveBuilder::new(harness.dataset_id, &wire).expect("build receiver");
        let received = receiver.finish_all().expect("finish all");

        assert_eq!(received.objects.len(), 1);
        let obj = received.objects.values().next().unwrap();
        assert_eq!(obj.payload, payload);
    }
}
