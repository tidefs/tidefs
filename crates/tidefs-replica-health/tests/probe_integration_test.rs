// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::VecDeque;
use tidefs_membership_epoch::EpochId;
use tidefs_replica_health::health_probe::{HealthProbe, HealthSample, ProbeEvidenceClass};
use tidefs_replica_health::health_quorum::{HealthQuorum, QuorumHealthStatus};
use tidefs_replica_health::probe::{
    ProbeConfig, ProbeResult, ReplicaLivenessState, ReplicaLivenessTracker,
};
use tidefs_replica_health::NodeId;
use tidefs_replication_model::ReplicatedReceiptId;

/// Mock transport session that returns pre-programmed success/failure
/// responses for liveness probes.
struct MockTransport {
    responses: VecDeque<MockResponse>,
    call_count: usize,
}

enum MockResponse {
    Success { latency_ns: u64 },
    Failure,
}

impl MockTransport {
    fn new() -> Self {
        MockTransport {
            responses: VecDeque::new(),
            call_count: 0,
        }
    }

    fn enqueue_success(&mut self, latency_ns: u64) {
        self.responses
            .push_back(MockResponse::Success { latency_ns });
    }

    fn enqueue_failure(&mut self) {
        self.responses.push_back(MockResponse::Failure);
    }

    fn probe(&mut self) -> MockProbeOutcome {
        self.call_count += 1;
        match self.responses.pop_front() {
            Some(MockResponse::Success { latency_ns }) => MockProbeOutcome::Success { latency_ns },
            Some(MockResponse::Failure) => MockProbeOutcome::Failure,
            None => MockProbeOutcome::Failure,
        }
    }
}

enum MockProbeOutcome {
    Success { latency_ns: u64 },
    Failure,
}

fn run_probe_cycle(
    transport: &mut MockTransport,
    tracker: &mut ReplicaLivenessTracker,
    replica_id: NodeId,
    now_ns: u64,
) -> ProbeResult {
    match transport.probe() {
        MockProbeOutcome::Success { latency_ns } => {
            tracker.record_probe_success(replica_id, latency_ns, now_ns)
        }
        MockProbeOutcome::Failure => tracker.record_probe_failure(replica_id, now_ns),
    }
}

#[test]
fn full_probe_cycle_unknown_to_healthy() {
    let mut transport = MockTransport::new();
    let config = ProbeConfig {
        degradation_threshold: 3,
        failure_threshold: 5,
        recovery_threshold: 2,
        probe_interval_ns: 500_000_000,
        probe_timeout_ns: 10_000_000_000,
    };
    let mut tracker = ReplicaLivenessTracker::new(config);
    let node = NodeId::new(1);

    transport.enqueue_success(1_000_000);
    let result = run_probe_cycle(&mut transport, &mut tracker, node, 0);
    assert!(result.success);
    assert!(result.state_changed);
    assert_eq!(result.new_state, ReplicaLivenessState::Healthy);
    assert_eq!(tracker.current_state(node), ReplicaLivenessState::Healthy);

    for i in 0..5 {
        transport.enqueue_success(500_000);
        let result = run_probe_cycle(&mut transport, &mut tracker, node, (i + 1) * 1_000_000_000);
        assert!(!result.state_changed);
        assert_eq!(result.new_state, ReplicaLivenessState::Healthy);
    }
}

#[test]
fn probe_cycle_healthy_to_degraded_to_failed() {
    let mut transport = MockTransport::new();
    let config = ProbeConfig {
        degradation_threshold: 3,
        failure_threshold: 3,
        recovery_threshold: 2,
        probe_interval_ns: 500_000_000,
        probe_timeout_ns: 10_000_000_000,
    };
    let mut tracker = ReplicaLivenessTracker::new(config);
    let node = NodeId::new(1);

    transport.enqueue_success(1_000_000);
    run_probe_cycle(&mut transport, &mut tracker, node, 0);
    assert_eq!(tracker.current_state(node), ReplicaLivenessState::Healthy);

    for _ in 0..3 {
        transport.enqueue_failure();
    }
    let r1 = run_probe_cycle(&mut transport, &mut tracker, node, 1_000_000_000);
    assert!(!r1.state_changed);
    let r2 = run_probe_cycle(&mut transport, &mut tracker, node, 2_000_000_000);
    assert!(!r2.state_changed);
    let r3 = run_probe_cycle(&mut transport, &mut tracker, node, 3_000_000_000);
    assert!(r3.state_changed);
    assert_eq!(r3.new_state, ReplicaLivenessState::Degraded);

    for _ in 0..3 {
        transport.enqueue_failure();
    }
    run_probe_cycle(&mut transport, &mut tracker, node, 4_000_000_000);
    run_probe_cycle(&mut transport, &mut tracker, node, 5_000_000_000);
    let r6 = run_probe_cycle(&mut transport, &mut tracker, node, 6_000_000_000);
    assert!(r6.state_changed);
    assert_eq!(r6.new_state, ReplicaLivenessState::Failed);

    transport.enqueue_failure();
    let r7 = run_probe_cycle(&mut transport, &mut tracker, node, 7_000_000_000);
    assert!(!r7.state_changed);
    assert_eq!(r7.new_state, ReplicaLivenessState::Failed);

    transport.enqueue_success(500_000);
    let r8 = run_probe_cycle(&mut transport, &mut tracker, node, 8_000_000_000);
    assert!(!r8.state_changed);
    transport.enqueue_success(600_000);
    let r9 = run_probe_cycle(&mut transport, &mut tracker, node, 9_000_000_000);
    assert!(r9.state_changed);
    assert_eq!(r9.new_state, ReplicaLivenessState::Healthy);
}

#[test]
fn snapshot_matches_transport_probe_outcomes() {
    let mut transport = MockTransport::new();
    let config = ProbeConfig {
        degradation_threshold: 2,
        failure_threshold: 2,
        recovery_threshold: 1,
        probe_interval_ns: 500_000_000,
        probe_timeout_ns: 10_000_000_000,
    };
    let mut tracker = ReplicaLivenessTracker::new(config);

    transport.enqueue_success(1_000_000);
    run_probe_cycle(&mut transport, &mut tracker, NodeId::new(1), 0);
    assert_eq!(
        tracker.current_state(NodeId::new(1)),
        ReplicaLivenessState::Healthy
    );

    transport.enqueue_success(1_000_000);
    run_probe_cycle(&mut transport, &mut tracker, NodeId::new(2), 0);
    transport.enqueue_failure();
    run_probe_cycle(&mut transport, &mut tracker, NodeId::new(2), 1_000_000_000);
    transport.enqueue_failure();
    let r = run_probe_cycle(&mut transport, &mut tracker, NodeId::new(2), 2_000_000_000);
    assert!(r.state_changed);
    assert_eq!(r.new_state, ReplicaLivenessState::Degraded);

    transport.enqueue_success(1_000_000);
    run_probe_cycle(&mut transport, &mut tracker, NodeId::new(3), 0);
    for _ in 0..2 {
        transport.enqueue_failure();
    }
    run_probe_cycle(&mut transport, &mut tracker, NodeId::new(3), 1_000_000_000);
    run_probe_cycle(&mut transport, &mut tracker, NodeId::new(3), 2_000_000_000);
    for _ in 0..2 {
        transport.enqueue_failure();
    }
    run_probe_cycle(&mut transport, &mut tracker, NodeId::new(3), 3_000_000_000);
    run_probe_cycle(&mut transport, &mut tracker, NodeId::new(3), 4_000_000_000);
    assert_eq!(
        tracker.current_state(NodeId::new(3)),
        ReplicaLivenessState::Failed
    );

    let _ = tracker.current_state(NodeId::new(4));

    let snap = tracker.snapshot();
    assert_eq!(snap.healthy_count, 1);
    assert_eq!(snap.degraded_count, 1);
    assert_eq!(snap.failed_count, 1);
    assert_eq!(snap.unknown_count, 1);
    assert_eq!(snap.total_count, 4);
    assert!(!snap.all_healthy());
    assert!(snap.can_quorum_write(2));
    assert!(!snap.can_quorum_write(3));
}

#[test]
fn transport_failure_simulation_matches_state_transitions() {
    let mut transport = MockTransport::new();
    let config = ProbeConfig {
        degradation_threshold: 2,
        failure_threshold: 3,
        recovery_threshold: 2,
        probe_interval_ns: 100_000_000,
        probe_timeout_ns: 1_000_000_000,
    };
    let mut tracker = ReplicaLivenessTracker::new(config);
    let node = NodeId::new(1);

    transport.enqueue_success(500_000);
    run_probe_cycle(&mut transport, &mut tracker, node, 0);
    assert_eq!(tracker.current_state(node), ReplicaLivenessState::Healthy);
    let snap = tracker.snapshot();
    assert_eq!(snap.healthy_count, 1);
    assert!(snap.all_healthy());

    transport.enqueue_failure();
    run_probe_cycle(&mut transport, &mut tracker, node, 1_000_000_000);
    transport.enqueue_failure();
    run_probe_cycle(&mut transport, &mut tracker, node, 2_000_000_000);
    assert_eq!(tracker.current_state(node), ReplicaLivenessState::Degraded);
    let snap = tracker.snapshot();
    assert_eq!(snap.degraded_count, 1);
    assert_eq!(snap.healthy_count, 0);

    for i in 0..3 {
        transport.enqueue_failure();
        run_probe_cycle(&mut transport, &mut tracker, node, (3 + i) * 1_000_000_000);
    }
    assert_eq!(tracker.current_state(node), ReplicaLivenessState::Failed);
    let snap = tracker.snapshot();
    assert_eq!(snap.failed_count, 1);

    for i in 0..2 {
        transport.enqueue_success(300_000);
        run_probe_cycle(&mut transport, &mut tracker, node, (6 + i) * 1_000_000_000);
    }
    assert_eq!(tracker.current_state(node), ReplicaLivenessState::Healthy);
    let snap = tracker.snapshot();
    assert_eq!(snap.healthy_count, 1);
    assert_eq!(snap.failed_count, 0);
    assert!(snap.all_healthy());
}

#[test]
fn multiple_replicas_independent_state_tracking() {
    let mut transport = MockTransport::new();
    let config = ProbeConfig::default();
    let mut tracker = ReplicaLivenessTracker::new(config);

    for id in 1..=3 {
        transport.enqueue_success(1_000_000);
        run_probe_cycle(&mut transport, &mut tracker, NodeId::new(id), 0);
        assert_eq!(
            tracker.current_state(NodeId::new(id)),
            ReplicaLivenessState::Healthy
        );
    }

    for _ in 0..3 {
        transport.enqueue_failure();
        run_probe_cycle(&mut transport, &mut tracker, NodeId::new(1), 1_000_000_000);
    }
    assert_eq!(
        tracker.current_state(NodeId::new(1)),
        ReplicaLivenessState::Degraded
    );

    transport.enqueue_success(500_000);
    run_probe_cycle(&mut transport, &mut tracker, NodeId::new(2), 1_000_000_000);
    assert_eq!(
        tracker.current_state(NodeId::new(2)),
        ReplicaLivenessState::Healthy
    );

    for _ in 0..8 {
        transport.enqueue_failure();
        run_probe_cycle(&mut transport, &mut tracker, NodeId::new(3), 1_000_000_000);
    }
    assert_eq!(
        tracker.current_state(NodeId::new(3)),
        ReplicaLivenessState::Failed
    );

    let snap = tracker.snapshot();
    assert_eq!(snap.healthy_count, 1);
    assert_eq!(snap.degraded_count, 1);
    assert_eq!(snap.failed_count, 1);
    assert_eq!(snap.total_count, 3);
    assert!(!snap.all_healthy());
}

#[test]
fn rebuild_initiated_resets_tracker_state() {
    let mut transport = MockTransport::new();
    let config = ProbeConfig {
        degradation_threshold: 2,
        failure_threshold: 2,
        recovery_threshold: 2,
        probe_interval_ns: 500_000_000,
        probe_timeout_ns: 10_000_000_000,
    };
    let mut tracker = ReplicaLivenessTracker::new(config);
    let node = NodeId::new(1);

    transport.enqueue_success(1_000_000);
    run_probe_cycle(&mut transport, &mut tracker, node, 0);
    for _ in 0..2 {
        transport.enqueue_failure();
        run_probe_cycle(&mut transport, &mut tracker, node, 1_000_000_000);
    }
    for _ in 0..2 {
        transport.enqueue_failure();
        run_probe_cycle(&mut transport, &mut tracker, node, 2_000_000_000);
    }
    assert_eq!(tracker.current_state(node), ReplicaLivenessState::Failed);

    let result = tracker.mark_rebuild_initiated(node, 3_000_000_000);
    assert!(result.state_changed);
    assert_eq!(result.new_state, ReplicaLivenessState::Healthy);
    assert_eq!(tracker.current_state(node), ReplicaLivenessState::Healthy);

    let snap = tracker.snapshot();
    assert_eq!(snap.healthy_count, 1);
    assert_eq!(snap.failed_count, 0);
    assert!(snap.all_healthy());
}

#[test]
fn snapshot_quorum_write_calculation() {
    let mut transport = MockTransport::new();
    let mut tracker = ReplicaLivenessTracker::new(ProbeConfig::default());

    for id in 1..=3 {
        transport.enqueue_success(1_000_000);
        run_probe_cycle(&mut transport, &mut tracker, NodeId::new(id), 0);
    }

    let snap = tracker.snapshot();
    assert!(snap.can_quorum_write(2));
    assert!(snap.can_quorum_write(3));
    assert!(!snap.can_quorum_write(4));
    assert!(snap.can_quorum_write(0));
}

// ── Evidence classification integration tests ──────────────────────

#[test]
fn evidence_class_from_attestation_with_receipt() {
    let secret = [0xABu8; 32];
    let probe = HealthProbe::new(secret);
    let nonce = probe.generate_nonce();
    let att = probe.attest(
        1,
        EpochId::new(5),
        &nonce,
        1000,
        Some(ReplicatedReceiptId(7)),
    );
    assert!(probe.verify(&att));
    assert_eq!(att.receipt_id, Some(ReplicatedReceiptId(7)));

    let sample = HealthSample::from_attestation(&att, true, Some(50_000));
    let cls = sample.classify_evidence(EpochId::new(5), 2000, 10_000_000_000);
    assert_eq!(cls, ProbeEvidenceClass::FreshRepairEvidence);
    assert!(cls.is_repair_eligible());
}

#[test]
fn missing_receipt_attestation_is_not_repair_eligible() {
    let secret = [0xABu8; 32];
    let probe = HealthProbe::new(secret);
    let nonce = probe.generate_nonce();
    let att = probe.attest(1, EpochId::new(5), &nonce, 1000, None);
    assert!(probe.verify(&att));

    let sample = HealthSample::from_attestation(&att, true, Some(50_000));
    let cls = sample.classify_evidence(EpochId::new(5), 2000, 10_000_000_000);
    assert_eq!(cls, ProbeEvidenceClass::MissingReceiptEvidence);
    assert!(!cls.is_repair_eligible());
}

#[test]
fn older_epoch_attestation_rejected_as_repair_evidence() {
    let secret = [0xABu8; 32];
    let probe = HealthProbe::new(secret);
    let nonce = probe.generate_nonce();
    let att = probe.attest(
        1,
        EpochId::new(3),
        &nonce,
        1000,
        Some(ReplicatedReceiptId(7)),
    );
    assert!(probe.verify(&att));

    let sample = HealthSample::from_attestation(&att, true, Some(50_000));
    let cls = sample.classify_evidence(EpochId::new(5), 2000, 10_000_000_000);
    assert_eq!(cls, ProbeEvidenceClass::OlderEpochEvidence);
    assert!(!cls.is_repair_eligible());
}

#[test]
fn stale_timestamp_attestation_rejected_as_repair_evidence() {
    let secret = [0xABu8; 32];
    let probe = HealthProbe::new(secret);
    let nonce = probe.generate_nonce();
    let att = probe.attest(
        1,
        EpochId::new(5),
        &nonce,
        1000,
        Some(ReplicatedReceiptId(7)),
    );
    assert!(probe.verify(&att));

    let sample = HealthSample::from_attestation(&att, true, Some(50_000));
    // now_ns = 20_000_000_000, staleness = 5_000_000_000 -> stale
    let cls = sample.classify_evidence(EpochId::new(5), 20_000_000_000, 5_000_000_000);
    assert_eq!(cls, ProbeEvidenceClass::StaleEvidence);
    assert!(!cls.is_repair_eligible());
}

#[test]
fn stale_to_fresh_evidence_recovery() {
    let secret = [0xABu8; 32];
    let probe = HealthProbe::new(secret);
    let nonce = probe.generate_nonce();

    // Old attestation (stale)
    let att_stale = probe.attest(
        1,
        EpochId::new(5),
        &nonce,
        1000,
        Some(ReplicatedReceiptId(7)),
    );
    let sample_stale = HealthSample::from_attestation(&att_stale, true, Some(50_000));
    let cls_stale = sample_stale.classify_evidence(EpochId::new(5), 20_000_000_000, 5_000_000_000);
    assert_eq!(cls_stale, ProbeEvidenceClass::StaleEvidence);

    // Fresh attestation (new timestamp within threshold)
    let nonce2 = probe.generate_nonce();
    let att_fresh = probe.attest(
        1,
        EpochId::new(5),
        &nonce2,
        19_000_000_000,
        Some(ReplicatedReceiptId(7)),
    );
    let sample_fresh = HealthSample::from_attestation(&att_fresh, true, Some(50_000));
    let cls_fresh = sample_fresh.classify_evidence(EpochId::new(5), 20_000_000_000, 5_000_000_000);
    assert_eq!(cls_fresh, ProbeEvidenceClass::FreshRepairEvidence);
}

#[test]
fn quorum_evidence_counters_integration() {
    let mut q = HealthQuorum::new();
    let secret = [0xABu8; 32];
    let probe = HealthProbe::new(secret);

    // Fresh repair evidence: ts=2000, now=3000, threshold=2000 → diff=1000 <= 2000
    let nonce1 = probe.generate_nonce();
    let att1 = probe.attest(
        1,
        EpochId::new(5),
        &nonce1,
        2000,
        Some(ReplicatedReceiptId(10)),
    );
    q.add_sample(HealthSample::from_attestation(&att1, true, Some(50_000)));

    // Stale evidence: ts=100, now=3000, threshold=2000 → diff=2900 > 2000
    let nonce2 = probe.generate_nonce();
    let att2 = probe.attest(
        2,
        EpochId::new(5),
        &nonce2,
        100,
        Some(ReplicatedReceiptId(20)),
    );
    q.add_sample(HealthSample::from_attestation(&att2, true, Some(50_000)));

    // Missing receipt
    let nonce3 = probe.generate_nonce();
    let att3 = probe.attest(3, EpochId::new(5), &nonce3, 2000, None);
    q.add_sample(HealthSample::from_attestation(&att3, true, Some(50_000)));

    // Older epoch → missing evidence
    let nonce4 = probe.generate_nonce();
    let att4 = probe.attest(
        4,
        EpochId::new(3),
        &nonce4,
        2000,
        Some(ReplicatedReceiptId(30)),
    );
    q.add_sample(HealthSample::from_attestation(&att4, true, Some(50_000)));

    let result = q.compute(EpochId::new(5), 3000, 2000);
    assert_eq!(result.reachable_count, 4);
    assert_eq!(result.fresh_repair_evidence_count, 1);
    assert_eq!(result.stale_evidence_count, 1);
    assert_eq!(result.missing_evidence_count, 2);
    assert_eq!(result.status, QuorumHealthStatus::Healthy);
}

#[test]
fn evidence_class_labels_match_expectation() {
    assert_eq!(
        ProbeEvidenceClass::FreshRepairEvidence.label(),
        "fresh_repair_evidence"
    );
    assert_eq!(ProbeEvidenceClass::StaleEvidence.label(), "stale_evidence");
    assert_eq!(
        ProbeEvidenceClass::MissingReceiptEvidence.label(),
        "missing_receipt_evidence"
    );
    assert_eq!(
        ProbeEvidenceClass::OlderEpochEvidence.label(),
        "older_epoch_evidence"
    );
}
