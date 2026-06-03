use std::collections::VecDeque;
use tidefs_replica_health::probe::{
    ProbeConfig, ProbeResult, ReplicaLivenessState, ReplicaLivenessTracker,
};
use tidefs_replica_health::NodeId;

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
