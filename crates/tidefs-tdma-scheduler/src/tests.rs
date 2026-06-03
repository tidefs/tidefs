use super::*;
use tidefs_membership_epoch::EpochId;

fn test_config() -> TdmaSchedulerConfig {
    TdmaSchedulerConfig {
        slot_duration_ms: 100,
        max_slots_per_round: 32,
        starvation_bound_rounds: 3,
    }
}

fn test_epoch() -> EpochId {
    EpochId(1)
}

// ---------------------------------------------------------------------------
// Slot state machine
// ---------------------------------------------------------------------------

#[test]
fn slot_state_terminal() {
    assert!(!SlotState::Pending.is_terminal());
    assert!(!SlotState::Active.is_terminal());
    assert!(SlotState::Complete.is_terminal());
    assert!(SlotState::Expired.is_terminal());
}

#[test]
fn slot_new_pending() {
    let slot = TdmaSlot::new_pending(42, 100, 1000, 1100);
    assert_eq!(slot.node_id, 42);
    assert_eq!(slot.object_id, 100);
    assert_eq!(slot.slot_start, 1000);
    assert_eq!(slot.slot_end, 1100);
    assert_eq!(slot.state, SlotState::Pending);
    assert_eq!(slot.duration_ms(), 100);
}

#[test]
fn slot_is_stale() {
    let slot = TdmaSlot::new_pending(1, 1, 0, 100);
    assert!(!slot.is_stale(50)); // before end
    assert!(slot.is_stale(100)); // at end
    assert!(slot.is_stale(150)); // after end
}

#[test]
fn slot_is_active_at() {
    let slot = TdmaSlot::new_pending(1, 1, 100, 200);
    assert!(!slot.is_active_at(50)); // before start
    assert!(slot.is_active_at(100)); // at start
    assert!(slot.is_active_at(150)); // during
    assert!(!slot.is_active_at(200)); // at end (exclusive)
    assert!(!slot.is_active_at(250)); // after end
}

#[test]
fn slot_terminal_not_active() {
    let mut slot = TdmaSlot::new_pending(1, 1, 100, 200);
    slot.state = SlotState::Complete;
    assert!(!slot.is_active_at(150));
    slot.state = SlotState::Expired;
    assert!(!slot.is_active_at(150));
}

// ---------------------------------------------------------------------------
// Scheduler: basic allocation
// ---------------------------------------------------------------------------

#[test]
fn allocate_single_node() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    let nodes = vec![10];
    let alloc = s.allocate(1, &nodes, 1000).unwrap();

    assert_eq!(alloc.slot.node_id, 10);
    assert_eq!(alloc.slot.object_id, 1);
    assert_eq!(alloc.slot.slot_start, 1000);
    assert_eq!(alloc.slot.slot_end, 1100);
    assert_eq!(alloc.slot.state, SlotState::Pending);
    assert_eq!(alloc.next_slot_at, 1100);
    assert_eq!(s.stats().total_allocations, 1);
}

#[test]
fn allocate_no_nodes_errors() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    let err = s.allocate(1, &[], 1000).unwrap_err();
    assert!(matches!(err, TdmaSchedulerError::NoRequestingNodes(1)));
}

#[test]
fn allocate_duplicate_fails_while_active() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    let nodes = vec![10, 20];
    s.allocate(1, &nodes, 1000).unwrap();
    // Second allocation before expiry fails
    let err = s.allocate(1, &nodes, 1050).unwrap_err();
    assert!(matches!(
        err,
        TdmaSchedulerError::SlotAlreadyActive(1, 10, 1100)
    ));
}

#[test]
fn allocate_after_expiry_succeeds() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    let nodes = vec![10, 20];
    s.allocate(1, &nodes, 1000).unwrap();
    // After slot end, new allocation succeeds (stale slot auto-cleaned)
    let alloc = s.allocate(1, &nodes, 1100).unwrap();
    assert_eq!(alloc.slot.node_id, 20); // round-robin moves to next
    assert_eq!(s.stats().total_expirations, 1); // previous slot expired
    assert_eq!(s.stats().total_allocations, 2);
}

// ---------------------------------------------------------------------------
// Scheduler: round-robin fairness
// ---------------------------------------------------------------------------

#[test]
fn round_robin_two_nodes() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    let nodes = vec![10, 20];

    // First allocation goes to position 0 = node 10
    let a1 = s.allocate(1, &nodes, 0).unwrap();
    assert_eq!(a1.slot.node_id, 10);

    // Release it so we can allocate again
    s.release(1, 10).unwrap();

    // Second allocation goes to position 1 = node 20
    let a2 = s.allocate(1, &nodes, 200).unwrap();
    assert_eq!(a2.slot.node_id, 20);

    s.release(1, 20).unwrap();

    // Third wraps back to node 10
    let a3 = s.allocate(1, &nodes, 400).unwrap();
    assert_eq!(a3.slot.node_id, 10);
}

#[test]
fn round_robin_three_nodes() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    let nodes = vec![100, 200, 300];

    let a1 = s.allocate(1, &nodes, 0).unwrap();
    assert_eq!(a1.slot.node_id, 100);
    s.release(1, 100).unwrap();

    let a2 = s.allocate(1, &nodes, 200).unwrap();
    assert_eq!(a2.slot.node_id, 200);
    s.release(1, 200).unwrap();

    let a3 = s.allocate(1, &nodes, 400).unwrap();
    assert_eq!(a3.slot.node_id, 300);
    s.release(1, 300).unwrap();

    let a4 = s.allocate(1, &nodes, 600).unwrap();
    assert_eq!(a4.slot.node_id, 100);
}

// ---------------------------------------------------------------------------
// Scheduler: release
// ---------------------------------------------------------------------------

#[test]
fn release_marks_complete() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    let nodes = vec![10];
    s.allocate(1, &nodes, 1000).unwrap();
    s.release(1, 10).unwrap();

    assert_eq!(s.stats().total_releases, 1);
    assert_eq!(s.stats().active_slots, 0);
    assert!(!s.is_holder(1, 10));
}

#[test]
fn release_wrong_node_errors() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    s.allocate(1, &[10], 1000).unwrap();
    let err = s.release(1, 99).unwrap_err();
    assert!(matches!(
        err,
        TdmaSchedulerError::NotSlotHolder {
            object: 1,
            node: 99
        }
    ));
}

#[test]
fn release_no_active_slot_errors() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    let err = s.release(1, 10).unwrap_err();
    assert!(matches!(err, TdmaSchedulerError::NoActiveSlot(1)));
}

// ---------------------------------------------------------------------------
// Scheduler: sweep expired
// ---------------------------------------------------------------------------

#[test]
fn sweep_expired_marks_stale() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    s.allocate(1, &[10], 1000).unwrap(); // expires at 1100

    let expired = s.sweep_expired(1100);
    assert_eq!(expired, vec![1]);
    assert_eq!(s.stats().total_expirations, 1);
    assert_eq!(s.stats().active_slots, 0);
}

#[test]
fn sweep_does_not_touch_active() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    s.allocate(1, &[10], 1000).unwrap();

    let expired = s.sweep_expired(1050); // not yet expired
    assert!(expired.is_empty());
    assert_eq!(s.stats().total_expirations, 0);
}

#[test]
fn sweep_multiple_objects() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    s.allocate(1, &[10], 0).unwrap(); // expires 100
    s.allocate(2, &[20], 50).unwrap(); // expires 150
    s.allocate(3, &[30], 200).unwrap(); // expires 300

    let expired = s.sweep_expired(150);
    assert_eq!(expired.len(), 2); // objects 1 and 2
    assert!(expired.contains(&1));
    assert!(expired.contains(&2));
}

// ---------------------------------------------------------------------------
// Scheduler: node failure
// ---------------------------------------------------------------------------

#[test]
fn handle_node_failure_expires_slots() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    s.allocate(1, &[10], 1000).unwrap();
    s.allocate(2, &[20], 1000).unwrap();
    s.allocate(3, &[10], 1000).unwrap();

    let affected = s.handle_node_failure(10);
    assert_eq!(affected.len(), 2);
    assert!(affected.contains(&1));
    assert!(affected.contains(&3));
    assert_eq!(s.stats().total_expirations, 2);
}

#[test]
fn handle_node_failure_no_match() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    s.allocate(1, &[10], 1000).unwrap();

    let affected = s.handle_node_failure(99);
    assert!(affected.is_empty());
}

// ---------------------------------------------------------------------------
// Scheduler: epoch advance
// ---------------------------------------------------------------------------

#[test]
fn advance_epoch_drains_all() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    s.allocate(1, &[10], 1000).unwrap();
    s.allocate(2, &[20], 1000).unwrap();

    let drained = s.advance_epoch(EpochId(2));
    assert_eq!(drained.len(), 2);
    assert!(drained.contains(&1));
    assert!(drained.contains(&2));
    assert_eq!(s.current_epoch(), EpochId(2));
    assert_eq!(s.stats().active_slots, 0);
    assert_eq!(s.stats().current_epoch, EpochId(2));
}

#[test]
fn after_epoch_advance_fresh_allocations_work() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    s.allocate(1, &[10, 20], 1000).unwrap();
    s.advance_epoch(EpochId(2));

    // After epoch advance, round-robin resets
    let alloc = s.allocate(1, &[10, 20], 2000).unwrap();
    assert_eq!(alloc.slot.node_id, 10); // position reset to 0
    assert_eq!(alloc.slot.slot_start, 2000);
}

// ---------------------------------------------------------------------------
// Scheduler: starvation detection
// ---------------------------------------------------------------------------

#[test]
fn starvation_counter_increments_for_skipped_nodes() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    let nodes = vec![10, 20, 30];

    // Round 1: node 10 gets slot, 20 and 30 starved
    s.allocate(1, &nodes, 0).unwrap();
    assert_eq!(s.starvation_count(1, 10), 0);
    assert_eq!(s.starvation_count(1, 20), 1);
    assert_eq!(s.starvation_count(1, 30), 1);
    s.release(1, 10).unwrap();

    // Round 2: node 20 gets slot, 10 and 30 starved
    s.allocate(1, &nodes, 200).unwrap();
    assert_eq!(s.starvation_count(1, 10), 1);
    assert_eq!(s.starvation_count(1, 20), 0);
    assert_eq!(s.starvation_count(1, 30), 2);
    s.release(1, 20).unwrap();

    // Round 3: node 30 gets slot, 10 and 20 starved
    s.allocate(1, &nodes, 400).unwrap();
    assert_eq!(s.starvation_count(1, 10), 2);
    assert_eq!(s.starvation_count(1, 20), 1);
    assert_eq!(s.starvation_count(1, 30), 0);
}

#[test]
fn starvation_event_fires_at_bound() {
    // With 3 nodes and bound=2, node 30 is skipped for 2 consecutive
    // rounds, hitting the bound in round 2. Node 10 hits it in round 3.
    let mut s = TdmaScheduler::new(
        TdmaSchedulerConfig {
            starvation_bound_rounds: 2,
            ..test_config()
        },
        test_epoch(),
    );
    let nodes = vec![10, 20, 30];

    // Round 1: 10 gets slot, 20 starve(1), 30 starve(1)
    s.allocate(1, &nodes, 0).unwrap();
    assert_eq!(s.stats().starvation_events, 0);
    s.release(1, 10).unwrap();

    // Round 2: 20 gets slot, 10 starve(1), 30 starve(2) -> event
    s.allocate(1, &nodes, 200).unwrap();
    assert_eq!(s.stats().starvation_events, 1);
    s.release(1, 20).unwrap();

    // Round 3: 30 gets slot, 10 starve(2) -> event, 20 starve(1)
    s.allocate(1, &nodes, 400).unwrap();
    assert_eq!(s.stats().starvation_events, 2);
}

// ---------------------------------------------------------------------------
// Scheduler: query helpers
// ---------------------------------------------------------------------------

#[test]
fn is_holder_returns_correctly() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    s.allocate(1, &[10], 1000).unwrap();

    assert!(s.is_holder(1, 10));
    assert!(!s.is_holder(1, 20));
    assert!(!s.is_holder(2, 10));

    s.release(1, 10).unwrap();
    assert!(!s.is_holder(1, 10));
}

#[test]
fn active_slot_returns_slot() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    assert!(s.active_slot(1).is_none());

    s.allocate(1, &[10], 1000).unwrap();
    let slot = s.active_slot(1).unwrap();
    assert_eq!(slot.node_id, 10);
}

#[test]
fn object_count_tracks_schedules() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    assert_eq!(s.object_count(), 0);

    s.allocate(1, &[10], 1000).unwrap();
    assert_eq!(s.object_count(), 1);

    s.allocate(2, &[20], 1000).unwrap();
    assert_eq!(s.object_count(), 2);
}

// ---------------------------------------------------------------------------
// Scheduler: config defaults
// ---------------------------------------------------------------------------

#[test]
fn default_config_values() {
    let config = TdmaSchedulerConfig::default();
    assert_eq!(config.slot_duration_ms, 10);
    assert_eq!(config.max_slots_per_round, 128);
    assert_eq!(config.starvation_bound_rounds, 4);
}

// ---------------------------------------------------------------------------
// Scheduler: multi-object isolation
// ---------------------------------------------------------------------------

#[test]
fn multi_object_independent_schedules() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    let nodes_a = vec![10, 20];
    let nodes_b = vec![30, 40];

    // Object 1: node 10 gets slot
    let a1 = s.allocate(1, &nodes_a, 0).unwrap();
    assert_eq!(a1.slot.node_id, 10);

    // Object 2: independent schedule, node 30 gets slot
    let a2 = s.allocate(2, &nodes_b, 0).unwrap();
    assert_eq!(a2.slot.node_id, 30);

    // Both can have active slots simultaneously
    assert!(s.is_holder(1, 10));
    assert!(s.is_holder(2, 30));
}

// ---------------------------------------------------------------------------
// Scheduler: epoch mismatch (via advance_epoch drain semantics)
// ---------------------------------------------------------------------------

#[test]
fn advance_epoch_resets_starvation() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    let nodes = vec![10, 20, 30];

    // Build up starvation
    s.allocate(1, &nodes, 0).unwrap();
    s.release(1, 10).unwrap();
    s.allocate(1, &nodes, 200).unwrap();
    s.release(1, 20).unwrap();
    // Starvation at this point: 10=1, 30=2

    s.advance_epoch(EpochId(2));

    assert_eq!(s.starvation_count(1, 10), 0);
    assert_eq!(s.starvation_count(1, 20), 0);
    assert_eq!(s.starvation_count(1, 30), 0);
}

// ---------------------------------------------------------------------------
// Scheduler: drain semantics preserve expired slots as terminal
// ---------------------------------------------------------------------------

#[test]
fn expired_slot_not_active_for_new_allocation() {
    let mut s = TdmaScheduler::new(test_config(), test_epoch());
    s.allocate(1, &[10, 20], 1000).unwrap(); // expires at 1100

    // At 1100, the previous slot is stale and auto-cleaned
    let alloc = s.allocate(1, &[10, 20], 1100).unwrap();
    assert_eq!(alloc.slot.node_id, 20); // round-robin advanced
    assert_eq!(s.stats().total_expirations, 1);
}
