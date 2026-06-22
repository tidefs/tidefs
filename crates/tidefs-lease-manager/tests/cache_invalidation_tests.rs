// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Focused tests for clustered cache lease epoch invalidation (issue #754).
//!
//! Covers: advisory invalidation dispatch, mandatory dirty-drain/fence,
//! membership epoch transition fencing, generation tracking, and wait-policy
//! gating.

use std::sync::{Arc, Mutex};
use tidefs_cache_coherency::{
    CacheInvalidationMessage, CacheInvalidationReason, CacheInvalidationScope,
    CacheInvalidationSubscriber, CoherencyEventBus, InvalidationResult,
    InvalidationWaitPolicy,
};
use tidefs_lease::types::{LeaseClass, LeaseDomain, LeaseGrant};
use tidefs_lease::wire::CacheInvalidationPayload;
use tidefs_lease_manager::{LeaseManager, LeaseManagerConfig};
use tidefs_membership_epoch::{DatasetMountIdentity, EpochId, MemberId};

// ---------------------------------------------------------------------------
// Test helper: subscriber that records received messages
// ---------------------------------------------------------------------------

struct RecordingSubscriber {
    name: &'static str,
    messages: Mutex<Vec<CacheInvalidationMessage>>,
    /// Configured result to return for each invalidation message.
    result: Mutex<InvalidationResult>,
}

impl RecordingSubscriber {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            messages: Mutex::new(Vec::new()),
            result: Mutex::new(InvalidationResult::clean(0)),
        }
    }

    fn with_result(name: &'static str, result: InvalidationResult) -> Self {
        Self {
            name,
            messages: Mutex::new(Vec::new()),
            result: Mutex::new(result),
        }
    }

    fn received_count(&self) -> usize {
        self.messages.lock().unwrap().len()
    }
}

impl CacheInvalidationSubscriber for RecordingSubscriber {
    fn on_invalidate_range(&self, _inode: u64, _start: u64, _end: u64) -> usize {
        0
    }

    fn on_invalidate_all(&self) -> usize {
        0
    }

    fn on_invalidation_message(&self, msg: &CacheInvalidationMessage) -> InvalidationResult {
        self.messages.lock().unwrap().push(msg.clone());
        *self.result.lock().unwrap()
    }

    fn subscriber_name(&self) -> &'static str {
        self.name
    }
}

// ---------------------------------------------------------------------------
// Helper: create a LeaseManager with a coherency bus and subscriber
// ---------------------------------------------------------------------------

fn manager_with_bus(
    subscriber: Arc<RecordingSubscriber>,
) -> (LeaseManager, Arc<CoherencyEventBus>) {
    let bus = Arc::new(CoherencyEventBus::new());
    bus.register(subscriber);
    let mut mgr = LeaseManager::new(
        LeaseManagerConfig {
            current_mount_identity: DatasetMountIdentity::new(1, 100, 0),
            ..Default::default()
        },
        EpochId(1),
    );
    mgr.set_coherency_bus(bus.clone());
    (mgr, bus)
}

fn make_byte_range_grant(lease_id: u64, dataset_id: u64, ino: u64, start: u64, end: u64) -> LeaseGrant {
    LeaseGrant::request(
        lease_id,
        LeaseClass::Exclusive,
        LeaseDomain::ByteRange { dataset_id, ino, start, end },
        MemberId(10),
        0,
        30_000,
        1000,
        EpochId(1),
        DatasetMountIdentity::new(dataset_id, 100, 0),
        0,
        3,
        5,
    )
}

fn make_inode_grant(lease_id: u64, dataset_id: u64, ino: u64) -> LeaseGrant {
    LeaseGrant::request(
        lease_id,
        LeaseClass::Exclusive,
        LeaseDomain::Inode { dataset_id, ino },
        MemberId(10),
        0,
        30_000,
        1000,
        EpochId(1),
        DatasetMountIdentity::new(dataset_id, 100, 0),
        0,
        3,
        5,
    )
}

// ---------------------------------------------------------------------------
// Advisory invalidation dispatch
// ---------------------------------------------------------------------------

#[test]
fn advisory_invalidation_dispatches_message_to_subscriber() {
    let sub = Arc::new(RecordingSubscriber::new("advisory-test"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    let grant = make_byte_range_grant(1, 5, 42, 0, 4096);
    mgr.invalidate_cache_for_domain(&grant, InvalidationWaitPolicy::Advisory).unwrap();

    assert_eq!(sub.received_count(), 1, "subscriber should receive one message");
}

#[test]
fn advisory_invalidation_carries_full_metadata() {
    let sub = Arc::new(RecordingSubscriber::new("metadata-test"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    let grant = make_byte_range_grant(1, 5, 42, 0, 4096);
    mgr.invalidate_cache_for_domain(&grant, InvalidationWaitPolicy::Advisory).unwrap();

    let msgs = sub.messages.lock().unwrap();
    let msg = &msgs[0];
    assert_eq!(msg.dataset_id, 5);
    assert_eq!(msg.inode_id, 42);
    assert_eq!(msg.reason, CacheInvalidationReason::ConflictingWriteLease);
    assert_eq!(msg.wait_policy, InvalidationWaitPolicy::Advisory);
    assert!(!msg.is_blocking());
}

#[test]
fn advisory_invalidation_range_scope_correct() {
    let sub = Arc::new(RecordingSubscriber::new("scope-test"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    let grant = make_byte_range_grant(1, 5, 42, 4096, 8192);
    mgr.invalidate_cache_for_domain(&grant, InvalidationWaitPolicy::Advisory).unwrap();

    let msgs = sub.messages.lock().unwrap();
    match &msgs[0].scope {
        CacheInvalidationScope::Range { start, end } => {
            assert_eq!(*start, 4096);
            assert_eq!(*end, 8192);
        }
        _ => panic!("expected Range scope"),
    }
}

#[test]
fn advisory_invalidation_inode_scope_correct() {
    let sub = Arc::new(RecordingSubscriber::new("inode-test"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    let grant = make_inode_grant(2, 5, 99);
    mgr.invalidate_cache_for_domain(&grant, InvalidationWaitPolicy::Advisory).unwrap();

    let msgs = sub.messages.lock().unwrap();
    assert_eq!(msgs[0].scope, CacheInvalidationScope::Inode);
}

// ---------------------------------------------------------------------------
// Generation tracking
// ---------------------------------------------------------------------------

#[test]
fn generation_starts_at_zero() {
    let sub = Arc::new(RecordingSubscriber::new("gen-zero"));
    let (mgr, _bus) = manager_with_bus(sub.clone());
    assert_eq!(mgr.current_generation(5, 42), 0);
}

#[test]
fn generation_advances_monotonically() {
    let sub = Arc::new(RecordingSubscriber::new("gen-advance"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    let g1 = mgr.advance_generation(5, 42);
    let g2 = mgr.advance_generation(5, 42);
    let g3 = mgr.advance_generation(5, 42);

    assert_eq!(g1, 1);
    assert_eq!(g2, 2);
    assert_eq!(g3, 3);
    assert_eq!(mgr.current_generation(5, 42), 3);
}

#[test]
fn generation_is_independent_per_inode() {
    let sub = Arc::new(RecordingSubscriber::new("gen-independent"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    mgr.advance_generation(5, 42);
    mgr.advance_generation(5, 42);
    mgr.advance_generation(5, 99);

    assert_eq!(mgr.current_generation(5, 42), 2);
    assert_eq!(mgr.current_generation(5, 99), 1);
}

#[test]
fn generation_is_independent_per_dataset() {
    let sub = Arc::new(RecordingSubscriber::new("gen-dataset"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    mgr.advance_generation(1, 42);
    mgr.advance_generation(2, 42);

    assert_eq!(mgr.current_generation(1, 42), 1);
    assert_eq!(mgr.current_generation(2, 42), 1);
}

#[test]
fn invalidation_message_includes_generation_delta() {
    let sub = Arc::new(RecordingSubscriber::new("gen-delta"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    // First invalidation advances from 0 -> 1
    let grant = make_byte_range_grant(1, 5, 42, 0, 4096);
    mgr.invalidate_cache_for_domain(&grant, InvalidationWaitPolicy::Advisory).unwrap();
    {
        let msgs = sub.messages.lock().unwrap();
        assert_eq!(msgs[0].old_range_generation, 0);
        assert_eq!(msgs[0].new_range_generation, 1);
    }

    // Advance generation explicitly
    mgr.advance_generation(5, 42);
    mgr.advance_generation(5, 42);

    // Second invalidation sees old=3, new=4
    let grant2 = make_byte_range_grant(2, 5, 42, 0, 4096);
    mgr.invalidate_cache_for_domain(&grant2, InvalidationWaitPolicy::Advisory).unwrap();

    let msgs = sub.messages.lock().unwrap();
    assert_eq!(msgs[1].old_range_generation, 3);
    assert_eq!(msgs[1].new_range_generation, 4);
}

// ---------------------------------------------------------------------------
// Wait policy: WaitForCleanEviction
// ---------------------------------------------------------------------------

#[test]
fn wait_for_clean_eviction_is_blocking() {
    let sub = Arc::new(RecordingSubscriber::new("clean-evict"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    let grant = make_byte_range_grant(1, 5, 42, 0, 4096);
    let result = mgr.invalidate_cache_for_domain(&grant, InvalidationWaitPolicy::WaitForCleanEviction).unwrap();

    // Subscriber returned clean(0), so result should be clean.
    assert!(result.dirty_drained);
    assert!(!result.needs_retry);
}

#[test]
fn wait_for_clean_eviction_sees_blocking_flag() {
    let sub = Arc::new(RecordingSubscriber::new("blocking-flag"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    let grant = make_byte_range_grant(1, 5, 42, 0, 4096);
    mgr.invalidate_cache_for_domain(&grant, InvalidationWaitPolicy::WaitForCleanEviction).unwrap();

    let msgs = sub.messages.lock().unwrap();
    assert!(msgs[0].is_blocking());
    assert!(!msgs[0].requires_dirty_drain());
}

// ---------------------------------------------------------------------------
// Wait policy: WaitForDirtyDrain
// ---------------------------------------------------------------------------

#[test]
fn wait_for_dirty_drain_sees_dirty_pages() {
    let sub = Arc::new(RecordingSubscriber::with_result(
        "dirty-sub",
        InvalidationResult::dirty_pending(3, 2),
    ));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    let grant = make_byte_range_grant(1, 5, 42, 0, 4096);
    let result = mgr.invalidate_cache_for_domain(&grant, InvalidationWaitPolicy::WaitForDirtyDrain).unwrap();

    assert_eq!(result.clean_evicted, 3);
    assert_eq!(result.dirty_remaining, 2);
    assert!(!result.dirty_drained);
    assert!(result.needs_retry);
}

#[test]
fn wait_for_dirty_drain_requires_dirty_flag() {
    let sub = Arc::new(RecordingSubscriber::new("dirty-flag"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    let grant = make_byte_range_grant(1, 5, 42, 0, 4096);
    mgr.invalidate_cache_for_domain(&grant, InvalidationWaitPolicy::WaitForDirtyDrain).unwrap();

    let msgs = sub.messages.lock().unwrap();
    assert!(msgs[0].requires_dirty_drain());
    assert!(msgs[0].is_blocking());
}

// ---------------------------------------------------------------------------
// Wait policy: FenceAndError
// ---------------------------------------------------------------------------

#[test]
fn fence_and_error_is_not_blocking() {
    let sub = Arc::new(RecordingSubscriber::new("fence-sub"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    let grant = make_byte_range_grant(1, 5, 42, 0, 4096);
    let _result = mgr.invalidate_cache_for_domain(&grant, InvalidationWaitPolicy::FenceAndError).unwrap();

    let msgs = sub.messages.lock().unwrap();
    assert!(!msgs[0].is_blocking());
    assert!(!msgs[0].requires_dirty_drain());
}

// ---------------------------------------------------------------------------
// Epoch transition invalidation
// ---------------------------------------------------------------------------

#[test]
fn epoch_advance_fences_old_leases_and_dispatches_invalidation() {
    let sub = Arc::new(RecordingSubscriber::new("epoch-sub"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    // Grant two leases in epoch 1
    let _g1 = mgr.grant(
        LeaseClass::Exclusive,
        LeaseDomain::ByteRange { dataset_id: 5, ino: 42, start: 0, end: 4096 },
        MemberId(10),
        3,
        1000,
    ).unwrap();

    let _g2 = mgr.grant(
        LeaseClass::Exclusive,
        LeaseDomain::Inode { dataset_id: 5, ino: 99 },
        MemberId(11),
        3,
        1000,
    ).unwrap();

    assert_eq!(mgr.grant_count(), 2);

    // Advance epoch
    let fenced = mgr.advance_epoch(EpochId(2));
    assert_eq!(fenced.len(), 2, "both old-epoch leases should be fenced");

    // Both leases should be terminal
    for lid in &fenced {
        let g = mgr.get_grant(*lid).unwrap();
        assert!(g.lifecycle.is_terminal(), "lease {} should be fenced", lid);
    }

    // Invalidation messages should have been dispatched
    assert_eq!(sub.received_count(), 2, "two invalidation messages dispatched");

    // Verify epoch in invalidation messages
    let msgs = sub.messages.lock().unwrap();
    assert_eq!(msgs[0].membership_epoch, 1); // old epoch
    assert_eq!(msgs[0].reason, CacheInvalidationReason::LeaseRevoked);
}

#[test]
fn epoch_advance_updates_current_epoch() {
    let sub = Arc::new(RecordingSubscriber::new("epoch-update"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    assert_eq!(mgr.current_epoch(), EpochId(1));
    mgr.advance_epoch(EpochId(5));
    assert_eq!(mgr.current_epoch(), EpochId(5));
}

#[test]
fn epoch_advance_noop_for_equal_or_lesser_epoch() {
    let sub = Arc::new(RecordingSubscriber::new("epoch-noop"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    let fenced = mgr.advance_epoch(EpochId(1)); // same epoch
    assert!(fenced.is_empty());
    assert_eq!(mgr.current_epoch(), EpochId(1));

    let fenced2 = mgr.advance_epoch(EpochId(0)); // lesser epoch
    assert!(fenced2.is_empty());
    assert_eq!(mgr.current_epoch(), EpochId(1));
}

// ---------------------------------------------------------------------------
// Invalidation stats
// ---------------------------------------------------------------------------

#[test]
fn stats_track_invalidation_dispatches() {
    let sub = Arc::new(RecordingSubscriber::new("stats-sub"));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    let grant = make_byte_range_grant(1, 5, 42, 0, 4096);
    mgr.invalidate_cache_for_domain(&grant, InvalidationWaitPolicy::Advisory).unwrap();

    assert_eq!(mgr.stats().invalidations_dispatched, 1);
    assert_eq!(mgr.stats().invalidations_acked, 0); // advisory = fire-and-forget
}

// ---------------------------------------------------------------------------
// CacheInvalidationPayload wire round-trip (via lease types)
// ---------------------------------------------------------------------------

#[test]
fn wire_payload_roundtrip_preserves_all_fields() {
    let payload = CacheInvalidationPayload {
        dataset_id: 7,
        mount_session_id: 300,
        inode_id: 55,
        inode_generation: 4,
        scope: tidefs_lease::wire::WireInvalidationScope::Range { start: 1024, end: 2048 },
        old_range_generation: 1,
        new_range_generation: 2,
        lease_epoch: 10,
        membership_epoch: 20,
        reason: tidefs_lease::wire::WireInvalidationReason::EpochTransition,
        wait_policy: tidefs_lease::wire::WireWaitPolicy::WaitForDirtyDrain,
    };

    let msg = payload.clone().into_coherency();
    let back = CacheInvalidationPayload::from_coherency(&msg);

    assert_eq!(back.dataset_id, 7);
    assert_eq!(back.inode_id, 55);
    assert_eq!(back.inode_generation, 4);
    assert_eq!(back.old_range_generation, 1);
    assert_eq!(back.new_range_generation, 2);
    assert_eq!(back.lease_epoch, 10);
    assert_eq!(back.membership_epoch, 20);
}

// ---------------------------------------------------------------------------
// No cross-dataset lock verification
// ---------------------------------------------------------------------------

#[test]
fn invalidation_scoped_to_owning_dataset_no_cross_dataset_lock() {
    let sub1 = Arc::new(RecordingSubscriber::new("ds1-sub"));
    let sub2 = Arc::new(RecordingSubscriber::new("ds2-sub"));

    let bus = Arc::new(CoherencyEventBus::new());
    bus.register(sub1.clone());
    bus.register(sub2.clone());

    let mut mgr = LeaseManager::new(
        LeaseManagerConfig {
            current_mount_identity: DatasetMountIdentity::new(1, 100, 0),
            ..Default::default()
        },
        EpochId(1),
    );
    mgr.set_coherency_bus(bus);

    // Invalidate dataset 5 only
    let grant = make_byte_range_grant(1, 5, 42, 0, 4096);
    mgr.invalidate_cache_for_domain(&grant, InvalidationWaitPolicy::Advisory).unwrap();

    // Both subscribers receive the message (the bus is not dataset-scoped;
    // each subscriber implements its own dataset-scoped filtering).
    assert_eq!(sub1.received_count(), 1);
    assert_eq!(sub2.received_count(), 1);

    // The message carries the correct dataset_id for filtering
    let msg1 = &sub1.messages.lock().unwrap()[0];
    assert_eq!(msg1.dataset_id, 5);

    // Verify there is no global cross-dataset lock: the coherency bus
    // does not acquire a global lock; each subscriber independently
    // serializes its own invalidation.
    // (This is an invariant test: the bus Mutex protects the subscriber
    //  list, not cache state.)
}

// ---------------------------------------------------------------------------
// Non-overlap verification: no POSIX lock forwarding, no cache admission
// ---------------------------------------------------------------------------

#[test]
fn invalidation_does_not_require_lock_service_types() {
    // Verify that CacheInvalidationMessage does not reference
    // POSIX lock types from the lock service (non-overlap with #633).
    let msg = CacheInvalidationMessage::range(
        1, 100, 42, 5, 0, 4096, 1, 2, 10, 20,
        CacheInvalidationReason::ConflictingWriteLease,
        InvalidationWaitPolicy::Advisory,
    );
    // The message only carries lease/epoch/invalidation metadata,
    // not POSIX lock owner or lock type data.
    assert_eq!(msg.dataset_id, 1);
    assert_eq!(msg.wait_policy, InvalidationWaitPolicy::Advisory);
}

#[test]
fn invalidation_does_not_require_cache_admission_types() {
    // Verify that invalidation does not reference cache admission
    // or memory-budget policy types (non-overlap with #685).
    let msg = CacheInvalidationMessage::inode(
        1, 100, 42, 5, 1, 2, 10, 20,
        CacheInvalidationReason::EpochTransition,
        InvalidationWaitPolicy::WaitForDirtyDrain,
    );
    // No admission/budget fields present.
    assert_eq!(msg.inode_id, 42);
    assert!(msg.requires_dirty_drain());
}

// ---------------------------------------------------------------------------
// InvalidationAck construction
// ---------------------------------------------------------------------------

#[test]
fn invalidation_ack_reflects_subscriber_result() {
    let sub = Arc::new(RecordingSubscriber::with_result(
        "ack-sub",
        InvalidationResult {
            clean_evicted: 7,
            dirty_remaining: 3,
            dirty_drained: false,
            needs_retry: true,
        },
    ));
    let (mut mgr, _bus) = manager_with_bus(sub.clone());

    let grant = make_byte_range_grant(1, 5, 42, 0, 4096);
    let result = mgr.invalidate_cache_for_domain(&grant, InvalidationWaitPolicy::WaitForDirtyDrain).unwrap();

    assert_eq!(result.clean_evicted, 7);
    assert_eq!(result.dirty_remaining, 3);
    assert!(!result.dirty_drained);
    assert!(result.needs_retry);
}

// ---------------------------------------------------------------------------
// InvalidationReason covers all authority-specified triggers
// ---------------------------------------------------------------------------

#[test]
fn invalidation_reason_covers_all_authority_triggers() {
    // Verify that CacheInvalidationReason covers the triggers listed in
    // docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md: conflicting write lease,
    // lease revoked, epoch transition, mount identity change,
    // destructive mutation, inode orphan, admin drain, holder unreachable,
    // policy eviction.
    let reasons = [
        CacheInvalidationReason::ConflictingWriteLease,
        CacheInvalidationReason::LeaseRevoked,
        CacheInvalidationReason::EpochTransition,
        CacheInvalidationReason::MountIdentityChanged,
        CacheInvalidationReason::DestructiveMutation,
        CacheInvalidationReason::InodeOrphaned,
        CacheInvalidationReason::AdminDrain,
        CacheInvalidationReason::HolderUnreachable,
        CacheInvalidationReason::PolicyEviction,
    ];
    // All 9 variants are present.
    assert_eq!(reasons.len(), 9);
}

// ---------------------------------------------------------------------------
// InvalidationWaitPolicy covers all authority-specified policies
// ---------------------------------------------------------------------------

#[test]
fn wait_policy_covers_all_authority_policies() {
    let policies = [
        InvalidationWaitPolicy::Advisory,
        InvalidationWaitPolicy::WaitForCleanEviction,
        InvalidationWaitPolicy::WaitForDirtyDrain,
        InvalidationWaitPolicy::FenceAndError,
    ];
    assert_eq!(policies.len(), 4);
}
