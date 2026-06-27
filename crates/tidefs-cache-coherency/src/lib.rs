// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Cache coherency event bus and invalidation subscriber trait.
//!
//! Lightweight crate (zero non-std deps) providing the [`CoherencyEventBus`]
//! dispatch mechanism and the [`CacheInvalidationSubscriber`] trait that
//! bridges lease revocation events to page-cache invalidation for mmap
//! coherency across clustered clients.
//!
//! This crate is intentionally dependency-free so it can sit in the
//! storage-core dependency closure without pulling in POSIX-adapter or
//! control-plane scaffold crates.
//!
//! ## Coherency Contract
//!
//! The TideFS cache coherency model satisfies these invariants:
//!
//! 1. **No global locks across datasets.**  Invalidation is scoped to a
//!    single inode (`on_invalidate_inode`) or byte range
//!    (`on_invalidate_range`).  The coherency event bus never acquires a
//!    global cross-dataset lock; each subscriber independently serializes
//!    its own invalidation.
//!
//! 2. **Dirty/writeback pages survive coherency invalidation.**
//!    `on_invalidate_range` evicts only clean, unpinned, non-writeback
//!    pages.  Dirty data is preserved until writeback completes.  This
//!    guarantees that a lease revocation does not silently discard
//!    uncommitted writes.
//!
//! 3. **Unlink and truncate are authoritative.**
//!    `PageCache::unlink_invalidate` and `PageCache::truncate_invalidate`
//!    remove all pages (including dirty) for the affected inode, because
//!    the data is no longer reachable after the operation commits.
//!
//! 4. **Crash integration.**  After intent-log replay, any dirty state
//!    that existed pre-crash is either replayed from the log or cleanly
//!    invalidated with a classified gap (see `tidefs-crash-oracle`).
//!
//! ## Clustered Invalidation
//!
//! The [`CacheInvalidationMessage`] type carries lease/epoch invalidation
//! metadata for cross-node cache coherency as decided by
//! `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md`.  A [`CoherencyEventBus`]
//! dispatches these messages to registered subscribers; each subscriber
//! must honour the wait policy encoded in the message.

use std::fmt;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Invalidation wait policy
// ---------------------------------------------------------------------------

/// Policy that governs how a cache subscriber must handle invalidation.
///
/// Defined by `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md` §"Lease And
/// Epoch Model".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidationWaitPolicy {
    /// Best-effort eviction of clean entries.  The stale-generation rule
    /// still guards correctness; advisory delivery is a latency
    /// optimisation only.
    Advisory,
    /// The invalidation sender waits for clean cache eviction to complete
    /// before granting a conflicting lease or publishing an epoch.
    WaitForCleanEviction,
    /// The invalidation sender waits for all dirty/writeback overlapping
    /// the invalidated range to be drained, transferred, or classified
    /// before proceeding.
    WaitForDirtyDrain,
    /// The invalidation sender errors or fences the conflicting operation
    /// immediately and does not wait for cache state changes.
    FenceAndError,
}

impl Default for InvalidationWaitPolicy {
    fn default() -> Self {
        Self::Advisory
    }
}

// ---------------------------------------------------------------------------
// Cache invalidation reason
// ---------------------------------------------------------------------------

/// Why a cache invalidation is being issued.
///
/// Kept dependency-free so the coherency contract stays in the
/// storage-core closure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheInvalidationReason {
    /// A conflicting write lease is being granted to another node.
    ConflictingWriteLease,
    /// A lease was revoked (admin, policy, node failure).
    LeaseRevoked,
    /// The membership epoch advanced; all prior-epoch leases are fenced.
    EpochTransition,
    /// The dataset mount identity changed (remount or dataset migration).
    MountIdentityChanged,
    /// A destructive data mutation (truncate, hole-punch, collapse, insert)
    /// has committed.
    DestructiveMutation,
    /// An inode was unlinked and has no remaining links or open handles.
    InodeOrphaned,
    /// Administrative cache flush or drain (node shutdown, pool offlining).
    AdminDrain,
    /// The holder node became unreachable.
    HolderUnreachable,
    /// A policy or quota limit forced eviction.
    PolicyEviction,
}

// ---------------------------------------------------------------------------
// Cache invalidation scope
// ---------------------------------------------------------------------------

/// Granularity of a cache invalidation event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheInvalidationScope {
    /// Invalidate a specific byte range `[start, end)` within an inode.
    Range { start: u64, end: u64 },
    /// Invalidate all cached data for an inode.
    Inode,
    /// Invalidate all cached data for a dataset.
    Dataset,
}

// ---------------------------------------------------------------------------
// Cache invalidation message
// ---------------------------------------------------------------------------

/// A clustered cache invalidation event carrying the full lease/epoch
/// authority metadata.
///
/// This struct is the canonical cross-node invalidation payload as
/// defined by `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md`.  Lease managers
/// and membership epoch services construct these messages; cache
/// subscribers consume them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheInvalidationMessage {
    /// Dataset that owns the cached data.
    pub dataset_id: u64,
    /// Mount or session identity that currently projects the dataset.
    pub mount_session_id: u64,
    /// Inode whose cached data is affected.
    pub inode_id: u64,
    /// Inode generation at the time of invalidation.
    ///
    /// A subscriber must not serve cached data from a superseded generation.
    pub inode_generation: u64,
    /// Scope of the invalidation: range, whole inode, or whole dataset.
    pub scope: CacheInvalidationScope,
    /// The range generation that the stale cache was filled from.
    pub old_range_generation: u64,
    /// The range generation that will be authoritative after invalidation.
    pub new_range_generation: u64,
    /// The lease epoch under which the conflict or revocation occurred.
    pub lease_epoch: u64,
    /// The membership epoch at the time of invalidation.
    pub membership_epoch: u64,
    /// Why this invalidation is being issued.
    pub reason: CacheInvalidationReason,
    /// How the subscriber must handle this invalidation.
    pub wait_policy: InvalidationWaitPolicy,
}

impl CacheInvalidationMessage {
    /// Construct a range-scoped invalidation message.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn range(
        dataset_id: u64,
        mount_session_id: u64,
        inode_id: u64,
        inode_generation: u64,
        start: u64,
        end: u64,
        old_range_generation: u64,
        new_range_generation: u64,
        lease_epoch: u64,
        membership_epoch: u64,
        reason: CacheInvalidationReason,
        wait_policy: InvalidationWaitPolicy,
    ) -> Self {
        Self {
            dataset_id,
            mount_session_id,
            inode_id,
            inode_generation,
            scope: CacheInvalidationScope::Range { start, end },
            old_range_generation,
            new_range_generation,
            lease_epoch,
            membership_epoch,
            reason,
            wait_policy,
        }
    }

    /// Construct an inode-scoped invalidation message.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn inode(
        dataset_id: u64,
        mount_session_id: u64,
        inode_id: u64,
        inode_generation: u64,
        old_range_generation: u64,
        new_range_generation: u64,
        lease_epoch: u64,
        membership_epoch: u64,
        reason: CacheInvalidationReason,
        wait_policy: InvalidationWaitPolicy,
    ) -> Self {
        Self {
            dataset_id,
            mount_session_id,
            inode_id,
            inode_generation,
            scope: CacheInvalidationScope::Inode,
            old_range_generation,
            new_range_generation,
            lease_epoch,
            membership_epoch,
            reason,
            wait_policy,
        }
    }

    /// Construct a dataset-scoped invalidation message.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn dataset(
        dataset_id: u64,
        mount_session_id: u64,
        old_range_generation: u64,
        new_range_generation: u64,
        lease_epoch: u64,
        membership_epoch: u64,
        reason: CacheInvalidationReason,
        wait_policy: InvalidationWaitPolicy,
    ) -> Self {
        Self {
            dataset_id,
            mount_session_id,
            inode_id: 0,
            inode_generation: 0,
            scope: CacheInvalidationScope::Dataset,
            old_range_generation,
            new_range_generation,
            lease_epoch,
            membership_epoch,
            reason,
            wait_policy,
        }
    }

    /// Whether this invalidation requires the sender to wait before proceeding.
    #[must_use]
    pub fn is_blocking(&self) -> bool {
        matches!(
            self.wait_policy,
            InvalidationWaitPolicy::WaitForCleanEviction
                | InvalidationWaitPolicy::WaitForDirtyDrain
        )
    }

    /// Whether dirty/writeback pages must be drained (not just clean pages evicted).
    #[must_use]
    pub fn requires_dirty_drain(&self) -> bool {
        matches!(self.wait_policy, InvalidationWaitPolicy::WaitForDirtyDrain)
    }
}

impl fmt::Display for CacheInvalidationMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.scope {
            CacheInvalidationScope::Range { start, end } => {
                write!(
                    f,
                    "invalidate dataset={} mount={} ino={} gen={} range=[{},{}) old_gen={} new_gen={} lease_epoch={} memb_epoch={} reason={:?} policy={:?}",
                    self.dataset_id,
                    self.mount_session_id,
                    self.inode_id,
                    self.inode_generation,
                    start,
                    end,
                    self.old_range_generation,
                    self.new_range_generation,
                    self.lease_epoch,
                    self.membership_epoch,
                    self.reason,
                    self.wait_policy,
                )
            }
            CacheInvalidationScope::Inode => {
                write!(
                    f,
                    "invalidate dataset={} mount={} ino={} gen={} (whole inode) old_gen={} new_gen={} lease_epoch={} memb_epoch={} reason={:?} policy={:?}",
                    self.dataset_id,
                    self.mount_session_id,
                    self.inode_id,
                    self.inode_generation,
                    self.old_range_generation,
                    self.new_range_generation,
                    self.lease_epoch,
                    self.membership_epoch,
                    self.reason,
                    self.wait_policy,
                )
            }
            CacheInvalidationScope::Dataset => {
                write!(
                    f,
                    "invalidate dataset={} mount={} (whole dataset) old_gen={} new_gen={} lease_epoch={} memb_epoch={} reason={:?} policy={:?}",
                    self.dataset_id,
                    self.mount_session_id,
                    self.old_range_generation,
                    self.new_range_generation,
                    self.lease_epoch,
                    self.membership_epoch,
                    self.reason,
                    self.wait_policy,
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Invalidation result
// ---------------------------------------------------------------------------

/// Outcome returned by a subscriber after handling an invalidation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidationResult {
    /// Number of clean entries evicted.
    pub clean_evicted: usize,
    /// Number of dirty/writeback entries still pending.
    pub dirty_remaining: usize,
    /// Whether all dirty entries have been drained.
    pub dirty_drained: bool,
    /// Whether the subscriber needs more time (retry later).
    pub needs_retry: bool,
}

impl InvalidationResult {
    /// All work done: clean evicted, no dirty remaining.
    #[must_use]
    pub fn clean(evicted: usize) -> Self {
        Self {
            clean_evicted: evicted,
            dirty_remaining: 0,
            dirty_drained: true,
            needs_retry: false,
        }
    }

    /// Dirty pages still exist; caller must wait or fence.
    #[must_use]
    pub fn dirty_pending(clean_evicted: usize, dirty_remaining: usize) -> Self {
        Self {
            clean_evicted,
            dirty_remaining,
            dirty_drained: dirty_remaining == 0,
            needs_retry: dirty_remaining > 0,
        }
    }

    /// Fenced without action (error path).
    #[must_use]
    pub fn fenced() -> Self {
        Self {
            clean_evicted: 0,
            dirty_remaining: 0,
            dirty_drained: false,
            needs_retry: false,
        }
    }
}

// ---------------------------------------------------------------------------
// CacheInvalidationSubscriber trait
// ---------------------------------------------------------------------------

/// A subscriber that receives invalidation events from the coherency layer.
///
/// When a lease is revoked or a membership epoch transitions, the coherency
/// event bus dispatches invalidation events to all registered subscribers.
/// Each subscriber is responsible for evicting stale entries from its cache.
pub trait CacheInvalidationSubscriber: Send + Sync {
    /// Invalidate clean, unpinned cache entries whose byte range overlaps
    /// with [start, end) for the given inode.  Dirty and writeback pages
    /// are preserved.
    ///
    /// This is the primary mmap coherency primitive: when a conflicting
    /// lease is granted to another client, the lease manager revokes the
    /// local lease and calls this method to evict stale pages.
    ///
    /// Returns the number of entries invalidated.
    fn on_invalidate_range(&self, inode: u64, start: u64, end: u64) -> usize;

    /// Invalidate all clean entries for the given inode (entire file).
    /// Returns the number of entries invalidated.
    fn on_invalidate_inode(&self, inode: u64) -> usize {
        self.on_invalidate_range(inode, 0, u64::MAX)
    }

    /// Invalidate all entries in this subscriber's cache.
    /// Returns the number of entries invalidated.
    fn on_invalidate_all(&self) -> usize;

    /// Handle a clustered cache invalidation message carrying full
    /// lease/epoch authority metadata.
    ///
    /// The default implementation maps the message to the legacy
    /// range/inode/all methods for backward compatibility.  Subscribers
    /// that want to honour wait policies and generation tracking should
    /// override this method.
    ///
    /// Returns an [`InvalidationResult`] describing clean eviction count
    /// and remaining dirty state.
    fn on_invalidation_message(&self, msg: &CacheInvalidationMessage) -> InvalidationResult {
        let clean_evicted = match msg.scope {
            CacheInvalidationScope::Range { start, end } => {
                self.on_invalidate_range(msg.inode_id, start, end)
            }
            CacheInvalidationScope::Inode => self.on_invalidate_inode(msg.inode_id),
            CacheInvalidationScope::Dataset => self.on_invalidate_all(),
        };
        InvalidationResult::clean(clean_evicted)
    }

    /// Human-readable name for diagnostics.
    fn subscriber_name(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// CoherencyEventBus
// ---------------------------------------------------------------------------

/// A bus that dispatches coherency invalidation events to registered
/// [`CacheInvalidationSubscriber`]s.
///
/// The lease manager and membership service push events through this bus
/// when authoritative state changes.  Each registered subscriber evicts
/// affected entries from its cache.
///
/// Thread-safe: internal state is protected by a [`Mutex`].
pub struct CoherencyEventBus {
    subscribers: Mutex<Vec<Arc<dyn CacheInvalidationSubscriber>>>,
}

impl CoherencyEventBus {
    /// Create a new empty event bus.
    #[must_use]
    pub fn new() -> Self {
        Self {
            subscribers: Mutex::new(Vec::new()),
        }
    }

    /// Register a subscriber to receive invalidation events.
    pub fn register(&self, subscriber: Arc<dyn CacheInvalidationSubscriber>) {
        self.subscribers.lock().unwrap().push(subscriber);
    }

    /// Dispatch a byte-range invalidation to all registered subscribers.
    ///
    /// Called by the lease manager when a conflicting lease is granted and
    /// the local holder's lease is revoked.
    ///
    /// Returns the total number of entries invalidated across all subscribers.
    pub fn dispatch_range_invalidation(&self, inode: u64, start: u64, end: u64) -> usize {
        let subs = self.subscribers.lock().unwrap();
        subs.iter()
            .map(|s| s.on_invalidate_range(inode, start, end))
            .sum()
    }

    /// Dispatch a full-inode invalidation to all registered subscribers.
    ///
    /// Called when an inode is truncated, unlinked, or its lease is
    /// unconditionally revoked.
    ///
    /// Returns the total number of entries invalidated across all subscribers.
    pub fn dispatch_inode_invalidation(&self, inode: u64) -> usize {
        let subs = self.subscribers.lock().unwrap();
        subs.iter().map(|s| s.on_invalidate_inode(inode)).sum()
    }

    /// Dispatch a full-cache invalidation to all registered subscribers.
    ///
    /// Called during node drain, membership epoch transition, or other
    /// bulk-coherency events.
    ///
    /// Returns the total number of entries invalidated across all subscribers.
    pub fn dispatch_full_invalidation(&self) -> usize {
        let subs = self.subscribers.lock().unwrap();
        subs.iter().map(|s| s.on_invalidate_all()).sum()
    }

    /// Dispatch a clustered cache invalidation message to all subscribers.
    ///
    /// Each subscriber receives the full [`CacheInvalidationMessage`]
    /// and returns an [`InvalidationResult`].  The caller aggregates
    /// results across all subscribers.
    ///
    /// Returns the aggregated invalidation result across all subscribers.
    pub fn dispatch_invalidation_message(
        &self,
        msg: &CacheInvalidationMessage,
    ) -> InvalidationResult {
        let subs = self.subscribers.lock().unwrap();
        let mut total_clean = 0usize;
        let mut total_dirty = 0usize;
        let mut all_drained = true;
        let mut any_retry = false;

        for s in subs.iter() {
            let r = s.on_invalidation_message(msg);
            total_clean = total_clean.saturating_add(r.clean_evicted);
            total_dirty = total_dirty.saturating_add(r.dirty_remaining);
            if !r.dirty_drained {
                all_drained = false;
            }
            if r.needs_retry {
                any_retry = true;
            }
        }

        InvalidationResult {
            clean_evicted: total_clean,
            dirty_remaining: total_dirty,
            dirty_drained: all_drained,
            needs_retry: any_retry,
        }
    }

    /// Number of registered subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.lock().unwrap().len()
    }
}

impl Default for CoherencyEventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CoherencyEventBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoherencyEventBus")
            .field("subscriber_count", &self.subscriber_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestSub {
        events: Mutex<Vec<(u64, u64, u64)>>,
    }

    impl CacheInvalidationSubscriber for TestSub {
        fn on_invalidate_range(&self, inode: u64, start: u64, end: u64) -> usize {
            self.events.lock().unwrap().push((inode, start, end));
            1
        }
        fn on_invalidate_all(&self) -> usize {
            0
        }
        fn subscriber_name(&self) -> &'static str {
            "test-sub"
        }
    }

    #[test]
    fn bus_dispatch_range() {
        let bus = CoherencyEventBus::new();
        let sub = Arc::new(TestSub {
            events: Mutex::new(Vec::new()),
        });
        bus.register(sub.clone());

        let total = bus.dispatch_range_invalidation(5, 4096, 8192);
        assert_eq!(total, 1);
        let events = sub.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], (5, 4096, 8192));
    }

    #[test]
    fn bus_dispatch_inode() {
        let bus = CoherencyEventBus::new();
        struct InodeSub {
            inodes: Mutex<Vec<u64>>,
        }
        impl CacheInvalidationSubscriber for InodeSub {
            fn on_invalidate_range(&self, _i: u64, _s: u64, _e: u64) -> usize {
                0
            }
            fn on_invalidate_inode(&self, inode: u64) -> usize {
                self.inodes.lock().unwrap().push(inode);
                1
            }
            fn on_invalidate_all(&self) -> usize {
                0
            }
            fn subscriber_name(&self) -> &'static str {
                "inode-sub"
            }
        }
        let sub = Arc::new(InodeSub {
            inodes: Mutex::new(Vec::new()),
        });
        bus.register(sub.clone());
        bus.dispatch_inode_invalidation(42);
        assert_eq!(sub.inodes.lock().unwrap()[0], 42);
    }

    #[test]
    fn bus_default_and_debug() {
        let bus = CoherencyEventBus::default();
        assert_eq!(bus.subscriber_count(), 0);
        let dbg = format!("{bus:?}");
        assert!(dbg.contains("CoherencyEventBus"));
        assert!(dbg.contains("subscriber_count"));
    }

    #[test]
    fn bus_subscriber_count() {
        let bus = CoherencyEventBus::new();
        assert_eq!(bus.subscriber_count(), 0);
        bus.register(Arc::new(TestSub {
            events: Mutex::new(Vec::new()),
        }));
        assert_eq!(bus.subscriber_count(), 1);
    }

    // ── Clustered invalidation message tests ─────────────────────────

    #[test]
    fn invalidation_message_range_construction() {
        let msg = CacheInvalidationMessage::range(
            1,
            100,
            42,
            5,
            0,
            4096,
            1,
            2,
            10,
            20,
            CacheInvalidationReason::ConflictingWriteLease,
            InvalidationWaitPolicy::WaitForCleanEviction,
        );
        assert_eq!(msg.dataset_id, 1);
        assert_eq!(msg.mount_session_id, 100);
        assert_eq!(msg.inode_id, 42);
        assert_eq!(msg.inode_generation, 5);
        assert_eq!(msg.old_range_generation, 1);
        assert_eq!(msg.new_range_generation, 2);
        assert_eq!(msg.lease_epoch, 10);
        assert_eq!(msg.membership_epoch, 20);
        assert_eq!(msg.reason, CacheInvalidationReason::ConflictingWriteLease);
        assert_eq!(
            msg.wait_policy,
            InvalidationWaitPolicy::WaitForCleanEviction
        );
        assert!(msg.is_blocking());
        assert!(!msg.requires_dirty_drain());
        if let CacheInvalidationScope::Range { start, end } = msg.scope {
            assert_eq!(start, 0);
            assert_eq!(end, 4096);
        } else {
            panic!("expected Range scope");
        }
    }

    #[test]
    fn invalidation_message_inode_construction() {
        let msg = CacheInvalidationMessage::inode(
            2,
            200,
            99,
            3,
            5,
            6,
            15,
            25,
            CacheInvalidationReason::EpochTransition,
            InvalidationWaitPolicy::WaitForDirtyDrain,
        );
        assert_eq!(msg.dataset_id, 2);
        assert_eq!(msg.inode_id, 99);
        assert_eq!(msg.scope, CacheInvalidationScope::Inode);
        assert!(msg.requires_dirty_drain());
    }

    #[test]
    fn invalidation_message_dataset_construction() {
        let msg = CacheInvalidationMessage::dataset(
            3,
            300,
            7,
            8,
            30,
            40,
            CacheInvalidationReason::AdminDrain,
            InvalidationWaitPolicy::FenceAndError,
        );
        assert_eq!(msg.scope, CacheInvalidationScope::Dataset);
        assert_eq!(msg.inode_id, 0);
        assert!(!msg.is_blocking());
    }

    #[test]
    fn invalidation_message_display() {
        let msg = CacheInvalidationMessage::range(
            1,
            100,
            42,
            5,
            0,
            4096,
            1,
            2,
            10,
            20,
            CacheInvalidationReason::ConflictingWriteLease,
            InvalidationWaitPolicy::Advisory,
        );
        let s = format!("{msg}");
        assert!(s.contains("dataset=1"));
        assert!(s.contains("ino=42"));
        assert!(s.contains("range=[0,4096)"));
    }

    #[test]
    fn wait_policy_default_is_advisory() {
        assert_eq!(
            InvalidationWaitPolicy::default(),
            InvalidationWaitPolicy::Advisory
        );
    }

    #[test]
    fn invalidation_result_clean() {
        let r = InvalidationResult::clean(5);
        assert_eq!(r.clean_evicted, 5);
        assert_eq!(r.dirty_remaining, 0);
        assert!(r.dirty_drained);
        assert!(!r.needs_retry);
    }

    #[test]
    fn invalidation_result_dirty_pending() {
        let r = InvalidationResult::dirty_pending(3, 2);
        assert_eq!(r.clean_evicted, 3);
        assert_eq!(r.dirty_remaining, 2);
        assert!(!r.dirty_drained);
        assert!(r.needs_retry);
    }

    #[test]
    fn invalidation_result_fenced() {
        let r = InvalidationResult::fenced();
        assert_eq!(r.clean_evicted, 0);
        assert!(!r.dirty_drained);
        assert!(!r.needs_retry);
    }

    // ── Clustered invalidation dispatch tests ────────────────────────

    struct MsgTrackingSub {
        messages: Mutex<Vec<CacheInvalidationMessage>>,
        result: InvalidationResult,
    }

    impl CacheInvalidationSubscriber for MsgTrackingSub {
        fn on_invalidate_range(&self, _inode: u64, _start: u64, _end: u64) -> usize {
            0
        }
        fn on_invalidate_all(&self) -> usize {
            0
        }
        fn on_invalidation_message(&self, msg: &CacheInvalidationMessage) -> InvalidationResult {
            self.messages.lock().unwrap().push(msg.clone());
            self.result
        }
        fn subscriber_name(&self) -> &'static str {
            "msg-tracking-sub"
        }
    }

    #[test]
    fn bus_dispatch_invalidation_message() {
        let bus = CoherencyEventBus::new();
        let sub = Arc::new(MsgTrackingSub {
            messages: Mutex::new(Vec::new()),
            result: InvalidationResult::clean(3),
        });
        bus.register(sub.clone());

        let msg = CacheInvalidationMessage::range(
            1,
            100,
            42,
            5,
            0,
            4096,
            1,
            2,
            10,
            20,
            CacheInvalidationReason::ConflictingWriteLease,
            InvalidationWaitPolicy::WaitForDirtyDrain,
        );
        let result = bus.dispatch_invalidation_message(&msg);
        assert_eq!(result.clean_evicted, 3);
        assert!(result.dirty_drained);
        assert!(!result.needs_retry);

        let captured = sub.messages.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].inode_id, 42);
    }

    #[test]
    fn bus_dispatch_invalidation_aggregates_results() {
        let bus = CoherencyEventBus::new();
        let sub1 = Arc::new(MsgTrackingSub {
            messages: Mutex::new(Vec::new()),
            result: InvalidationResult::dirty_pending(2, 1),
        });
        let sub2 = Arc::new(MsgTrackingSub {
            messages: Mutex::new(Vec::new()),
            result: InvalidationResult::clean(4),
        });
        bus.register(sub1);
        bus.register(sub2);

        let msg = CacheInvalidationMessage::inode(
            2,
            200,
            99,
            3,
            5,
            6,
            15,
            25,
            CacheInvalidationReason::EpochTransition,
            InvalidationWaitPolicy::WaitForDirtyDrain,
        );
        let result = bus.dispatch_invalidation_message(&msg);
        // sub1: 2 clean + 1 dirty; sub2: 4 clean + 0 dirty
        assert_eq!(result.clean_evicted, 6);
        assert_eq!(result.dirty_remaining, 1);
        assert!(!result.dirty_drained);
        assert!(result.needs_retry);
    }
}
