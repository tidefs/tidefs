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

use std::fmt;
use std::sync::{Arc, Mutex};

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
}
