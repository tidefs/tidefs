//! FUSE interrupt abort registry.
//!
//! Provides AbortHandle (a shared cancellation signal) and AbortRegistry
//! (a map keyed by FUSE `unique` request IDs) so blocking filesystem
//! operations can be cleanly aborted when the kernel delivers
//! FUSE_INTERRUPT.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// A lightweight cancellation token for a single in-flight FUSE request.
///
/// Blocking operations poll [`AbortHandle::is_aborted`] and return
/// `EINTR` when the handle has been signalled.
#[derive(Clone, Debug)]
pub struct AbortHandle {
    flag: Arc<AtomicBool>,
}

impl AbortHandle {
    /// Create a new, un-signalled handle.
    pub(crate) fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Return `true` when the kernel has requested cancellation.
    #[inline]
    pub fn is_aborted(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    /// Signal the handle (called by the interrupt path).
    pub(crate) fn signal(&self) {
        self.flag.store(true, Ordering::Release);
    }
}

/// Thread-safe registry mapping FUSE `unique` request IDs to
/// in-flight `AbortHandle`s.
///
/// The session dispatch loop registers a handle before entering a
/// blocking operation and removes it on completion.  The INTERRUPT
/// handler looks up the target unique and signals the handle.
#[derive(Debug, Default)]
pub(crate) struct AbortRegistry {
    inner: Mutex<HashMap<u64, AbortHandle>>,
}

impl AbortRegistry {
    /// Register a new abort handle for `unique`.
    ///
    /// Returns a clone suitable for passing to the blocking operation.
    /// If a handle already exists for this `unique` the old one is
    /// silently replaced (handles for completed requests that raced
    /// with an interrupt).
    pub(crate) fn register(&self, unique: u64) -> AbortHandle {
        let handle = AbortHandle::new();
        self.inner
            .lock()
            .expect("AbortRegistry poisoned")
            .insert(unique, handle.clone());
        handle
    }

    /// Signal the abort handle for `unique` and remove it.
    ///
    /// Returns `true` when a handle existed and was signalled.
    pub(crate) fn signal(&self, unique: u64) -> bool {
        let mut map = self.inner.lock().expect("AbortRegistry poisoned");
        if let Some(handle) = map.remove(&unique) {
            handle.signal();
            true
        } else {
            false
        }
    }

    /// Remove the abort handle for `unique` without signalling it.
    ///
    /// Called when a blocking operation completes normally.
    pub(crate) fn remove(&self, unique: u64) {
        self.inner
            .lock()
            .expect("AbortRegistry poisoned")
            .remove(&unique);
    }

    /// Number of registered handles (for tests).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().expect("AbortRegistry poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn handle_not_signalled_initially() {
        let h = AbortHandle::new();
        assert!(!h.is_aborted());
    }

    #[test]
    fn handle_signal_and_check() {
        let h = AbortHandle::new();
        h.signal();
        assert!(h.is_aborted());
    }

    #[test]
    fn handle_clone_shares_state() {
        let h1 = AbortHandle::new();
        let h2 = h1.clone();
        h1.signal();
        assert!(h2.is_aborted());
    }

    #[test]
    fn registry_register_and_signal() {
        let reg = AbortRegistry::default();
        let h = reg.register(42);
        assert!(!h.is_aborted());
        assert_eq!(reg.len(), 1);

        let found = reg.signal(42);
        assert!(found);
        assert!(h.is_aborted());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn registry_signal_missing_returns_false() {
        let reg = AbortRegistry::default();
        assert!(!reg.signal(999));
    }

    #[test]
    fn registry_remove_cleans_up() {
        let reg = AbortRegistry::default();
        let _h = reg.register(7);
        assert_eq!(reg.len(), 1);
        reg.remove(7);
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn registry_reregister_replaces() {
        let reg = AbortRegistry::default();
        let h1 = reg.register(1);
        let h2 = reg.register(1);
        assert_eq!(reg.len(), 1);
        // h2 is the new active handle; signalling via registry should
        // affect h2, not h1.
        reg.signal(1);
        assert!(h2.is_aborted());
        assert!(!h1.is_aborted());
    }

    #[test]
    fn abort_handle_thread_safety() {
        let h = AbortHandle::new();
        let h2 = h.clone();
        let t = thread::spawn(move || {
            h2.signal();
        });
        t.join().unwrap();
        assert!(h.is_aborted());
    }

    #[test]
    fn abort_registry_concurrent_ops() {
        let reg = Arc::new(AbortRegistry::default());
        let reg2 = Arc::clone(&reg);
        let h = reg.register(100);

        let t = thread::spawn(move || {
            reg2.signal(100);
        });
        t.join().unwrap();
        assert!(h.is_aborted());
    }
}
