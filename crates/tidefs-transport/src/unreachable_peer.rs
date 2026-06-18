// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Unreachable peer escalation callback.
//!
//! When transport exhausts session reconnection backoff for a peer,
//! the registered callback is invoked so the membership layer can
//! automatically trigger peer departure.
//!
//! ## Integration
//!
//! The membership layer registers its callback via
//! `Transport::set_unreachable_peer_callback`. When reconnection
//! exhausts for a peer session, transport invokes the callback,
//! bridging bottom-up transport failure to top-down membership departure.
//!
//! This is the complementary direction to epoch-advancement session
//! teardown: transport failure to membership departure (bottom-up) vs.
//! membership epoch advancement to session teardown (top-down).

use std::sync::Arc;

pub use tidefs_membership_types::UnreachablePeerCallback;

/// Type alias for the registered callback slot.
pub type UnreachablePeerCallbackRef = Option<Arc<dyn UnreachablePeerCallback>>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /// Mock callback that records invocations.
    struct MockCallback {
        invocations: AtomicU64,
        last_peer: AtomicU64,
    }

    impl MockCallback {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                invocations: AtomicU64::new(0),
                last_peer: AtomicU64::new(0),
            })
        }

        fn count(&self) -> u64 {
            self.invocations.load(Ordering::Relaxed)
        }

        fn last_peer(&self) -> u64 {
            self.last_peer.load(Ordering::Relaxed)
        }
    }

    impl UnreachablePeerCallback for MockCallback {
        fn on_peer_unreachable(&self, peer_id: u64) {
            self.invocations.fetch_add(1, Ordering::Relaxed);
            self.last_peer.store(peer_id, Ordering::Relaxed);
        }
    }

    #[test]
    fn mock_callback_invoked_with_correct_peer_id() {
        let cb = MockCallback::new();
        cb.on_peer_unreachable(42);
        assert_eq!(cb.count(), 1);
        assert_eq!(cb.last_peer(), 42);
    }

    #[test]
    fn mock_callback_multiple_invocations() {
        let cb = MockCallback::new();
        cb.on_peer_unreachable(1);
        cb.on_peer_unreachable(2);
        cb.on_peer_unreachable(3);
        assert_eq!(cb.count(), 3);
        assert_eq!(cb.last_peer(), 3);
    }

    #[test]
    fn callback_ref_none_is_safe() {
        let ref_: UnreachablePeerCallbackRef = None;
        assert!(ref_.is_none());
    }

    #[test]
    fn callback_ref_some_stores_arc() {
        let cb = MockCallback::new();
        let ref_: UnreachablePeerCallbackRef = Some(cb.clone());
        assert!(ref_.is_some());
        cb.on_peer_unreachable(99);
        assert_eq!(cb.count(), 1);
    }

    #[test]
    fn callback_thread_safe() {
        let cb = MockCallback::new();
        let cb2 = cb.clone();
        std::thread::spawn(move || {
            cb2.on_peer_unreachable(100);
        })
        .join()
        .unwrap();
        assert_eq!(cb.count(), 1);
        assert_eq!(cb.last_peer(), 100);
    }

    #[test]
    fn callback_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MockCallback>();
    }
}
