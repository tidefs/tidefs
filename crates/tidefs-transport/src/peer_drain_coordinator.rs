//! Peer drain coordinator: aggregates per-session drain completion across
//! all sessions to a single peer and produces a single awaitable signal
//! consumable by the membership departure protocol.
//!
//! ## Purpose
//!
//! The membership departure protocol (#6211) needs a proactive aggregate
//! signal — "all sessions to peer X are fully drained" — before it can
//! safely finalize the peer's departure. Per-session drain primitives
//! (`SessionDrainHandle`, `drain_session_gracefully`) operate at the
//! individual session level. This module aggregates them into a
//! peer-level completion signal.
//!
//! ## Integration
//!
//! - `PeerDrainCoordinator::begin_peer_drain()` takes a set of `SessionId`s
//!   and returns a `(PeerDrainHandle, PeerDrainDriver)` pair.
//! - The caller initiates per-session drain on each session and calls
//!   `PeerDrainDriver::complete_session()` as each session finishes.
//! - The holder of `PeerDrainHandle` awaits completion via `.wait()`.
//!
//! ## Relationship to existing drain infrastructure
//!
//! - [`drain_protocol`](crate::drain_protocol): connection-level
//!   `DrainInitiator`/`DrainResponder` wire handshake.
//! - [`session_drain`](crate::session_drain): per-session token-based
//!   completion tracking (`SessionDrainHandle`).
//! - `peer_drain_coordinator`: peer-level aggregation over all sessions
//!   to a given peer.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tidefs_membership_epoch::MemberId;
use tokio::sync::Notify;

use crate::types::SessionId;

// ---------------------------------------------------------------------------
// PeerDrainOutcome
// ---------------------------------------------------------------------------

/// Outcome of draining all sessions to a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerDrainOutcome {
    /// All sessions drained successfully within the deadline.
    AllDrained {
        /// Number of sessions that were drained.
        session_count: usize,
    },
    /// Some sessions drained, while others exceeded the deadline.
    PartialDrain {
        /// Number of sessions that drained successfully.
        drained: usize,
        /// Sessions that did not drain within the deadline.
        remaining: Vec<SessionId>,
    },
    /// No active sessions existed for this peer.
    NoSessions,
}

// ---------------------------------------------------------------------------
// PeerDrainError
// ---------------------------------------------------------------------------

/// Errors returned by peer drain coordination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerDrainError {
    /// The drain deadline elapsed before all sessions completed.
    DeadlineExceeded,
    /// The specified peer was not found.
    PeerNotFound,
    /// A drain is already in progress for this peer.
    DrainAlreadyInProgress,
}

// ---------------------------------------------------------------------------
// PeerDrainInner
// ---------------------------------------------------------------------------

/// Shared state between [`PeerDrainHandle`] and [`PeerDrainDriver`].
struct PeerDrainInner {
    /// Total number of sessions being drained.
    total_sessions: usize,
    /// How many sessions have completed.
    completed: AtomicUsize,
    /// Session IDs still outstanding (not yet marked complete).
    remaining: Mutex<Vec<SessionId>>,
    /// Woken each time a session completes.
    notify: Notify,
    /// Absolute deadline for the drain.
    deadline: Instant,
}

// ---------------------------------------------------------------------------
// PeerDrainHandle
// ---------------------------------------------------------------------------

/// A handle that resolves when all sessions to a peer are drained.
///
/// Created by [`PeerDrainCoordinator::begin_peer_drain`]. The holder
/// awaits the handle to learn the drain outcome. Internally, the handle
/// polls the completion counter and deadline.
pub struct PeerDrainHandle {
    inner: Arc<PeerDrainInner>,
}

impl PeerDrainHandle {
    /// Wait for the peer drain to reach a terminal outcome.
    ///
    /// Returns [`PeerDrainOutcome::AllDrained`] when every session has
    /// been drained, [`PeerDrainOutcome::PartialDrain`] when the
    /// deadline expires with sessions still outstanding, or
    /// [`PeerDrainOutcome::NoSessions`] when no sessions were registered.
    pub async fn wait(self) -> PeerDrainOutcome {
        loop {
            let completed = self.inner.completed.load(Ordering::SeqCst);
            let total = self.inner.total_sessions;

            if total == 0 {
                return PeerDrainOutcome::NoSessions;
            }

            if completed >= total {
                return PeerDrainOutcome::AllDrained {
                    session_count: total,
                };
            }

            if Instant::now() >= self.inner.deadline {
                let remaining = self.inner.remaining.lock().unwrap().clone();
                return PeerDrainOutcome::PartialDrain {
                    drained: completed,
                    remaining,
                };
            }

            // Wait for a notification; the driver signals on each completion.
            self.inner.notify.notified().await;
        }
    }
}

// ---------------------------------------------------------------------------
// PeerDrainDriver
// ---------------------------------------------------------------------------

/// Driver-side interface for signaling per-session drain completions.
///
/// After calling [`PeerDrainCoordinator::begin_peer_drain`], the caller
/// uses `PeerDrainDriver` to mark each session as drained. Each call to
/// [`complete_session`](Self::complete_session) wakes the
/// [`PeerDrainHandle`].
pub struct PeerDrainDriver {
    inner: Arc<PeerDrainInner>,
}

impl PeerDrainDriver {
    /// Mark a session as fully drained.
    ///
    /// Removes the session from the outstanding set and notifies the
    /// waiting [`PeerDrainHandle`].
    pub fn complete_session(&self, session_id: SessionId) {
        let removed = {
            let mut remaining = self.inner.remaining.lock().unwrap();
            let before = remaining.len();
            remaining.retain(|s| *s != session_id);
            remaining.len() != before
        };

        if removed {
            self.inner.completed.fetch_add(1, Ordering::SeqCst);
            self.inner.notify.notify_one();
        }
    }
}

// ---------------------------------------------------------------------------
// PeerDrainCoordinator
// ---------------------------------------------------------------------------

/// Coordinates draining all sessions to a peer.
///
/// Maintains a registry of active peer drains to prevent double-drain.
/// For each peer, at most one drain may be in progress at a time.
pub struct PeerDrainCoordinator {
    active_drains: Mutex<HashMap<MemberId, Arc<PeerDrainInner>>>,
}

impl PeerDrainCoordinator {
    /// Create a new, empty coordinator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            active_drains: Mutex::new(HashMap::new()),
        }
    }

    /// Begin draining all sessions to a peer.
    ///
    /// Returns a [`PeerDrainHandle`] for awaiting the outcome and a
    /// [`PeerDrainDriver`] for signaling per-session completions.
    /// The caller should initiate per-session drain for each `session_id`
    /// and call [`PeerDrainDriver::complete_session`] as each finishes.
    ///
    /// When `session_ids` is empty, returns immediately with
    /// [`PeerDrainOutcome::NoSessions`] without registering an active drain.
    ///
    /// # Errors
    ///
    /// Returns [`PeerDrainError::DrainAlreadyInProgress`] if a drain is
    /// already active for this peer.
    pub fn begin_peer_drain(
        &self,
        member_id: MemberId,
        session_ids: &[SessionId],
        deadline: Duration,
    ) -> Result<(PeerDrainHandle, PeerDrainDriver), PeerDrainError> {
        let mut drains = self.active_drains.lock().unwrap();

        if drains.contains_key(&member_id) {
            return Err(PeerDrainError::DrainAlreadyInProgress);
        }

        if session_ids.is_empty() {
            // No sessions: return handle that resolves to NoSessions.
            // Do not register in active_drains — nothing is in progress.
            drop(drains);
            let inner = Arc::new(PeerDrainInner {
                total_sessions: 0,
                completed: AtomicUsize::new(0),
                remaining: Mutex::new(Vec::new()),
                notify: Notify::new(),
                deadline: Instant::now(),
            });
            return Ok((
                PeerDrainHandle {
                    inner: Arc::clone(&inner),
                },
                PeerDrainDriver { inner },
            ));
        }

        let inner = Arc::new(PeerDrainInner {
            total_sessions: session_ids.len(),
            completed: AtomicUsize::new(0),
            remaining: Mutex::new(session_ids.to_vec()),
            notify: Notify::new(),
            deadline: Instant::now() + deadline,
        });

        drains.insert(member_id, Arc::clone(&inner));

        Ok((
            PeerDrainHandle {
                inner: Arc::clone(&inner),
            },
            PeerDrainDriver { inner },
        ))
    }

    /// Remove a completed drain from the active set.
    ///
    /// Call after the drain handle resolves to allow a subsequent drain
    /// for the same peer.
    pub fn finish_peer_drain(&self, member_id: MemberId) {
        let mut drains = self.active_drains.lock().unwrap();
        drains.remove(&member_id);
    }

    /// Return whether a drain is currently in progress for the given peer.
    #[must_use]
    pub fn is_draining(&self, member_id: MemberId) -> bool {
        let drains = self.active_drains.lock().unwrap();
        drains.contains_key(&member_id)
    }
}

impl Default for PeerDrainCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(id: u64) -> SessionId {
        SessionId::new(id)
    }

    fn member(id: u64) -> MemberId {
        MemberId::new(id)
    }

    // ------------------------------------------------------------------
    // No sessions
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn no_sessions_immediate() {
        let coord = PeerDrainCoordinator::new();
        let (handle, _driver) = coord
            .begin_peer_drain(member(1), &[], Duration::from_secs(5))
            .unwrap();

        let outcome = handle.wait().await;
        assert_eq!(outcome, PeerDrainOutcome::NoSessions);
        assert!(!coord.is_draining(member(1)));
    }

    // ------------------------------------------------------------------
    // Single session
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn single_session_all_drained() {
        let coord = PeerDrainCoordinator::new();
        let (handle, driver) = coord
            .begin_peer_drain(member(1), &[sid(10)], Duration::from_secs(5))
            .unwrap();

        assert!(coord.is_draining(member(1)));

        driver.complete_session(sid(10));
        let outcome = handle.wait().await;

        assert_eq!(outcome, PeerDrainOutcome::AllDrained { session_count: 1 });
    }

    // ------------------------------------------------------------------
    // Multiple sessions
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn multiple_sessions_all_drained() {
        let coord = PeerDrainCoordinator::new();
        let (handle, driver) = coord
            .begin_peer_drain(
                member(2),
                &[sid(100), sid(101), sid(102)],
                Duration::from_secs(5),
            )
            .unwrap();

        // Complete in reverse order; order is irrelevant.
        driver.complete_session(sid(102));
        driver.complete_session(sid(100));
        driver.complete_session(sid(101));

        let outcome = handle.wait().await;
        assert_eq!(outcome, PeerDrainOutcome::AllDrained { session_count: 3 });
    }

    // ------------------------------------------------------------------
    // Deadline exceeded → PartialDrain
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn deadline_exceeded_partial_drain() {
        let coord = PeerDrainCoordinator::new();
        let (handle, driver) = coord
            .begin_peer_drain(
                member(3),
                &[sid(200), sid(201), sid(202)],
                Duration::from_millis(1),
            )
            .unwrap();

        // Complete only one session.
        driver.complete_session(sid(200));

        // Give the deadline time to pass.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let outcome = handle.wait().await;
        assert!(matches!(outcome, PeerDrainOutcome::PartialDrain { .. }));
        if let PeerDrainOutcome::PartialDrain { drained, remaining } = outcome {
            assert_eq!(drained, 1);
            assert_eq!(remaining.len(), 2);
            assert!(remaining.contains(&sid(201)));
            assert!(remaining.contains(&sid(202)));
        }
    }

    // ------------------------------------------------------------------
    // Drain already in progress
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn drain_already_in_progress() {
        let coord = PeerDrainCoordinator::new();

        let (_handle1, _driver1) = coord
            .begin_peer_drain(member(4), &[sid(300)], Duration::from_secs(5))
            .unwrap();

        let result = coord.begin_peer_drain(member(4), &[sid(301)], Duration::from_secs(5));
        assert!(matches!(
            result,
            Err(PeerDrainError::DrainAlreadyInProgress)
        ));
    }

    // ------------------------------------------------------------------
    // finish_peer_drain allows re-drain
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn finish_allows_second_drain() {
        let coord = PeerDrainCoordinator::new();

        let (handle1, driver1) = coord
            .begin_peer_drain(member(5), &[sid(400)], Duration::from_secs(5))
            .unwrap();
        driver1.complete_session(sid(400));
        let _ = handle1.wait().await;

        coord.finish_peer_drain(member(5));

        // Second drain for the same peer should now succeed.
        let (handle2, driver2) = coord
            .begin_peer_drain(member(5), &[sid(401)], Duration::from_secs(5))
            .unwrap();
        driver2.complete_session(sid(401));
        let outcome = handle2.wait().await;
        assert_eq!(outcome, PeerDrainOutcome::AllDrained { session_count: 1 });
    }

    // ------------------------------------------------------------------
    // is_draining idempotency
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn is_draining_reflects_state() {
        let coord = PeerDrainCoordinator::new();
        assert!(!coord.is_draining(member(6)));

        let (handle, driver) = coord
            .begin_peer_drain(member(6), &[sid(500)], Duration::from_secs(5))
            .unwrap();
        assert!(coord.is_draining(member(6)));

        driver.complete_session(sid(500));
        let _ = handle.wait().await;
        // Still marked active until finish_peer_drain is called.
        assert!(coord.is_draining(member(6)));

        coord.finish_peer_drain(member(6));
        assert!(!coord.is_draining(member(6)));
    }

    // ------------------------------------------------------------------
    // Large session count
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn large_session_count_all_drained() {
        let coord = PeerDrainCoordinator::new();
        let ids: Vec<SessionId> = (0..64).map(SessionId::new).collect();

        let (handle, driver) = coord
            .begin_peer_drain(member(7), &ids, Duration::from_secs(5))
            .unwrap();

        for &id in &ids {
            driver.complete_session(id);
        }

        let outcome = handle.wait().await;
        assert_eq!(
            outcome,
            PeerDrainOutcome::AllDrained {
                session_count: ids.len()
            }
        );
    }

    // ------------------------------------------------------------------
    // Complete same session twice is safe (idempotent driver)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn complete_same_session_twice() {
        let coord = PeerDrainCoordinator::new();
        let (handle, driver) = coord
            .begin_peer_drain(member(8), &[sid(600), sid(601)], Duration::from_secs(5))
            .unwrap();

        driver.complete_session(sid(600));
        driver.complete_session(sid(600)); // duplicate — safe
        assert_eq!(driver.inner.completed.load(Ordering::SeqCst), 1);
        assert_eq!(driver.inner.remaining.lock().unwrap().len(), 1);

        driver.complete_session(sid(601));

        let outcome = handle.wait().await;
        assert_eq!(outcome, PeerDrainOutcome::AllDrained { session_count: 2 });
    }

    // ------------------------------------------------------------------
    // Multiple concurrent drains for different peers don't interfere
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn independent_peer_drains_dont_interfere() {
        let coord = PeerDrainCoordinator::new();

        let (h1, d1) = coord
            .begin_peer_drain(member(10), &[sid(1)], Duration::from_secs(5))
            .unwrap();
        let (h2, d2) = coord
            .begin_peer_drain(member(20), &[sid(2)], Duration::from_secs(5))
            .unwrap();

        d2.complete_session(sid(2));
        d1.complete_session(sid(1));

        let o1 = h1.wait().await;
        let o2 = h2.wait().await;

        assert_eq!(o1, PeerDrainOutcome::AllDrained { session_count: 1 });
        assert_eq!(o2, PeerDrainOutcome::AllDrained { session_count: 1 });
    }
}
