// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Cross-session send scheduling with weighted fair queueing (WFQ)
//! across active peer sessions.
//!
//! ## Design
//!
//! When the transport runtime holds concurrent sessions to multiple peers,
//! each session's per-session [`SendPipeline`](super::outbound_send::SendPipeline)
//! operates independently. Without cross-session coordination, a bulk data
//! transfer to one peer can saturate the local outbound path and starve
//! membership-control or replication traffic to other peers.
//!
//! [`CrossSessionScheduler`] sits above per-session send pipelines and uses
//! deficit round-robin (a WFQ approximation) to fairly interleave send
//! opportunities across sessions. Each registered session is assigned a
//! configurable weight; the scheduler tracks a per-session deficit counter,
//! refills deficits each round in proportion to weight, and picks the
//! session with the largest positive deficit that has pending messages.
//!
//! ## Integration
//!
//! Sessions register on creation via [`register`](CrossSessionScheduler::register)
//! and deregister on teardown via [`deregister`](CrossSessionScheduler::deregister).
//! The scheduler is held as `Arc<CrossSessionScheduler>` by the transport
//! runtime. A background scheduling loop calls
//! [`schedule_next`](CrossSessionScheduler::schedule_next) to pick the next
//! eligible session, then dispatches framed messages from that session's
//! outbound queue (via the per-session [`SendPipelineHandle`]).
//!
//! The per-peer weight map enables asymmetric bandwidth allocation:
//! replication sources can be given higher weight, while backfill targets
//! receive lower weight to avoid competing with client I/O.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;

use tokio::sync::Notify;

use crate::types::SessionId;

// ---------------------------------------------------------------------------
// CrossSessionSchedulerConfig
// ---------------------------------------------------------------------------

/// Configuration for the cross-session WFQ scheduler.
///
/// Weights control the proportional send bandwidth allocated to each
/// session. A session with weight 4 gets (roughly) twice the send
/// opportunities of a session with weight 2 when both have backlog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossSessionSchedulerConfig {
    /// Default weight assigned to sessions without a per-peer override.
    pub default_weight: u32,
    /// Maximum messages to dispatch per session per scheduling round.
    /// Prevents a single heavy session from monopolizing the scheduler
    /// even when its deficit is large.
    pub max_burst: usize,
    /// Optional per-peer weight overrides. When a session registers
    /// with a peer address that has an entry in this map, the override
    /// weight is used instead of `default_weight`.
    pub peer_weights: HashMap<SocketAddr, u32>,
}

impl Default for CrossSessionSchedulerConfig {
    fn default() -> Self {
        Self {
            default_weight: 1,
            max_burst: 8,
            peer_weights: HashMap::new(),
        }
    }
}

impl CrossSessionSchedulerConfig {
    /// Validate the configuration. Returns `Err(…)` on invalid values.
    pub fn validate(&self) -> Result<(), String> {
        if self.default_weight == 0 {
            return Err("default_weight must be > 0".into());
        }
        if self.max_burst == 0 {
            return Err("max_burst must be > 0".into());
        }
        for (addr, &w) in &self.peer_weights {
            if w == 0 {
                return Err(format!(
                    "peer_weights entry for {addr} has weight 0; weights must be > 0"
                ));
            }
        }
        Ok(())
    }

    /// Resolve the weight for a given peer address.
    pub fn weight_for(&self, peer_addr: SocketAddr) -> u32 {
        self.peer_weights
            .get(&peer_addr)
            .copied()
            .unwrap_or(self.default_weight)
    }
}

// ---------------------------------------------------------------------------
// SessionSendEntry
// ---------------------------------------------------------------------------

/// Per-session state tracked by the cross-session scheduler.
#[derive(Clone, Debug)]
pub struct SessionSendEntry {
    /// Transport session identifier.
    pub session_id: SessionId,
    /// Peer socket address for this session.
    pub peer_addr: SocketAddr,
    /// Assigned WFQ weight.
    pub weight: u32,
    /// Deficit counter for deficit round-robin.
    pub deficit: i64,
    /// Instant when this session was registered.
    pub registered_at: Instant,
    /// Total number of times this session was selected by `schedule_next`.
    pub times_scheduled: u64,
}

// ---------------------------------------------------------------------------
// CrossSessionScheduler
// ---------------------------------------------------------------------------

/// Cross-session weighted fair queueing scheduler.
///
/// Coordinates send opportunities across multiple active peer sessions
/// so that no single session monopolizes the local outbound path.
///
/// ## Lifecycle
///
/// 1. Create with [`new`](Self::new) or [`with_defaults`](Self::with_defaults).
/// 2. Register sessions with [`register`](Self::register) as they are
///    established.
/// 3. Periodically call [`schedule_next`](Self::schedule_next) to pick
///    the next session that should send.
/// 4. Deregister sessions with [`deregister`](Self::deregister) on
///    teardown.
///
/// All methods use `&self` and internal `tokio::sync::Mutex`, so the
/// scheduler can be wrapped in an `Arc` and shared across tasks.
pub struct CrossSessionScheduler {
    inner: tokio::sync::Mutex<SchedulerInner>,
    /// Woken when a session registers (so a sleeping scheduling loop
    /// can re-check for work).
    pub notify: Notify,
}

impl std::fmt::Debug for CrossSessionScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrossSessionScheduler")
            .finish_non_exhaustive()
    }
}

struct SchedulerInner {
    config: CrossSessionSchedulerConfig,
    sessions: HashMap<SessionId, SessionSendEntry>,
    /// Round-robin ordering: sessions are considered in this order.
    round_robin_order: VecDeque<SessionId>,
    /// Total completed scheduling rounds (refill cycles).
    total_rounds: u64,
    /// Total `schedule_next` calls that returned a session.
    total_scheduled: u64,
}

impl CrossSessionScheduler {
    /// Create a new scheduler with the given configuration.
    pub fn new(config: CrossSessionSchedulerConfig) -> Self {
        config
            .validate()
            .expect("CrossSessionSchedulerConfig validation failed");
        Self {
            inner: tokio::sync::Mutex::new(SchedulerInner {
                config,
                sessions: HashMap::new(),
                round_robin_order: VecDeque::new(),
                total_rounds: 0,
                total_scheduled: 0,
            }),
            notify: Notify::new(),
        }
    }

    /// Create a new scheduler with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(CrossSessionSchedulerConfig::default())
    }

    /// Register a session for cross-session scheduling.
    ///
    /// `weight` may be `None` to fall back to the configured default or
    /// per-peer override. Returns `true` if the session was newly
    /// registered, `false` if it was already present (idempotent).
    pub async fn register(
        &self,
        session_id: SessionId,
        peer_addr: SocketAddr,
        weight: Option<u32>,
    ) -> bool {
        let mut inner = self.inner.lock().await;
        if inner.sessions.contains_key(&session_id) {
            return false;
        }
        let resolved_weight = weight.unwrap_or_else(|| inner.config.weight_for(peer_addr));
        let entry = SessionSendEntry {
            session_id,
            peer_addr,
            weight: resolved_weight,
            deficit: 0,
            registered_at: Instant::now(),
            times_scheduled: 0,
        };
        inner.sessions.insert(session_id, entry);
        inner.round_robin_order.push_back(session_id);
        self.notify.notify_one();
        true
    }

    /// Deregister a session from cross-session scheduling.
    ///
    /// Returns the removed [`SessionSendEntry`] if the session was
    /// registered, or `None` if it was not found.
    pub async fn deregister(&self, session_id: SessionId) -> Option<SessionSendEntry> {
        let mut inner = self.inner.lock().await;
        let entry = inner.sessions.remove(&session_id)?;
        inner.round_robin_order.retain(|&sid| sid != session_id);
        Some(entry)
    }

    /// Pick the next session that should send, using deficit round-robin.
    ///
    /// Returns the [`SessionId`] of the selected session, or `None` when
    /// no sessions are registered.
    ///
    /// When all registered sessions have non-positive deficit, deficits
    /// are refilled (each session gets its weight added to deficit) and
    /// a new round begins.
    pub async fn schedule_next(&self) -> Option<SessionId> {
        let mut inner = self.inner.lock().await;
        if inner.sessions.is_empty() {
            return None;
        }

        // Try to find a session with positive deficit.
        if let Some(sid) = Self::pick_eligible(&mut inner) {
            return Some(sid);
        }

        // All deficits drained: refill for a new round.
        inner.total_rounds = inner.total_rounds.wrapping_add(1);
        for entry in inner.sessions.values_mut() {
            entry.deficit = entry.deficit.saturating_add(entry.weight as i64);
        }

        // Try again after refill.
        if let Some(sid) = Self::pick_eligible(&mut inner) {
            return Some(sid);
        }

        // Still nothing (e.g., max_burst exceeded for all sessions or
        // all weights are 0). This shouldn't happen with valid config.
        None
    }

    /// Internal: scan round-robin order for the first session with
    /// positive deficit, decrement its deficit, and return its id.
    fn pick_eligible(inner: &mut SchedulerInner) -> Option<SessionId> {
        let len = inner.round_robin_order.len();
        if len == 0 {
            return None;
        }
        for _ in 0..len {
            let sid = inner.round_robin_order.pop_front().unwrap();
            if let Some(entry) = inner.sessions.get_mut(&sid) {
                if entry.deficit > 0 {
                    entry.deficit -= 1;
                    entry.times_scheduled = entry.times_scheduled.wrapping_add(1);
                    inner.total_scheduled = inner.total_scheduled.wrapping_add(1);
                    // Re-queue at the back for next round.
                    inner.round_robin_order.push_back(sid);
                    return Some(sid);
                }
            }
            // Session still registered but no deficit; re-queue for next round.
            inner.round_robin_order.push_back(sid);
        }
        None
    }

    // ------------------------------------------------------------------
    // Introspection
    // ------------------------------------------------------------------

    /// Number of currently registered sessions.
    pub async fn session_count(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.sessions.len()
    }

    /// Whether no sessions are registered.
    pub async fn is_empty(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.sessions.is_empty()
    }

    /// Get a snapshot of all registered session entries.
    pub async fn session_entries(&self) -> Vec<SessionSendEntry> {
        let inner = self.inner.lock().await;
        inner.sessions.values().cloned().collect()
    }

    /// Get the entry for a specific session, if registered.
    pub async fn session_entry(&self, session_id: SessionId) -> Option<SessionSendEntry> {
        let inner = self.inner.lock().await;
        inner.sessions.get(&session_id).cloned()
    }

    /// Total scheduling rounds completed (number of deficit refill cycles).
    pub async fn total_rounds(&self) -> u64 {
        let inner = self.inner.lock().await;
        inner.total_rounds
    }

    /// Total `schedule_next` calls that returned a session.
    pub async fn total_scheduled(&self) -> u64 {
        let inner = self.inner.lock().await;
        inner.total_scheduled
    }

    /// The scheduler configuration (read-only snapshot).
    pub async fn config(&self) -> CrossSessionSchedulerConfig {
        let inner = self.inner.lock().await;
        inner.config.clone()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    fn test_session_id(id: u64) -> SessionId {
        SessionId(id)
    }

    // -- Config validation --

    #[test]
    fn config_default_is_valid() {
        let cfg = CrossSessionSchedulerConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_zero_default_weight_rejected() {
        let cfg = CrossSessionSchedulerConfig {
            default_weight: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_zero_max_burst_rejected() {
        let cfg = CrossSessionSchedulerConfig {
            max_burst: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_zero_peer_weight_rejected() {
        let mut cfg = CrossSessionSchedulerConfig::default();
        cfg.peer_weights.insert(test_addr(1), 0);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_weight_for_falls_back_to_default() {
        let cfg = CrossSessionSchedulerConfig::default();
        assert_eq!(cfg.weight_for(test_addr(9999)), cfg.default_weight);
    }

    #[test]
    fn config_weight_for_uses_override() {
        let mut cfg = CrossSessionSchedulerConfig::default();
        cfg.peer_weights.insert(test_addr(10), 7);
        assert_eq!(cfg.weight_for(test_addr(10)), 7);
    }

    // -- Registration / deregistration --

    #[tokio::test]
    async fn empty_scheduler_returns_none() {
        let s = CrossSessionScheduler::with_defaults();
        assert!(s.is_empty().await);
        assert_eq!(s.session_count().await, 0);
        assert!(s.schedule_next().await.is_none());
    }

    #[tokio::test]
    async fn register_and_deregister_session() {
        let s = CrossSessionScheduler::with_defaults();
        let sid = test_session_id(1);
        let addr = test_addr(9001);

        assert!(s.register(sid, addr, None).await);
        assert_eq!(s.session_count().await, 1);

        let entry = s.session_entry(sid).await.unwrap();
        assert_eq!(entry.session_id, sid);
        assert_eq!(entry.peer_addr, addr);
        assert_eq!(entry.weight, 1); // default

        let removed = s.deregister(sid).await.unwrap();
        assert_eq!(removed.session_id, sid);
        assert!(s.is_empty().await);
        assert!(s.schedule_next().await.is_none());
    }

    #[tokio::test]
    async fn register_duplicate_is_idempotent() {
        let s = CrossSessionScheduler::with_defaults();
        let sid = test_session_id(42);
        assert!(s.register(sid, test_addr(1), None).await);
        assert!(!s.register(sid, test_addr(1), None).await);
        assert_eq!(s.session_count().await, 1);
    }

    #[tokio::test]
    async fn deregister_nonexistent_returns_none() {
        let s = CrossSessionScheduler::with_defaults();
        assert!(s.deregister(test_session_id(999)).await.is_none());
    }

    #[tokio::test]
    async fn register_with_explicit_weight() {
        let s = CrossSessionScheduler::with_defaults();
        let sid = test_session_id(10);
        s.register(sid, test_addr(1), Some(5)).await;
        let entry = s.session_entry(sid).await.unwrap();
        assert_eq!(entry.weight, 5);
    }

    #[tokio::test]
    async fn register_uses_per_peer_override() {
        let addr = test_addr(7000);
        let mut cfg = CrossSessionSchedulerConfig::default();
        cfg.peer_weights.insert(addr, 9);

        let s = CrossSessionScheduler::new(cfg);
        s.register(test_session_id(1), addr, None).await;
        let entry = s.session_entry(test_session_id(1)).await.unwrap();
        assert_eq!(entry.weight, 9);
    }

    // -- Deficit round-robin fairness --

    #[tokio::test]
    async fn schedule_round_robin_with_equal_weights() {
        let s = CrossSessionScheduler::with_defaults();
        let sid_a = test_session_id(1);
        let sid_b = test_session_id(2);
        let sid_c = test_session_id(3);

        s.register(sid_a, test_addr(1), Some(1)).await;
        s.register(sid_b, test_addr(2), Some(1)).await;
        s.register(sid_c, test_addr(3), Some(1)).await;

        let mut counts: HashMap<SessionId, u64> = HashMap::new();
        for _ in 0..30 {
            let next = s.schedule_next().await.unwrap();
            *counts.entry(next).or_default() += 1;
        }

        assert_eq!(counts.get(&sid_a).copied().unwrap_or(0), 10);
        assert_eq!(counts.get(&sid_b).copied().unwrap_or(0), 10);
        assert_eq!(counts.get(&sid_c).copied().unwrap_or(0), 10);
    }

    #[tokio::test]
    async fn schedule_weighted_fairness() {
        let cfg = CrossSessionSchedulerConfig {
            default_weight: 1,
            ..Default::default()
        };
        let s = CrossSessionScheduler::new(cfg);

        let sid_light = test_session_id(1);
        let sid_heavy = test_session_id(2);

        s.register(sid_light, test_addr(1), Some(1)).await;
        s.register(sid_heavy, test_addr(2), Some(4)).await;

        let mut counts: HashMap<SessionId, u64> = HashMap::new();
        for _ in 0..50 {
            let next = s.schedule_next().await.unwrap();
            *counts.entry(next).or_default() += 1;
        }

        let light = counts.get(&sid_light).copied().unwrap_or(0);
        let heavy = counts.get(&sid_heavy).copied().unwrap_or(0);

        // With weights 1:4, heavy should get ~4x more.
        assert!(heavy > light, "heavy={heavy} should exceed light={light}");
        assert!(
            heavy >= 2 * light,
            "heavy={heavy} should be at least 2x light={light}"
        );
    }

    #[tokio::test]
    async fn schedule_after_deregister() {
        let s = CrossSessionScheduler::with_defaults();
        s.register(test_session_id(1), test_addr(1), Some(1)).await;
        s.register(test_session_id(2), test_addr(2), Some(1)).await;

        for _ in 0..4 {
            s.schedule_next().await;
        }

        s.deregister(test_session_id(1)).await;

        for _ in 0..10 {
            let next = s.schedule_next().await.unwrap();
            assert_eq!(next, test_session_id(2));
        }
    }

    #[tokio::test]
    async fn schedule_empty_after_deregister_all() {
        let s = CrossSessionScheduler::with_defaults();
        s.register(test_session_id(1), test_addr(1), Some(1)).await;
        s.register(test_session_id(2), test_addr(2), Some(1)).await;
        s.deregister(test_session_id(1)).await;
        s.deregister(test_session_id(2)).await;
        assert!(s.schedule_next().await.is_none());
    }

    // -- Notification --

    #[tokio::test]
    async fn notify_wakes_on_register() {
        let s = std::sync::Arc::new(CrossSessionScheduler::with_defaults());
        let s_clone = std::sync::Arc::clone(&s);

        let handle = tokio::spawn(async move {
            tokio::select! {
                _ = s_clone.notify.notified() => true,
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => false,
            }
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        s.register(test_session_id(1), test_addr(1), None).await;

        let got_notify = handle.await.unwrap();
        assert!(got_notify, "notify should fire on register");
    }

    // -- Introspection counters --

    #[tokio::test]
    async fn total_rounds_and_scheduled_counters() {
        let s = CrossSessionScheduler::with_defaults();
        s.register(test_session_id(1), test_addr(1), Some(1)).await;

        assert_eq!(s.total_rounds().await, 0);
        assert_eq!(s.total_scheduled().await, 0);

        s.schedule_next().await;
        assert_eq!(s.total_rounds().await, 1);
        assert_eq!(s.total_scheduled().await, 1);

        s.schedule_next().await;
        assert_eq!(s.total_rounds().await, 2);
        assert_eq!(s.total_scheduled().await, 2);
    }

    #[tokio::test]
    async fn session_entry_tracks_times_scheduled() {
        let s = CrossSessionScheduler::with_defaults();
        s.register(test_session_id(1), test_addr(1), Some(1)).await;

        s.schedule_next().await;
        let entry = s.session_entry(test_session_id(1)).await.unwrap();
        assert_eq!(entry.times_scheduled, 1);

        s.schedule_next().await;
        let entry = s.session_entry(test_session_id(1)).await.unwrap();
        assert_eq!(entry.times_scheduled, 2);
    }

    // -- config() snapshot --

    #[tokio::test]
    async fn config_snapshot_matches() {
        let cfg = CrossSessionSchedulerConfig {
            default_weight: 3,
            ..Default::default()
        };
        let s = CrossSessionScheduler::new(cfg.clone());
        let snap = s.config().await;
        assert_eq!(snap.default_weight, 3);
        assert_eq!(snap, cfg);
    }

    // -- notify does not fire on deregister or schedule_next --

    #[tokio::test]
    async fn notify_only_fires_on_register() {
        let s = std::sync::Arc::new(CrossSessionScheduler::with_defaults());
        let s_clone = std::sync::Arc::clone(&s);

        s.register(test_session_id(1), test_addr(1), None).await;

        // Drain initial notify.
        s_clone.notify.notified().await;

        let handle = tokio::spawn(async move {
            tokio::select! {
                _ = s_clone.notify.notified() => true,
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(200)) => false,
            }
        });

        s.deregister(test_session_id(1)).await;

        let got_notify = handle.await.unwrap();
        assert!(!got_notify, "notify should not fire on deregister");
    }

    // -- Cross-session interleaving stress test --

    #[tokio::test]
    async fn interleaving_with_weighted_sessions() {
        let s = CrossSessionScheduler::with_defaults();
        s.register(test_session_id(10), test_addr(10), Some(1))
            .await;
        s.register(test_session_id(20), test_addr(20), Some(1))
            .await;
        s.register(test_session_id(30), test_addr(30), Some(4))
            .await;

        let mut schedule_seq: Vec<u64> = Vec::new();
        for _ in 0..60 {
            schedule_seq.push(s.schedule_next().await.unwrap().0);
        }

        let a_count = schedule_seq.iter().filter(|&&id| id == 10).count();
        let b_count = schedule_seq.iter().filter(|&&id| id == 20).count();
        let c_count = schedule_seq.iter().filter(|&&id| id == 30).count();

        assert!(a_count > 0, "session A should be scheduled");
        assert!(b_count > 0, "session B should be scheduled");
        assert!(c_count > 0, "session C should be scheduled");

        assert!(c_count > a_count, "C={c_count} should exceed A={a_count}");
        assert!(c_count > b_count, "C={c_count} should exceed B={b_count}");

        let diff = (a_count as i64 - b_count as i64).abs();
        assert!(diff <= 3, "A and B should be roughly equal (diff={diff})");
    }
}
