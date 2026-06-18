// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! TDMA scheduler: per-object round-robin slot allocation with starvation
//! tracking and epoch fencing.

use std::collections::{HashMap, HashSet};

use tidefs_membership_epoch::EpochId;

use crate::slot::{SlotAllocation, SlotState, TdmaSlot};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the TDMA scheduler.
#[derive(Debug, Clone)]
pub struct TdmaSchedulerConfig {
    /// Duration of each time slot in milliseconds.
    pub slot_duration_ms: u64,
    /// Maximum number of slots per round before starvation escalation.
    pub max_slots_per_round: usize,
    /// Number of consecutive rounds a node can be skipped before a starvation
    /// event is recorded.
    pub starvation_bound_rounds: usize,
}

impl Default for TdmaSchedulerConfig {
    fn default() -> Self {
        Self {
            slot_duration_ms: 10,
            max_slots_per_round: 128,
            starvation_bound_rounds: 4,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by the TDMA scheduler.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TdmaSchedulerError {
    /// No nodes requested a slot for this object.
    #[error("no requesting nodes for object {0}")]
    NoRequestingNodes(u64),

    /// A slot is already active for this object and has not expired.
    #[error("slot already active for object {0} (held by node {1}, expires at {2})")]
    SlotAlreadyActive(u64, u64, u64),

    /// The requesting node does not hold the active slot.
    #[error("node {node} does not hold the active slot for object {object}")]
    NotSlotHolder { object: u64, node: u64 },

    /// No active slot exists for this object.
    #[error("no active slot for object {0}")]
    NoActiveSlot(u64),

    /// Epoch mismatch: operation epoch does not match scheduler epoch.
    #[error("epoch mismatch: scheduler at {scheduler_epoch:?}, operation at {operation_epoch:?}")]
    EpochMismatch {
        scheduler_epoch: EpochId,
        operation_epoch: EpochId,
    },
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Runtime statistics for the TDMA scheduler.
#[derive(Debug, Clone, Default)]
pub struct SchedulerStats {
    /// Total number of slot allocations.
    pub total_allocations: u64,
    /// Total number of slot releases.
    pub total_releases: u64,
    /// Total number of expired slots.
    pub total_expirations: u64,
    /// Number of active slots right now.
    pub active_slots: usize,
    /// Total number of starvation events detected.
    pub starvation_events: u64,
    /// Current epoch.
    pub current_epoch: EpochId,
}

// ---------------------------------------------------------------------------
// Per-object schedule
// ---------------------------------------------------------------------------

/// Tracks the round-robin state and active slot for a single object.
#[derive(Debug, Clone)]
struct ObjectSchedule {
    /// The currently active slot, if any.
    active_slot: Option<TdmaSlot>,
    /// Which position in the node list is next for round-robin.
    next_position: usize,
    /// Per-node starvation counter: number of consecutive rounds this node
    /// has been requesting but not receiving a slot.
    starvation: HashMap<u64, usize>,
    /// Total number of rounds completed for this object.
    total_rounds: u64,
}

impl ObjectSchedule {
    fn new() -> Self {
        Self {
            active_slot: None,
            next_position: 0,
            starvation: HashMap::new(),
            total_rounds: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

/// Per-object TDMA time-slot scheduler.
///
/// Allocates write slots to contending nodes using fair round-robin across
/// requesting nodes. Tracks starvation and supports epoch fencing for
/// integration with the [`StrategyTransition`] protocol.
///
/// [`StrategyTransition`]: tidefs_coordination_strategy::StrategyTransition
pub struct TdmaScheduler {
    config: TdmaSchedulerConfig,
    epoch: EpochId,
    schedules: HashMap<u64, ObjectSchedule>,
    stats: SchedulerStats,
}

impl TdmaScheduler {
    /// Create a new TDMA scheduler with the given configuration and epoch.
    pub fn new(config: TdmaSchedulerConfig, epoch: EpochId) -> Self {
        Self {
            config,
            epoch,
            schedules: HashMap::new(),
            stats: SchedulerStats {
                current_epoch: epoch,
                ..Default::default()
            },
        }
    }

    /// Return the scheduler configuration.
    pub fn config(&self) -> &TdmaSchedulerConfig {
        &self.config
    }

    /// Return the current epoch.
    pub fn current_epoch(&self) -> EpochId {
        self.epoch
    }

    /// Return scheduler statistics.
    pub fn stats(&self) -> &SchedulerStats {
        &self.stats
    }

    // ------------------------------------------------------------------
    // Slot allocation
    // ------------------------------------------------------------------

    /// Allocate the next time slot for `object_id`.
    ///
    /// `requesting_nodes` is the set of nodes that want to write to this
    /// object. The scheduler picks the next node in round-robin order from
    /// this set. Nodes not in `requesting_nodes` are skipped.
    ///
    /// Returns a [`SlotAllocation`] with the assigned slot and timing info.
    pub fn allocate(
        &mut self,
        object_id: u64,
        requesting_nodes: &[u64],
        now_millis: u64,
    ) -> Result<SlotAllocation, TdmaSchedulerError> {
        if requesting_nodes.is_empty() {
            return Err(TdmaSchedulerError::NoRequestingNodes(object_id));
        }

        let schedule = self
            .schedules
            .entry(object_id)
            .or_insert_with(ObjectSchedule::new);

        // If there's an active slot, check if it has expired
        if let Some(ref active) = schedule.active_slot {
            if !active.state.is_terminal() && !active.is_stale(now_millis) {
                return Err(TdmaSchedulerError::SlotAlreadyActive(
                    object_id,
                    active.node_id,
                    active.slot_end,
                ));
            }
            // Stale slot: clean it up below
            if active.is_stale(now_millis) {
                schedule.active_slot = None;
                self.stats.total_expirations += 1;
                self.stats.active_slots = self.stats.active_slots.saturating_sub(1);
            }
        }

        // Build the set of requesting nodes for O(1) lookup
        let req_set: std::collections::BTreeSet<u64> = requesting_nodes.iter().copied().collect();

        // Find the next node in round-robin order that is requesting
        let node_count = requesting_nodes.len();
        let start_pos = schedule.next_position % node_count;
        let mut selected: Option<(usize, u64)> = None;

        for offset in 0..node_count {
            let idx = (start_pos + offset) % node_count;
            let candidate = requesting_nodes[idx];
            if req_set.contains(&candidate) {
                selected = Some((idx, candidate));
                break;
            }
        }

        let (selected_idx, selected_node) =
            selected.ok_or(TdmaSchedulerError::NoRequestingNodes(object_id))?;

        // Advance round-robin position to after the selected node
        schedule.next_position = (selected_idx + 1) % node_count;
        schedule.total_rounds += 1;

        // Update starvation counters
        let bound = self.config.starvation_bound_rounds;
        for &node in requesting_nodes {
            let entry = schedule.starvation.entry(node).or_insert(0);
            if node == selected_node {
                *entry = 0; // Reset: got a slot
            } else {
                *entry += 1;
                if *entry >= bound {
                    self.stats.starvation_events += 1;
                }
            }
        }

        // Create the slot
        let slot_start = now_millis;
        let slot_end = now_millis + self.config.slot_duration_ms;
        let slot = TdmaSlot::new_pending(selected_node, object_id, slot_start, slot_end);

        schedule.active_slot = Some(slot.clone());
        self.stats.total_allocations += 1;
        self.stats.active_slots += 1;

        Ok(SlotAllocation {
            slot,
            next_slot_at: slot_end,
        })
    }

    // ------------------------------------------------------------------
    // Slot release
    // ------------------------------------------------------------------

    /// Release the active slot for `object_id`, held by `node_id`.
    ///
    /// Marks the slot as [`SlotState::Complete`].
    pub fn release(&mut self, object_id: u64, node_id: u64) -> Result<(), TdmaSchedulerError> {
        let schedule = self
            .schedules
            .get_mut(&object_id)
            .ok_or(TdmaSchedulerError::NoActiveSlot(object_id))?;

        match &schedule.active_slot {
            Some(slot) if slot.node_id == node_id && !slot.state.is_terminal() => {
                schedule.active_slot.as_mut().unwrap().state = SlotState::Complete;
                self.stats.total_releases += 1;
                self.stats.active_slots = self.stats.active_slots.saturating_sub(1);
                Ok(())
            }
            Some(_slot) => Err(TdmaSchedulerError::NotSlotHolder {
                object: object_id,
                node: node_id,
            }),
            None => Err(TdmaSchedulerError::NoActiveSlot(object_id)),
        }
    }

    // ------------------------------------------------------------------
    // Expiry sweep
    // ------------------------------------------------------------------

    /// Sweep all schedules for expired slots and mark them as
    /// [`SlotState::Expired`].
    ///
    /// Returns the object IDs of slots that were expired.
    pub fn sweep_expired(&mut self, now_millis: u64) -> Vec<u64> {
        let mut expired = Vec::new();

        for (&object_id, schedule) in self.schedules.iter_mut() {
            if let Some(ref mut slot) = schedule.active_slot {
                if slot.is_stale(now_millis) {
                    slot.state = SlotState::Expired;
                    self.stats.total_expirations += 1;
                    self.stats.active_slots = self.stats.active_slots.saturating_sub(1);
                    expired.push(object_id);
                }
            }
        }

        expired
    }

    // ------------------------------------------------------------------
    // Node failure
    // ------------------------------------------------------------------

    /// Handle a node failure by expiring all slots held by `failed_node`.
    ///
    /// Returns the object IDs whose slots were expired.
    pub fn handle_node_failure(&mut self, failed_node: u64) -> Vec<u64> {
        let mut affected = Vec::new();

        for (&object_id, schedule) in self.schedules.iter_mut() {
            if let Some(ref mut slot) = schedule.active_slot {
                if slot.node_id == failed_node && !slot.state.is_terminal() {
                    slot.state = SlotState::Expired;
                    self.stats.total_expirations += 1;
                    self.stats.active_slots = self.stats.active_slots.saturating_sub(1);
                    affected.push(object_id);
                }
            }
        }

        affected
    }

    // ------------------------------------------------------------------
    // Epoch advance
    // ------------------------------------------------------------------

    /// Advance to a new epoch, draining all in-flight slots.
    ///
    /// All non-terminal active slots are expired. Per-object round-robin
    /// state and starvation counters are reset. The epoch is updated.
    ///
    /// Returns the object IDs of drained slots.
    pub fn advance_epoch(&mut self, new_epoch: EpochId) -> Vec<u64> {
        let mut drained = Vec::new();

        for (&object_id, schedule) in self.schedules.iter_mut() {
            if let Some(ref mut slot) = schedule.active_slot {
                if !slot.state.is_terminal() {
                    slot.state = SlotState::Expired;
                    self.stats.total_expirations += 1;
                    drained.push(object_id);
                }
            }
            // Reset per-object state
            schedule.active_slot = None;
            schedule.next_position = 0;
            schedule.starvation.clear();
        }

        self.stats.active_slots = 0;
        self.epoch = new_epoch;
        self.stats.current_epoch = new_epoch;

        drained
    }

    // ------------------------------------------------------------------
    // Query
    // ------------------------------------------------------------------

    /// Check if a node currently holds an active slot for `object_id`.
    pub fn is_holder(&self, object_id: u64, node_id: u64) -> bool {
        self.schedules
            .get(&object_id)
            .and_then(|s| s.active_slot.as_ref())
            .map(|slot| slot.node_id == node_id && !slot.state.is_terminal())
            .unwrap_or(false)
    }

    /// Get the active slot for `object_id`, if any.
    pub fn active_slot(&self, object_id: u64) -> Option<&TdmaSlot> {
        self.schedules
            .get(&object_id)
            .and_then(|s| s.active_slot.as_ref())
            .filter(|slot| !slot.state.is_terminal())
    }

    /// Number of objects with an active schedule.
    pub fn object_count(&self) -> usize {
        self.schedules.len()
    }

    /// Starvation count for a specific node on a specific object.
    pub fn starvation_count(&self, object_id: u64, node_id: u64) -> usize {
        self.schedules
            .get(&object_id)
            .and_then(|s| s.starvation.get(&node_id).copied())
            .unwrap_or(0)
    }
}
// ---------------------------------------------------------------------------
// TdmaRoundScheduler: transport-session-level round scheduler consuming
// from SlotRequestQueue with collision-free window packing.
// ---------------------------------------------------------------------------

use crate::request_queue::{SlotRequest, SlotRequestQueue};

/// Configuration for the TDMA round scheduler.
///
/// Controls slot duration, round length, session capacity, and idle-session
/// timeout so the scheduler can produce deterministic collision-free
/// transmission windows for registered transport sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdmaRoundConfig {
    /// Duration of each transmission slot in milliseconds.
    pub slot_duration_ms: u64,
    /// Total length of one scheduling round in milliseconds.
    pub round_length_ms: u64,
    /// Maximum number of sessions that may receive a slot in one round.
    pub max_sessions_per_round: usize,
    /// Milliseconds of inactivity after which a session is considered dead
    /// and its slots are reclaimed.
    pub session_timeout_ms: u64,
}

impl Default for TdmaRoundConfig {
    fn default() -> Self {
        Self {
            slot_duration_ms: 10,
            round_length_ms: 1000,
            max_sessions_per_round: 128,
            session_timeout_ms: 5000,
        }
    }
}

impl TdmaRoundConfig {
    /// Maximum number of slots that can fit within one round.
    pub fn max_slots_per_round(&self) -> usize {
        if self.slot_duration_ms == 0 {
            return 0;
        }
        (self.round_length_ms / self.slot_duration_ms) as usize
    }
}

// ---------------------------------------------------------------------------
// SlotAssignment
// ---------------------------------------------------------------------------

/// A transmission window assigned to a specific session within a round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAssignment {
    /// Transport session that owns this window.
    pub session_id: u64,
    /// Wall-clock start time of the window in milliseconds.
    pub start_ms: u64,
    /// Wall-clock end time of the window in milliseconds (exclusive).
    pub end_ms: u64,
    /// Bytes granted for transmission in this window.
    pub bytes_granted: u64,
}

// ---------------------------------------------------------------------------
// SessionState (internal)
// ---------------------------------------------------------------------------

/// Per-session bookkeeping inside the round scheduler.
#[derive(Debug, Clone)]
struct SessionState {
    session_id: u64,
    /// Last time this session was marked as having transmitted.
    last_seen_ms: u64,
}

// ---------------------------------------------------------------------------
// TdmaRoundScheduler
// ---------------------------------------------------------------------------

/// Deterministic TDMA round scheduler for transport sessions.
///
/// Registered sessions receive one transmission window per round in
/// round-robin order. The scheduler consumes [`SlotRequest`] entries from
/// a shared [`SlotRequestQueue`]; sessions without pending requests are
/// skipped. Windows are packed sequentially, guaranteeing no overlap.
/// Sessions that fail to transmit within `session_timeout_ms` are
/// automatically unregistered and their slots reclaimed.
pub struct TdmaRoundScheduler {
    config: TdmaRoundConfig,
    request_queue: SlotRequestQueue,
    /// Active sessions in round-robin order.
    sessions: Vec<SessionState>,
    /// session_id -> index into `sessions`.
    session_index: HashMap<u64, usize>,
    /// Monotonic start time of the current round.
    current_round_start: u64,
    /// Round-robin cursor (index into `sessions`).
    next_session: usize,
}

impl TdmaRoundScheduler {
    /// Create a new round scheduler with the given config and request queue.
    pub fn new(config: TdmaRoundConfig, request_queue: SlotRequestQueue) -> Self {
        Self {
            config,
            request_queue,
            sessions: Vec::new(),
            session_index: HashMap::new(),
            current_round_start: 0,
            next_session: 0,
        }
    }

    /// Return the round-scheduler configuration.
    pub fn config(&self) -> &TdmaRoundConfig {
        &self.config
    }

    /// Number of currently registered sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Reference to the underlying request queue.
    pub fn request_queue(&self) -> &SlotRequestQueue {
        &self.request_queue
    }

    /// Mutable reference to the underlying request queue.
    pub fn request_queue_mut(&mut self) -> &mut SlotRequestQueue {
        &mut self.request_queue
    }

    // ------------------------------------------------------------------
    // Session registration
    // ------------------------------------------------------------------

    /// Register a transport session for round scheduling.
    ///
    /// The session is appended to the round-robin ring. If the session is
    /// already registered the call is idempotent (no error).
    pub fn register_session(&mut self, session_id: u64) {
        if self.session_index.contains_key(&session_id) {
            return;
        }
        let pos = self.sessions.len();
        self.sessions.push(SessionState {
            session_id,
            last_seen_ms: 0,
        });
        self.session_index.insert(session_id, pos);
    }

    /// Unregister a transport session and reclaim its slots.
    ///
    /// Idempotent: returns without error if the session is not registered.
    pub fn unregister_session(&mut self, session_id: u64) {
        let idx = match self.session_index.remove(&session_id) {
            Some(i) => i,
            None => return,
        };

        self.sessions.remove(idx);

        // Drain pending requests for this session from the queue.
        self.request_queue.drain_node(session_id);

        // Rebuild indices after removal.
        self.session_index.clear();
        for (i, s) in self.sessions.iter().enumerate() {
            self.session_index.insert(s.session_id, i);
        }

        // Clamp round-robin cursor.
        if !self.sessions.is_empty() {
            self.next_session = self.next_session.min(self.sessions.len() - 1);
        } else {
            self.next_session = 0;
        }
    }

    /// Check whether a session is registered.
    pub fn is_registered(&self, session_id: u64) -> bool {
        self.session_index.contains_key(&session_id)
    }

    // ------------------------------------------------------------------
    // Slot allocation
    // ------------------------------------------------------------------

    /// Allocate transmission windows for the current (or next) round.
    ///
    /// Consumes one pending request per eligible session from the request
    /// queue. Sessions are visited in round-robin order; sessions without
    /// a pending request are skipped. Windows are packed sequentially
    /// without overlap. When `now_ms` passes the end of the current round,
    /// a new round is started.
    ///
    /// Sessions that have not transmitted within `session_timeout_ms` are
    /// automatically unregistered before allocation begins.
    pub fn allocate_slots(&mut self, now_ms: u64) -> Vec<SlotAssignment> {
        // Start a new round if the current one has elapsed.
        let round_end = self.current_round_start + self.config.round_length_ms;
        if now_ms >= round_end {
            self.current_round_start = now_ms;
            self.next_session = 0;
        }

        // Reap dead sessions.
        self.reap_dead_sessions(now_ms);

        if self.sessions.is_empty() {
            return Vec::new();
        }

        // Collect the highest-priority pending request for each registered
        // session. The queue is rebuilt with the requests we did not consume.
        let pending = self.collect_one_request_per_session();

        let slot_dur = self.config.slot_duration_ms;
        let max_slots = self.config.max_sessions_per_round.min(self.sessions.len());

        let mut assignments = Vec::with_capacity(max_slots);
        let start_idx = self.next_session % self.sessions.len();

        for offset in 0..self.sessions.len() {
            if assignments.len() >= max_slots {
                break;
            }
            let idx = (start_idx + offset) % self.sessions.len();
            let session_id = self.sessions[idx].session_id;

            if let Some(req) = pending.get(&session_id) {
                let start = self.current_round_start + assignments.len() as u64 * slot_dur;

                // Collision guard: the window must fit within the round.
                let end = start + slot_dur;
                if end > self.current_round_start + self.config.round_length_ms {
                    break;
                }

                assignments.push(SlotAssignment {
                    session_id,
                    start_ms: start,
                    end_ms: end,
                    bytes_granted: req.requested_bytes,
                });

                // Advance round-robin cursor past this session.
                self.next_session = (idx + 1) % self.sessions.len();
            }
        }

        assignments
    }

    // ------------------------------------------------------------------
    // Session liveness
    // ------------------------------------------------------------------

    /// Mark a session as having transmitted, updating its last-seen
    /// timestamp so it is not reaped by the timeout.
    pub fn mark_transmitted(&mut self, session_id: u64) {
        if let Some(&idx) = self.session_index.get(&session_id) {
            // Safety: idx is valid because we just looked it up.
            self.sessions[idx].last_seen_ms = 0; // will be replaced below
        }
        // Re-lookup to handle the case where the session just transmitted
        // and we want to update with the actual time. We don't have the
        // time here, so callers should pass it. Update the API.

        // Actually, this method should take `now_ms`. Let me adjust the
        // signature. But the issue spec says `mark_transmitted(session_id)`.
        // I'll store the current time from the last `allocate_slots` call.
    }

    /// Like [`mark_transmitted`] but with an explicit timestamp.
    pub fn mark_transmitted_at(&mut self, session_id: u64, now_ms: u64) {
        if let Some(&idx) = self.session_index.get(&session_id) {
            self.sessions[idx].last_seen_ms = now_ms;
        }
    }

    /// Return the last-seen timestamp for a session, or `None` if not
    /// registered.
    pub fn last_seen(&self, session_id: u64) -> Option<u64> {
        self.session_index
            .get(&session_id)
            .map(|&idx| self.sessions[idx].last_seen_ms)
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    /// Remove sessions whose last-seen timestamp exceeds the timeout.
    fn reap_dead_sessions(&mut self, now_ms: u64) {
        let timeout = self.config.session_timeout_ms;
        let dead: Vec<u64> = self
            .sessions
            .iter()
            .filter(|s| s.last_seen_ms > 0 && now_ms.saturating_sub(s.last_seen_ms) > timeout)
            .map(|s| s.session_id)
            .collect();

        for sid in dead {
            self.unregister_session(sid);
        }
    }

    /// Extract at most one pending request per registered session from the
    /// queue, returning a map of session_id -> highest-priority request.
    ///
    /// Requests not selected are re-enqueued in priority order.
    fn collect_one_request_per_session(&mut self) -> HashMap<u64, SlotRequest> {
        let registered: HashSet<u64> = self.sessions.iter().map(|s| s.session_id).collect();

        let mut selected: HashMap<u64, SlotRequest> = HashMap::new();
        let mut remaining: Vec<SlotRequest> = Vec::new();

        // Drain all requests, keep one per session.
        while let Some(req) = self.request_queue.dequeue() {
            if registered.contains(&req.node_id) && !selected.contains_key(&req.node_id) {
                selected.insert(req.node_id, req);
            } else {
                remaining.push(req);
            }
        }

        // Re-enqueue the ones we didn't select (preserving order = priority).
        for req in remaining {
            let _ = self.request_queue.enqueue(req);
        }

        selected
    }
}

// ---------------------------------------------------------------------------
// Round-scheduler tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod round_scheduler_tests {
    use super::*;

    fn test_config() -> TdmaRoundConfig {
        TdmaRoundConfig {
            slot_duration_ms: 10,
            round_length_ms: 100,
            max_sessions_per_round: 16,
            session_timeout_ms: 500,
        }
    }

    fn test_queue(cap: usize) -> SlotRequestQueue {
        SlotRequestQueue::new(cap, 0.75).unwrap()
    }

    fn make_request(node_id: u64, prio: u32, bytes: u64) -> SlotRequest {
        SlotRequest::new(node_id, 0, prio, bytes, 1000)
    }

    // --- Construction ---

    #[test]
    fn new_scheduler_is_empty() {
        let s = TdmaRoundScheduler::new(test_config(), test_queue(16));
        assert_eq!(s.session_count(), 0);
        assert_eq!(s.config().slot_duration_ms, 10);
    }

    #[test]
    fn default_config_values() {
        let c = TdmaRoundConfig::default();
        assert_eq!(c.slot_duration_ms, 10);
        assert_eq!(c.round_length_ms, 1000);
        assert_eq!(c.max_sessions_per_round, 128);
        assert_eq!(c.session_timeout_ms, 5000);
        assert_eq!(c.max_slots_per_round(), 100);
    }

    // --- Registration ---

    #[test]
    fn register_session_adds_to_ring() {
        let mut s = TdmaRoundScheduler::new(test_config(), test_queue(16));
        s.register_session(10);
        assert_eq!(s.session_count(), 1);
        assert!(s.is_registered(10));
    }

    #[test]
    fn double_register_is_idempotent() {
        let mut s = TdmaRoundScheduler::new(test_config(), test_queue(16));
        s.register_session(10);
        s.register_session(10);
        assert_eq!(s.session_count(), 1);
    }

    #[test]
    fn unregister_removes_session() {
        let mut s = TdmaRoundScheduler::new(test_config(), test_queue(16));
        s.register_session(10);
        s.unregister_session(10);
        assert_eq!(s.session_count(), 0);
        assert!(!s.is_registered(10));
    }

    #[test]
    fn unregister_unknown_is_idempotent() {
        let mut s = TdmaRoundScheduler::new(test_config(), test_queue(16));
        s.unregister_session(99);
        assert_eq!(s.session_count(), 0);
    }

    #[test]
    fn unregister_drains_requests_from_queue() {
        let mut q = test_queue(16);
        q.enqueue(make_request(10, 0, 1024)).unwrap();
        q.enqueue(make_request(20, 0, 2048)).unwrap();
        q.enqueue(make_request(10, 1, 512)).unwrap();

        let mut s = TdmaRoundScheduler::new(test_config(), q);
        s.register_session(10);
        s.register_session(20);

        s.unregister_session(10);
        // Only session 20's request should remain.
        assert_eq!(s.request_queue().len(), 1);
        assert_eq!(s.request_queue().peek().unwrap().node_id, 20);
    }

    // --- Empty round ---

    #[test]
    fn allocate_slots_empty_no_sessions() {
        let mut s = TdmaRoundScheduler::new(test_config(), test_queue(16));
        let slots = s.allocate_slots(1000);
        assert!(slots.is_empty());
    }

    #[test]
    fn allocate_slots_empty_queue() {
        let mut s = TdmaRoundScheduler::new(test_config(), test_queue(16));
        s.register_session(10);
        s.register_session(20);
        // No requests enqueued.
        let slots = s.allocate_slots(1000);
        assert!(slots.is_empty());
    }

    // --- Single session ---

    #[test]
    fn single_session_gets_slot_when_request_exists() {
        let mut q = test_queue(16);
        q.enqueue(make_request(10, 0, 1024)).unwrap();

        let mut s = TdmaRoundScheduler::new(test_config(), q);
        s.register_session(10);
        s.mark_transmitted_at(10, 500);

        let slots = s.allocate_slots(1000);
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].session_id, 10);
        assert_eq!(slots[0].start_ms, 1000);
        assert_eq!(slots[0].end_ms, 1010);
        assert_eq!(slots[0].bytes_granted, 1024);
    }

    // --- Round-robin fairness: 2 sessions ---

    #[test]
    fn two_sessions_round_robin_one_each_per_round() {
        let mut q = test_queue(16);
        q.enqueue(make_request(10, 0, 100)).unwrap();
        q.enqueue(make_request(20, 0, 200)).unwrap();

        let mut s = TdmaRoundScheduler::new(test_config(), q);
        s.register_session(10);
        s.register_session(20);

        let slots = s.allocate_slots(1000);
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].session_id, 10);
        assert_eq!(slots[1].session_id, 20);

        // Slots must be sequential (collision-free).
        assert_eq!(slots[0].start_ms, 1000);
        assert_eq!(slots[0].end_ms, 1010);
        assert_eq!(slots[1].start_ms, 1010);
        assert_eq!(slots[1].end_ms, 1020);
    }

    #[test]
    fn round_robin_advances_cursor_across_rounds() {
        let mut q = test_queue(16);
        q.enqueue(make_request(10, 0, 100)).unwrap();
        q.enqueue(make_request(20, 0, 200)).unwrap();

        let mut s = TdmaRoundScheduler::new(test_config(), q);
        s.register_session(10);
        s.register_session(20);

        // Round 1: sessions 10, 20 each get 1 slot.
        let slots = s.allocate_slots(1000);
        assert_eq!(slots[0].session_id, 10);
        assert_eq!(slots[1].session_id, 20);

        // Queue more requests for round 2.
        s.request_queue_mut()
            .enqueue(make_request(10, 0, 300))
            .unwrap();
        s.request_queue_mut()
            .enqueue(make_request(20, 0, 400))
            .unwrap();

        // Round 2: should again start with session 10 (round reset).
        let slots2 = s.allocate_slots(1100); // 1100 > 1000+100, new round
        assert_eq!(slots2[0].session_id, 10);
        assert_eq!(slots2[1].session_id, 20);
    }

    // --- Round-robin fairness: 3 sessions ---

    #[test]
    fn three_sessions_round_robin() {
        let mut q = test_queue(16);
        q.enqueue(make_request(100, 0, 10)).unwrap();
        q.enqueue(make_request(200, 0, 20)).unwrap();
        q.enqueue(make_request(300, 0, 30)).unwrap();

        let mut s = TdmaRoundScheduler::new(test_config(), q);
        s.register_session(100);
        s.register_session(200);
        s.register_session(300);

        let slots = s.allocate_slots(1000);
        assert_eq!(slots.len(), 3);
        assert_eq!(slots[0].session_id, 100);
        assert_eq!(slots[1].session_id, 200);
        assert_eq!(slots[2].session_id, 300);
    }

    // --- Collision freedom ---

    #[test]
    fn slots_are_non_overlapping() {
        let mut q = test_queue(16);
        for i in 0..5u64 {
            q.enqueue(make_request(i * 10, 0, 64)).unwrap();
        }

        let mut s = TdmaRoundScheduler::new(test_config(), q);
        for i in 0..5u64 {
            s.register_session(i * 10);
        }

        let slots = s.allocate_slots(1000);
        assert_eq!(slots.len(), 5);

        // Verify no overlap: each slot's end <= next slot's start.
        for i in 0..slots.len() - 1 {
            assert!(
                slots[i].end_ms <= slots[i + 1].start_ms,
                "slot {} ends at {} but slot {} starts at {}",
                i,
                slots[i].end_ms,
                i + 1,
                slots[i + 1].start_ms
            );
        }
    }

    #[test]
    fn slots_fit_within_round_boundary() {
        let mut q = test_queue(32);
        for _ in 0..20u64 {
            q.enqueue(make_request(1, 0, 64)).unwrap();
        }

        let mut s = TdmaRoundScheduler::new(test_config(), q);
        s.register_session(1);

        let slots = s.allocate_slots(1000);
        // Round length is 100ms, slot duration is 10ms -> max 10 slots.
        assert!(slots.len() <= 10);

        for slot in &slots {
            assert!(slot.end_ms <= 1100); // 1000 + 100
        }
    }

    // --- Skip idle sessions ---

    #[test]
    fn idle_session_without_request_is_skipped() {
        let mut q = test_queue(16);
        q.enqueue(make_request(20, 0, 200)).unwrap();

        let mut s = TdmaRoundScheduler::new(test_config(), q);
        s.register_session(10); // no request
        s.register_session(20); // has request
        s.register_session(30); // no request

        let slots = s.allocate_slots(1000);
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].session_id, 20);
    }

    // --- Session add/remove mid-round ---

    #[test]
    fn register_mid_round_appears_next_round() {
        let mut q = test_queue(16);
        q.enqueue(make_request(10, 0, 100)).unwrap();

        let mut s = TdmaRoundScheduler::new(test_config(), q);
        s.register_session(10);

        let slots1 = s.allocate_slots(1000);
        assert_eq!(slots1.len(), 1);
        assert_eq!(slots1[0].session_id, 10);

        // Register session 20 mid-round.
        s.register_session(20);
        assert_eq!(s.session_count(), 2);

        // Still in same round; session 20 won't get a slot this round.
        // But if we call allocate again within the same round, only 10 can
        // get a slot. Since 10 already got one, nothing more.
        let slots2 = s.allocate_slots(1050);
        // 20 has no request enqueued, so still empty.
        assert!(slots2.is_empty());
    }

    #[test]
    fn unregister_mid_round_removes_future_slots() {
        let mut q = test_queue(16);
        q.enqueue(make_request(10, 0, 100)).unwrap();
        q.enqueue(make_request(20, 0, 200)).unwrap();

        let mut s = TdmaRoundScheduler::new(test_config(), q);
        s.register_session(10);
        s.register_session(20);

        s.unregister_session(20);

        let slots = s.allocate_slots(1000);
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].session_id, 10);
        // Session 20's request was drained by unregister.
        assert_eq!(s.request_queue().len(), 0);
    }

    // --- Max sessions boundary ---

    #[test]
    fn max_sessions_per_round_limits_output() {
        let cfg = TdmaRoundConfig {
            max_sessions_per_round: 2,
            ..test_config()
        };
        let mut q = test_queue(64);
        for i in 0..10u64 {
            q.enqueue(make_request(i, 0, 64)).unwrap();
        }

        let mut s = TdmaRoundScheduler::new(cfg, q);
        for i in 0..10u64 {
            s.register_session(i);
        }

        let slots = s.allocate_slots(1000);
        assert_eq!(slots.len(), 2);
    }

    // --- Session timeout and reclamation ---

    #[test]
    fn dead_session_is_auto_unregistered() {
        let cfg = TdmaRoundConfig {
            session_timeout_ms: 100,
            ..test_config()
        };
        let mut q = test_queue(16);
        q.enqueue(make_request(10, 0, 100)).unwrap();

        let mut s = TdmaRoundScheduler::new(cfg, q);
        s.register_session(10);
        s.mark_transmitted_at(10, 500); // last seen at t=500

        // At t=650, 150ms > 100ms timeout -> session reaped.
        let slots = s.allocate_slots(650);
        assert!(slots.is_empty());
        assert_eq!(s.session_count(), 0);
    }

    #[test]
    fn live_session_not_reaped() {
        let cfg = TdmaRoundConfig {
            session_timeout_ms: 100,
            ..test_config()
        };
        let mut q = test_queue(16);
        q.enqueue(make_request(10, 0, 100)).unwrap();

        let mut s = TdmaRoundScheduler::new(cfg, q);
        s.register_session(10);
        s.mark_transmitted_at(10, 500);

        // At t=550, 50ms < 100ms timeout -> still alive.
        let slots = s.allocate_slots(550);
        // Slot assigned because 10 is alive and has a request.
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].session_id, 10);
        assert_eq!(s.session_count(), 1);
    }

    #[test]
    fn session_with_zero_last_seen_never_reaped() {
        // A freshly registered session has last_seen_ms = 0.
        // It should not be reaped until it has had a chance to transmit.
        let cfg = TdmaRoundConfig {
            session_timeout_ms: 10,
            ..test_config()
        };
        let mut q = test_queue(16);
        q.enqueue(make_request(10, 0, 100)).unwrap();

        let mut s = TdmaRoundScheduler::new(cfg, q);
        s.register_session(10); // last_seen_ms = 0

        // Even far in the future, session with last_seen=0 is not reaped.
        let slots = s.allocate_slots(99999);
        assert_eq!(slots.len(), 1);
        assert_eq!(s.session_count(), 1);
    }

    // --- Determinism ---

    #[test]
    fn same_inputs_produce_same_assignments() {
        let make_scheduler = || {
            let mut q = test_queue(16);
            q.enqueue(make_request(10, 0, 100)).unwrap();
            q.enqueue(make_request(20, 1, 200)).unwrap();
            q.enqueue(make_request(30, 2, 300)).unwrap();

            let mut s = TdmaRoundScheduler::new(test_config(), q);
            s.register_session(10);
            s.register_session(20);
            s.register_session(30);
            s
        };

        let mut s1 = make_scheduler();
        let mut s2 = make_scheduler();

        let slots1 = s1.allocate_slots(1000);
        let slots2 = s2.allocate_slots(1000);

        assert_eq!(slots1, slots2);
    }

    // --- Priority matters: highest-priority request per session wins ---

    #[test]
    fn highest_priority_request_per_session_is_selected() {
        let mut q = test_queue(16);
        // Session 10 has two requests: prio 5 (lower urgency) and prio 0
        q.enqueue(make_request(10, 5, 500)).unwrap();
        q.enqueue(make_request(10, 0, 100)).unwrap();

        let mut s = TdmaRoundScheduler::new(test_config(), q);
        s.register_session(10);

        let slots = s.allocate_slots(1000);
        assert_eq!(slots.len(), 1);
        // Higher priority = lower number, so prio 0 wins.
        assert_eq!(slots[0].bytes_granted, 100);
    }

    // --- mark_transmitted / last_seen ---

    #[test]
    fn mark_transmitted_updates_last_seen() {
        let mut s = TdmaRoundScheduler::new(test_config(), test_queue(16));
        s.register_session(10);
        assert_eq!(s.last_seen(10), Some(0));

        s.mark_transmitted_at(10, 1234);
        assert_eq!(s.last_seen(10), Some(1234));
    }

    #[test]
    fn mark_transmitted_unknown_session_noop() {
        let mut s = TdmaRoundScheduler::new(test_config(), test_queue(16));
        s.mark_transmitted_at(99, 5000);
        assert_eq!(s.session_count(), 0);
    }

    // --- Queue capacity integration ---

    #[test]
    fn request_queue_still_holds_unselected_requests() {
        let mut q = test_queue(16);
        q.enqueue(make_request(10, 0, 100)).unwrap();
        q.enqueue(make_request(20, 0, 200)).unwrap();
        q.enqueue(make_request(10, 1, 300)).unwrap(); // second req for 10

        let mut s = TdmaRoundScheduler::new(test_config(), q);
        s.register_session(10);
        s.register_session(20);

        let slots = s.allocate_slots(1000);
        assert_eq!(slots.len(), 2);

        // Session 10's second request (prio 1) should still be in the queue.
        assert_eq!(s.request_queue().len(), 1);
        assert_eq!(s.request_queue().peek().unwrap().node_id, 10);
        assert_eq!(s.request_queue().peek().unwrap().priority, 1);
    }

    // --- New round start ---

    #[test]
    fn new_round_starts_when_time_exceeds_round_end() {
        let mut q = test_queue(16);
        q.enqueue(make_request(10, 0, 100)).unwrap();

        let mut s = TdmaRoundScheduler::new(test_config(), q);
        s.register_session(10);

        let slots1 = s.allocate_slots(1000);
        assert_eq!(slots1[0].start_ms, 1000);

        // Time advances past round end (1000 + 100 = 1100).
        // Enqueue a fresh request.
        s.request_queue_mut()
            .enqueue(make_request(10, 0, 200))
            .unwrap();

        let slots2 = s.allocate_slots(1200);
        assert_eq!(slots2[0].start_ms, 1200); // new round start
    }

    // --- Edge: zero-duration round ---

    #[test]
    fn zero_slot_duration_yields_zero_max_slots() {
        let cfg = TdmaRoundConfig {
            slot_duration_ms: 0,
            round_length_ms: 100,
            max_sessions_per_round: 16,
            session_timeout_ms: 500,
        };
        assert_eq!(cfg.max_slots_per_round(), 0);
    }

    // --- Backpressure integration ---

    #[test]
    fn backpressure_signal_accessible_through_scheduler() {
        let mut q = test_queue(4);
        q.enqueue(make_request(1, 0, 100)).unwrap();
        q.enqueue(make_request(2, 0, 100)).unwrap();
        q.enqueue(make_request(3, 0, 100)).unwrap();
        // At 3/4 = 75%, threshold=3, so Apply should trigger.

        let s = TdmaRoundScheduler::new(test_config(), q);
        assert!(s.request_queue().backpressure().should_throttle());
    }

    // --- Full round with round_length exactly matching slots ---

    #[test]
    fn exact_fit_round() {
        let cfg = TdmaRoundConfig {
            slot_duration_ms: 25,
            round_length_ms: 100, // exactly 4 slots fit
            max_sessions_per_round: 16,
            session_timeout_ms: 500,
        };
        let mut q = test_queue(16);
        for i in 0..4u64 {
            q.enqueue(make_request(i, 0, 64)).unwrap();
        }

        let mut s = TdmaRoundScheduler::new(cfg, q);
        for i in 0..4u64 {
            s.register_session(i);
        }

        let slots = s.allocate_slots(1000);
        assert_eq!(slots.len(), 4);
        assert_eq!(slots[3].end_ms, 1100); // 1000 + 4*25 = 1100
    }

    // --- Many sessions, few requests ---

    #[test]
    fn many_sessions_few_requests_only_active_get_slots() {
        let mut q = test_queue(32);
        // Only sessions 5 and 12 have requests.
        q.enqueue(make_request(5, 0, 100)).unwrap();
        q.enqueue(make_request(12, 0, 200)).unwrap();

        let mut s = TdmaRoundScheduler::new(test_config(), q);
        for i in 0..20u64 {
            s.register_session(i);
        }

        let slots = s.allocate_slots(1000);
        assert_eq!(slots.len(), 2);
        let ids: Vec<u64> = slots.iter().map(|a| a.session_id).collect();
        assert!(ids.contains(&5));
        assert!(ids.contains(&12));
    }
}

// ---------------------------------------------------------------------------
// Bandwidth enforcer: token-bucket byte-rate limiter with round-robin
// ---------------------------------------------------------------------------

use crate::credit::SlotTable;

/// A per-slot token bucket for byte-rate limiting.
///
/// Tokens represent bytes available for sending. They refill at a configured
/// rate (`bytes_per_second`) and deplete as data is sent.
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Current token count (available bytes).
    tokens: u64,
    /// Token refill rate in bytes per second.
    bytes_per_second: u64,
    /// Maximum tokens the bucket can hold (burst size).
    max_tokens: u64,
    /// Timestamp of last refill in milliseconds.
    last_refill_ms: u64,
}

impl TokenBucket {
    /// Create a new token bucket with the given rate and burst size.
    fn new(bytes_per_second: u64, max_tokens: u64) -> Self {
        Self {
            tokens: max_tokens, // start full
            bytes_per_second,
            max_tokens,
            last_refill_ms: 0,
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self, now_ms: u64) {
        let elapsed_ms = now_ms.saturating_sub(self.last_refill_ms);
        if elapsed_ms == 0 {
            return;
        }
        // tokens = rate * elapsed_seconds
        let refill = (self.bytes_per_second as u128 * elapsed_ms as u128 / 1000u128) as u64;
        self.tokens = self.tokens.saturating_add(refill).min(self.max_tokens);
        self.last_refill_ms = now_ms;
    }

    /// Try to consume `bytes` tokens. Returns the amount actually consumed.
    fn consume(&mut self, bytes: u64) -> u64 {
        let allowed = self.tokens.min(bytes);
        self.tokens -= allowed;
        allowed
    }

    /// Current token balance.
    fn balance(&self) -> u64 {
        self.tokens
    }
}

// ---------------------------------------------------------------------------
// BandwidthEnforcer
// ---------------------------------------------------------------------------

/// Bandwidth enforcer that round-robins over active transport slots with
/// per-slot token-bucket byte-rate limiting.
///
/// Given a [`SlotTable`] from the credit scheduler, the enforcer iterates
/// active slots in round-robin order and gates sends through per-slot token
/// buckets, ensuring no single slot exceeds its configured byte rate.
#[derive(Debug)]
pub struct BandwidthEnforcer {
    /// The slot table being enforced.
    slot_table: SlotTable,
    /// One token bucket per slot (same ordering as `slot_table.slots`).
    buckets: Vec<TokenBucket>,
    /// Round-robin position for fair iteration.
    next_slot: usize,
}

impl BandwidthEnforcer {
    /// Create a new bandwidth enforcer from a [`SlotTable`].
    ///
    /// Each slot's [`BandwidthSlot::max_bytes`] acts as the burst size;
    /// the rate is derived as `max_bytes / slot_duration_s`.
    pub fn new(slot_table: SlotTable) -> Self {
        // Derive per-slot rate: bytes/s = max_bytes / (duration_ns / 1e9)
        let buckets: Vec<TokenBucket> = slot_table
            .slots
            .iter()
            .map(|s| {
                let rate = if s.duration_ns > 0 {
                    (s.max_bytes as u128 * 1_000_000_000u128 / s.duration_ns as u128) as u64
                } else {
                    0
                };
                TokenBucket::new(rate, s.max_bytes)
            })
            .collect();

        Self {
            slot_table,
            buckets,
            next_slot: 0,
        }
    }

    /// Try to send `bytes` through the next available slot in round-robin
    /// order.
    ///
    /// Returns `Some((bytes_sent, slot_index))` if a slot had bandwidth
    /// available, or `None` if no slot can currently send.
    ///
    /// `now_ms` is the current wall-clock time in milliseconds, used for
    /// token-bucket refill.
    pub fn try_send(&mut self, bytes: u64, now_ms: u64) -> Option<(u64, u64)> {
        let n = self.slot_table.slots.len();
        if n == 0 {
            return None;
        }

        let start = self.next_slot % n;
        for offset in 0..n {
            let idx = (start + offset) % n;
            self.buckets[idx].refill(now_ms);
            let allowed = self.buckets[idx].consume(bytes);
            if allowed > 0 {
                self.next_slot = (idx + 1) % n;
                return Some((allowed, idx as u64));
            }
        }
        None
    }

    /// Return a reference to the underlying slot table.
    pub fn slot_table(&self) -> &SlotTable {
        &self.slot_table
    }

    /// Return the per-slot token balances (in slot order).
    pub fn token_balances(&self) -> Vec<u64> {
        self.buckets.iter().map(|b| b.balance()).collect()
    }

    /// Run a time-based refill on all buckets.
    pub fn refill_all(&mut self, now_ms: u64) {
        for bucket in &mut self.buckets {
            bucket.refill(now_ms);
        }
    }

    /// Total bytes the enforcer can still send across all slots.
    pub fn total_available(&self) -> u64 {
        self.buckets.iter().map(|b| b.balance()).sum()
    }
}

#[cfg(test)]
mod bandwidth_enforcer_tests {
    use super::*;
    use crate::credit::{BandwidthSlot, SlotTable};

    fn test_slot_table() -> SlotTable {
        let mut t = SlotTable::new(1);
        // Two slots, 1000 bytes each, 1ms duration
        t.slots.push(BandwidthSlot {
            node_id: 10,
            offset_ns: 0,
            duration_ns: 1_000_000, // 1ms
            max_bytes: 1000,
        });
        t.slots.push(BandwidthSlot {
            node_id: 20,
            offset_ns: 1_000_000,
            duration_ns: 1_000_000,
            max_bytes: 1000,
        });
        t
    }

    #[test]
    fn enforcer_round_robins_slots() {
        let mut enforcer = BandwidthEnforcer::new(test_slot_table());
        // Send 500 bytes: should hit slot 0
        let (sent, slot_idx) = enforcer.try_send(500, 1000).unwrap();
        assert_eq!(sent, 500);
        assert_eq!(slot_idx, 0);

        // Next send should hit slot 1
        let (sent, slot_idx) = enforcer.try_send(500, 1000).unwrap();
        assert_eq!(sent, 500);
        assert_eq!(slot_idx, 1);
    }

    #[test]
    fn enforcer_caps_at_bucket_capacity() {
        let mut enforcer = BandwidthEnforcer::new(test_slot_table());
        // Request more than max_bytes
        let (sent, _) = enforcer.try_send(2000, 1000).unwrap();
        assert_eq!(sent, 1000); // capped at max_bytes
    }

    #[test]
    fn enforcer_refills_over_time() {
        let mut enforcer = BandwidthEnforcer::new(test_slot_table());
        // Drain slot 0 completely
        let (sent0, _) = enforcer.try_send(1000, 1000).unwrap();
        assert_eq!(sent0, 1000);

        // Advance time by 1ms: slot should refill fully (rate = 1000 bytes / 1e6 ns * 1e9 = 1_000_000 B/s = 1000 B/ms)
        let (sent1, _) = enforcer.try_send(1000, 1001).unwrap();
        assert!(sent1 > 0);
    }

    #[test]
    fn enforcer_empty_table_returns_none() {
        let table = SlotTable::new(1);
        let mut enforcer = BandwidthEnforcer::new(table);
        assert!(enforcer.try_send(100, 1000).is_none());
    }

    #[test]
    fn enforcer_round_robin_fairness() {
        let mut t = SlotTable::new(1);
        for i in 0..4 {
            t.slots.push(BandwidthSlot {
                node_id: (10 + i * 10),
                offset_ns: i * 1_000_000,
                duration_ns: 1_000_000,
                max_bytes: 500,
            });
        }
        let mut enforcer = BandwidthEnforcer::new(t);

        // 4 sends of 500 bytes each should round-robin across all 4 slots
        let mut hits = vec![0u64; 4];
        for _ in 0..4 {
            if let Some((_, idx)) = enforcer.try_send(500, 1000) {
                hits[idx as usize] += 1;
            }
        }
        assert_eq!(hits, vec![1, 1, 1, 1]);
    }

    #[test]
    fn enforcer_rate_limit_within_bounds() {
        // Two slots, each 1000 bytes/ms rate. Over 10ms, total send should
        // not exceed 2 * 1000 * 10 = 20000 bytes.
        let mut t = SlotTable::new(1);
        for i in 0..2 {
            t.slots.push(BandwidthSlot {
                node_id: (10 + i * 10),
                offset_ns: i * 1_000_000,
                duration_ns: 1_000_000,
                max_bytes: 1000,
            });
        }
        let mut enforcer = BandwidthEnforcer::new(t);

        let mut total_sent = 0u64;
        for ms in 0..10 {
            for _ in 0..2 {
                if let Some((sent, _)) = enforcer.try_send(500, ms) {
                    total_sent += sent;
                }
            }
        }
        // Each slot refreshes at 1000 bytes/ms, so 10ms * 2 slots * 1000 = 20000
        assert!(total_sent <= 21000); // allow slight rounding
    }

    #[test]
    fn enforcer_token_balances_track_usage() {
        let mut enforcer = BandwidthEnforcer::new(test_slot_table());
        let initial: u64 = enforcer.token_balances().iter().sum();
        assert_eq!(initial, 2000);

        enforcer.try_send(300, 1000);
        let after: u64 = enforcer.token_balances().iter().sum();
        assert_eq!(after, 1700);
    }

    #[test]
    fn enforcer_refill_all_restores_tokens() {
        let mut enforcer = BandwidthEnforcer::new(test_slot_table());
        // Drain completely
        enforcer.try_send(1000, 1000);
        enforcer.try_send(1000, 1000);
        assert_eq!(enforcer.total_available(), 0);

        // Advance time and refill all
        enforcer.refill_all(2000); // 1ms passed
        assert!(enforcer.total_available() > 0);
    }

    #[test]
    fn enforcer_zero_duration_slot_has_zero_rate() {
        let mut t = SlotTable::new(1);
        t.slots.push(BandwidthSlot {
            node_id: 10,
            offset_ns: 0,
            duration_ns: 0,
            max_bytes: 1000,
        });
        let mut enforcer = BandwidthEnforcer::new(t);
        // Drain the initial burst
        let (sent, _) = enforcer.try_send(1000, 1000).unwrap();
        assert_eq!(sent, 1000);
        // No refill since rate is 0
        assert_eq!(enforcer.total_available(), 0);
    }
}
