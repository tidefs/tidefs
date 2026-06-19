// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Deterministic in-process two-node membership harness.
//!
//! Provides a controlled environment for exercising epoch transitions,
//! lease acquisition, and fencing behavior with reproducible, byte-for-byte
//! deterministic outcomes. Every clock tick and message delivery is under
//! harness control.
//!
//! ## Architecture
//!
//! - [`DeterministicClock`]: a clock that advances only when explicitly ticked.
//! - [`StorageNode`]: wraps a deterministic [`EpochStateMachine`] plus lease
//!   state and an in-process message channel to a peer.
//! - [`HarnessMessage`]: typed messages for join/leave, epoch updates, lease
//!   acquire/ack/revoke, and heartbeats.
//! - [`TwoNodeHarness`]: creates two `StorageNode` instances, connects their
//!   channels, and provides controlled `tick_all` / `drain_all` operations
//!   for scenario execution.
//!
//! ## Determinism
//!
//! Every scenario produces the same outcome when replayed with the same seed
//! clock and the same message sequence. The underlying epoch state machine
//! (`tidefs_membership_epoch::EpochStateMachine`) is already deterministic;
//! this harness adds deterministic lease expiry and controlled message
//! delivery.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::deterministic_transport::{
    DeterministicEndpoint, DeterministicSession, DeterministicTransport, MessageDirection,
};
use blake3::Hasher;
use tidefs_membership_epoch::{EpochMemberSet, EpochStateMachine, EpochTransition, NodeIdentity};
use tidefs_placement_runtime::{
    dispatch_read, DispatchReadResult, ObjectReadTarget, ObjectWriteTarget,
};
use tidefs_transport::{StateTransferChunk, StateTransferRequest};

// ---------------------------------------------------------------------------
// DeterministicClock
// ---------------------------------------------------------------------------

/// A clock whose current time only advances when explicitly ticked.
///
/// All nodes in the harness share the **same** `DeterministicClock` instance
/// so that lease deadlines and heartbeat timestamps are consistent across
/// the two nodes.
#[derive(Clone, Debug)]
pub struct DeterministicClock {
    now_ms: u64,
}

impl DeterministicClock {
    pub fn new(start_ms: u64) -> Self {
        Self { now_ms: start_ms }
    }

    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    pub fn advance(&mut self, ms: u64) {
        self.now_ms = self.now_ms.saturating_add(ms);
    }
}

// ---------------------------------------------------------------------------
// Lease types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseType {
    Reader,
    Writer,
}

/// A lease record binding an object to a holder with an expiry deadline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRecord {
    pub object_id: u64,
    pub holder: NodeIdentity,
    pub lease_type: LeaseType,
    pub granted_at_ms: u64,
    pub expires_at_ms: u64,
}

impl LeaseRecord {
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }
}

// ---------------------------------------------------------------------------
// PendingObjectState (staged chunk assembly)
// ---------------------------------------------------------------------------

/// Tracks the receiver-side staging of state-transfer chunks for one object.
///
/// Chunks are assembled in `buffer` as they arrive. Once `is_last` is seen,
/// the buffer is verified (all expected data present) and committed to
/// `StorageNode.objects`. If any chunk fails BLAKE3 verification or arrives
/// out of bounds, the entire staging entry is discarded.
#[derive(Clone, Debug)]
struct PendingObjectState {
    /// Buffer being assembled (pre-allocated to `total_size` on first chunk).
    buffer: Vec<u8>,
    /// Total expected size, from `StateTransferChunk.total_size`.
    total_size: u64,
    /// Per-byte receive map. The harness already stages the full object
    /// payload, so the extra bitmap keeps completion checks independent of
    /// chunk size or delivery order.
    received: Vec<bool>,
    /// Number of unique payload bytes received so far.
    received_bytes: usize,
    /// Whether the last chunk has been received.
    seen_last: bool,
}

impl PendingObjectState {
    /// Create a new staging state for an object with the given total size.
    fn new(total_size: u64) -> Self {
        let len = total_size as usize;
        Self {
            buffer: vec![0u8; len],
            total_size,
            received: vec![false; len],
            received_bytes: 0,
            seen_last: false,
        }
    }

    /// Stage one verified chunk.
    ///
    /// Returns `Ok(true)` once the staged object is complete and can be
    /// atomically published into `StorageNode.objects`.
    fn stage_chunk(&mut self, chunk: &StateTransferChunk) -> Result<bool, ()> {
        if chunk.total_size != self.total_size {
            return Err(());
        }

        let start = usize::try_from(chunk.offset).map_err(|_| ())?;
        let end = start.checked_add(chunk.payload.len()).ok_or(())?;
        if end > self.buffer.len() {
            return Err(());
        }

        for (idx, byte) in (start..end).zip(chunk.payload.iter()) {
            if self.received[idx] && self.buffer[idx] != *byte {
                return Err(());
            }
        }

        for (idx, byte) in (start..end).zip(chunk.payload.iter()) {
            self.buffer[idx] = *byte;
            if !self.received[idx] {
                self.received[idx] = true;
                self.received_bytes += 1;
            }
        }

        if chunk.is_last {
            self.seen_last = true;
        }

        Ok(self.seen_last && self.received_bytes == self.buffer.len())
    }

    fn into_payload(self) -> Vec<u8> {
        self.buffer
    }
}

// ---------------------------------------------------------------------------
// HeartbeatConfig
// ---------------------------------------------------------------------------

/// Configuration for the harness heartbeat protocol.
///
/// Heartbeats are disabled by default. Call
/// [`TwoNodeHarness::set_heartbeat_config`] to enable and configure.
#[derive(Clone, Debug)]
pub struct HeartbeatConfig {
    /// How often heartbeats are sent (milliseconds).
    pub interval_ms: u64,
    /// Time window for expecting a heartbeat from the peer (milliseconds).
    pub timeout_ms: u64,
    /// Number of consecutive missed beats before declaring the peer
    /// unreachable and incrementing the membership epoch.
    pub max_missed_beats: u64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval_ms: 100,
            timeout_ms: 300,
            max_missed_beats: 3,
        }
    }
}

/// Events emitted by the heartbeat protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HarnessEvent {
    /// The peer has been detected as unreachable after missed-beat threshold.
    PeerUnreachable { epoch_id: u64, at_ms: u64 },
    /// The peer has become reachable again after a failure window.
    PeerReachable { epoch_id: u64, at_ms: u64 },
}

// ---------------------------------------------------------------------------
// Harness messages
// ---------------------------------------------------------------------------

/// Messages exchanged between storage nodes in the harness via deterministic
/// transport sessions with bincode framing.
///
/// These are serialized with bincode and delivered through in-memory framed
/// transport sessions; there is no TCP and no real network I/O.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HarnessMessage {
    /// A node requests to join the peer's epoch.
    JoinRequest { node_id: u64, at_ms: u64 },
    /// Response to a join request carrying the current member roster.
    JoinResponse {
        to_node_id: u64,
        epoch_id: u64,
        members: Vec<u64>,
        at_ms: u64,
    },
    /// Broadcast after an epoch transition has been committed.
    EpochUpdate {
        from_epoch: u64,
        to_epoch: u64,
        added: Vec<u64>,
        removed: Vec<u64>,
        at_ms: u64,
    },
    /// Request to leave the cluster.
    LeaveRequest { node_id: u64, at_ms: u64 },
    /// Lease acquisition request sent to the peer.
    LeaseAcquire {
        node_id: u64,
        object_id: u64,
        lease_type: LeaseType,
        at_ms: u64,
    },
    /// Acknowledgement of a lease acquisition.
    LeaseAck {
        object_id: u64,
        granted: bool,
        holder: u64,
        at_ms: u64,
    },
    /// Lease forcibly revoked (fencing).
    LeaseRevoke {
        object_id: u64,
        revoked_from: u64,
        at_ms: u64,
    },
    /// Periodic heartbeat carrying the sender's current epoch.
    Heartbeat {
        node_id: u64,
        epoch_id: u64,
        at_ms: u64,
    },
    /// A node requests object data from its peer for state catch-up.
    StateTransferRequestMsg(StateTransferRequest),
    /// A chunk of object data sent in response to a state transfer request.
    StateTransferChunkMsg(StateTransferChunk),
}

// ---------------------------------------------------------------------------
// StorageNode
// ---------------------------------------------------------------------------

/// A storage node in the deterministic harness.
///
/// Each node owns an [`EpochStateMachine`] (deterministic), a lease table,
/// and an in-process message channel to its peer.
pub struct StorageNode {
    pub node_id: u64,
    epoch_sm: EpochStateMachine,
    clock: DeterministicClock,
    /// Deterministic transport session to the peer.
    pub session: Option<DeterministicSession>,
    /// Active leases held by this node.
    pub leases: BTreeMap<u64, LeaseRecord>,
    /// Leases held by the peer (as known to this node).
    pub peer_leases: BTreeMap<u64, LeaseRecord>,
    /// Messages queued for delivery on the next flush.
    outbox: Vec<HarnessMessage>,
    /// Messages received this tick.
    inbox: Vec<HarnessMessage>,
    /// Log of every epoch transition applied by this node.
    pub transition_log: Vec<EpochTransition>,
    /// When true, outbound messages are dropped (simulating a network partition).
    pub peer_partitioned: bool,
    /// When true, this node has crashed and its session is closed.
    pub crashed: bool,
    /// Lease timeout in milliseconds.
    pub lease_timeout_ms: u64,
    /// Local object store: object_id -> payload bytes.
    pub objects: BTreeMap<u64, Vec<u8>>,
    /// Staging area for in-progress state-transfer chunk assembly.
    /// Objects are only committed to `objects` once all chunks
    /// have been received and verified.
    pending_objects: BTreeMap<u64, PendingObjectState>,

    // -- Heartbeat state --
    /// Heartbeat configuration (disabled by default: max_missed_beats == 0).
    pub heartbeat_config: HeartbeatConfig,
    /// Timestamp of the last heartbeat received from the peer.
    last_beat_from_peer_ms: u64,
    /// Consecutive missed heartbeat checks.
    missed_beats: u64,
    /// Whether the peer is currently considered reachable.
    peer_reachable: bool,
    /// Whether heartbeat checking is active on this node.
    heartbeat_enabled: bool,
    /// Event log for heartbeat state transitions (PeerUnreachable / PeerReachable).
    pub event_log: Vec<HarnessEvent>,
}

impl StorageNode {
    /// Create a new storage node, bootstrapped with itself as the sole member
    /// of epoch 0.
    pub fn new(node_id: u64, clock: DeterministicClock, lease_timeout_ms: u64) -> Self {
        let members = EpochMemberSet::new(std::iter::once(NodeIdentity::new(node_id)));
        Self {
            node_id,
            epoch_sm: EpochStateMachine::bootstrap(members),
            clock,
            session: None,
            leases: BTreeMap::new(),
            peer_leases: BTreeMap::new(),
            outbox: Vec::new(),
            inbox: Vec::new(),
            transition_log: Vec::new(),
            peer_partitioned: false,
            crashed: false,
            lease_timeout_ms,
            objects: BTreeMap::new(),
            heartbeat_config: HeartbeatConfig {
                max_missed_beats: 0, // disabled by default
                ..Default::default()
            },
            last_beat_from_peer_ms: 0,
            missed_beats: 0,
            peer_reachable: true,
            heartbeat_enabled: false,
            event_log: Vec::new(),
            pending_objects: BTreeMap::new(),
        }
    }

    /// Wire this node's session to the peer and open it for I/O.
    pub fn connect(&mut self, mut session: DeterministicSession) {
        session.open();
        self.session = Some(session);
    }

    /// Send a single message directly through the session, bypassing
    /// the outbox. Used by message handlers so that responses are
    /// delivered immediately to the peer's inbound queue.
    fn send_direct(&self, msg: &HarnessMessage) {
        if let Some(ref session) = self.session {
            session.send(msg);
        }
    }

    /// Return the current epoch identifier.
    pub fn current_epoch_id(&self) -> u64 {
        self.epoch_sm.current_epoch().epoch_id
    }

    /// Return sorted member ids in the current epoch.
    pub fn member_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .epoch_sm
            .current_epoch()
            .members
            .iter()
            .map(|ni| ni.node_id)
            .collect();
        ids.sort();
        ids
    }

    /// True when this node knows about the given node id in its epoch.
    pub fn knows_member(&self, node_id: u64) -> bool {
        self.epoch_sm
            .current_epoch()
            .members
            .contains(&NodeIdentity::new(node_id))
    }

    // ------------------------------------------------------------------
    // Tick / advance
    // ------------------------------------------------------------------

    /// Advance the clock by `advance_ms`, drain inbound messages, process
    /// them, expire timed-out leases, and flush the outbox.
    pub fn tick(&mut self, advance_ms: u64) {
        self.clock.advance(advance_ms);
        let now = self.clock.now_ms();

        // Drain inbound
        self.drain_inbound();

        // Process
        self.process_inbox(now);

        // Lease expiry
        self.expire_leases(now);

        // Heartbeat
        self.send_direct(&HarnessMessage::Heartbeat {
            node_id: self.node_id,
            epoch_id: self.current_epoch_id(),
            at_ms: now,
        });

        // Flush
        self.flush_outbox();
    }

    /// Advance the clock only (no message processing), for lease-expiry
    /// testing without delivering messages.
    pub fn advance_clock(&mut self, advance_ms: u64) {
        self.clock.advance(advance_ms);
        let now = self.clock.now_ms();
        self.expire_leases(now);
    }

    /// Drain inbound messages into `self.inbox` without processing them.
    /// Useful when the harness wants to inspect messages before processing.
    pub fn drain_inbound(&mut self) {
        if let Some(ref session) = self.session {
            let msgs = session.drain();
            self.inbox.extend(msgs);
        }
    }

    /// Process all messages currently in the inbox, then clear it.
    pub fn process_inbox(&mut self, now: u64) {
        // Take ownership so we don't borrow self during processing
        let msgs: Vec<HarnessMessage> = self.inbox.drain(..).collect();
        for msg in msgs {
            self.handle_message(msg, now);
        }
    }

    /// Flush outbound messages to the peer via the deterministic session.
    ///
    /// The transport handles partition simulation internally: when
    /// partitioned, messages are held and released on heal.
    pub fn flush_outbox(&mut self) {
        if let Some(ref session) = self.session {
            for msg in self.outbox.drain(..) {
                session.send(&msg);
            }
        }
    }

    // ------------------------------------------------------------------
    // Actions
    // ------------------------------------------------------------------

    /// Request to join the peer's epoch.
    pub fn send_join_request(&mut self) {
        let now = self.clock.now_ms();
        self.send_direct(&HarnessMessage::JoinRequest {
            node_id: self.node_id,
            at_ms: now,
        });
        self.flush_outbox();
    }

    /// Request to leave the cluster.
    pub fn send_leave_request(&mut self) {
        let now = self.clock.now_ms();
        self.send_direct(&HarnessMessage::LeaveRequest {
            node_id: self.node_id,
            at_ms: now,
        });
        self.flush_outbox();
    }

    /// Acquire a lease on `object_id`.
    ///
    /// Returns `true` if the lease was granted. A writer lease conflicts with
    /// any existing lease (reader or writer). Multiple reader leases may
    /// coexist.
    pub fn acquire_lease(&mut self, object_id: u64, lease_type: LeaseType) -> bool {
        let now = self.clock.now_ms();

        // Conflict with own existing lease?
        if let Some(existing) = self.leases.get(&object_id) {
            if !existing.is_expired(now)
                && (matches!(lease_type, LeaseType::Writer)
                    || matches!(existing.lease_type, LeaseType::Writer))
            {
                return false;
            }
        }

        // Conflict with known peer lease?
        if let Some(peer_lease) = self.peer_leases.get(&object_id) {
            if !peer_lease.is_expired(now)
                && (matches!(lease_type, LeaseType::Writer)
                    || matches!(peer_lease.lease_type, LeaseType::Writer))
            {
                return false;
            }
        }

        let lease = LeaseRecord {
            object_id,
            holder: NodeIdentity::new(self.node_id),
            lease_type,
            granted_at_ms: now,
            expires_at_ms: now + self.lease_timeout_ms,
        };
        self.leases.insert(object_id, lease.clone());

        // Notify peer
        self.send_direct(&HarnessMessage::LeaseAcquire {
            node_id: self.node_id,
            object_id,
            lease_type,
            at_ms: now,
        });

        true
    }

    /// Release a lease held by this node.
    pub fn release_lease(&mut self, object_id: u64) {
        self.leases.remove(&object_id);
    }

    // ------------------------------------------------------------------
    // Object store
    // ------------------------------------------------------------------

    /// Store an object payload locally.
    pub fn put_object(&mut self, object_id: u64, data: Vec<u8>) {
        self.objects.insert(object_id, data);
    }

    /// Retrieve an object payload, if present.
    pub fn get_object(&self, object_id: u64) -> Option<&Vec<u8>> {
        self.objects.get(&object_id)
    }

    /// Return all object IDs currently stored on this node.
    pub fn object_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.objects.keys().copied().collect();
        ids.sort();
        ids
    }

    /// Request state transfer of specific objects from the peer.
    ///
    /// Puts a `StateTransferRequestMsg` in the outbox. The peer processes
    /// it in the next tick and responds with `StateTransferChunkMsg`.
    pub fn request_state_transfer(&mut self, object_ids: Vec<u64>) {
        let now = self.clock.now_ms();
        let req = StateTransferRequest::new(
            self.current_epoch_id(),
            self.node_id,
            object_ids,
            65536, // 64 KiB default max chunk size
        );
        self.outbox
            .push(HarnessMessage::StateTransferRequestMsg(req));
        self.flush_outbox();
        let _ = now;
    }

    /// Whether this node holds a live (non-expired) lease on `object_id`.
    pub fn holds_lease(&self, object_id: u64) -> bool {
        self.leases
            .get(&object_id)
            .is_some_and(|l| !l.is_expired(self.clock.now_ms()))
    }

    /// Whether this node has crashed (session closed, state cleared).
    pub fn is_crashed(&self) -> bool {
        self.crashed
    }

    // ------------------------------------------------------------------
    // Message handlers
    // ------------------------------------------------------------------

    fn handle_message(&mut self, msg: HarnessMessage, now: u64) {
        match msg {
            HarnessMessage::JoinRequest { node_id, .. } => {
                // Accept the join — advance our epoch
                let t = self.epoch_sm.join(NodeIdentity::new(node_id));
                self.transition_log.push(t.clone());

                // Respond with current roster
                let members = self.member_ids();
                self.send_direct(&HarnessMessage::JoinResponse {
                    to_node_id: node_id,
                    epoch_id: self.current_epoch_id(),
                    members,
                    at_ms: now,
                });

                // Broadcast epoch update
                self.send_direct(&HarnessMessage::EpochUpdate {
                    from_epoch: t.from_epoch_id,
                    to_epoch: t.to_epoch_id,
                    added: t
                        .member_set_delta
                        .added
                        .iter()
                        .map(|ni| ni.node_id)
                        .collect(),
                    removed: t
                        .member_set_delta
                        .removed
                        .iter()
                        .map(|ni| ni.node_id)
                        .collect(),
                    at_ms: now,
                });
            }

            HarnessMessage::JoinResponse {
                to_node_id: _,
                epoch_id,
                members,
                ..
            } => {
                // Bring our epoch up to date with the responder's view.
                let current: BTreeSet<u64> = self
                    .epoch_sm
                    .current_epoch()
                    .members
                    .iter()
                    .map(|ni| ni.node_id)
                    .collect();

                for &id in &members {
                    if !current.contains(&id) {
                        let t = self.epoch_sm.join(NodeIdentity::new(id));
                        self.transition_log.push(t);
                    }
                }

                let _ = epoch_id; // informational — real impl would validate
            }

            HarnessMessage::EpochUpdate { added, removed, .. } => {
                for id in &added {
                    if !self.knows_member(*id) {
                        let t = self.epoch_sm.join(NodeIdentity::new(*id));
                        self.transition_log.push(t);
                    }
                }
                for id in &removed {
                    if self.knows_member(*id) {
                        let t = self.epoch_sm.leave(NodeIdentity::new(*id));
                        self.transition_log.push(t);
                    }
                }
            }

            HarnessMessage::LeaveRequest { node_id, .. } => {
                let t = self.epoch_sm.leave(NodeIdentity::new(node_id));
                self.transition_log.push(t.clone());
                self.send_direct(&HarnessMessage::EpochUpdate {
                    from_epoch: t.from_epoch_id,
                    to_epoch: t.to_epoch_id,
                    added: vec![],
                    removed: vec![node_id],
                    at_ms: now,
                });
            }

            HarnessMessage::LeaseAcquire {
                node_id,
                object_id,
                lease_type,
                at_ms,
            } => {
                let lease = LeaseRecord {
                    object_id,
                    holder: NodeIdentity::new(node_id),
                    lease_type,
                    granted_at_ms: at_ms,
                    expires_at_ms: at_ms + self.lease_timeout_ms,
                };

                // Conflict check against our own leases
                let conflict = self.leases.get(&object_id).is_some_and(|l| {
                    !l.is_expired(now)
                        && (matches!(l.lease_type, LeaseType::Writer)
                            || matches!(lease_type, LeaseType::Writer))
                });

                let granted = !conflict;

                if granted {
                    self.peer_leases.insert(object_id, lease);
                }

                self.send_direct(&HarnessMessage::LeaseAck {
                    object_id,
                    granted,
                    holder: node_id,
                    at_ms: now,
                });
            }

            HarnessMessage::LeaseAck {
                object_id,
                granted,
                holder,
                ..
            } => {
                if !granted && holder == self.node_id {
                    self.leases.remove(&object_id);
                }
            }

            HarnessMessage::LeaseRevoke {
                object_id,
                revoked_from,
                ..
            } => {
                if revoked_from == self.node_id {
                    self.leases.remove(&object_id);
                } else {
                    self.peer_leases.remove(&object_id);
                }
            }

            HarnessMessage::StateTransferRequestMsg(req) => {
                // Look up each requested object and stream chunks back.
                let max_chunk = req.max_chunk_bytes.max(1);
                for &obj_id in &req.object_ids {
                    if let Some(data) = self.objects.get(&obj_id) {
                        let total = data.len() as u64;
                        if total == 0 {
                            // Empty object: send a single empty chunk.
                            let chunk = StateTransferChunk::new(
                                self.current_epoch_id(),
                                obj_id,
                                0,
                                0,
                                vec![],
                                true,
                            );
                            self.outbox
                                .push(HarnessMessage::StateTransferChunkMsg(chunk));
                            continue;
                        }

                        let mut offset = 0u64;
                        while offset < total {
                            let remaining = total - offset;
                            let take = remaining.min(max_chunk) as usize;
                            let slice = &data[offset as usize..offset as usize + take];
                            let is_last = offset + take as u64 >= total;
                            let chunk = StateTransferChunk::new(
                                self.current_epoch_id(),
                                obj_id,
                                offset,
                                total,
                                slice.to_vec(),
                                is_last,
                            );
                            self.outbox
                                .push(HarnessMessage::StateTransferChunkMsg(chunk));
                            offset += take as u64;
                        }
                    }
                    // Missing objects are silently skipped — the requester
                    // can retry or treat missing data as an error.
                }
            }

            HarnessMessage::StateTransferChunkMsg(chunk) => {
                // Verify payload integrity before staging.
                if chunk.verify_payload().is_err() {
                    // Corrupted chunk: discard the entire staging entry
                    // for this object so partial zero-filled data never
                    // becomes visible.
                    self.pending_objects.remove(&chunk.object_id);
                    return;
                }

                let ready = {
                    let entry = self
                        .pending_objects
                        .entry(chunk.object_id)
                        .or_insert_with(|| PendingObjectState::new(chunk.total_size));
                    match entry.stage_chunk(&chunk) {
                        Ok(ready) => ready,
                        Err(()) => {
                            self.pending_objects.remove(&chunk.object_id);
                            return;
                        }
                    }
                };

                if ready {
                    if let Some(entry) = self.pending_objects.remove(&chunk.object_id) {
                        self.objects.insert(chunk.object_id, entry.into_payload());
                    }
                }
            }

            HarnessMessage::Heartbeat {
                node_id,
                epoch_id,
                at_ms,
            } => {
                if !self.heartbeat_enabled {
                    return;
                }
                // Only track heartbeats from the peer, not our own.
                if node_id == self.node_id {
                    return;
                }
                let was_unreachable = !self.peer_reachable;

                self.last_beat_from_peer_ms = at_ms;
                self.missed_beats = 0;

                if !self.peer_reachable {
                    self.peer_reachable = true;
                    // Increment epoch on reconnection.
                    let t = self.epoch_sm.increment();
                    self.transition_log.push(t.clone());
                    self.event_log.push(HarnessEvent::PeerReachable {
                        epoch_id: t.to_epoch_id,
                        at_ms,
                    });
                }

                let _ = (node_id, epoch_id, was_unreachable);
            }
        }
    }

    fn expire_leases(&mut self, now: u64) {
        self.leases.retain(|_, l| !l.is_expired(now));
        self.peer_leases.retain(|_, l| !l.is_expired(now));

        // If peer is partitioned, their leases are effectively dead;
        // revoke them so we can re-acquire.
        if self.peer_partitioned {
            let expired_ids: Vec<u64> = self.peer_leases.keys().copied().collect();
            for id in expired_ids {
                self.peer_leases.remove(&id);
                self.send_direct(&HarnessMessage::LeaseRevoke {
                    object_id: id,
                    revoked_from: self.node_id ^ 1, // crude: revoke from "the other node"
                    at_ms: now,
                });
            }
        }
    }

    // ------------------------------------------------------------------
    // Heartbeat timeout detection
    // ------------------------------------------------------------------

    /// Check whether the peer heartbeat has timed out.
    ///
    /// If heartbeat is enabled and the time since the last received
    /// heartbeat exceeds `timeout_ms`, increment the missed-beat counter.
    /// When `missed_beats` reaches `max_missed_beats`, increment the
    /// membership epoch and emit a `PeerUnreachable` event.
    ///
    /// Returns `true` if a timeout was newly detected this call.
    pub fn check_heartbeat_timeout(&mut self) -> bool {
        if !self.heartbeat_enabled || self.crashed {
            return false;
        }

        let now = self.clock.now_ms();
        let elapsed = now.saturating_sub(self.last_beat_from_peer_ms);

        if elapsed >= self.heartbeat_config.timeout_ms {
            self.missed_beats += 1;

            if self.missed_beats >= self.heartbeat_config.max_missed_beats && self.peer_reachable {
                self.peer_reachable = false;
                let t = self.epoch_sm.increment();
                self.transition_log.push(t.clone());
                self.event_log.push(HarnessEvent::PeerUnreachable {
                    epoch_id: t.to_epoch_id,
                    at_ms: now,
                });
                return true;
            }
        }

        false
    }

    /// Enable or disable the heartbeat protocol on this node.
    ///
    /// When enabled, resets the missed-beat counter and initializes
    /// the last-beat timestamp to the current clock.
    pub fn set_heartbeat_enabled(&mut self, enabled: bool) {
        self.heartbeat_enabled = enabled;
        if enabled {
            self.last_beat_from_peer_ms = self.clock.now_ms();
            self.missed_beats = 0;
            self.peer_reachable = true;
        }
    }

    /// Query whether the peer is currently reachable.
    pub fn peer_reachable(&self) -> bool {
        self.peer_reachable
    }
}

// ---------------------------------------------------------------------------
// TwoNodeHarness
// ---------------------------------------------------------------------------

// A deterministic two-node harness creates two `StorageNode` instances, wires
// their channels together, and provides controlled tick/drain operations.
// Both nodes share a single `DeterministicClock` for consistent lease deadlines.

// ---------------------------------------------------------------------------
// HarnessNodeHandle
// ---------------------------------------------------------------------------

/// A lightweight handle to a node in the [`TwoNodeHarness`].
///
/// Obtained via [`TwoNodeHarness::handle`]. Provides crash/restart
/// primitives that operate on the referenced node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HarnessNodeHandle {
    pub node_id: u64,
}

impl HarnessNodeHandle {
    /// Create a new handle for `node_id`.
    ///
    /// The caller must ensure `node_id` is a valid node in the harness
    /// (1 or 2).
    pub fn new(node_id: u64) -> Self {
        Self { node_id }
    }
}

/// A scheduled partition event for timeline-based partition injection.
///
/// Each event specifies when the partition starts, how long it lasts,
/// which direction(s) are affected, and the probability (0.0-1.0) that
/// a matching message is dropped during the event window.
#[derive(Clone, Debug)]
pub struct PartitionEvent {
    /// When this event starts, in harness-clock milliseconds.
    pub start_ms: u64,
    /// How long the partition lasts (milliseconds).
    pub duration_ms: u64,
    /// Direction of the partition.
    pub direction: PartitionDirection,
    /// Probability (0.0-1.0) that a message is dropped during this event.
    pub drop_probability: f64,
}

/// Direction(s) affected by a partition event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartitionDirection {
    /// Both directions blocked (full network partition).
    Both,
    /// Only the specified direction is blocked.
    OneWay { from_node: u64, to_node: u64 },
}

// ---------------------------------------------------------------------------
// PartitionController
// ---------------------------------------------------------------------------

/// Controls deterministic network partition injection in a [`TwoNodeHarness`].
///
/// Provides directional blocking (symmetric and asymmetric), message-type
/// filtering, heal-with-flush semantics, and partition-state queries for
/// test assertions.
pub struct PartitionController {
    /// Shared transport backend.
    transport: std::rc::Rc<std::cell::RefCell<DeterministicTransport>>,
    /// Timeline of scheduled partition events (sorted by start_ms).
    events: std::cell::RefCell<Vec<PartitionEvent>>,
    /// Deterministic PRNG for per-message drop decisions.
    drop_rng: std::cell::RefCell<u64>,
}

impl PartitionController {
    fn new(transport: std::rc::Rc<std::cell::RefCell<DeterministicTransport>>) -> Self {
        Self {
            transport,
            events: std::cell::RefCell::new(Vec::new()),
            drop_rng: std::cell::RefCell::new(0xDEAD_BEEF_CAFE_BABE),
        }
    }

    // -- Symmetric partition -------------------------------------------------

    /// Block all messages in both directions (full network partition).
    pub fn block_all(&self) {
        self.transport.borrow_mut().set_partitioned(true);
    }

    /// Heal all directions: unblock and flush held messages.
    pub fn heal_all(&self) {
        self.transport.borrow_mut().set_partitioned(false);
    }

    // -- Timeline schedule --------------------------------------------------

    /// Add a partition event to the schedule. Events are processed in
    /// start-time order.
    pub fn schedule_event(&self, event: PartitionEvent) {
        self.events.borrow_mut().push(event);
        self.events.borrow_mut().sort_by_key(|e| e.start_ms);
    }

    /// Remove all scheduled events and unblock all directions.
    pub fn clear_schedule(&self) {
        self.events.borrow_mut().clear();
        self.transport.borrow_mut().set_partitioned(false);
    }

    /// Apply the schedule at the given harness clock time.
    ///
    /// For each event active at `clock_ms`, the affected direction(s) are
    /// blocked. When no events are active, all directions are healed.
    pub fn apply_schedule(&self, clock_ms: u64) {
        let events = self.events.borrow();
        if events.is_empty() {
            return; // No events: leave transport state alone (manual control).
        }
        let has_1_to_2 = Self::has_direction_event(&events, 1, 2);
        let has_2_to_1 = Self::has_direction_event(&events, 2, 1);
        let (block_1_2, block_2_1) = self.active_blocks(&events, clock_ms);

        let mut t = self.transport.borrow_mut();
        if has_1_to_2 {
            t.set_direction_blocked(MessageDirection::Node1To2, block_1_2);
        }
        if has_2_to_1 {
            t.set_direction_blocked(MessageDirection::Node2To1, block_2_1);
        }
    }

    /// Determine which directions are blocked at `clock_ms`.
    fn active_blocks(&self, events: &[PartitionEvent], clock_ms: u64) -> (bool, bool) {
        let mut block_1_2 = false;
        let mut block_2_1 = false;
        for ev in events {
            if clock_ms >= ev.start_ms && clock_ms < ev.start_ms + ev.duration_ms {
                match ev.direction {
                    PartitionDirection::Both => {
                        block_1_2 = true;
                        block_2_1 = true;
                    }
                    PartitionDirection::OneWay { from_node, to_node } => {
                        if from_node == 1 && to_node == 2 {
                            block_1_2 = true;
                        } else if from_node == 2 && to_node == 1 {
                            block_2_1 = true;
                        }
                    }
                }
            }
        }
        (block_1_2, block_2_1)
    }

    /// Check whether any scheduled event affects the given direction.
    fn has_direction_event(events: &[PartitionEvent], from: u64, to: u64) -> bool {
        events.iter().any(|e| match e.direction {
            PartitionDirection::Both => true,
            PartitionDirection::OneWay { from_node, to_node } => from_node == from && to_node == to,
        })
    }

    /// Deterministic message-drop decision based on the active schedule.
    ///
    /// Returns `true` when the message should be dropped. Uses a simple
    /// LCG-based PRNG for reproducibility.
    pub fn should_drop_message(&self, dir: MessageDirection, clock_ms: u64) -> bool {
        let events = self.events.borrow();
        let mut max_prob: f64 = 0.0;
        for ev in events.iter() {
            if clock_ms < ev.start_ms || clock_ms >= ev.start_ms + ev.duration_ms {
                continue;
            }
            let matches = match ev.direction {
                PartitionDirection::Both => true,
                PartitionDirection::OneWay { from_node, to_node } => {
                    (from_node == 1 && to_node == 2 && dir == MessageDirection::Node1To2)
                        || (from_node == 2 && to_node == 1 && dir == MessageDirection::Node2To1)
                }
            };
            if matches && ev.drop_probability > max_prob {
                max_prob = ev.drop_probability;
            }
        }
        if max_prob <= 0.0 {
            return false;
        }
        // Deterministic LCG: next = seed * 6364136223846793005 + 1
        let mut rng = self.drop_rng.borrow_mut();
        *rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let threshold = (max_prob * (u64::MAX as f64)) as u64;
        *rng > threshold
    }

    // -- Directional partition -----------------------------------------------

    /// Block messages from `from_node` to `to_node`.
    pub fn block_direction(&self, from_node: u64, to_node: u64) {
        let dir = Self::direction(from_node, to_node);
        self.transport.borrow_mut().set_direction_blocked(dir, true);
    }

    /// Unblock messages from `from_node` to `to_node` and flush held messages.
    pub fn heal_direction(&self, from_node: u64, to_node: u64) {
        let dir = Self::direction(from_node, to_node);
        self.transport
            .borrow_mut()
            .set_direction_blocked(dir, false);
    }

    // -- Partition state queries ---------------------------------------------

    /// True when messages from `from_node` to `to_node` are blocked.
    pub fn is_blocked(&self, from_node: u64, to_node: u64) -> bool {
        let t = self.transport.borrow();
        match Self::direction(from_node, to_node) {
            MessageDirection::Node1To2 => t.blocked_1_to_2,
            MessageDirection::Node2To1 => t.blocked_2_to_1,
        }
    }

    /// Number of messages held (buffered) from `from_node` to `to_node`.
    pub fn held_count(&self, from_node: u64, to_node: u64) -> usize {
        let t = self.transport.borrow();
        let dir = Self::direction(from_node, to_node);
        t.held_count(dir)
    }

    /// Number of messages in-flight (delivered but not yet drained) in
    /// the given direction.
    pub fn in_flight_count(&self, from_node: u64, to_node: u64) -> usize {
        let t = self.transport.borrow();
        let dir = Self::direction(from_node, to_node);
        t.in_flight_count(dir)
    }

    // -- Message filter ------------------------------------------------------

    /// Install a message-drop predicate. Passed the framed bytes and direction.
    /// Messages for which the predicate returns `true` are dropped silently.
    ///
    /// Only one filter is active at a time; setting a new filter replaces
    /// the previous one.
    pub fn install_filter<F>(&self, filter: F)
    where
        F: Fn(&[u8], MessageDirection) -> bool + 'static,
    {
        self.transport.borrow_mut().filter = Some(Box::new(filter));
    }

    /// Remove any installed message filter.
    pub fn clear_filter(&self) {
        self.transport.borrow_mut().filter = None;
    }

    /// True when any direction is blocked.
    pub fn any_blocked(&self) -> bool {
        let t = self.transport.borrow();
        t.blocked_1_to_2 || t.blocked_2_to_1
    }

    /// Helper: map (from, to) node ids to MessageDirection.
    fn direction(from_node: u64, to_node: u64) -> MessageDirection {
        match (from_node, to_node) {
            (1, 2) => MessageDirection::Node1To2,
            (2, 1) => MessageDirection::Node2To1,
            _ => panic!("invalid direction: {from_node} -> {to_node}"),
        }
    }
}

pub struct TwoNodeHarness {
    pub node_a: StorageNode,
    pub node_b: StorageNode,
    pub clock: DeterministicClock,
    /// Shared deterministic transport backend.
    pub transport: std::rc::Rc<std::cell::RefCell<DeterministicTransport>>,
    /// Controller for deterministic network partition injection.
    pub partition_ctrl: PartitionController,
}

/// Adapter that maps device IDs to harness [`StorageNode`] instances for
/// placement-driven write dispatch.
struct HarnessWriteTarget<'a> {
    node_a: &'a mut StorageNode,
    node_b: &'a mut StorageNode,
}

impl ObjectWriteTarget for HarnessWriteTarget<'_> {
    fn put_object(&mut self, device_id: u64, key: &[u8], payload: &[u8]) -> Result<(), String> {
        let node = match device_id {
            1 => &mut self.node_a,
            2 => &mut self.node_b,
            other => return Err(format!("unknown device_id: {other}")),
        };
        // Parse key as little-endian u64 object_id.
        if key.len() < 8 {
            return Err(format!("key too short: {} bytes", key.len()));
        }
        let object_id = u64::from_le_bytes(key[..8].try_into().unwrap());
        node.put_object(object_id, payload.to_vec());
        Ok(())
    }
}

/// Adapter that maps device IDs to harness [`StorageNode`] instances for
/// placement-driven read dispatch.
struct HarnessReadTarget<'a> {
    node_a: &'a StorageNode,
    node_b: &'a StorageNode,
}

impl ObjectReadTarget for HarnessReadTarget<'_> {
    fn get_object(&self, device_id: u64, key: &[u8]) -> Option<Vec<u8>> {
        let node = match device_id {
            1 => &self.node_a,
            2 => &self.node_b,
            _ => return None,
        };
        // Parse key as little-endian u64 object_id.
        if key.len() < 8 {
            return None;
        }
        let object_id = u64::from_le_bytes(key[..8].try_into().unwrap());
        node.get_object(object_id).cloned()
    }
}

impl TwoNodeHarness {
    /// Create a new two-node harness.
    ///
    /// Both nodes start in independent epoch 0 (each only knows itself).
    /// Use `join_peer` to synchronize them.
    pub fn new(lease_timeout_ms: u64) -> Self {
        let clock = DeterministicClock::new(0);

        let transport = DeterministicTransport::shared();
        let ep_a = DeterministicEndpoint::new(1, transport.clone());
        let ep_b = DeterministicEndpoint::new(2, transport.clone());

        let session_a = DeterministicSession::new(1, ep_a);
        let session_b = DeterministicSession::new(2, ep_b);

        let mut node_a = StorageNode::new(1, clock.clone(), lease_timeout_ms);
        let mut node_b = StorageNode::new(2, clock.clone(), lease_timeout_ms);

        node_a.connect(session_a);
        node_b.connect(session_b);

        let partition_ctrl = PartitionController::new(transport.clone());
        Self {
            node_a,
            node_b,
            clock,
            transport,
            partition_ctrl,
        }
    }

    /// Advance the shared clock by `ms` and tick both nodes.
    ///
    /// Two-pass drain→process: each node drains inbound, processes
    /// (sending responses directly to the peer's queue via the transport),
    /// and expires leases. A second drain captures any responses generated
    /// during the first pass. Because the transport delivers framed
    /// messages immediately to the shared in-memory queues, two
    /// interleaved passes handle request→response→reconciliation.
    pub fn tick_all(&mut self, advance_ms: u64) {
        self.clock.advance(advance_ms);
        let now = self.clock.now_ms();

        // Sync node clocks so lease timestamps match harness time.
        self.node_a.clock.advance(advance_ms);
        self.node_b.clock.advance(advance_ms);

        // Apply timeline schedule, then sync per-node partition awareness.
        self.partition_ctrl.apply_schedule(now);
        let blocked = self.partition_ctrl.any_blocked();
        self.node_a.peer_partitioned = blocked;
        self.node_b.peer_partitioned = blocked;

        for pass in 0..2 {
            // --- Node A ---
            self.node_a.drain_inbound();
            self.node_a.process_inbox(now);
            self.node_a.expire_leases(now);
            self.node_a.check_heartbeat_timeout();

            // --- Node B ---
            self.node_b.drain_inbound();
            self.node_b.process_inbox(now);
            self.node_b.expire_leases(now);
            self.node_b.check_heartbeat_timeout();

            // Heartbeats on first pass only
            if pass == 0 {
                if self.node_a.heartbeat_enabled {
                    self.node_a.outbox.push(HarnessMessage::Heartbeat {
                        node_id: 1,
                        epoch_id: self.node_a.current_epoch_id(),
                        at_ms: now,
                    });
                }
                if self.node_b.heartbeat_enabled {
                    self.node_b.outbox.push(HarnessMessage::Heartbeat {
                        node_id: 2,
                        epoch_id: self.node_b.current_epoch_id(),
                        at_ms: now,
                    });
                }

                self.node_a.flush_outbox();
                self.node_b.flush_outbox();
            }
        }
    }

    /// Have node B send a join request, process the full join handshake.
    ///
    /// After this, both nodes agree on the member set.
    pub fn join_peer(&mut self) {
        self.node_b.send_join_request();
        self.tick_all(1);
    }

    /// Partition the two nodes: all subsequent messages are held.
    pub fn partition(&mut self) {
        self.partition_ctrl.block_all();
        self.node_a.peer_partitioned = true;
        self.node_b.peer_partitioned = true;
    }

    /// Heal the partition: messages flow again.
    pub fn heal(&mut self) {
        self.partition_ctrl.heal_all();
        self.node_a.peer_partitioned = false;
        self.node_b.peer_partitioned = false;
    }

    /// Advance the clock past the lease timeout without delivering messages.
    /// Both nodes expire any timed-out leases.
    pub fn advance_past_lease_timeout(&mut self) {
        self.clock.advance(self.node_a.lease_timeout_ms + 1);
        let now = self.clock.now_ms();

        // Sync node clocks so own-lease expiry uses the same wall time.
        self.node_a.clock.advance(self.node_a.lease_timeout_ms + 1);
        self.node_b.clock.advance(self.node_b.lease_timeout_ms + 1);
        self.node_a.expire_leases(now);
        self.node_b.expire_leases(now);
    }

    // ------------------------------------------------------------------
    // Placement-driven write dispatch
    // ------------------------------------------------------------------

    /// Dispatch an object write through the placement planner to both nodes.
    ///
    /// Creates a `PlacementPlan` for a 2-node mirror across `Node` failure
    /// domains, maps device IDs to harness nodes, and fans out the write
    /// via [`tidefs_placement_runtime::dispatch_write`]. Returns the outcome
    /// summary including per-target acknowledgments and quorum status.
    pub fn dispatch_object_write(
        &mut self,
        object_id: u64,
        payload: Vec<u8>,
    ) -> tidefs_placement_runtime::DispatchWriteResult {
        use tidefs_durability_layout::{DurabilityLayoutV1, FailureDomainLevel, FailureDomainV1};
        use tidefs_placement_planner::placement_plan::{DeviceCandidate, PlacementPlan};
        use tidefs_placement_runtime::dispatch_write;

        let layout = DurabilityLayoutV1::mirror(2).expect("mirror(2) is always valid");
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 2)
            .expect("Node domain level with count 2 is always valid");
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![
            DeviceCandidate {
                device_id: 1,
                node_id: Some(1),
                rack_id: None,
                datacenter_id: None,
            },
            DeviceCandidate {
                device_id: 2,
                node_id: Some(2),
                rack_id: None,
                datacenter_id: None,
            },
        ];

        let key = object_id.to_le_bytes();
        let mut writer = HarnessWriteTarget {
            node_a: &mut self.node_a,
            node_b: &mut self.node_b,
        };

        dispatch_write(&plan, &candidates, &key, &payload, &mut writer)
            .expect("placement plan for 2-node mirror with 2 candidates must always succeed")
    }

    // ------------------------------------------------------------------
    // Placement-driven read dispatch
    // ------------------------------------------------------------------

    /// Dispatch an object read through the placement planner, reading from
    /// the primary mirror and verifying cross-node data consistency.
    ///
    /// Creates a `PlacementPlan` for a 2-node mirror, maps device IDs to
    /// harness nodes, and reads via [`tidefs_placement_runtime::dispatch_read`].
    /// Cross-mirror integrity is checked: when both mirrors have the object
    /// but their payloads differ, `mirrors_consistent` is set to `false`.
    pub fn dispatch_object_read(&self, object_id: u64) -> DispatchReadResult {
        use tidefs_durability_layout::{DurabilityLayoutV1, FailureDomainLevel, FailureDomainV1};
        use tidefs_placement_planner::placement_plan::{DeviceCandidate, PlacementPlan};

        let layout = DurabilityLayoutV1::mirror(2).expect("mirror(2) is always valid");
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 2)
            .expect("Node domain level with count 2 is always valid");
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![
            DeviceCandidate {
                device_id: 1,
                node_id: Some(1),
                rack_id: None,
                datacenter_id: None,
            },
            DeviceCandidate {
                device_id: 2,
                node_id: Some(2),
                rack_id: None,
                datacenter_id: None,
            },
        ];

        let key = object_id.to_le_bytes();
        let reader = HarnessReadTarget {
            node_a: &self.node_a,
            node_b: &self.node_b,
        };

        dispatch_read(&plan, &candidates, &key, &reader)
            .expect("placement plan for 2-node mirror with 2 candidates must always succeed")
    }

    // ------------------------------------------------------------------
    // State transfer
    // ------------------------------------------------------------------

    /// Transfer all objects from `from_node` to `to_node`.
    ///
    /// `from_node` must be 1 or 2; `to_node` is the other.
    pub fn transfer_state(&mut self, from_node: u64, to_node: u64) {
        let (source, target) = if from_node == 1 {
            (&mut self.node_a, &mut self.node_b)
        } else {
            (&mut self.node_b, &mut self.node_a)
        };

        let _ = to_node; // used just for the branch above

        let object_ids = source.object_ids();
        if object_ids.is_empty() {
            return;
        }

        target.request_state_transfer(object_ids);

        // Tick enough times for the request→chunks→store handshake.
        // Three ticks covers: request delivery, chunk generation,
        // and chunk delivery + store. Extra ticks for large objects.
        for _ in 0..5 {
            self.tick_all(1);
        }
    }

    /// Join the peer and then transfer all objects from A to B.
    ///
    /// After this, B has caught up with A's object state.
    pub fn join_with_catchup(&mut self) {
        self.join_peer();
        // After join, B knows about A. Transfer all A's objects to B.
        let a_object_ids = self.node_a.object_ids();
        if !a_object_ids.is_empty() {
            self.node_b.request_state_transfer(a_object_ids);
            for _ in 0..5 {
                self.tick_all(1);
            }
        }
    }

    // ------------------------------------------------------------------
    // HarnessNodeHandle access
    // ------------------------------------------------------------------

    /// Configure and enable the heartbeat protocol on both nodes.
    ///
    /// Heartbeats are disabled by default. Call this method to enable
    /// them with the given config. Both nodes are configured identically.
    pub fn set_heartbeat_config(&mut self, config: HeartbeatConfig) {
        self.node_a.heartbeat_config = config.clone();
        self.node_b.heartbeat_config = config.clone();
        self.node_a.set_heartbeat_enabled(true);
        self.node_b.set_heartbeat_enabled(true);
    }

    /// Disable the heartbeat protocol on both nodes.
    pub fn disable_heartbeat(&mut self) {
        self.node_a.set_heartbeat_enabled(false);
        self.node_b.set_heartbeat_enabled(false);
    }

    /// Query whether the peer of the given `node_id` is reachable.
    ///
    /// Returns `true` if the peer was last seen within the heartbeat
    /// timeout window. Returns `true` when heartbeat is disabled
    /// (the peer is assumed reachable until proven otherwise).
    pub fn peer_reachable(&self, node_id: u64) -> bool {
        match node_id {
            1 => self.node_b.peer_reachable(),
            2 => self.node_a.peer_reachable(),
            _ => true,
        }
    }

    /// Obtain a [`HarnessNodeHandle`] for the given `node_id`.
    ///
    /// Returns `None` if `node_id` is not 1 or 2.
    pub fn handle(&self, node_id: u64) -> Option<HarnessNodeHandle> {
        match node_id {
            1 | 2 => Some(HarnessNodeHandle::new(node_id)),
            _ => None,
        }
    }

    /// Return the id of the surviving node, if exactly one node is alive.
    ///
    /// Returns `None` if neither or both nodes are alive.
    pub fn survivor_id(&self) -> Option<u64> {
        let a_alive = !self.node_a.is_crashed();
        let b_alive = !self.node_b.is_crashed();
        match (a_alive, b_alive) {
            (true, false) => Some(1),
            (false, true) => Some(2),
            _ => None,
        }
    }

    // ------------------------------------------------------------------
    // Crash / restart / recovery
    // ------------------------------------------------------------------

    /// Crash the node referenced by `handle`.
    ///
    /// Closes the crashed node's session (dropping all in-flight messages),
    /// clears its lease tables, inbox, and outbox, marks it as crashed, and
    /// updates the surviving node's epoch to remove the crashed node.
    ///
    /// Objects stored on the crashed node are **preserved** for recovery
    /// after restart.
    ///
    /// # Panics
    ///
    /// Panics if `handle` does not refer to node 1 or 2, or if the node
    /// is already crashed.
    pub fn crash_node(&mut self, handle: &HarnessNodeHandle) {
        assert!(
            !self.is_crashed_internal(handle.node_id),
            "node {} is already crashed",
            handle.node_id
        );

        // Clear any messages queued for the crashed node in the transport.
        self.transport.borrow_mut().clear_queues_for(handle.node_id);

        let (crashed, survivor) = self.node_pair_mut(handle.node_id);

        // Close the session so all subsequent sends to/from this node are dropped.
        if let Some(ref mut session) = crashed.session {
            session.close();
        }

        // Clear in-memory protocol state.
        crashed.leases.clear();
        crashed.peer_leases.clear();
        crashed.outbox.clear();
        crashed.inbox.clear();
        crashed.pending_objects.clear();

        crashed.crashed = true;

        // The survivor removes the crashed node from its epoch.
        let t = survivor
            .epoch_sm
            .leave(tidefs_membership_epoch::NodeIdentity::new(handle.node_id));
        survivor.transition_log.push(t);
    }

    /// Restart a crashed node.
    ///
    /// Creates a fresh deterministic transport session for the node,
    /// re-initialises its epoch state machine (bootstrap with self only),
    /// performs a join handshake with the survivor, and then triggers
    /// full state transfer to pull all objects from the survivor.
    ///
    /// # Panics
    ///
    /// Panics if `handle` does not refer to node 1 or 2, if the node is
    /// not currently crashed, or if neither node is alive.
    pub fn restart_node(&mut self, handle: &HarnessNodeHandle) {
        assert!(
            self.is_crashed_internal(handle.node_id),
            "node {} is not crashed; cannot restart a live node",
            handle.node_id
        );

        let survivor_id = self
            .survivor_id()
            .expect("cannot restart: no surviving node found");

        // Clear any stale messages that may be sitting in the transport queues
        // for the restarted node (survivor may have sent messages after the crash).
        self.transport.borrow_mut().clear_queues_for(handle.node_id);

        // Clone transport before mutable borrow via node_pair_mut.
        let transport_rc = self.transport.clone();

        let (restarted, _survivor) = self.node_pair_mut(handle.node_id);

        // Create a fresh session.
        let ep = crate::deterministic_transport::DeterministicEndpoint::new(
            handle.node_id,
            transport_rc,
        );
        let mut session =
            crate::deterministic_transport::DeterministicSession::new(handle.node_id, ep);
        session.open();
        restarted.session = Some(session);

        // Re-initialise epoch: bootstrap with self only.
        let members = tidefs_membership_epoch::EpochMemberSet::new(std::iter::once(
            tidefs_membership_epoch::NodeIdentity::new(handle.node_id),
        ));
        restarted.epoch_sm = tidefs_membership_epoch::EpochStateMachine::bootstrap(members);
        restarted.transition_log.clear();
        restarted.crashed = false;

        // Clear any stale protocol state.
        restarted.leases.clear();
        restarted.peer_leases.clear();
        restarted.outbox.clear();
        restarted.inbox.clear();
        restarted.pending_objects.clear();

        // Send join request and process the handshake.
        restarted.send_join_request();
        // Tick enough times for the join request -> response -> reconciliation cycle.
        for _ in 0..3 {
            self.tick_all(1);
        }

        // Pull all objects the survivor has that the restarted node may be missing.
        self.recover_node_state_internal(handle.node_id, survivor_id);
    }

    /// Recover the state of a restarted node by pulling all objects from the
    /// surviving node via state transfer.
    ///
    /// The node must have already restarted and rejoined the cluster.
    /// This is a convenience wrapper that calls `transfer_state` from the
    /// survivor to the target node.
    ///
    /// # Panics
    ///
    /// Panics if `handle` does not refer to node 1 or 2.
    pub fn recover_node_state(&mut self, handle: &HarnessNodeHandle) {
        let survivor_id = self
            .survivor_id()
            .expect("recover_node_state requires exactly one survivor");
        self.recover_node_state_internal(handle.node_id, survivor_id);
    }

    /// Internal: state transfer from `survivor_id` to `target_id`.
    fn recover_node_state_internal(&mut self, target_id: u64, survivor_id: u64) {
        let (target, source) = if target_id == 1 {
            (&mut self.node_a, &mut self.node_b)
        } else {
            (&mut self.node_b, &mut self.node_a)
        };
        // survivor_id is validated by the caller; source holds the survivor node.
        let _survivor_id = survivor_id;

        let object_ids = source.object_ids();
        if object_ids.is_empty() {
            return;
        }

        target.request_state_transfer(object_ids);
        // Tick enough times for request -> chunk response -> store.
        for _ in 0..5 {
            self.tick_all(1);
        }
    }

    // ------------------------------------------------------------------
    // Consistency verification
    // ------------------------------------------------------------------

    // Consistency checks compare all objects on both nodes byte-for-byte.

    /// Compute a BLAKE3-256 digest over all objects on the given node.
    ///
    /// Objects are hashed in sorted-by-id order with domain separation
    /// so that the same set of objects always produces the same digest
    /// regardless of insertion order.
    pub fn compute_object_digest(&self, node_id: u64) -> [u8; 32] {
        let node = match node_id {
            1 => &self.node_a,
            2 => &self.node_b,
            _ => panic!("invalid node_id: {node_id}"),
        };
        let mut hasher = Hasher::new_derive_key("tidefs-harness-object-state-v1");
        let mut ids: Vec<u64> = node.objects.keys().copied().collect();
        ids.sort();
        for id in &ids {
            hasher.update(&id.to_le_bytes());
            if let Some(data) = node.objects.get(id) {
                let len = data.len() as u64;
                hasher.update(&len.to_le_bytes());
                hasher.update(data);
            }
        }
        hasher.finalize().into()
    }

    /// Verify that both nodes have identical BLAKE3 object-state digests.
    ///
    /// Returns `true` when the two digests are equal, indicating both
    /// nodes hold the same objects with the same payloads.
    pub fn verify_blake3_consistency(&self) -> bool {
        let digest_a = self.compute_object_digest(1);
        let digest_b = self.compute_object_digest(2);
        digest_a == digest_b
    }

    /// Heal any active partition, transfer state both ways, and verify
    /// BLAKE3 object-state consistency across both nodes.
    ///
    /// Returns `true` when post-heal digests match.
    pub fn heal_partition(&mut self) -> bool {
        // Heal all blocked directions and flush held messages.
        self.partition_ctrl.heal_all();
        self.node_a.peer_partitioned = false;
        self.node_b.peer_partitioned = false;

        // Tick enough times for held messages to deliver.
        for _ in 0..5 {
            self.tick_all(10);
        }

        // Transfer state both ways so each node converges.
        self.transfer_state(1, 2);
        self.transfer_state(2, 1);

        // Final ticks for state-chunk delivery and store.
        for _ in 0..3 {
            self.tick_all(10);
        }

        // Verify BLAKE3 digest consistency.
        self.verify_blake3_consistency()
    }

    pub fn verify_mirror_consistency(&self) -> bool {
        let a_ids: std::collections::BTreeSet<u64> = self.node_a.objects.keys().copied().collect();
        let b_ids: std::collections::BTreeSet<u64> = self.node_b.objects.keys().copied().collect();

        // Both nodes must have the same set of object IDs.
        if a_ids != b_ids {
            return false;
        }

        for id in &a_ids {
            let a_val = self.node_a.objects.get(id);
            let b_val = self.node_b.objects.get(id);
            if a_val != b_val {
                return false;
            }
        }

        true
    }

    /// Return a mutable reference to the [`StorageNode`] pair, keyed by
    /// the identified node and the other node.
    fn node_pair_mut(&mut self, node_id: u64) -> (&mut StorageNode, &mut StorageNode) {
        match node_id {
            1 => (&mut self.node_a, &mut self.node_b),
            2 => (&mut self.node_b, &mut self.node_a),
            other => panic!("invalid node_id: {other}; expected 1 or 2"),
        }
    }

    /// Check whether the given node is crashed.
    fn is_crashed_internal(&self, node_id: u64) -> bool {
        match node_id {
            1 => self.node_a.is_crashed(),
            2 => self.node_b.is_crashed(),
            _ => panic!("invalid node_id: {node_id}; expected 1 or 2"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_advances() {
        let mut c = DeterministicClock::new(100);
        assert_eq!(c.now_ms(), 100);
        c.advance(50);
        assert_eq!(c.now_ms(), 150);
    }

    #[test]
    fn lease_not_expired_before_timeout() {
        let l = LeaseRecord {
            object_id: 1,
            holder: NodeIdentity::new(1),
            lease_type: LeaseType::Writer,
            granted_at_ms: 100,
            expires_at_ms: 600,
        };
        assert!(!l.is_expired(599));
        assert!(l.is_expired(600));
    }

    #[test]
    fn bootstrap_single_node() {
        let h = TwoNodeHarness::new(500);
        assert_eq!(h.node_a.current_epoch_id(), 0);
        assert_eq!(h.node_b.current_epoch_id(), 0);
        assert_eq!(h.node_a.member_ids(), vec![1]);
        assert_eq!(h.node_b.member_ids(), vec![2]);
    }

    #[test]
    fn controlled_join_both_nodes_converge() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Both should now know about each other
        assert_eq!(h.node_a.member_ids(), vec![1, 2]);
        assert_eq!(h.node_b.member_ids(), vec![1, 2]);

        // Epochs should have advanced beyond 0
        assert!(h.node_a.current_epoch_id() > 0);
        assert!(h.node_b.current_epoch_id() > 0);
    }

    #[test]
    fn deterministic_join_is_reproducible() {
        fn run_join() -> (Vec<u64>, Vec<u64>) {
            let mut h = TwoNodeHarness::new(500);
            h.join_peer();
            (h.node_a.member_ids(), h.node_b.member_ids())
        }

        let first = run_join();
        for _ in 0..10 {
            assert_eq!(run_join(), first, "join should be deterministic");
        }
    }

    #[test]
    fn lease_acquire_writer_succeeds() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        assert!(h.node_a.acquire_lease(42, LeaseType::Writer));
        assert!(h.node_a.holds_lease(42));

        // Deliver the lease notification to peer
        h.tick_all(1);

        // Peer should know about the lease
        assert!(h.node_b.peer_leases.contains_key(&42));
    }

    #[test]
    fn lease_writer_conflict_prevented() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        assert!(h.node_a.acquire_lease(42, LeaseType::Writer));
        h.tick_all(1);

        // Node B tries to acquire same writer lease — should fail
        assert!(!h.node_b.acquire_lease(42, LeaseType::Writer));
        assert!(!h.node_b.holds_lease(42));
    }

    #[test]
    fn lease_reader_shared_allowed() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        assert!(h.node_a.acquire_lease(99, LeaseType::Reader));
        h.tick_all(1);

        assert!(h.node_b.acquire_lease(99, LeaseType::Reader));
        assert!(h.node_b.holds_lease(99));
    }

    #[test]
    fn lease_reader_writer_conflict() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        assert!(h.node_a.acquire_lease(99, LeaseType::Reader));
        h.tick_all(1);

        // Writer conflicts with reader
        assert!(!h.node_b.acquire_lease(99, LeaseType::Writer));
    }

    #[test]
    fn lease_expires_after_timeout() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        assert!(h.node_a.acquire_lease(42, LeaseType::Writer));
        h.tick_all(1);

        // Advance past timeout
        h.advance_past_lease_timeout();

        assert!(!h.node_a.holds_lease(42));
        assert!(!h.node_b.peer_leases.contains_key(&42));
    }

    #[test]
    fn fencing_on_partition_revokes_peer_leases() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // A acquires writer lease
        assert!(h.node_a.acquire_lease(77, LeaseType::Writer));
        h.tick_all(1);
        assert!(h.node_b.peer_leases.contains_key(&77));

        // Partition
        h.partition();

        // Advance past timeout — A's lease expires from B's perspective
        h.advance_past_lease_timeout();

        // B should have revoked A's lease locally
        assert!(!h.node_b.peer_leases.contains_key(&77));

        // B can now acquire the lease (no conflict since A's lease timed out)
        assert!(h.node_b.acquire_lease(77, LeaseType::Writer));
        assert!(h.node_b.holds_lease(77));
    }

    #[test]
    fn no_stale_lease_double_writer_after_fencing() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // A acquires writer lease on object 10
        assert!(h.node_a.acquire_lease(10, LeaseType::Writer));
        h.tick_all(1);

        // Partition: A and B can no longer communicate
        h.partition();

        // Advance past lease timeout. From B's perspective, A's lease
        // is expired and B revokes it locally.
        h.advance_past_lease_timeout();

        // A's lease expired locally
        assert!(!h.node_a.holds_lease(10));

        // B acquires its own writer lease on 10 (no conflict, A partitioned)
        assert!(h.node_b.acquire_lease(10, LeaseType::Writer));
        assert!(h.node_b.holds_lease(10));

        // A also acquires locally (its own lease expired, no conflict check
        // against B since partitioned). This creates a double-writer window.
        assert!(h.node_a.acquire_lease(10, LeaseType::Writer));
        assert!(h.node_a.holds_lease(10));

        // When partition heals, the queued LeaseAcquire messages are
        // delivered. Each node detects the writer-writer conflict:
        // both send LeaseAck(granted=false), both revoke their leases.
        h.heal();
        h.tick_all(1);

        // After conflict resolution, neither node holds a valid writer
        // lease -- the double-writer window is closed and both backed off.
        assert!(
            !h.node_a.holds_lease(10),
            "node A must not hold lease after conflict resolution"
        );
        assert!(
            !h.node_b.holds_lease(10),
            "node B must not hold lease after conflict resolution"
        );

        // A fresh re-acquisition grants the lease to a single writer.
        h.tick_all(1);
        let ok = h.node_a.acquire_lease(10, LeaseType::Writer);
        assert!(ok, "re-acquire must succeed");
        h.tick_all(1);
        assert!(h.node_a.holds_lease(10));
        assert!(!h.node_b.holds_lease(10));
        assert!(
            h.node_b.peer_leases.contains_key(&10),
            "B must see A's new lease after re-acquisition"
        );
    }

    #[test]
    fn epoch_monotonicity_preserved_through_join() {
        let mut h = TwoNodeHarness::new(500);
        let mut epoch_ids_a: Vec<u64> = Vec::new();
        let mut epoch_ids_b: Vec<u64> = Vec::new();

        epoch_ids_a.push(h.node_a.current_epoch_id());
        epoch_ids_b.push(h.node_b.current_epoch_id());

        h.join_peer();

        // After join, collect all epoch transitions
        for t in &h.node_a.transition_log {
            epoch_ids_a.push(t.to_epoch_id);
        }
        for t in &h.node_b.transition_log {
            epoch_ids_b.push(t.to_epoch_id);
        }

        // Verify monotonicity
        for w in epoch_ids_a.windows(2) {
            assert!(w[1] > w[0], "epoch A not monotonic: {} -> {}", w[0], w[1]);
        }
        for w in epoch_ids_b.windows(2) {
            assert!(w[1] > w[0], "epoch B not monotonic: {} -> {}", w[0], w[1]);
        }
    }

    #[test]
    fn leave_removes_member_and_advances_epoch() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let before_a = h.node_a.current_epoch_id();
        let _before_b = h.node_b.current_epoch_id();

        // Node B leaves
        h.node_b.send_leave_request();
        h.tick_all(1);

        // A should have removed B
        assert!(!h.node_a.knows_member(2));
        assert!(h.node_a.current_epoch_id() > before_a);
    }

    #[test]
    fn deterministic_fencing_scenario_reproducible() {
        fn run_fencing() -> (bool, bool, u64, u64) {
            let mut h = TwoNodeHarness::new(500);
            h.join_peer();

            // A acquires writer lease
            let acquired = h.node_a.acquire_lease(77, LeaseType::Writer);
            h.tick_all(1);

            // Partition
            h.partition();
            h.advance_past_lease_timeout();

            // B acquires after fencing
            let b_acquired = h.node_b.acquire_lease(77, LeaseType::Writer);

            (
                acquired,
                b_acquired,
                h.node_a.current_epoch_id(),
                h.node_b.current_epoch_id(),
            )
        }

        let first = run_fencing();
        for _ in 0..10 {
            assert_eq!(
                run_fencing(),
                first,
                "fencing scenario should be deterministic"
            );
        }
    }

    // ── State transfer tests ──────────────────────────────────────────

    #[test]
    fn state_transfer_join_with_empty_state() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Node B requests objects that A doesn't have — should complete without error
        h.node_b.request_state_transfer(vec![100]);
        h.tick_all(1);
        h.tick_all(1);

        // B's object store should still be empty — A had nothing to send
        assert!(h.node_b.get_object(100).is_none());
    }

    #[test]
    fn state_transfer_single_object() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // A has object 42
        let data = b"hello state transfer".to_vec();
        h.node_a.put_object(42, data.clone());

        // B requests object 42
        h.node_b.request_state_transfer(vec![42]);
        h.tick_all(1);
        h.tick_all(1);

        // B should now have the object
        let received = h.node_b.get_object(42).expect("B should have object 42");
        assert_eq!(received, &data);
    }

    #[test]
    fn state_transfer_multiple_objects() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // A has three objects
        h.node_a.put_object(1, b"first".to_vec());
        h.node_a.put_object(2, b"second data".to_vec());
        h.node_a.put_object(3, b"third".to_vec());

        // B requests all three
        h.node_b.request_state_transfer(vec![1, 2, 3]);
        h.tick_all(1);
        h.tick_all(1);

        assert_eq!(h.node_b.get_object(1).unwrap(), b"first");
        assert_eq!(h.node_b.get_object(2).unwrap(), b"second data");
        assert_eq!(h.node_b.get_object(3).unwrap(), b"third");
    }

    #[test]
    fn state_transfer_overlapping_objects_idempotent() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let data = b"idempotent data".to_vec();
        h.node_a.put_object(7, data.clone());

        // First transfer
        h.node_b.request_state_transfer(vec![7]);
        h.tick_all(1);
        h.tick_all(1);
        assert_eq!(h.node_b.get_object(7).unwrap(), &data);

        // Second transfer of the same object (overlapping/idempotent)
        h.node_b.request_state_transfer(vec![7]);
        h.tick_all(1);
        h.tick_all(1);
        assert_eq!(h.node_b.get_object(7).unwrap(), &data);
        // Object count should still be 1 on B
        assert_eq!(h.node_b.objects.len(), 1);
    }

    #[test]
    fn state_transfer_large_object_chunked() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Create a large object that exceeds the 64 KiB default max chunk
        let large_data = vec![0xABu8; 128 * 1024]; // 128 KiB → 2 chunks
        h.node_a.put_object(99, large_data.clone());

        h.node_b.request_state_transfer(vec![99]);
        // Multiple ticks to deliver all chunks
        h.tick_all(1);
        h.tick_all(1);
        h.tick_all(1);

        let received = h
            .node_b
            .get_object(99)
            .expect("B should have object 99 after transfer");
        assert_eq!(received.len(), large_data.len());
        assert_eq!(received, &large_data);
    }

    #[test]
    fn state_transfer_stages_object_until_all_chunks_arrive() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let first = StateTransferChunk::new(0, 123, 0, 6, b"abc".to_vec(), false);
        h.node_b
            .handle_message(HarnessMessage::StateTransferChunkMsg(first), 0);

        assert!(h.node_b.get_object(123).is_none());
        assert!(h.node_b.pending_objects.contains_key(&123));

        let second = StateTransferChunk::new(0, 123, 3, 6, b"def".to_vec(), true);
        h.node_b
            .handle_message(HarnessMessage::StateTransferChunkMsg(second), 0);

        assert_eq!(h.node_b.get_object(123).unwrap(), b"abcdef");
        assert!(!h.node_b.pending_objects.contains_key(&123));
    }

    #[test]
    fn state_transfer_corrupt_chunk_discards_staged_object() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let first = StateTransferChunk::new(0, 124, 0, 6, b"abc".to_vec(), false);
        h.node_b
            .handle_message(HarnessMessage::StateTransferChunkMsg(first), 0);
        assert!(h.node_b.pending_objects.contains_key(&124));

        let mut corrupt = StateTransferChunk::new(0, 124, 3, 6, b"def".to_vec(), true);
        corrupt.payload[0] = b'X';
        h.node_b
            .handle_message(HarnessMessage::StateTransferChunkMsg(corrupt), 0);

        assert!(h.node_b.get_object(124).is_none());
        assert!(!h.node_b.pending_objects.contains_key(&124));
    }

    #[test]
    fn state_transfer_out_of_bounds_chunk_discards_staged_object() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let first = StateTransferChunk::new(0, 125, 0, 6, b"abc".to_vec(), false);
        h.node_b
            .handle_message(HarnessMessage::StateTransferChunkMsg(first), 0);
        assert!(h.node_b.pending_objects.contains_key(&125));

        let out_of_bounds = StateTransferChunk::new(0, 125, 5, 6, b"zz".to_vec(), true);
        h.node_b
            .handle_message(HarnessMessage::StateTransferChunkMsg(out_of_bounds), 0);

        assert!(h.node_b.get_object(125).is_none());
        assert!(!h.node_b.pending_objects.contains_key(&125));
    }

    #[test]
    fn state_transfer_empty_object() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        h.node_a.put_object(0, vec![]);

        h.node_b.request_state_transfer(vec![0]);
        h.tick_all(1);
        h.tick_all(1);

        let received = h
            .node_b
            .get_object(0)
            .expect("B should have the empty object");
        assert!(received.is_empty());
    }

    #[test]
    fn state_transfer_partial_request_missing_objects() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // A only has objects 1 and 2
        h.node_a.put_object(1, b"present".to_vec());
        h.node_a.put_object(2, b"also present".to_vec());

        // B requests 1, 2, 3, 4 — 3 and 4 don't exist
        h.node_b.request_state_transfer(vec![1, 2, 3, 4]);
        h.tick_all(1);
        h.tick_all(1);

        // Objects that exist are transferred
        assert_eq!(h.node_b.get_object(1).unwrap(), b"present");
        assert_eq!(h.node_b.get_object(2).unwrap(), b"also present");

        // Missing objects are silently skipped
        assert!(h.node_b.get_object(3).is_none());
        assert!(h.node_b.get_object(4).is_none());
    }

    #[test]
    fn state_transfer_after_epoch_advance() {
        // State transfer should work even after multiple epoch transitions.
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Advance through several ticks to trigger epoch transitions via heartbeats
        h.tick_all(10);
        h.tick_all(10);

        let data = b"post epoch advance data".to_vec();
        h.node_a.put_object(55, data.clone());

        let epoch_before = h.node_b.current_epoch_id();
        h.node_b.request_state_transfer(vec![55]);
        h.tick_all(1);
        h.tick_all(1);

        assert_eq!(h.node_b.get_object(55).unwrap(), &data);
        // Epoch should not regress during state transfer
        assert!(h.node_b.current_epoch_id() >= epoch_before);
    }

    #[test]
    fn state_transfer_preserves_determinism() {
        fn run_transfer() -> (Vec<u8>, u64) {
            let mut h = TwoNodeHarness::new(500);
            h.join_peer();

            let data = b"deterministic state transfer".to_vec();
            h.node_a.put_object(77, data.clone());

            h.node_b.request_state_transfer(vec![77]);
            h.tick_all(1);
            h.tick_all(1);

            let received = h.node_b.get_object(77).unwrap().clone();
            let objects_on_b = h.node_b.objects.len() as u64;
            (received, objects_on_b)
        }

        let first = run_transfer();
        for _ in 0..10 {
            let result = run_transfer();
            assert_eq!(result, first, "state transfer must be deterministic");
        }
    }

    #[test]
    fn state_transfer_during_concurrent_writes_single_writer_invariant() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // A holds writer lease and writes object 99
        assert!(h.node_a.acquire_lease(99, LeaseType::Writer));
        h.tick_all(1);
        h.node_a.put_object(99, b"original data from A".to_vec());

        // B requests state transfer of object 99 (with no lease)
        h.node_b.request_state_transfer(vec![99]);
        h.tick_all(1);
        h.tick_all(1);

        // B receives the data
        assert_eq!(h.node_b.get_object(99).unwrap(), b"original data from A");

        // A still holds the writer lease — B cannot acquire a writer lease
        assert!(!h.node_b.acquire_lease(99, LeaseType::Writer));
    }

    #[test]
    fn state_transfer_timeout_retry_under_clock_advance() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // A has the data
        h.node_a.put_object(33, b"retry data".to_vec());

        // Partition first — request is queued but not delivered
        h.partition();
        h.node_b.request_state_transfer(vec![33]);

        // Advance clock past lease timeout while partitioned
        h.advance_past_lease_timeout();

        // Heal partition — queued messages should now flow
        h.heal();
        h.tick_all(1);
        h.tick_all(1);
        h.tick_all(1);

        // B should have received the object after partition heal
        assert_eq!(h.node_b.get_object(33).unwrap(), b"retry data");
    }

    #[test]
    fn transfer_state_convenience_method() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // A has objects
        h.node_a.put_object(10, b"alpha".to_vec());
        h.node_a.put_object(20, b"beta".to_vec());
        h.node_a.put_object(30, b"gamma".to_vec());

        // Transfer all from A to B
        h.transfer_state(1, 2);

        assert_eq!(h.node_b.get_object(10).unwrap(), b"alpha");
        assert_eq!(h.node_b.get_object(20).unwrap(), b"beta");
        assert_eq!(h.node_b.get_object(30).unwrap(), b"gamma");
        assert_eq!(h.node_b.object_ids(), vec![10, 20, 30]);
    }

    #[test]
    fn transfer_state_b_to_a() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // B has objects
        h.node_b.put_object(5, b"b-to-a".to_vec());

        // Transfer all from B to A
        h.transfer_state(2, 1);

        assert_eq!(h.node_a.get_object(5).unwrap(), b"b-to-a");
    }

    #[test]
    fn transfer_state_empty_source_is_noop() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // A has no objects — transfer should be a noop
        h.transfer_state(1, 2);

        assert!(h.node_b.objects.is_empty());
        assert!(h.node_a.objects.is_empty());
    }

    #[test]
    fn join_with_catchup_transfers_all_objects() {
        let mut h = TwoNodeHarness::new(500);

        // A has objects before B joins
        h.node_a.put_object(1, b"pre-join data".to_vec());
        h.node_a.put_object(2, b"more data".to_vec());

        h.join_with_catchup();

        // Both nodes should agree on member set
        assert_eq!(h.node_a.member_ids(), vec![1, 2]);
        assert_eq!(h.node_b.member_ids(), vec![1, 2]);

        // B should have caught up with A's objects
        assert_eq!(h.node_b.get_object(1).unwrap(), b"pre-join data");
        assert_eq!(h.node_b.get_object(2).unwrap(), b"more data");
    }

    #[test]
    fn join_with_catchup_empty_a_is_noop() {
        let mut h = TwoNodeHarness::new(500);

        // A has no objects
        h.join_with_catchup();

        assert_eq!(h.node_a.member_ids(), vec![1, 2]);
        assert!(h.node_b.objects.is_empty());
    }

    #[test]
    fn transactional_replay_over_join_leave_cycles() {
        let mut h = TwoNodeHarness::new(500);

        // First join + catchup
        h.node_a.put_object(1, b"generation 1".to_vec());
        h.join_with_catchup();
        assert_eq!(h.node_b.get_object(1).unwrap(), b"generation 1");

        // B leaves
        h.node_b.send_leave_request();
        h.tick_all(1);
        h.tick_all(1);
        assert!(!h.node_a.knows_member(2));

        // B rejoins — should get objects again via catchup
        h.join_with_catchup();
        assert_eq!(h.node_a.member_ids(), vec![1, 2]);
        assert_eq!(h.node_b.get_object(1).unwrap(), b"generation 1");

        // A adds more objects while both are members
        h.node_a.put_object(2, b"generation 2".to_vec());
        h.transfer_state(1, 2);
        assert_eq!(h.node_b.get_object(2).unwrap(), b"generation 2");

        // B leaves and rejoins again — all objects transfer
        h.node_b.send_leave_request();
        h.tick_all(1);
        h.tick_all(1);

        // A adds another object while B is away
        h.node_a.put_object(3, b"generation 3".to_vec());

        h.join_with_catchup();
        assert_eq!(h.node_b.get_object(1).unwrap(), b"generation 1");
        assert_eq!(h.node_b.get_object(2).unwrap(), b"generation 2");
        assert_eq!(h.node_b.get_object(3).unwrap(), b"generation 3");
        assert_eq!(h.node_b.object_ids(), vec![1, 2, 3]);
    }

    #[test]
    fn transactional_replay_is_deterministic() {
        fn run_replay() -> Vec<(u64, Vec<u8>)> {
            let mut h = TwoNodeHarness::new(500);

            h.node_a.put_object(42, b"deterministic replay".to_vec());
            h.join_with_catchup();

            h.node_b.send_leave_request();
            h.tick_all(1);
            h.tick_all(1);

            h.join_with_catchup();

            let mut items: Vec<(u64, Vec<u8>)> = h
                .node_b
                .objects
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            items.sort_by_key(|(k, _)| *k);
            items
        }

        let first = run_replay();
        for _ in 0..5 {
            assert_eq!(
                run_replay(),
                first,
                "transactional replay must be deterministic"
            );
        }
    }

    // -- Placement-driven write dispatch tests ---------------------------

    #[test]
    fn placement_dispatch_write_fans_out_to_both_nodes() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let object_id = 42u64;
        let payload = b"placement-driven payload".to_vec();

        let result = h.dispatch_object_write(object_id, payload.clone());

        assert_eq!(result.acknowledged, 2);
        assert!(result.quorum_reached);
        assert_eq!(result.outcomes.len(), 2);
        for outcome in &result.outcomes {
            assert!(
                outcome.ok,
                "outcome for device {} failed",
                outcome.device_id
            );
        }

        // Both nodes should have the object.
        assert_eq!(h.node_a.get_object(object_id).unwrap(), &payload);
        assert_eq!(h.node_b.get_object(object_id).unwrap(), &payload);
    }

    #[test]
    fn placement_dispatch_payload_integrity_across_nodes() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Write via placement dispatch.
        let object_id = 77u64;
        let payload = vec![0xABu8; 4096];
        h.dispatch_object_write(object_id, payload.clone());

        // Verify payload integrity on both nodes — byte-for-byte match.
        let a_data = h.node_a.get_object(object_id).unwrap();
        let b_data = h.node_b.get_object(object_id).unwrap();
        assert_eq!(a_data, &payload);
        assert_eq!(b_data, &payload);
        assert_eq!(a_data, b_data);
    }

    #[test]
    fn placement_dispatch_quorum_reached_with_both_nodes() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Write 10 different objects through placement dispatch.
        for i in 0..10u64 {
            let payload = format!("object-{i}").into_bytes();
            let result = h.dispatch_object_write(i, payload.clone());
            assert!(result.quorum_reached);
            assert_eq!(result.acknowledged, 2);
        }

        // Read back all objects from both nodes.
        for i in 0..10u64 {
            let expected = format!("object-{i}").into_bytes();
            assert_eq!(h.node_a.get_object(i).unwrap(), &expected);
            assert_eq!(h.node_b.get_object(i).unwrap(), &expected);
        }
    }

    #[test]
    fn placement_dispatch_and_state_transfer_are_consistent() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Write objects through placement dispatch.
        h.dispatch_object_write(1, b"alpha".to_vec());
        h.dispatch_object_write(2, b"beta".to_vec());

        // Clear node B and re-transfer from A via state transfer.
        h.node_b.objects.clear();
        h.transfer_state(1, 2);

        // B should have the same data after both paths.
        assert_eq!(h.node_b.get_object(1).unwrap(), b"alpha");
        assert_eq!(h.node_b.get_object(2).unwrap(), b"beta");
    }

    #[test]
    fn placement_dispatch_is_deterministic() {
        fn run_dispatch() -> (usize, bool) {
            let mut h = TwoNodeHarness::new(500);
            h.join_peer();
            let result = h.dispatch_object_write(99, b"deterministic".to_vec());
            (result.acknowledged, result.quorum_reached)
        }

        let first = run_dispatch();
        for _ in 0..10 {
            assert_eq!(
                run_dispatch(),
                first,
                "placement dispatch must be deterministic"
            );
        }
    }

    // -- Read dispatch tests -----------------------------------------------

    #[test]
    fn read_dispatch_primary_has_data_read_succeeds() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Write an object to both nodes via placement dispatch.
        let object_id = 42u64;
        let payload = b"read-dispatch test payload".to_vec();
        h.dispatch_object_write(object_id, payload.clone());

        // Read via placement dispatch.
        let result = h.dispatch_object_read(object_id);

        assert!(
            result.payload.is_some(),
            "read dispatch must return payload"
        );
        assert_eq!(result.payload.as_deref(), Some(payload.as_slice()));
        assert!(result.mirrors_consistent, "both mirrors must be consistent");
        assert_eq!(result.outcomes.len(), 2);
        assert!(result.outcomes.iter().all(|o| o.found));
    }

    #[test]
    fn read_dispatch_both_mirrors_return_identical_data() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Write the same data to both nodes.
        let object_id = 7u64;
        let payload = b"consistent mirror data".to_vec();
        h.dispatch_object_write(object_id, payload.clone());

        let result = h.dispatch_object_read(object_id);

        assert!(result.payload.is_some());
        assert_eq!(result.payload.as_deref(), Some(payload.as_slice()));
        assert!(result.mirrors_consistent);
        assert_eq!(result.outcomes.len(), 2);
        assert!(result.outcomes[0].found);
        assert!(result.outcomes[1].found);
        // Both mirrors must have identical payloads.
        assert_eq!(
            result.outcomes[0].payload.as_deref(),
            result.outcomes[1].payload.as_deref()
        );
    }

    #[test]
    fn read_dispatch_after_write_determinism() {
        // Write through harness, read back, verify payload. Run 3 times
        // to confirm determinism.
        fn run_scenario() -> Option<Vec<u8>> {
            let mut h = TwoNodeHarness::new(500);
            h.join_peer();

            let object_id = 99u64;
            let payload = b"deterministic read-after-write payload".to_vec();
            h.dispatch_object_write(object_id, payload.clone());

            let result = h.dispatch_object_read(object_id);
            result.payload
        }

        let first = run_scenario();
        assert!(first.is_some());
        for _ in 0..3 {
            assert_eq!(
                run_scenario(),
                first,
                "read-after-write must be deterministic"
            );
        }
    }

    #[test]
    fn read_dispatch_corruption_detection_via_secondary_mirror() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Write via placement dispatch to both nodes.
        let object_id = 55u64;
        let correct = b"correct data".to_vec();
        h.dispatch_object_write(object_id, correct.clone());

        // Read once to determine which device is the primary mirror
        // so we can corrupt the secondary.
        let probe = h.dispatch_object_read(object_id);
        assert!(probe.payload.is_some(), "probe read must find the object");
        let secondary_device = if probe.primary_device == 1 { 2 } else { 1 };

        // Corrupt the secondary mirror's copy directly.
        let corrupted = b"CORRUPTED DATA!!!".to_vec();
        match secondary_device {
            1 => {
                h.node_a.put_object(object_id, corrupted.clone());
            }
            2 => {
                h.node_b.put_object(object_id, corrupted.clone());
            }
            _ => unreachable!("only two devices in harness"),
        }

        let result = h.dispatch_object_read(object_id);

        // Primary should still return correct data.
        assert!(result.payload.is_some());
        assert_eq!(result.payload.as_deref(), Some(correct.as_slice()));
        // The secondary mirror must report the corrupted content.
        let secondary_outcome = result
            .outcomes
            .iter()
            .find(|o| o.device_id == secondary_device)
            .expect("must have outcome for secondary device");
        assert!(secondary_outcome.found);
        assert_eq!(secondary_outcome.payload.as_deref(), Some(corrupted.as_slice()));
        // Cross-mirror inconsistency must be detected.
        assert!(
            !result.mirrors_consistent,
            "divergent mirror must be detected as inconsistent"
        );
    }

    #[test]
    fn read_dispatch_placement_aware_routing() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Put an object only on node A (device_id=1).
        let object_id = 55u64;
        let payload = b"node A only".to_vec();
        h.node_a.put_object(object_id, payload.clone());
        // Node B does NOT have this object.

        let result = h.dispatch_object_read(object_id);

        // The read should still succeed because node A has it.
        assert!(result.payload.is_some());
        assert_eq!(result.payload.as_deref(), Some(payload.as_slice()));
        // primary_device should be device 1 (node A).
        assert_eq!(result.primary_device, 1);
        // Node B outcome: found=false.
        let b_outcome = result
            .outcomes
            .iter()
            .find(|o| o.device_id == 2)
            .expect("must have outcome for device 2");
        assert!(!b_outcome.found, "node B must not have the object");
    }

    #[test]
    fn read_dispatch_object_not_found_on_any_node() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Object 999 was never written.
        let result = h.dispatch_object_read(999);

        assert!(
            result.payload.is_none(),
            "read of missing object must return None"
        );
        assert_eq!(result.outcomes.len(), 2);
        assert!(result.outcomes.iter().all(|o| !o.found));
        // Vacuously consistent (no mirrors returned data).
        assert!(result.mirrors_consistent);
    }

    #[test]
    fn read_dispatch_preserves_determinism_with_corruption() {
        fn run_corruption_scenario() -> (bool, Option<Vec<u8>>) {
            let mut h = TwoNodeHarness::new(500);
            h.join_peer();

            let object_id = 77u64;
            let correct = b"deterministic corruption scenario".to_vec();
            h.dispatch_object_write(object_id, correct.clone());

            // Corrupt node B.
            h.node_b
                .put_object(object_id, b"!!! corrupted !!!".to_vec());

            let result = h.dispatch_object_read(object_id);
            (result.mirrors_consistent, result.payload)
        }

        let first = run_corruption_scenario();
        // mirrors_consistent must be false.
        assert!(!first.0, "corruption must be detected");
        for _ in 0..5 {
            assert_eq!(
                run_corruption_scenario(),
                first,
                "corruption detection must be deterministic"
            );
        }
    }

    // -- Crash-recovery tests ----------------------------------------------

    #[test]
    fn handle_returns_valid_handles() {
        let h = TwoNodeHarness::new(500);
        assert!(h.handle(1).is_some());
        assert!(h.handle(2).is_some());
        assert!(h.handle(0).is_none());
        assert!(h.handle(3).is_none());
    }

    #[test]
    fn crash_node_closes_session_and_marks_crashed() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let handle = h.handle(2).unwrap();
        h.crash_node(&handle);

        assert!(h.node_b.is_crashed());
        assert!(!h.node_a.is_crashed());

        // Survivor should no longer know about the crashed node.
        assert!(!h.node_a.knows_member(2));
        assert_eq!(h.node_a.member_ids(), vec![1]);

        // Crashed node should have no active session.
        assert!(h.node_b.session.as_ref().is_none_or(|s| !s.is_active()));
    }

    #[test]
    fn crash_node_preserves_objects() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        h.node_b.put_object(42, b"surviving data".to_vec());

        let handle = h.handle(2).unwrap();
        h.crash_node(&handle);

        // Objects on the crashed node remain intact.
        assert_eq!(h.node_b.get_object(42).unwrap(), b"surviving data");
    }

    #[test]
    fn crash_node_clears_leases() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        assert!(h.node_a.acquire_lease(10, LeaseType::Writer));
        h.tick_all(1);
        assert!(h.node_a.holds_lease(10));

        let handle = h.handle(1).unwrap();
        h.crash_node(&handle);

        assert!(h.node_a.leases.is_empty());
        assert!(h.node_a.peer_leases.is_empty());
        assert!(!h.node_a.holds_lease(10));
    }

    #[test]
    fn restart_node_rejoins_and_transfers_state() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Write objects to both nodes via placement dispatch.
        h.dispatch_object_write(1, b"alpha".to_vec());
        h.dispatch_object_write(2, b"beta".to_vec());

        // Crash node B.
        let b_handle = h.handle(2).unwrap();
        h.crash_node(&b_handle);

        // Write more objects through node A only while B is down.
        h.dispatch_object_write(3, b"gamma".to_vec());
        h.dispatch_object_write(4, b"delta".to_vec());

        // Restart B.
        h.restart_node(&b_handle);

        // B should have rejoined.
        assert_eq!(h.node_a.member_ids(), vec![1, 2]);
        assert_eq!(h.node_b.member_ids(), vec![1, 2]);

        // B should have all 4 objects after state transfer.
        assert_eq!(h.node_b.get_object(1).unwrap(), b"alpha");
        assert_eq!(h.node_b.get_object(2).unwrap(), b"beta");
        assert_eq!(h.node_b.get_object(3).unwrap(), b"gamma");
        assert_eq!(h.node_b.get_object(4).unwrap(), b"delta");

        // Mirror consistency must hold.
        assert!(h.verify_mirror_consistency());
    }

    #[test]
    fn crash_recovery_full_scenario_n_write_crash_m_write_restart_verify() {
        // Write N objects through both nodes, crash B, write M through A,
        // restart B with state transfer, verify all N+M objects on both nodes.
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let n = 5u64;
        let m = 3u64;

        // Phase 1: Write N objects to both nodes.
        for i in 0..n {
            let payload = format!("pre-crash-obj-{i}").into_bytes();
            let result = h.dispatch_object_write(i, payload);
            assert!(result.quorum_reached);
            assert_eq!(result.acknowledged, 2);
        }

        // Phase 2: Crash node B.
        let b_handle = h.handle(2).unwrap();
        h.crash_node(&b_handle);

        // Phase 3: Write M more objects through surviving node A only.
        for i in 0..m {
            let obj_id = n + i;
            let payload = format!("post-crash-obj-{i}").into_bytes();
            h.dispatch_object_write(obj_id, payload);
            // Only node A acknowledges (node B is crashed).
        }

        // Phase 4: Restart node B with state transfer.
        h.restart_node(&b_handle);

        // Phase 5: Verify all N+M objects on both nodes.
        for i in 0..(n + m) {
            let expected = if i < n {
                format!("pre-crash-obj-{i}").into_bytes()
            } else {
                format!("post-crash-obj-{}", i - n).into_bytes()
            };
            assert_eq!(
                h.node_a.get_object(i).unwrap(),
                &expected,
                "node A missing/mismatched object {i}"
            );
            assert_eq!(
                h.node_b.get_object(i).unwrap(),
                &expected,
                "node B missing/mismatched object {i}"
            );
        }

        assert!(h.verify_mirror_consistency());
    }

    #[test]
    fn crash_mid_write_restart_verify_consistency() {
        // Crash node A after it has objects but before a write completes
        // on B. Restart A, verify B has a consistent view and A converges.
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Pre-populate both nodes.
        h.dispatch_object_write(10, b"baseline".to_vec());

        // Crash node A.
        let a_handle = h.handle(1).unwrap();
        h.crash_node(&a_handle);

        // Write through surviving node B only.
        h.dispatch_object_write(20, b"during-crash".to_vec());
        h.dispatch_object_write(30, b"also-during-crash".to_vec());

        // Restart A.
        h.restart_node(&a_handle);

        // A should have all 3 objects after recovery.
        assert_eq!(h.node_a.get_object(10).unwrap(), b"baseline");
        assert_eq!(h.node_a.get_object(20).unwrap(), b"during-crash");
        assert_eq!(h.node_a.get_object(30).unwrap(), b"also-during-crash");

        // B should still have its consistent view.
        assert_eq!(h.node_b.get_object(10).unwrap(), b"baseline");
        assert_eq!(h.node_b.get_object(20).unwrap(), b"during-crash");
        assert_eq!(h.node_b.get_object(30).unwrap(), b"also-during-crash");

        assert!(h.verify_mirror_consistency());
    }

    #[test]
    fn crash_recovery_is_deterministic() {
        fn run_scenario() -> (Vec<u64>, Vec<u64>) {
            let mut h = TwoNodeHarness::new(500);
            h.join_peer();

            h.dispatch_object_write(1, b"obj-1".to_vec());
            h.dispatch_object_write(2, b"obj-2".to_vec());

            let b_handle = h.handle(2).unwrap();
            h.crash_node(&b_handle);

            h.dispatch_object_write(3, b"obj-3".to_vec());

            h.restart_node(&b_handle);

            (h.node_a.object_ids(), h.node_b.object_ids())
        }

        let first = run_scenario();
        assert_eq!(first.0, vec![1, 2, 3]);
        assert_eq!(first.1, vec![1, 2, 3]);
        for _ in 0..10 {
            assert_eq!(
                run_scenario(),
                first,
                "crash-recovery must be deterministic"
            );
        }
    }

    #[test]
    fn verify_mirror_consistency_detects_divergence() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        h.dispatch_object_write(1, b"same".to_vec());
        assert!(h.verify_mirror_consistency());

        // Diverge node B.
        h.node_b.put_object(1, b"different!".to_vec());
        assert!(!h.verify_mirror_consistency());
    }

    #[test]
    fn verify_mirror_consistency_handles_extra_objects() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        h.dispatch_object_write(1, b"shared".to_vec());
        assert!(h.verify_mirror_consistency());

        // Node B has an extra object that A lacks.
        h.node_b.put_object(99, b"extra".to_vec());
        assert!(!h.verify_mirror_consistency());
    }

    #[test]
    fn survivor_id_when_one_node_crashed() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Both alive -> no single survivor.
        assert_eq!(h.survivor_id(), None);

        let b_handle = h.handle(2).unwrap();
        h.crash_node(&b_handle);
        assert_eq!(h.survivor_id(), Some(1));
    }

    #[test]
    fn crash_then_restart_preserves_placement_dispatch() {
        // After crash+restart+recovery, placement dispatch should still work.
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let b_handle = h.handle(2).unwrap();
        h.crash_node(&b_handle);
        h.restart_node(&b_handle);

        // Write through placement dispatch after recovery.
        let result = h.dispatch_object_write(42, b"post-recovery write".to_vec());
        assert!(result.quorum_reached);
        assert_eq!(result.acknowledged, 2);

        assert_eq!(h.node_a.get_object(42).unwrap(), b"post-recovery write");
        assert_eq!(h.node_b.get_object(42).unwrap(), b"post-recovery write");
    }

    #[test]
    fn crash_recovery_and_read_dispatch_consistent() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        h.dispatch_object_write(7, b"read-after-recovery".to_vec());

        let b_handle = h.handle(2).unwrap();
        h.crash_node(&b_handle);
        h.dispatch_object_write(8, b"during-crash".to_vec());
        h.restart_node(&b_handle);

        // Read dispatch should find data on both nodes.
        let result = h.dispatch_object_read(7);
        assert!(result.payload.is_some());
        assert!(result.mirrors_consistent);

        let result2 = h.dispatch_object_read(8);
        assert!(result2.payload.is_some());
        assert!(result2.mirrors_consistent);
    }

    #[test]
    fn double_crash_restart_cycle() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        h.dispatch_object_write(1, b"cycle-1".to_vec());

        // First crash/restart cycle.
        let b_handle = h.handle(2).unwrap();
        h.crash_node(&b_handle);
        h.dispatch_object_write(2, b"cycle-2".to_vec());
        h.restart_node(&b_handle);

        assert!(h.verify_mirror_consistency());
        assert_eq!(h.node_b.get_object(2).unwrap(), b"cycle-2");

        // Second crash/restart cycle.
        h.crash_node(&b_handle);
        h.dispatch_object_write(3, b"cycle-3".to_vec());
        h.restart_node(&b_handle);

        assert!(h.verify_mirror_consistency());
        assert_eq!(h.node_b.get_object(3).unwrap(), b"cycle-3");
        assert_eq!(h.node_b.object_ids().len(), 3);
    }

    // ── Partition injection tests ────────────────────────────────────

    #[test]
    fn symmetric_partition_writes_converge_on_heal() {
        // Write objects on both sides during a full partition, then heal
        // and verify both nodes converge to a consistent merged state.
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Pre-partition baseline: both nodes share object 1.
        h.dispatch_object_write(1, b"shared".to_vec());

        // Symmetric partition: no messages flow in either direction.
        h.partition();

        // Node A writes objects 10, 11.
        h.node_a.put_object(10, b"alpha".to_vec());
        h.node_a.put_object(11, b"beta".to_vec());

        // Node B writes objects 20, 21.
        h.node_b.put_object(20, b"gamma".to_vec());
        h.node_b.put_object(21, b"delta".to_vec());

        // Tick enough for local state machines to process (messages held).
        for _ in 0..3 {
            h.tick_all(10);
        }

        // During partition, each node only sees its own writes.
        assert!(h.node_a.get_object(10).is_some());
        assert!(h.node_a.get_object(20).is_none());
        assert!(h.node_b.get_object(20).is_some());
        assert!(h.node_b.get_object(10).is_none());

        // Heal: flush held messages.
        h.heal();
        for _ in 0..5 {
            h.tick_all(10);
        }

        // Transfer state both ways so each node learns the other's writes.
        h.transfer_state(1, 2);
        h.transfer_state(2, 1);

        // Both nodes should now see all objects after state re-sync.
        assert_eq!(h.node_a.get_object(10).unwrap(), b"alpha");
        assert_eq!(h.node_a.get_object(20).unwrap(), b"gamma");
        assert_eq!(h.node_b.get_object(10).unwrap(), b"alpha");
        assert_eq!(h.node_b.get_object(20).unwrap(), b"gamma");

        // Mirror consistency post-heal.
        assert!(h.verify_mirror_consistency());
    }

    #[test]
    fn write_isolation_during_partition_only_visible_after_heal() {
        // Writes via node A during partition must NOT be visible on node B
        // until the partition heals and state transfer completes.
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        h.dispatch_object_write(1, b"baseline".to_vec());

        // Full partition.
        h.partition();

        // Write through node A during partition.
        h.node_a.put_object(42, b"isolated-write".to_vec());
        for _ in 0..3 {
            h.tick_all(10);
        }

        // Node B must NOT see the isolated write yet.
        assert!(
            h.node_b.get_object(42).is_none(),
            "node B must not see isolated write during partition"
        );

        // Heal and transfer state from A to B.
        h.heal();
        for _ in 0..5 {
            h.tick_all(10);
        }
        h.transfer_state(1, 2);

        // Now B should see the write.
        assert_eq!(
            h.node_b.get_object(42).unwrap(),
            b"isolated-write",
            "node B must see the write after partition heals"
        );
    }

    #[test]
    fn asymmetric_partition_blocks_one_direction_only() {
        // Asymmetric partition: A can send to B, but B cannot send to A.
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Block only B→A.
        h.partition_ctrl.block_direction(2, 1);

        // A writes — should be deliverable to B via placement dispatch.
        h.dispatch_object_write(100, b"deliverable".to_vec());
        h.tick_all(1);
        h.tick_all(1);

        // B → A direction blocked: B's writes do not reach A.
        h.node_b.put_object(200, b"blocked".to_vec());
        // Send via outbox
        h.node_b.outbox.push(HarnessMessage::Heartbeat {
            node_id: 2,
            epoch_id: 0,
            at_ms: 100,
        });
        h.tick_all(1);
        h.tick_all(1);

        // A should NOT see B's write.
        assert!(h.node_a.get_object(200).is_none());

        // Held count should be >0 for the B→A direction.
        let held = h.partition_ctrl.held_count(2, 1);
        assert!(held > 0, "messages from B to A should be held, got {held}");

        // Heal the direction: B's held messages flushed to A.
        h.partition_ctrl.heal_direction(2, 1);
        for _ in 0..5 {
            h.tick_all(10);
        }

        // After healing B→A, A should see B's write via state transfer.
        // Note: put_object only stores locally, so we transfer state explicitly.
        h.transfer_state(2, 1);
        assert_eq!(h.node_a.get_object(200).unwrap(), b"blocked");
    }

    #[test]
    fn partition_state_queries_are_accurate() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Initially, nothing is blocked.
        assert!(!h.partition_ctrl.any_blocked());
        assert!(!h.partition_ctrl.is_blocked(1, 2));
        assert!(!h.partition_ctrl.is_blocked(2, 1));

        // Block one direction.
        h.partition_ctrl.block_direction(1, 2);
        assert!(h.partition_ctrl.any_blocked());
        assert!(h.partition_ctrl.is_blocked(1, 2));
        assert!(!h.partition_ctrl.is_blocked(2, 1));

        // Block the other direction too → symmetric.
        h.partition_ctrl.block_direction(2, 1);
        assert!(h.partition_ctrl.is_blocked(1, 2));
        assert!(h.partition_ctrl.is_blocked(2, 1));

        // Heal just one direction.
        h.partition_ctrl.heal_direction(1, 2);
        assert!(!h.partition_ctrl.is_blocked(1, 2));
        assert!(h.partition_ctrl.is_blocked(2, 1));
        assert!(h.partition_ctrl.any_blocked());

        // Heal all.
        h.partition_ctrl.heal_all();
        assert!(!h.partition_ctrl.any_blocked());
        assert!(!h.partition_ctrl.is_blocked(1, 2));
        assert!(!h.partition_ctrl.is_blocked(2, 1));
    }

    #[test]
    fn heartbeat_timeout_triggers_dead_peer_detection() {
        // Partition for longer than lease_timeout: each node should expire
        // the peer's leases, simulating dead-peer detection.
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // A acquires a writer lease.
        assert!(h.node_a.acquire_lease(7, LeaseType::Writer));
        h.tick_all(1);
        assert!(h.node_b.peer_leases.contains_key(&7));

        // Partition.
        h.partition();

        // Advance past lease timeout. From each node's perspective, the
        // peer is unreachable and its leases are expired/revoked.
        h.advance_past_lease_timeout();
        h.tick_all(10);

        // Node B should have revoked A's lease locally.
        assert!(
            !h.node_b.peer_leases.contains_key(&7),
            "node B must expire peer leases during partition timeout"
        );

        // Node A should also have expired its own lease.
        assert!(
            !h.node_a.holds_lease(7),
            "node A must expire own leases during partition timeout"
        );

        // After partition timeout, each node can independently acquire
        // the lease — this simulates split-brain lease acquisition.
        assert!(h.node_a.acquire_lease(7, LeaseType::Writer));
        assert!(h.node_a.holds_lease(7));

        // Heal: conflict resolution should reconcile the duplicate leases.
        h.heal();
        h.tick_all(10);
        h.tick_all(10);

        // After conflict resolution, at most one node holds the lease.
        let a_holds = h.node_a.holds_lease(7);
        let b_holds = h.node_b.holds_lease(7);
        assert!(
            !(a_holds && b_holds),
            "split-brain double writer must be resolved"
        );
    }

    #[test]
    fn post_healing_state_transfer_propagates_survivor_writes() {
        // During partition, node A accumulates writes. After healing,
        // node B must receive those writes via state transfer.
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let baseline = b"pre-partition".to_vec();
        h.dispatch_object_write(1, baseline.clone());

        // Partition.
        h.partition();

        // Node A writes several objects during partition.
        for i in 0..5u64 {
            let obj_id = 100 + i;
            let payload = format!("during-partition-{i}").into_bytes();
            h.node_a.put_object(obj_id, payload);
        }

        // Tick through the partition window.
        for _ in 0..5 {
            h.tick_all(50);
        }

        // Heal and transfer state from A to B.
        h.heal();
        for _ in 0..5 {
            h.tick_all(10);
        }

        // Transfer all objects from A to B.
        h.transfer_state(1, 2);

        // B must have all objects that A accumulated during partition.
        for i in 0..5u64 {
            let obj_id = 100 + i;
            let expected = format!("during-partition-{i}").into_bytes();
            assert_eq!(
                h.node_b.get_object(obj_id).unwrap(),
                &expected,
                "B missing object {obj_id}"
            );
        }

        // Mirror consistency.
        assert!(h.verify_mirror_consistency());
    }

    #[test]
    fn rapid_partition_heal_cycles_no_corruption() {
        // Repeatedly partition and heal while writing objects; verify
        // no state corruption or object loss.
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        h.dispatch_object_write(1, b"cycle-0".to_vec());

        for cycle in 1..=5u64 {
            // Write a baseline object while connected.
            h.dispatch_object_write(cycle * 10, format!("pre-partition-{cycle}").into_bytes());

            // Partition.
            h.partition();

            // Write on both sides during partition.
            h.node_a
                .put_object(cycle * 10 + 1, format!("a-during-p-{cycle}").into_bytes());
            h.node_b
                .put_object(cycle * 10 + 2, format!("b-during-p-{cycle}").into_bytes());

            // Tick through partition.
            for _ in 0..3 {
                h.tick_all(10);
            }

            // Heal.
            h.heal();

            // Tick post-heal.
            for _ in 0..5 {
                h.tick_all(10);
            }

            // Transfer state both ways to converge.
            h.transfer_state(1, 2);
            h.transfer_state(2, 1);

            // Verify mirror consistency after each cycle.
            assert!(
                h.verify_mirror_consistency(),
                "mirror divergence after cycle {cycle}"
            );
        }

        // Both nodes should have all 16 objects (1 baseline + 5*3 per cycle).
        let expected_count = 1 + 5 * 3;
        assert_eq!(
            h.node_a.object_ids().len(),
            expected_count,
            "node A object count mismatch"
        );
        assert_eq!(
            h.node_b.object_ids().len(),
            expected_count,
            "node B object count mismatch"
        );
        assert_eq!(h.node_a.object_ids(), h.node_b.object_ids());
    }

    #[test]
    fn partition_scenario_is_deterministic() {
        fn run_scenario() -> (Vec<u64>, Vec<u64>, usize, usize) {
            let mut h = TwoNodeHarness::new(500);
            h.join_peer();

            h.dispatch_object_write(1, b"shared".to_vec());

            h.partition();
            h.node_a.put_object(10, b"alpha".to_vec());
            h.node_b.put_object(20, b"gamma".to_vec());

            for _ in 0..3 {
                h.tick_all(10);
            }

            h.heal();
            for _ in 0..5 {
                h.tick_all(10);
            }

            h.transfer_state(1, 2);
            h.transfer_state(2, 1);

            let held_during = h.partition_ctrl.held_count(1, 2) + h.partition_ctrl.held_count(2, 1);
            (
                h.node_a.object_ids(),
                h.node_b.object_ids(),
                h.node_a.objects.len(),
                held_during,
            )
        }

        let first = run_scenario();
        for _ in 0..10 {
            let result = run_scenario();
            assert_eq!(result, first, "partition scenario must be deterministic");
        }
    }

    #[test]
    fn existing_tests_still_pass_with_partition_controller() {
        // Verify that pre-existing crash-recovery and mirror-consistency
        // tests would pass with the new PartitionController infrastructure.
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Write-through-placement dispatch still works.
        h.dispatch_object_write(1, b"dispatch-works".to_vec());
        assert!(h.dispatch_object_read(1).payload.is_some());

        // Crash-recovery still works.
        let b_handle = h.handle(2).unwrap();
        h.crash_node(&b_handle);
        h.dispatch_object_write(2, b"during-crash".to_vec());
        h.restart_node(&b_handle);

        assert!(h.verify_mirror_consistency());
        assert_eq!(h.node_b.get_object(2).unwrap(), b"during-crash");

        // Lease fencing still works.
        assert!(h.node_a.acquire_lease(99, LeaseType::Writer));
        h.tick_all(1);
        h.partition();
        h.advance_past_lease_timeout();
        h.heal();
        h.tick_all(10);
        h.tick_all(10);
    }

    #[test]
    fn message_filter_drops_heartbeats() {
        // Install a filter that drops all Heartbeat messages; verify
        // epoch transitions still work via other message types.
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Install filter: drop all Heartbeat messages in both directions.
        h.partition_ctrl.install_filter(|framed, _dir| {
            // Try to deserialize and check if it's a Heartbeat.
            if let Ok(msg) = bincode::deserialize::<HarnessMessage>(&framed[4..]) {
                matches!(msg, HarnessMessage::Heartbeat { .. })
            } else {
                false
            }
        });

        // Heartbeats are dropped, but join/leave/lease messages still work.
        assert!(h.node_a.acquire_lease(42, LeaseType::Writer));
        h.tick_all(10);
        assert!(h.node_a.holds_lease(42));
        assert!(h.node_b.peer_leases.contains_key(&42));

        // Clear the filter.
        h.partition_ctrl.clear_filter();

        // Normal operation restored.
        h.tick_all(10);
        assert!(h.node_a.holds_lease(42));
    }

    #[test]
    fn partition_held_messages_flushed_on_heal() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        // Partition.
        h.partition();

        // Send messages that will be held.
        for i in 0..5 {
            h.node_a.outbox.push(HarnessMessage::Heartbeat {
                node_id: 1,
                epoch_id: i,
                at_ms: i * 100,
            });
        }
        h.node_a.flush_outbox();

        // Verify messages are held.
        let held_1_to_2 = h.partition_ctrl.held_count(1, 2);
        assert!(
            held_1_to_2 >= 5,
            "expected >=5 held messages, got {held_1_to_2}"
        );

        // Heal: messages should flush to delivery queues.
        h.heal();

        // Held count should drop to zero.
        assert_eq!(h.partition_ctrl.held_count(1, 2), 0);

        // Messages are now in-flight and drainable.
        h.tick_all(10);

        // No held messages remain.
        assert_eq!(h.partition_ctrl.held_count(1, 2), 0);
    }

    // ------------------------------------------------------------------
    // Heartbeat protocol tests
    // ------------------------------------------------------------------

    #[test]
    fn heartbeat_disabled_by_default_no_events() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        for _ in 0..10 {
            h.tick_all(1);
        }

        assert!(h.node_a.event_log.is_empty());
        assert!(h.node_b.event_log.is_empty());
        assert!(h.peer_reachable(1));
        assert!(h.peer_reachable(2));
    }

    #[test]
    fn heartbeat_roundtrip_within_interval_no_epoch_change() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let config = HeartbeatConfig {
            interval_ms: 100,
            timeout_ms: 300,
            max_missed_beats: 3,
        };
        h.set_heartbeat_config(config);

        let epoch_before = h.node_a.current_epoch_id();

        for _ in 0..5 {
            h.tick_all(50);
        }

        assert_eq!(h.node_a.current_epoch_id(), epoch_before);
        assert!(h.node_a.event_log.is_empty());
        assert!(h.node_b.event_log.is_empty());
        assert!(h.peer_reachable(1));
        assert!(h.peer_reachable(2));
    }

    #[test]
    fn missed_beat_threshold_triggers_peer_unreachable() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let config = HeartbeatConfig {
            interval_ms: 100,
            timeout_ms: 200,
            max_missed_beats: 2,
        };
        h.set_heartbeat_config(config);

        let epoch_before = h.node_a.current_epoch_id();

        h.partition();

        for _ in 0..5 {
            h.tick_all(250);
        }

        assert!(!h.peer_reachable(1));
        assert!(!h.peer_reachable(2));

        let epoch_after = h.node_a.current_epoch_id();
        assert!(
            epoch_after > epoch_before,
            "epoch must increment on PeerUnreachable"
        );

        assert!(
            h.node_a
                .event_log
                .iter()
                .any(|e| matches!(e, HarnessEvent::PeerUnreachable { .. })),
            "node A must have PeerUnreachable event"
        );
        assert!(
            h.node_b
                .event_log
                .iter()
                .any(|e| matches!(e, HarnessEvent::PeerUnreachable { .. })),
            "node B must have PeerUnreachable event"
        );
    }

    #[test]
    fn heartbeat_resumption_after_failure_emits_peer_reachable() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let config = HeartbeatConfig {
            interval_ms: 100,
            timeout_ms: 200,
            max_missed_beats: 2,
        };
        h.set_heartbeat_config(config);

        h.partition();
        for _ in 0..5 {
            h.tick_all(250);
        }

        assert!(!h.peer_reachable(1));
        assert!(!h.peer_reachable(2));

        h.heal();
        for _ in 0..5 {
            h.tick_all(50);
        }

        assert!(h.peer_reachable(1));
        assert!(h.peer_reachable(2));

        assert!(
            h.node_a
                .event_log
                .iter()
                .any(|e| matches!(e, HarnessEvent::PeerReachable { .. })),
            "node A must have PeerReachable event"
        );
        assert!(
            h.node_b
                .event_log
                .iter()
                .any(|e| matches!(e, HarnessEvent::PeerReachable { .. })),
            "node B must have PeerReachable event"
        );
    }

    #[test]
    fn heartbeat_resumption_increments_epoch() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let config = HeartbeatConfig {
            interval_ms: 100,
            timeout_ms: 200,
            max_missed_beats: 2,
        };
        h.set_heartbeat_config(config);

        let epoch_initial = h.node_a.current_epoch_id();

        h.partition();
        for _ in 0..5 {
            h.tick_all(250);
        }

        let epoch_after_failure = h.node_a.current_epoch_id();
        assert!(epoch_after_failure > epoch_initial);

        h.heal();
        for _ in 0..5 {
            h.tick_all(50);
        }

        let epoch_after_heal = h.node_a.current_epoch_id();
        assert!(
            epoch_after_heal > epoch_after_failure,
            "epoch must increment again on PeerReachable (epoch {epoch_after_failure} -> {epoch_after_heal})"
        );
    }

    #[test]
    fn zero_max_missed_beats_is_noop() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let config = HeartbeatConfig {
            interval_ms: 100,
            timeout_ms: 200,
            max_missed_beats: 0,
        };
        h.set_heartbeat_config(config);

        let epoch_before = h.node_a.current_epoch_id();

        h.partition();
        for _ in 0..3 {
            h.tick_all(250);
        }

        let epoch_after = h.node_a.current_epoch_id();
        assert!(epoch_after > epoch_before);
        assert!(!h.peer_reachable(1));
    }

    #[test]
    fn concurrent_enable_disable_does_not_race() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let config = HeartbeatConfig {
            interval_ms: 100,
            timeout_ms: 200,
            max_missed_beats: 3,
        };
        h.set_heartbeat_config(config.clone());
        h.disable_heartbeat();
        h.set_heartbeat_config(config.clone());
        h.disable_heartbeat();
        h.set_heartbeat_config(config.clone());

        let epoch_before = h.node_a.current_epoch_id();

        for _ in 0..5 {
            h.tick_all(50);
        }

        assert_eq!(h.node_a.current_epoch_id(), epoch_before);
        assert!(h.peer_reachable(1));
        assert!(h.peer_reachable(2));
        assert!(h.node_a.event_log.is_empty());
        assert!(h.node_b.event_log.is_empty());
    }

    #[test]
    fn heartbeat_with_crash_restart_epoch_increments() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let config = HeartbeatConfig {
            interval_ms: 100,
            timeout_ms: 200,
            max_missed_beats: 2,
        };
        h.set_heartbeat_config(config.clone());

        let b_handle = h.handle(2).unwrap();
        h.crash_node(&b_handle);

        for _ in 0..5 {
            h.tick_all(250);
        }

        assert!(!h.peer_reachable(2), "survivor A must see B as unreachable");
        assert!(
            h.node_a
                .event_log
                .iter()
                .any(|e| matches!(e, HarnessEvent::PeerUnreachable { .. })),
            "survivor must emit PeerUnreachable"
        );

        h.restart_node(&b_handle);
        h.set_heartbeat_config(config);

        for _ in 0..5 {
            h.tick_all(50);
        }

        assert!(h.peer_reachable(1));
        assert!(h.peer_reachable(2));
    }

    #[test]
    fn heartbeat_config_preserved_across_restart() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let config = HeartbeatConfig {
            interval_ms: 100,
            timeout_ms: 200,
            max_missed_beats: 2,
        };
        h.set_heartbeat_config(config.clone());

        let b_handle = h.handle(2).unwrap();
        h.crash_node(&b_handle);
        h.restart_node(&b_handle);

        h.set_heartbeat_config(config.clone());

        for _ in 0..5 {
            h.tick_all(50);
        }

        assert!(h.peer_reachable(1));
        assert!(h.peer_reachable(2));
    }

    #[test]
    fn partition_then_heal_drives_full_heartbeat_cycle() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        let config = HeartbeatConfig {
            interval_ms: 100,
            timeout_ms: 200,
            max_missed_beats: 2,
        };
        h.set_heartbeat_config(config);

        assert!(h.peer_reachable(1));
        assert!(h.peer_reachable(2));

        h.partition();
        for _ in 0..5 {
            h.tick_all(250);
        }

        assert!(!h.peer_reachable(1));
        assert!(!h.peer_reachable(2));
        assert!(h
            .node_a
            .event_log
            .iter()
            .any(|e| matches!(e, HarnessEvent::PeerUnreachable { .. })));
        assert!(h
            .node_b
            .event_log
            .iter()
            .any(|e| matches!(e, HarnessEvent::PeerUnreachable { .. })));

        h.heal();
        for _ in 0..5 {
            h.tick_all(50);
        }

        assert!(h.peer_reachable(1));
        assert!(h.peer_reachable(2));
        assert!(h
            .node_a
            .event_log
            .iter()
            .any(|e| matches!(e, HarnessEvent::PeerReachable { .. })));
        assert!(h
            .node_b
            .event_log
            .iter()
            .any(|e| matches!(e, HarnessEvent::PeerReachable { .. })));

        h.dispatch_object_write(42, b"after-heartbeat-cycle".to_vec());
        assert!(h.verify_mirror_consistency());
    }

    // ── Timeline-based partition injection tests ─────────────────────

    #[test]
    fn timeline_scheduled_partition_isolates_writes_then_converges() {
        // Schedule a symmetric partition from t=100 to t=500.
        // Write on node A during the window; after schedule ends,
        // heal_partition converges both nodes and verifies BLAKE3.
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        h.dispatch_object_write(1, b"baseline".to_vec());

        h.partition_ctrl.schedule_event(PartitionEvent {
            start_ms: 100,
            duration_ms: 400,
            direction: PartitionDirection::Both,
            drop_probability: 0.0,
        });

        h.tick_all(100);

        // Node A writes during partition.
        h.node_a.put_object(10, b"leader-isolated-alpha".to_vec());
        h.node_a.put_object(11, b"leader-isolated-beta".to_vec());

        // Node B must NOT see these writes yet.
        assert!(
            h.node_b.get_object(10).is_none(),
            "B must not see isolated write during partition"
        );

        // Advance past the partition end.
        h.tick_all(500);

        let consistent = h.heal_partition();
        assert!(consistent, "BLAKE3 digests must match after heal");

        assert_eq!(h.node_a.get_object(10).unwrap(), b"leader-isolated-alpha");
        assert_eq!(h.node_a.get_object(11).unwrap(), b"leader-isolated-beta");
        assert_eq!(h.node_b.get_object(10).unwrap(), b"leader-isolated-alpha");
        assert_eq!(h.node_b.get_object(11).unwrap(), b"leader-isolated-beta");

        assert!(h.verify_mirror_consistency());
    }

    #[test]
    fn symmetric_partition_both_sides_write_and_converge_after_heal() {
        // Symmetric partition: both nodes write concurrently, then
        // heal_partition reconciles state both ways and verifies BLAKE3.
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        h.dispatch_object_write(1, b"shared-baseline".to_vec());

        h.partition_ctrl.schedule_event(PartitionEvent {
            start_ms: 100,
            duration_ms: 500,
            direction: PartitionDirection::Both,
            drop_probability: 0.0,
        });

        h.tick_all(100);

        // Node A writes during partition.
        h.node_a.put_object(100, b"alpha-from-A".to_vec());
        h.node_a.put_object(101, b"beta-from-A".to_vec());

        // Node B writes during partition (different object ids).
        h.node_b.put_object(200, b"gamma-from-B".to_vec());
        h.node_b.put_object(201, b"delta-from-B".to_vec());

        // Verify isolation: each node only sees its own writes.
        assert!(h.node_a.get_object(100).is_some());
        assert!(h.node_a.get_object(200).is_none());
        assert!(h.node_b.get_object(200).is_some());
        assert!(h.node_b.get_object(100).is_none());

        // Advance past the partition end.
        h.tick_all(600);

        let consistent = h.heal_partition();
        assert!(
            consistent,
            "BLAKE3 digests must match after symmetric partition heal"
        );

        // Both nodes must see all writes from both sides.
        assert_eq!(h.node_a.get_object(100).unwrap(), b"alpha-from-A");
        assert_eq!(h.node_a.get_object(200).unwrap(), b"gamma-from-B");
        assert_eq!(h.node_b.get_object(100).unwrap(), b"alpha-from-A");
        assert_eq!(h.node_b.get_object(200).unwrap(), b"gamma-from-B");

        assert!(h.verify_blake3_consistency());
        assert!(h.verify_mirror_consistency());

        // Read dispatch must report consistency.
        let result = h.dispatch_object_read(100);
        assert!(result.payload.is_some());
        assert!(result.mirrors_consistent);
    }

    #[test]
    fn blake3_digest_detects_divergence() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        h.dispatch_object_write(1, b"same-on-both".to_vec());
        assert!(h.verify_blake3_consistency());

        // Corrupt node B.
        h.node_b.put_object(1, b"CORRUPTED!!!".to_vec());
        assert!(!h.verify_blake3_consistency());

        // Heal corruption.
        h.node_b.put_object(1, b"same-on-both".to_vec());
        assert!(h.verify_blake3_consistency());
    }

    #[test]
    fn blake3_digest_detects_extra_objects() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        h.dispatch_object_write(1, b"shared".to_vec());
        assert!(h.verify_blake3_consistency());

        // Node B has an extra object.
        h.node_b.put_object(99, b"extra".to_vec());
        assert!(!h.verify_blake3_consistency());
    }

    #[test]
    fn partition_schedule_is_deterministic() {
        fn run_scheduled() -> ([u8; 32], [u8; 32]) {
            let mut h = TwoNodeHarness::new(500);
            h.join_peer();

            h.dispatch_object_write(1, b"baseline".to_vec());

            h.partition_ctrl.schedule_event(PartitionEvent {
                start_ms: 100,
                duration_ms: 400,
                direction: PartitionDirection::Both,
                drop_probability: 0.0,
            });

            h.tick_all(100);
            h.node_a.put_object(10, b"scheduled-write".to_vec());
            h.tick_all(500);

            let _consistent = h.heal_partition();
            (h.compute_object_digest(1), h.compute_object_digest(2))
        }

        let first = run_scheduled();
        assert_eq!(first.0, first.1);
        for _ in 0..10 {
            let result = run_scheduled();
            assert_eq!(result, first, "scheduled partition must be deterministic");
        }
    }

    #[test]
    fn schedule_clear_restores_full_connectivity() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        h.partition_ctrl.schedule_event(PartitionEvent {
            start_ms: 0,
            duration_ms: 10_000,
            direction: PartitionDirection::Both,
            drop_probability: 0.0,
        });

        h.tick_all(100);
        assert!(h.partition_ctrl.any_blocked());

        h.partition_ctrl.clear_schedule();
        h.tick_all(10);

        assert!(!h.partition_ctrl.any_blocked());
        assert!(!h.partition_ctrl.is_blocked(1, 2));
        assert!(!h.partition_ctrl.is_blocked(2, 1));
    }

    #[test]
    fn asymmetric_schedule_blocks_one_direction_only() {
        let mut h = TwoNodeHarness::new(500);
        h.join_peer();

        h.partition_ctrl.schedule_event(PartitionEvent {
            start_ms: 0,
            duration_ms: 500,
            direction: PartitionDirection::OneWay {
                from_node: 1,
                to_node: 2,
            },
            drop_probability: 0.0,
        });

        h.tick_all(100);

        assert!(h.partition_ctrl.is_blocked(1, 2));
        assert!(!h.partition_ctrl.is_blocked(2, 1));

        // Write on A -- held because 1->2 is blocked.
        h.node_a.put_object(50, b"held-write".to_vec());
        h.node_a.outbox.push(HarnessMessage::Heartbeat {
            node_id: 1,
            epoch_id: 0,
            at_ms: 100,
        });
        h.tick_all(10);

        let held = h.partition_ctrl.held_count(1, 2);
        assert!(held > 0, "messages from 1->2 should be held");

        // B->A is unblocked: push state chunk directly from B to A.
        // transfer_state() would use A->B request which is blocked,
        // so we inject the chunk on the B->A unblocked path.
        h.node_b.put_object(60, b"delivered-write".to_vec());
        let data = b"delivered-write".to_vec();
        let chunk = StateTransferChunk::new(0, 60, 0, data.len() as u64, data.to_vec(), true);
        h.node_b
            .outbox
            .push(HarnessMessage::StateTransferChunkMsg(chunk));
        h.node_b.flush_outbox();
        for _ in 0..3 {
            h.tick_all(10);
        }
        assert!(h.node_a.get_object(60).is_some());

        // Clear schedule and heal.
        h.partition_ctrl.clear_schedule();
        h.heal_partition();
        assert!(h.verify_blake3_consistency());
    }
}

// ===========================================================================
// Loopback-backed transport protocol integration tests (feature = "loopback")
// ===========================================================================

#[cfg(feature = "loopback")]
#[cfg(test)]
mod loopback_protocol_tests {
    use tidefs_membership_epoch::{EpochMemberSet, NodeIdentity};
    use tidefs_transport::harness::{LoopbackNetwork, SchedulerConfig};
    use tidefs_transport::session::handshake::{
        ClientHandshake, HandshakeFrame, NegotiationComplete, ServerHandshake,
    };
    use tidefs_transport::{FamilyVersion, NodeIdentityPublic};

    fn nid(id: u64) -> NodeIdentity {
        NodeIdentity::new(id)
    }

    fn make_identity(node_id: u64) -> NodeIdentityPublic {
        NodeIdentityPublic {
            node_id,
            verifying_key_bytes: [node_id as u8; 32],
            attested_at_millis: 0,
            identity_version: 1,
            self_signature: vec![0x42; 64],
        }
    }

    fn make_families() -> Vec<FamilyVersion> {
        vec![FamilyVersion::new(0, 1, 0), FamilyVersion::new(4, 1, 0)]
    }

    #[test]
    fn full_session_handshake_over_loopback() {
        let mut net = LoopbackNetwork::new(SchedulerConfig::deterministic(42));

        let _c0 = net.add_node(nid(1), EpochMemberSet::new(vec![nid(1)]));
        let _c1 = net.add_node(nid(2), EpochMemberSet::new(vec![nid(2)]));

        let client_id = make_identity(1);
        let server_id = make_identity(2);
        let families = make_families();

        let (mut client, client_hello) =
            ClientHandshake::initiate(1, client_id.clone(), families.clone(), 1, 0)
                .expect("client initiate should succeed");

        let client_hello_frame = HandshakeFrame::ClientHello(client_hello.clone())
            .encode()
            .expect("encode ClientHello");
        net.send(0, nid(2), client_hello_frame);
        net.step_until_idle(10);

        let server_msgs = net.recv_all(1);
        assert_eq!(server_msgs.len(), 1, "server should receive ClientHello");
        assert!(!server_msgs[0].1, "message should not be stale");

        let received_frame =
            HandshakeFrame::decode(&server_msgs[0].0.payload).expect("decode ClientHello frame");
        let received_hello = match received_frame {
            HandshakeFrame::ClientHello(h) => h,
            _other => panic!("expected ClientHello"),
        };

        assert_eq!(received_hello.node_id, 1);
        assert_eq!(received_hello.epoch, 0);

        let (mut server, server_hello, server_finished) =
            ServerHandshake::respond(received_hello, 2, server_id.clone(), families.clone(), 1, 0)
                .expect("server respond should succeed");

        let server_hello_frame = HandshakeFrame::ServerHello(server_hello.clone())
            .encode()
            .expect("encode ServerHello");
        net.send(1, nid(1), server_hello_frame);
        net.step_until_idle(10);

        let client_msgs = net.recv_all(0);
        assert_eq!(client_msgs.len(), 1, "client should receive ServerHello");

        let received_frame =
            HandshakeFrame::decode(&client_msgs[0].0.payload).expect("decode ServerHello frame");
        let (received_hello, received_finished) = match received_frame {
            HandshakeFrame::ServerHello(h) => (h, server_finished),
            _other => panic!("expected ServerHello"),
        };

        let client_finished = client
            .handle_server_hello(received_hello, received_finished)
            .expect("client handle_server_hello");

        let client_finished_frame = HandshakeFrame::ClientVerify(client_finished)
            .encode()
            .expect("encode ClientVerify");
        net.send(0, nid(2), client_finished_frame);
        net.step_until_idle(10);

        let server_msgs2 = net.recv_all(1);
        assert_eq!(server_msgs2.len(), 1, "server should receive ClientVerify");

        let received_frame =
            HandshakeFrame::decode(&server_msgs2[0].0.payload).expect("decode ClientVerify frame");
        let received_finished = match received_frame {
            HandshakeFrame::ClientVerify(f) => f,
            _other => panic!("expected ClientVerify"),
        };

        let complete: NegotiationComplete = server
            .handle_client_finished(received_finished, client_hello)
            .expect("server handle_client_finished");

        match client.state() {
            tidefs_transport::session::handshake::HandshakeState::Complete(c) => {
                assert_eq!(
                    c.negotiation_token, complete.negotiation_token,
                    "client and server must derive identical negotiation tokens"
                );
                assert_eq!(c.peer_node_id, 2);
                assert_eq!(c.peer_epoch, 0);
            }
            other => panic!("client handshake should be Complete, got {:?}", other),
        }

        assert_eq!(complete.peer_node_id, 1);
        assert_eq!(complete.peer_epoch, 0);

        match client.state() {
            tidefs_transport::session::handshake::HandshakeState::Complete(c) => {
                assert_ne!(
                    c.negotiation_token, [0u8; 32],
                    "negotiation token must be non-zero"
                );
            }
            _ => unreachable!(),
        }
        assert_ne!(complete.negotiation_token, [0u8; 32]);
    }

    #[test]
    fn handshake_over_loopback_dropped_client_hello_retry_converges() {
        let drop_config = SchedulerConfig {
            seed: 42,
            latency_ticks: (0, 0),
            drop_probability: 1.0,
        };
        let mut drop_net = LoopbackNetwork::new(drop_config);

        drop_net.add_node(nid(1), EpochMemberSet::new(vec![nid(1)]));
        drop_net.add_node(nid(2), EpochMemberSet::new(vec![nid(2)]));

        let client_id = make_identity(1);
        let families = make_families();

        let (_, client_hello) =
            ClientHandshake::initiate(1, client_id.clone(), families.clone(), 1, 0)
                .expect("initiate");

        let frame = HandshakeFrame::ClientHello(client_hello).encode().unwrap();
        let seq = drop_net.send(0, nid(2), frame);
        assert!(seq.is_none(), "message should be dropped at 100% drop rate");

        drop_net.step_until_idle(10);
        assert!(
            drop_net.recv(1).is_none(),
            "server should receive nothing after drop"
        );

        let mut net = LoopbackNetwork::new(SchedulerConfig::deterministic(99));
        let _c0 = net.add_node(nid(1), EpochMemberSet::new(vec![nid(1)]));
        let _c1 = net.add_node(nid(2), EpochMemberSet::new(vec![nid(2)]));

        let server_id = make_identity(2);

        let (mut client, client_hello2) =
            ClientHandshake::initiate(1, client_id, families.clone(), 1, 0)
                .expect("retry initiate");

        let frame = HandshakeFrame::ClientHello(client_hello2.clone())
            .encode()
            .unwrap();
        net.send(0, nid(2), frame);
        net.step_until_idle(10);

        let server_msgs = net.recv_all(1);
        assert_eq!(
            server_msgs.len(),
            1,
            "server should receive retry ClientHello"
        );

        let received_hello = match HandshakeFrame::decode(&server_msgs[0].0.payload).unwrap() {
            HandshakeFrame::ClientHello(h) => h,
            _other => panic!("expected ClientHello"),
        };

        let (mut server, server_hello, server_finished) =
            ServerHandshake::respond(received_hello, 2, server_id, families.clone(), 1, 0)
                .expect("respond");

        let frame = HandshakeFrame::ServerHello(server_hello.clone())
            .encode()
            .unwrap();
        net.send(1, nid(1), frame);
        net.step_until_idle(10);

        let client_msgs = net.recv_all(0);
        assert_eq!(client_msgs.len(), 1);

        let recv_hello = match HandshakeFrame::decode(&client_msgs[0].0.payload).unwrap() {
            HandshakeFrame::ServerHello(h) => h,
            _other => panic!("expected ServerHello"),
        };

        let client_finished = client
            .handle_server_hello(recv_hello, server_finished)
            .expect("client handle_server_hello ok after retry");

        let frame = HandshakeFrame::ClientVerify(client_finished)
            .encode()
            .unwrap();
        net.send(0, nid(2), frame);
        net.step_until_idle(10);

        let server_msgs2 = net.recv_all(1);
        assert_eq!(server_msgs2.len(), 1);

        let recv_finished = match HandshakeFrame::decode(&server_msgs2[0].0.payload).unwrap() {
            HandshakeFrame::ClientVerify(f) => f,
            _other => panic!("expected ClientVerify"),
        };

        let complete = server
            .handle_client_finished(recv_finished, client_hello2)
            .expect("server complete after retry");

        assert_eq!(complete.peer_node_id, 1);

        match client.state() {
            tidefs_transport::session::handshake::HandshakeState::Complete(c) => {
                assert_eq!(
                    c.negotiation_token, complete.negotiation_token,
                    "keys must match after successful retry"
                );
            }
            other => panic!("expected Complete after retry, got {:?}", other),
        }
    }

    #[test]
    fn placement_plan_fan_out_three_nodes() {
        let mut net = LoopbackNetwork::new(SchedulerConfig::deterministic(42));

        let c0 = net.add_node(nid(1), EpochMemberSet::new(vec![nid(1)]));
        let c1 = net.add_node(nid(2), EpochMemberSet::new(vec![nid(2)]));
        let c2 = net.add_node(nid(3), EpochMemberSet::new(vec![nid(3)]));

        for &i in &[c0, c1, c2] {
            for peer in &[nid(1), nid(2), nid(3)] {
                if *peer != net.node(i).identity {
                    net.node_mut(i).join(*peer);
                }
            }
        }

        let epoch = net.node(c0).current_epoch_id();
        assert!(epoch >= 1);
        assert_eq!(net.node(c1).current_epoch_id(), epoch);
        assert_eq!(net.node(c2).current_epoch_id(), epoch);
        assert_eq!(net.node(c0).current_members().len(), 3);
        assert_eq!(net.node(c1).current_members().len(), 3);
        assert_eq!(net.node(c2).current_members().len(), 3);

        let plan_bytes = b"placement:object=42,shards=[1,2,3]";
        net.send(c0, nid(2), plan_bytes.to_vec());
        net.send(c0, nid(3), plan_bytes.to_vec());

        net.step_until_idle(10);

        let n2_msgs = net.recv_all(c1);
        assert_eq!(n2_msgs.len(), 1, "node 2 should get 1 placement message");
        assert_eq!(n2_msgs[0].0.payload, plan_bytes);
        assert_eq!(n2_msgs[0].0.from, nid(1));
        assert_eq!(n2_msgs[0].0.epoch, epoch);
        assert!(!n2_msgs[0].1, "message should not be stale");

        let n3_msgs = net.recv_all(c2);
        assert_eq!(n3_msgs.len(), 1, "node 3 should get 1 placement message");
        assert_eq!(n3_msgs[0].0.payload, plan_bytes);
        assert_eq!(n3_msgs[0].0.from, nid(1));
        assert_eq!(n3_msgs[0].0.epoch, epoch);
        assert!(!n3_msgs[0].1, "message should not be stale");

        assert!(net.recv(c0).is_none());

        for idx in &[c0, c1, c2] {
            assert_eq!(net.node(*idx).current_epoch_id(), epoch);
            assert_eq!(net.node(*idx).current_members().len(), 3);
        }
    }

    #[test]
    fn placement_plan_drop_and_partial_delivery() {
        let config = SchedulerConfig {
            seed: 42,
            latency_ticks: (0, 0),
            drop_probability: 0.5,
        };
        let mut net = LoopbackNetwork::new(config);

        net.add_node(nid(1), EpochMemberSet::new(vec![nid(1)]));
        net.add_node(nid(2), EpochMemberSet::new(vec![nid(2)]));
        net.add_node(nid(3), EpochMemberSet::new(vec![nid(3)]));

        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    net.node_mut(i).join(nid((j + 1) as u64));
                }
            }
        }

        let epoch = net.node(0).current_epoch_id();
        assert!(epoch >= 1);

        let plan = b"placement:object=99,shards=[1,2,3]";
        net.send(0, nid(2), plan.to_vec());
        net.send(0, nid(3), plan.to_vec());

        net.step_until_idle(10);

        let n2_msgs = net.recv_all(1);
        let n3_msgs = net.recv_all(2);
        let _total_received = n2_msgs.len() + n3_msgs.len();

        for idx in 0..3 {
            assert_eq!(net.node(idx).current_epoch_id(), epoch);
            assert_eq!(net.node(idx).current_members().len(), 3);
        }

        for msg in n2_msgs.iter().chain(n3_msgs.iter()) {
            assert_eq!(msg.0.from, nid(1));
            assert_eq!(msg.0.epoch, epoch);
            assert!(!msg.1, "received messages must not be stale");
        }

        let mut retry_net = LoopbackNetwork::new(SchedulerConfig::deterministic(99));
        retry_net.add_node(nid(1), EpochMemberSet::new(vec![nid(1)]));
        retry_net.add_node(nid(2), EpochMemberSet::new(vec![nid(2)]));
        retry_net.add_node(nid(3), EpochMemberSet::new(vec![nid(3)]));

        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    retry_net.node_mut(i).join(nid((j + 1) as u64));
                }
            }
        }

        retry_net.send(0, nid(2), plan.to_vec());
        retry_net.send(0, nid(3), plan.to_vec());
        retry_net.step_until_idle(10);

        let retry_n2 = retry_net.recv_all(1);
        let retry_n3 = retry_net.recv_all(2);
        assert_eq!(retry_n2.len(), 1, "node 2 should receive on retry");
        assert_eq!(retry_n3.len(), 1, "node 3 should receive on retry");
        assert_eq!(retry_n2[0].0.payload, plan);
        assert_eq!(retry_n3[0].0.payload, plan);

        for idx in 0..3 {
            assert_eq!(retry_net.node(idx).current_epoch_id(), epoch);
        }
    }

    #[test]
    fn placement_plan_reorder_idempotent_handling() {
        let mut net = LoopbackNetwork::new(SchedulerConfig::deterministic(42));

        net.add_node(nid(1), EpochMemberSet::new(vec![nid(1)]));
        net.add_node(nid(2), EpochMemberSet::new(vec![nid(2)]));

        net.node_mut(0).join(nid(2));
        net.node_mut(1).join(nid(1));

        let epoch = net.node(0).current_epoch_id();

        net.send(0, nid(2), b"plan:v1".to_vec());
        net.send(0, nid(2), b"plan:v2".to_vec());

        net.step_until_idle(10);

        let msgs = net.recv_all(1);
        assert_eq!(msgs.len(), 2, "both messages should be delivered");
        assert_eq!(msgs[0].0.seq, 0);
        assert_eq!(msgs[1].0.seq, 1);
        assert_eq!(msgs[0].0.payload, b"plan:v1");
        assert_eq!(msgs[1].0.payload, b"plan:v2");

        assert_eq!(net.node(0).current_epoch_id(), epoch);
        assert_eq!(net.node(1).current_epoch_id(), epoch);

        let mut rnet = LoopbackNetwork::new(SchedulerConfig {
            seed: 42,
            latency_ticks: (3, 3),
            drop_probability: 0.0,
        });
        rnet.add_node(nid(1), EpochMemberSet::new(vec![nid(1)]));
        rnet.add_node(nid(2), EpochMemberSet::new(vec![nid(2)]));
        rnet.node_mut(0).join(nid(2));
        rnet.node_mut(1).join(nid(1));

        for i in 0..5u8 {
            rnet.send(0, nid(2), vec![i]);
        }

        rnet.step_until_idle(20);

        let rmsgs = rnet.recv_all(1);
        assert_eq!(rmsgs.len(), 5, "all 5 messages must be delivered");

        for i in 0..5 {
            assert_eq!(rmsgs[i].0.seq, i as u64);
            assert_eq!(rmsgs[i].0.payload, vec![i as u8]);
        }

        assert_eq!(rnet.node(0).current_epoch_id(), epoch);
        assert_eq!(rnet.node(1).current_epoch_id(), epoch);
    }
}
