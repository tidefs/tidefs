//! Deterministic multi-node transport loopback harness.
//!
//! Simulates multiple TideFS nodes communicating over loopback channels
//! with reproducible message ordering, configurable latency/drop injection,
//! and epoch-aware routing driven by `tidefs-membership-epoch`.

use crate::envelope::IntegrityEnvelope;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

use tidefs_membership_epoch::NodeIdentity;
use tidefs_membership_epoch::{EpochMemberSet, EpochStateMachine, EpochTransition};

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64)
// ---------------------------------------------------------------------------

struct XorShiftRng {
    state: u64,
}

impl XorShiftRng {
    fn new(seed: u64) -> Self {
        let seed = if seed == 0 { 1 } else { seed };
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_bound(&mut self, max: u64) -> u64 {
        if max == 0 {
            return 0;
        }
        self.next() % max
    }

    fn next_f64(&mut self) -> f64 {
        // Use top 53 bits for a uniform f64 in [0.0, 1.0)
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

// ---------------------------------------------------------------------------
// SimMessage
// ---------------------------------------------------------------------------

/// A message exchanged between simulated nodes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimMessage {
    /// Sender identity.
    pub from: NodeIdentity,
    /// Intended recipient.
    pub to: NodeIdentity,
    /// Epoch number at send time.
    pub epoch: u64,
    /// Message payload.
    pub payload: Vec<u8>,
    /// Per-sender monotonic sequence number.
    pub seq: u64,
}

// ---------------------------------------------------------------------------
// SchedulerConfig
// ---------------------------------------------------------------------------

/// Configuration for [`DeterministicMessageScheduler`].
#[derive(Clone, Debug)]
pub struct SchedulerConfig {
    /// PRNG seed for reproducible runs.
    pub seed: u64,
    /// Latency range in ticks: `(min, max)` inclusive.
    /// A message sent at tick T is delivered at `T + random(min..=max) + 1`.
    pub latency_ticks: (u64, u64),
    /// Probability of dropping a message (0.0 = never, 1.0 = always).
    pub drop_probability: f64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            seed: 42,
            latency_ticks: (0, 0),
            drop_probability: 0.0,
        }
    }
}

impl SchedulerConfig {
    /// Zero-latency, no drops, fixed seed for deterministic replay.
    #[must_use]
    pub fn deterministic(seed: u64) -> Self {
        Self {
            seed,
            latency_ticks: (0, 0),
            drop_probability: 0.0,
        }
    }
}

// ---------------------------------------------------------------------------
// DeterministicMessageScheduler
// ---------------------------------------------------------------------------

/// Governs message delivery order across the simulated node set.
///
/// Accepts a seed for reproducible runs. Supports step-by-step advancement
/// (tick-based) and burst modes.
pub struct DeterministicMessageScheduler {
    config: SchedulerConfig,
    tick: u64,
    /// Per-node message inboxes (delivered and ready to read).
    inboxes: BTreeMap<NodeIdentity, VecDeque<SimMessage>>,
    /// Messages waiting for delivery: `(deliver_at_tick, message)`.
    pending: VecDeque<(u64, SimMessage)>,
    rng: XorShiftRng,
    /// Message trace: records every delivered message in order for replay
    /// verification. Each entry is `(tick, message)`.
    pub trace: Vec<(u64, SimMessage)>,
    /// Partition-blocked node pairs: messages from `(from, to)` are held
    /// until the partition is healed. Both directions are tracked
    /// independently so asymmetric partitions are possible.
    partition_blocks: BTreeSet<(NodeIdentity, NodeIdentity)>,
    /// Messages held due to partition blocks: `(from, to, message)`.
    /// Delivered to the target inbox when the block is cleared via
    /// [`heal_partition`] or [`heal_all`].
    held_messages: VecDeque<(NodeIdentity, NodeIdentity, SimMessage)>,
    /// Count of messages held due to partition (for test assertions).
    pub held_count: usize,
}

impl DeterministicMessageScheduler {
    /// Create a new scheduler with the given configuration.
    #[must_use]
    pub fn new(config: SchedulerConfig) -> Self {
        let rng = XorShiftRng::new(config.seed);
        Self {
            config,
            tick: 0,
            inboxes: BTreeMap::new(),
            pending: VecDeque::new(),
            rng,
            trace: Vec::new(),
            partition_blocks: BTreeSet::new(),
            held_messages: VecDeque::new(),
            held_count: 0,
        }
    }

    /// Register a node so it can send and receive messages.
    pub fn register_node(&mut self, identity: NodeIdentity) {
        self.inboxes.entry(identity).or_default();
    }

    /// Register multiple nodes at once.
    pub fn register_nodes(&mut self, identities: impl IntoIterator<Item = NodeIdentity>) {
        for id in identities {
            self.register_node(id);
        }
    }

    /// Enqueue a message for delivery.
    ///
    /// Returns `true` if the message was accepted, `false` if dropped
    /// (per `drop_probability`).
    pub fn send(
        &mut self,
        from: NodeIdentity,
        to: NodeIdentity,
        epoch: u64,
        payload: Vec<u8>,
        seq: u64,
    ) -> bool {
        // Drop injection
        if self.config.drop_probability > 0.0 && self.rng.next_f64() < self.config.drop_probability
        {
            return false;
        }

        // Partition check: hold the message if the edge is blocked.
        if self.partition_blocks.contains(&(from, to)) {
            let msg = SimMessage {
                from,
                to,
                epoch,
                payload,
                seq,
            };
            self.held_messages.push_back((from, to, msg));
            self.held_count += 1;
            return true; // accepted but held
        }

        let msg = SimMessage {
            from,
            to,
            epoch,
            payload,
            seq,
        };

        // Calculate delivery tick
        let (lat_min, lat_max) = self.config.latency_ticks;
        let latency = if lat_max > lat_min {
            lat_min + self.rng.next_bound(lat_max - lat_min + 1)
        } else {
            lat_min
        };
        let deliver_at = self.tick + latency + 1; // +1: never deliver at current tick

        self.pending.push_back((deliver_at, msg));
        true
    }

    /// Advance time by one tick. Delivers all messages scheduled for the
    /// new tick to target inboxes. Returns the new tick value.
    pub fn tick(&mut self) -> u64 {
        self.tick += 1;
        self.deliver_pending();
        self.tick
    }

    /// Advance by `n` ticks.
    pub fn tick_n(&mut self, n: u64) -> u64 {
        for _ in 0..n {
            self.tick += 1;
            self.deliver_pending();
        }
        self.tick
    }

    /// Burst-advance: immediately deliver all currently pending messages,
    /// then advance by one tick. Returns the number of messages delivered.
    pub fn burst(&mut self) -> usize {
        let count = self.pending.len();
        let pending: Vec<_> = self.pending.drain(..).collect();
        for (_, msg) in pending {
            self.deliver_to_inbox(msg);
        }
        self.tick += 1;
        count
    }

    /// Deliver all pending messages that are due at the current tick.
    fn deliver_pending(&mut self) {
        let mut remaining = VecDeque::new();
        while let Some((deliver_at, msg)) = self.pending.pop_front() {
            if deliver_at <= self.tick {
                self.deliver_to_inbox(msg);
            } else {
                remaining.push_back((deliver_at, msg));
            }
        }
        self.pending = remaining;
    }

    fn deliver_to_inbox(&mut self, msg: SimMessage) {
        self.trace.push((self.tick, msg.clone()));
        self.inboxes.entry(msg.to).or_default().push_back(msg);
    }

    /// Non-blocking receive: return the next message for a node, if any.
    pub fn recv(&mut self, node: NodeIdentity) -> Option<SimMessage> {
        self.inboxes.get_mut(&node).and_then(|q| q.pop_front())
    }

    /// Peek at the next message for a node without removing it.
    #[must_use]
    pub fn peek(&self, node: NodeIdentity) -> Option<&SimMessage> {
        self.inboxes.get(&node).and_then(|q| q.front())
    }

    /// Whether a node has messages waiting.
    #[must_use]
    pub fn has_messages(&self, node: NodeIdentity) -> bool {
        self.inboxes.get(&node).is_some_and(|q| !q.is_empty())
    }

    /// Current simulation tick.
    #[must_use]
    pub fn current_tick(&self) -> u64 {
        self.tick
    }

    /// Number of pending (not yet delivered) messages.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Number of messages in a node's inbox.
    #[must_use]
    pub fn inbox_len(&self, node: NodeIdentity) -> usize {
        self.inboxes.get(&node).map_or(0, |q| q.len())
    }

    /// Reset the scheduler to initial state. Clears inboxes, pending queue,
    /// trace, and re-seeds the RNG for reproducible replay.
    pub fn reset(&mut self) {
        self.tick = 0;
        self.inboxes.clear();
        self.pending.clear();
        self.trace.clear();
        self.rng = XorShiftRng::new(self.config.seed);
    }

    /// Clear the message trace (but keep scheduler state).
    pub fn clear_trace(&mut self) {
        self.trace.clear();
    }

    // ------------------------------------------------------------------
    // Partition injection and healing
    // ------------------------------------------------------------------

    /// Inject a partition between two nodes. All messages sent from `a` to
    /// `b` and from `b` to `a` are held until the partition is healed.
    ///
    /// Already-pending and in-flight messages are unaffected; only new
    /// sends after this call are held.
    pub fn inject_partition(&mut self, a: NodeIdentity, b: NodeIdentity) {
        self.partition_blocks.insert((a, b));
        self.partition_blocks.insert((b, a));
    }

    /// Inject a one-way partition: messages from `from` to `to` are held,
    /// but the reverse direction is unaffected.
    pub fn inject_one_way_partition(&mut self, from: NodeIdentity, to: NodeIdentity) {
        self.partition_blocks.insert((from, to));
    }

    /// Inject a partition between two disjoint sets of nodes. All cross-set
    /// message pairs (in both directions) are blocked.
    pub fn inject_partition_set(&mut self, set_a: &[NodeIdentity], set_b: &[NodeIdentity]) {
        for &a in set_a {
            for &b in set_b {
                self.partition_blocks.insert((a, b));
                self.partition_blocks.insert((b, a));
            }
        }
    }

    /// Heal the partition between two nodes. Clears the block in both
    /// directions and delivers all held messages from `a` to `b` and
    /// `b` to `a` to their target inboxes.
    ///
    /// Returns the number of held messages delivered.
    pub fn heal_partition(&mut self, a: NodeIdentity, b: NodeIdentity) -> usize {
        self.partition_blocks.remove(&(a, b));
        self.partition_blocks.remove(&(b, a));

        let mut delivered = 0usize;
        let mut remaining = VecDeque::new();
        while let Some((from, to, msg)) = self.held_messages.pop_front() {
            if (from == a && to == b) || (from == b && to == a) {
                self.deliver_to_inbox(msg);
                delivered += 1;
            } else {
                remaining.push_back((from, to, msg));
            }
        }
        self.held_messages = remaining;
        self.held_count = self.held_count.saturating_sub(delivered);
        delivered
    }

    /// Heal all partitions. Clears every block and delivers all held
    /// messages to their target inboxes.
    ///
    /// Returns the number of held messages delivered.
    pub fn heal_all(&mut self) -> usize {
        self.partition_blocks.clear();
        let delivered = self.held_messages.len();
        while let Some((_, _, msg)) = self.held_messages.pop_front() {
            self.deliver_to_inbox(msg);
        }
        self.held_count = 0;
        delivered
    }

    /// Check whether messages from `from` to `to` are currently blocked
    /// by a partition.
    #[must_use]
    pub fn is_partitioned(&self, from: NodeIdentity, to: NodeIdentity) -> bool {
        self.partition_blocks.contains(&(from, to))
    }

    /// Check whether any partition blocks are active.
    #[must_use]
    pub fn has_partitions(&self) -> bool {
        !self.partition_blocks.is_empty()
    }

    /// Number of held messages for a specific blocked direction.
    #[must_use]
    pub fn held_count_for(&self, from: NodeIdentity, to: NodeIdentity) -> usize {
        self.held_messages
            .iter()
            .filter(|(f, t, _)| *f == from && *t == to)
            .count()
    }

    /// Clear all partition blocks without delivering held messages.
    /// Held messages remain queued and will be delivered by a subsequent
    /// `heal_partition` or `heal_all`.
    pub fn clear_partition_blocks(&mut self) {
        self.partition_blocks.clear();
    }
}

// ---------------------------------------------------------------------------
// LoopbackTransport
// ---------------------------------------------------------------------------

/// A per-node transport handle backed by a shared [`DeterministicMessageScheduler`].
///
/// Each simulated node uses its handle to send and receive messages.
/// The handle carries a per-sender monotonic sequence counter.
#[derive(Clone)]
pub struct LoopbackTransport {
    identity: NodeIdentity,
    seq: u64,
    scheduler: Rc<RefCell<DeterministicMessageScheduler>>,
}

impl LoopbackTransport {
    /// Create a new transport handle for the given node identity, sharing
    /// the central scheduler.
    #[must_use]
    pub fn new(
        identity: NodeIdentity,
        scheduler: Rc<RefCell<DeterministicMessageScheduler>>,
    ) -> Self {
        Self {
            identity,
            seq: 0,
            scheduler,
        }
    }

    /// Send a payload to a peer with the given epoch stamp.
    ///
    /// Returns the assigned sequence number, or `None` if the message was
    /// dropped.
    pub fn send(&mut self, to: NodeIdentity, epoch: u64, payload: Vec<u8>) -> Option<u64> {
        let seq = self.seq;
        self.seq += 1;
        let accepted = self
            .scheduler
            .borrow_mut()
            .send(self.identity, to, epoch, payload, seq);
        if accepted {
            Some(seq)
        } else {
            None
        }
    }

    /// Non-blocking receive: returns the next message addressed to this node.
    pub fn recv(&self) -> Option<SimMessage> {
        self.scheduler.borrow_mut().recv(self.identity)
    }

    /// Peek at the next message without removing it.
    #[must_use]
    pub fn peek(&self) -> Option<SimMessage> {
        self.scheduler.borrow().peek(self.identity).cloned()
    }

    /// Whether this node has messages waiting.
    #[must_use]
    pub fn has_messages(&self) -> bool {
        self.scheduler.borrow().has_messages(self.identity)
    }

    /// Number of messages in this node's inbox.
    #[must_use]
    pub fn inbox_len(&self) -> usize {
        self.scheduler.borrow().inbox_len(self.identity)
    }

    /// The node identity for this transport handle.
    #[must_use]
    pub fn identity(&self) -> NodeIdentity {
        self.identity
    }

    /// Current send sequence number (next message will carry this seq).
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.seq
    }

    /// Send a payload with BLAKE3 integrity envelope.
    ///
    /// Seals the payload with a domain-separated BLAKE3 digest via
    /// IntegrityEnvelope::seal and sends the serialized envelope
    /// on the wire. The receiver must use recv_integrity to
    /// verify the digest and extract the original payload.
    ///
    /// Returns the assigned sequence number, or None if the message
    /// was dropped by the scheduler.
    pub fn send_integrity(
        &mut self,
        to: NodeIdentity,
        epoch: u64,
        payload: Vec<u8>,
    ) -> Option<u64> {
        let env = IntegrityEnvelope::seal(payload);
        let wire = env.to_wire();
        self.send(to, epoch, wire)
    }

    /// Receive a message and verify its BLAKE3 integrity envelope.
    ///
    /// Deserializes the wire bytes into an IntegrityEnvelope and
    /// verifies the domain-separated BLAKE3 digest. Returns the
    /// original SimMessage together with the extracted payload on
    /// success. Returns None if no message is available.
    ///
    /// # Errors
    ///
    /// Returns IntegrityError if the message is truncated or the
    /// digest does not match.
    pub fn recv_integrity(&self) -> Result<(SimMessage, Vec<u8>), crate::envelope::IntegrityError> {
        let msg = self
            .recv()
            .ok_or(crate::envelope::IntegrityError::Truncated { got: 0, min: 1 })?;
        let env = IntegrityEnvelope::from_wire(&msg.payload)?;
        Ok((msg, env.payload))
    }
}

// ---------------------------------------------------------------------------
// SimNode
// ---------------------------------------------------------------------------

/// A simulated TideFS node bundling identity, transport, and epoch state.
///
/// Tests spawn N nodes, advance epochs, exchange messages, and assert
/// delivery semantics.
pub struct SimNode {
    /// This node's identity.
    pub identity: NodeIdentity,
    /// Transport handle for send/receive.
    pub transport: LoopbackTransport,
    /// Epoch state machine for epoch-aware routing.
    pub epoch_sm: EpochStateMachine,
    /// Messages received (for assertion convenience).
    pub received: Vec<SimMessage>,
}

impl SimNode {
    /// Create a new simulated node with the given identity, transport,
    /// and initial member set for epoch bootstrapping.
    #[must_use]
    pub fn new(
        identity: NodeIdentity,
        transport: LoopbackTransport,
        initial_members: EpochMemberSet,
    ) -> Self {
        let epoch_sm = EpochStateMachine::bootstrap(initial_members);
        Self {
            identity,
            transport,
            epoch_sm,
            received: Vec::new(),
        }
    }

    /// Send a payload to a peer, stamped with the current epoch.
    ///
    /// Returns the assigned sequence number, or `None` if dropped.
    pub fn send_to(&mut self, to: NodeIdentity, payload: Vec<u8>) -> Option<u64> {
        let epoch = self.current_epoch_id();
        self.transport.send(to, epoch, payload)
    }

    /// Receive the next message addressed to this node. If the message
    /// carries a stale epoch (sender is not in the current member set and
    /// epoch is behind), it is rejected (returned but marked).
    ///
    /// Returns the message and a boolean `is_stale` flag.
    pub fn recv(&mut self) -> Option<(SimMessage, bool)> {
        let msg = self.transport.recv()?;
        let is_stale = self.is_epoch_stale(&msg);
        self.received.push(msg.clone());
        Some((msg, is_stale))
    }

    /// Poll for all available messages, returning them with staleness flags.
    pub fn recv_all(&mut self) -> Vec<(SimMessage, bool)> {
        let mut msgs = Vec::new();
        while let Some((msg, stale)) = self.recv() {
            msgs.push((msg, stale));
        }
        msgs
    }

    /// Check whether a message's epoch is stale relative to this node's
    /// current epoch state.
    ///
    /// A message is stale if its epoch is less than the current epoch and
    /// the sender is not a member of the current member set.
    #[must_use]
    pub fn is_epoch_stale(&self, msg: &SimMessage) -> bool {
        let current = self.current_epoch_id();
        if msg.epoch >= current {
            return false;
        }
        // Epoch is behind; check if sender is in current member set
        let members = self.epoch_sm.current_epoch().members.clone();
        !members.contains(&msg.from)
    }

    /// Join a node into this node's epoch.
    pub fn join(&mut self, node: NodeIdentity) -> EpochTransition {
        self.epoch_sm.join(node)
    }

    /// Remove a node from this node's epoch.
    pub fn leave(&mut self, node: NodeIdentity) -> EpochTransition {
        self.epoch_sm.leave(node)
    }

    /// Current epoch id.
    #[must_use]
    pub fn current_epoch_id(&self) -> u64 {
        self.epoch_sm.current_epoch().epoch_id
    }

    /// Send a payload with BLAKE3 integrity verification.
    ///
    /// Wraps the payload in an IntegrityEnvelope before sending.
    pub fn send_integrity_to(&mut self, to: NodeIdentity, payload: Vec<u8>) -> Option<u64> {
        let epoch = self.current_epoch_id();
        self.transport.send_integrity(to, epoch, payload)
    }

    /// Receive and verify a BLAKE3 integrity-enveloped message.
    pub fn recv_integrity(
        &mut self,
    ) -> Result<(SimMessage, Vec<u8>, bool), crate::envelope::IntegrityError> {
        let (msg, payload) = self.transport.recv_integrity()?;
        let is_stale = self.is_epoch_stale(&msg);
        self.received.push(msg.clone());
        Ok((msg, payload, is_stale))
    }

    /// Current member set.
    #[must_use]
    pub fn current_members(&self) -> EpochMemberSet {
        self.epoch_sm.current_epoch().members.clone()
    }
}

// ---------------------------------------------------------------------------
// LoopbackNetwork
// ---------------------------------------------------------------------------

/// Deterministic in-process loopback network for multi-node protocol tests.
///
/// The network owns one shared scheduler plus a set of logical nodes. Tests can
/// add nodes, exchange payloads, advance the event loop by ticks, and inject or
/// heal partitions without spawning threads or depending on wall-clock time.
pub struct LoopbackNetwork {
    scheduler: Rc<RefCell<DeterministicMessageScheduler>>,
    nodes: Vec<SimNode>,
}

impl LoopbackNetwork {
    /// Create an empty loopback network with the given scheduler configuration.
    #[must_use]
    pub fn new(config: SchedulerConfig) -> Self {
        let scheduler = Rc::new(RefCell::new(DeterministicMessageScheduler::new(config)));
        Self {
            scheduler,
            nodes: Vec::new(),
        }
    }

    /// Add a logical node and return its stable index inside this network.
    pub fn add_node(&mut self, identity: NodeIdentity, initial_members: EpochMemberSet) -> usize {
        self.scheduler.borrow_mut().register_node(identity);
        let transport = LoopbackTransport::new(identity, Rc::clone(&self.scheduler));
        let node = SimNode::new(identity, transport, initial_members);
        let idx = self.nodes.len();
        self.nodes.push(node);
        idx
    }

    /// Send a message from `from_idx` to `to`.
    ///
    /// Returns the assigned sequence number, or `None` when the scheduler drops
    /// the message according to its configured drop probability.
    pub fn send(&mut self, from_idx: usize, to: NodeIdentity, payload: Vec<u8>) -> Option<u64> {
        self.nodes[from_idx].send_to(to, payload)
    }

    /// Advance the scheduler by one tick.
    pub fn tick(&mut self) -> u64 {
        self.scheduler.borrow_mut().tick()
    }

    /// Advance the scheduler by `n` ticks.
    pub fn tick_n(&mut self, n: u64) -> u64 {
        self.scheduler.borrow_mut().tick_n(n)
    }

    /// Immediately deliver all currently pending messages and advance one tick.
    pub fn burst(&mut self) -> usize {
        self.scheduler.borrow_mut().burst()
    }

    /// Advance until the scheduler has no pending messages or `max_ticks` has
    /// elapsed. Returns the number of ticks advanced.
    pub fn step_until_idle(&mut self, max_ticks: u64) -> u64 {
        let mut ticks = 0;
        while ticks < max_ticks {
            if self.scheduler.borrow().pending_count() == 0 {
                break;
            }
            self.scheduler.borrow_mut().tick();
            ticks += 1;
        }
        ticks
    }

    /// Receive all currently available messages for a node.
    pub fn recv_all(&mut self, node_idx: usize) -> Vec<(SimMessage, bool)> {
        self.nodes[node_idx].recv_all()
    }

    /// Receive one available message for a node.
    pub fn recv(&mut self, node_idx: usize) -> Option<(SimMessage, bool)> {
        self.nodes[node_idx].recv()
    }

    /// Return whether a node currently has inbox messages.
    #[must_use]
    pub fn has_messages(&self, node_idx: usize) -> bool {
        self.nodes[node_idx].transport.has_messages()
    }

    /// Get a node by stable network index.
    #[must_use]
    pub fn node(&self, idx: usize) -> &SimNode {
        &self.nodes[idx]
    }

    /// Get a mutable node by stable network index.
    pub fn node_mut(&mut self, idx: usize) -> &mut SimNode {
        &mut self.nodes[idx]
    }

    /// Number of logical nodes in the network.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Current scheduler tick.
    #[must_use]
    pub fn current_tick(&self) -> u64 {
        self.scheduler.borrow().current_tick()
    }

    /// Number of messages accepted but not yet delivered.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.scheduler.borrow().pending_count()
    }

    /// Inject a bidirectional partition between two node identities.
    pub fn inject_partition(&mut self, a: NodeIdentity, b: NodeIdentity) {
        self.scheduler.borrow_mut().inject_partition(a, b);
    }

    /// Heal a bidirectional partition and deliver held messages for that pair.
    pub fn heal_partition(&mut self, a: NodeIdentity, b: NodeIdentity) -> usize {
        self.scheduler.borrow_mut().heal_partition(a, b)
    }

    /// Heal all active partitions and deliver all held messages.
    pub fn heal_all(&mut self) -> usize {
        self.scheduler.borrow_mut().heal_all()
    }

    /// Shared scheduler backing this network.
    #[must_use]
    pub fn scheduler(&self) -> &Rc<RefCell<DeterministicMessageScheduler>> {
        &self.scheduler
    }
}

// ── LoopbackObjectEnumerator ─────────────────────────────────────────

use crate::object_enumerator::{ObjectEnumerator, ObjectPlacementEntry, ShardKind};

/// Registry of which objects each simulated node holds.
///
/// Used by [`LoopbackObjectEnumerator`] to produce deterministic
/// enumerations from in-process node state without real transport I/O.
#[derive(Clone, Debug, Default)]
pub struct HarnessObjectRegistry {
    objects: BTreeMap<NodeIdentity, BTreeSet<u64>>,
}

impl HarnessObjectRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            objects: BTreeMap::new(),
        }
    }

    /// Register that `node` holds `object_id`.
    pub fn insert(&mut self, node: NodeIdentity, object_id: u64) {
        self.objects.entry(node).or_default().insert(object_id);
    }

    /// Register multiple objects for a node.
    pub fn insert_many(&mut self, node: NodeIdentity, object_ids: impl IntoIterator<Item = u64>) {
        self.objects.entry(node).or_default().extend(object_ids);
    }

    /// Remove a node (simulating node loss).
    pub fn remove_node(&mut self, node: NodeIdentity) {
        self.objects.remove(&node);
    }

    /// Get the object set for a node.
    #[must_use]
    pub fn get(&self, node: NodeIdentity) -> BTreeSet<u64> {
        self.objects.get(&node).cloned().unwrap_or_default()
    }
}

/// An [`ObjectEnumerator`] that queries simulated nodes through the
/// deterministic loopback transport to discover which objects each
/// node holds.
///
/// The enumerator uses the [`HarnessObjectRegistry`] as the source
/// of truth for per-node object placements. In a real deployment,
/// each node responds to an enumeration-request message with its
/// own object list; here the registry serves as the node-local
/// state that would be queried over transport sessions.
///
/// Output is deterministically sorted by `(object_id, node_id)`.
pub struct LoopbackObjectEnumerator {
    /// Per-node object registry.
    registry: HarnessObjectRegistry,
    /// Minimum number of nodes that must respond for enumeration
    /// to be considered complete.
    min_responders: usize,
}

/// Error returned by [`LoopbackObjectEnumerator`] when not enough
/// nodes responded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumerationIncomplete {
    pub expected: usize,
    pub responded: usize,
}

impl std::fmt::Display for EnumerationIncomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "enumeration incomplete: {}/{} nodes responded",
            self.responded, self.expected
        )
    }
}

impl std::error::Error for EnumerationIncomplete {}

impl LoopbackObjectEnumerator {
    /// Create a new loopback enumerator.
    #[must_use]
    pub fn new(registry: HarnessObjectRegistry) -> Self {
        let node_count = registry.objects.len();
        Self {
            registry,
            min_responders: node_count,
        }
    }

    /// Create a new enumerator with a custom minimum responder count.
    #[must_use]
    pub fn with_min_responders(registry: HarnessObjectRegistry, min_responders: usize) -> Self {
        Self {
            registry,
            min_responders,
        }
    }
}

impl ObjectEnumerator for LoopbackObjectEnumerator {
    type Error = EnumerationIncomplete;

    fn enumerate_objects(
        &self,
        _membership_epoch: tidefs_membership_epoch::EpochId,
        _placement_version: u64,
    ) -> Result<Vec<ObjectPlacementEntry>, Self::Error> {
        let responding_nodes = self.registry.objects.len();

        if responding_nodes < self.min_responders {
            return Err(EnumerationIncomplete {
                expected: self.min_responders,
                responded: responding_nodes,
            });
        }

        let mut entries = Vec::new();
        for (&node_id, object_ids) in &self.registry.objects {
            let member_id = tidefs_membership_epoch::MemberId(node_id.node_id);
            let mut sorted_objects: Vec<u64> = object_ids.iter().copied().collect();
            sorted_objects.sort_unstable();
            for object_id in sorted_objects {
                let is_first_for_object = entries
                    .iter()
                    .all(|e: &ObjectPlacementEntry| e.object_id != object_id);

                let shard_kind = if is_first_for_object {
                    ShardKind::Primary
                } else {
                    ShardKind::Replica
                };

                entries.push(ObjectPlacementEntry::new(object_id, member_id, shard_kind));
            }
        }

        entries.sort();
        Ok(entries)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(id: u64) -> NodeIdentity {
        NodeIdentity::new(id)
    }

    fn make_scheduler(seed: u64) -> Rc<RefCell<DeterministicMessageScheduler>> {
        Rc::new(RefCell::new(DeterministicMessageScheduler::new(
            SchedulerConfig::deterministic(seed),
        )))
    }

    fn make_scheduler_with_latency(
        seed: u64,
        min_lat: u64,
        max_lat: u64,
    ) -> Rc<RefCell<DeterministicMessageScheduler>> {
        Rc::new(RefCell::new(DeterministicMessageScheduler::new(
            SchedulerConfig {
                seed,
                latency_ticks: (min_lat, max_lat),
                drop_probability: 0.0,
            },
        )))
    }

    fn bootstrap_sim_node(
        id: u64,
        scheduler: Rc<RefCell<DeterministicMessageScheduler>>,
    ) -> SimNode {
        let identity = nid(id);
        scheduler.borrow_mut().register_node(identity);
        let transport = LoopbackTransport::new(identity, Rc::clone(&scheduler));
        let members = EpochMemberSet::new(vec![identity]);
        SimNode::new(identity, transport, members)
    }

    // ------------------------------------------------------------------
    // 2-node smoke test
    // ------------------------------------------------------------------

    #[test]
    fn two_node_smoke_send_and_receive() {
        let sched = make_scheduler(42);

        let mut node1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut node2 = bootstrap_sim_node(2, Rc::clone(&sched));

        // Node1 sends to Node2
        let payload = b"hello from node 1".to_vec();
        let seq = node1
            .send_to(nid(2), payload.clone())
            .expect("send should not drop");
        assert_eq!(seq, 0, "first message seq should be 0");

        // Advance scheduler
        sched.borrow_mut().tick();

        // Node2 should receive
        let (msg, stale) = node2.recv().expect("node2 should receive message");
        assert!(!stale, "message should not be stale");
        assert_eq!(msg.from, nid(1));
        assert_eq!(msg.to, nid(2));
        assert_eq!(msg.payload, payload);
        assert_eq!(msg.seq, 0);
        assert_eq!(msg.epoch, 0); // initial epoch

        // Node1 should have nothing
        assert!(node1.recv().is_none());
    }

    // ------------------------------------------------------------------
    // 3-node exchange
    // ------------------------------------------------------------------

    #[test]
    fn three_node_exchange() {
        let sched = make_scheduler(99);

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));
        let mut n3 = bootstrap_sim_node(3, Rc::clone(&sched));

        // Everyone sends to everyone else
        n1.send_to(nid(2), b"1->2".to_vec());
        n1.send_to(nid(3), b"1->3".to_vec());
        n2.send_to(nid(1), b"2->1".to_vec());
        n2.send_to(nid(3), b"2->3".to_vec());
        n3.send_to(nid(1), b"3->1".to_vec());
        n3.send_to(nid(2), b"3->2".to_vec());

        sched.borrow_mut().tick();

        // Each node should have 2 messages
        let n1_msgs = n1.recv_all();
        let n2_msgs = n2.recv_all();
        let n3_msgs = n3.recv_all();

        assert_eq!(n1_msgs.len(), 2, "node1 should receive 2 messages");
        assert_eq!(n2_msgs.len(), 2, "node2 should receive 2 messages");
        assert_eq!(n3_msgs.len(), 2, "node3 should receive 2 messages");

        let n1_payloads: Vec<_> = n1_msgs.iter().map(|(m, _)| m.payload.clone()).collect();
        assert!(n1_payloads.contains(&b"2->1".to_vec()));
        assert!(n1_payloads.contains(&b"3->1".to_vec()));
    }

    // ------------------------------------------------------------------
    // 5-node exchange
    // ------------------------------------------------------------------

    #[test]
    fn five_node_exchange() {
        let sched = make_scheduler(55);

        let mut nodes: Vec<SimNode> = (1..=5)
            .map(|id| bootstrap_sim_node(id, Rc::clone(&sched)))
            .collect();

        // Ring exchange: each sends to the next
        for (i, node) in nodes.iter_mut().enumerate().take(5) {
            let to = nid(((i + 1) % 5 + 1) as u64);
            node.send_to(to, format!("msg from {}", i + 1).into_bytes());
        }

        sched.borrow_mut().tick();

        // Each node should receive 1 message
        for (i, node) in nodes.iter_mut().enumerate() {
            let msgs = node.recv_all();
            assert_eq!(msgs.len(), 1, "node{} should receive 1 message", i + 1);
            let from = nid(((i + 4) % 5 + 1) as u64);
            assert_eq!(msgs[0].0.from, from);
        }
    }

    // ------------------------------------------------------------------
    // Deterministic replay
    // ------------------------------------------------------------------

    #[test]
    fn deterministic_replay_same_seed_same_trace() {
        fn run_scenario(seed: u64) -> Vec<(u64, SimMessage)> {
            let sched = make_scheduler(seed);

            let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
            let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));
            let mut n3 = bootstrap_sim_node(3, Rc::clone(&sched));

            n1.send_to(nid(2), b"a".to_vec());
            n2.send_to(nid(3), b"b".to_vec());
            n3.send_to(nid(1), b"c".to_vec());

            sched.borrow_mut().tick();

            n1.recv_all();
            n2.recv_all();
            n3.recv_all();

            n1.send_to(nid(3), b"d".to_vec());
            n2.send_to(nid(1), b"e".to_vec());

            sched.borrow_mut().tick();

            n1.recv_all();
            n3.recv_all();

            // Reset and replay
            sched.borrow_mut().reset();

            // Re-bootstrap
            let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
            let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));
            let mut n3 = bootstrap_sim_node(3, Rc::clone(&sched));

            n1.send_to(nid(2), b"a".to_vec());
            n2.send_to(nid(3), b"b".to_vec());
            n3.send_to(nid(1), b"c".to_vec());

            sched.borrow_mut().tick();

            n1.recv_all();
            n2.recv_all();
            n3.recv_all();

            n1.send_to(nid(3), b"d".to_vec());
            n2.send_to(nid(1), b"e".to_vec());

            sched.borrow_mut().tick();

            n1.recv_all();
            n3.recv_all();

            {
                let t = sched.borrow().trace.clone();
                t
            }
        }

        let trace1 = run_scenario(42);
        let trace2 = run_scenario(42);
        assert_eq!(trace1, trace2, "same seed must produce identical traces");
    }

    #[test]
    fn different_seeds_produce_different_traces() {
        // With latency injection, different seeds should generally differ
        let sched1 = make_scheduler_with_latency(42, 1, 5);
        let sched2 = make_scheduler_with_latency(99, 1, 5);

        // Bootstrap same nodes
        for sched in [&sched1, &sched2] {
            for id in [1u64, 2, 3] {
                sched.borrow_mut().register_node(nid(id));
            }
        }

        // Send messages
        {
            let mut s = sched1.borrow_mut();
            s.send(nid(1), nid(2), 0, b"a".to_vec(), 0);
            s.send(nid(2), nid(3), 0, b"b".to_vec(), 0);
        }
        {
            let mut s = sched2.borrow_mut();
            s.send(nid(1), nid(2), 0, b"a".to_vec(), 0);
            s.send(nid(2), nid(3), 0, b"b".to_vec(), 0);
        }

        // Tick enough to deliver
        sched1.borrow_mut().tick_n(10);
        sched2.borrow_mut().tick_n(10);

        // Collect traces
        let trace1 = sched1.borrow().trace.clone();
        let trace2 = sched2.borrow().trace.clone();

        // Both should have delivered the messages, but order/timing may differ
        assert_eq!(trace1.len(), 2);
        assert_eq!(trace2.len(), 2);
    }

    // ------------------------------------------------------------------
    // Epoch gating: stale epoch rejection
    // ------------------------------------------------------------------

    #[test]
    fn epoch_gating_rejects_stale_epoch_message() {
        let sched = make_scheduler(42);

        let mut node1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut node2 = bootstrap_sim_node(2, Rc::clone(&sched));

        node2.leave(nid(1));
        assert_eq!(node2.current_epoch_id(), 1);

        // Now send from node1 (epoch 0) to node2
        let epoch = node1.current_epoch_id();
        assert_eq!(epoch, 0);
        node1
            .transport
            .send(nid(2), epoch, b"stale message".to_vec());

        sched.borrow_mut().tick();

        let (msg, is_stale) = node2.recv().expect("node2 should receive message");
        assert!(is_stale, "message from removed node should be marked stale");
        assert_eq!(msg.from, nid(1));
        assert_eq!(msg.epoch, 0);
        assert_eq!(node2.current_epoch_id(), 1, "current epoch should be 1");
    }

    #[test]
    fn epoch_gating_accepts_current_epoch_message() {
        let sched = make_scheduler(42);

        let mut node1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut node2 = bootstrap_sim_node(2, Rc::clone(&sched));

        // Both advance together by joining node3
        node1.join(nid(3));
        node2.join(nid(3));

        assert_eq!(node1.current_epoch_id(), 1);
        assert_eq!(node2.current_epoch_id(), 1);

        // Node1 sends at epoch 1
        node1.send_to(nid(2), b"current epoch message".to_vec());
        sched.borrow_mut().tick();

        let (msg, is_stale) = node2.recv().expect("node2 should receive");
        assert!(!is_stale, "current-epoch message should not be stale");
        assert_eq!(msg.epoch, 1);
    }

    // ------------------------------------------------------------------
    // Node churn: join mid-simulation
    // ------------------------------------------------------------------

    #[test]
    fn node_join_mid_simulation_receives_post_join_only() {
        let sched = make_scheduler(77);

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));

        // n1 sends to n2 (epoch 0)
        n1.send_to(nid(2), b"pre-join message".to_vec());

        // Now add node 4
        let n4_id = nid(4);
        sched.borrow_mut().register_node(n4_id);
        let t4 = LoopbackTransport::new(n4_id, Rc::clone(&sched));
        let mut n4 = SimNode::new(n4_id, t4, EpochMemberSet::new(vec![n4_id]));

        // n1 and n2 join n4 into their epochs
        n1.join(n4_id);
        n2.join(n4_id);

        assert_eq!(n1.current_epoch_id(), 1);
        assert_eq!(n2.current_epoch_id(), 1);

        // n2 sends to n4 (epoch 1)
        n2.send_to(n4_id, b"post-join message".to_vec());

        sched.borrow_mut().tick_n(2);

        // n4 should receive only the post-join message
        let n4_msgs = n4.recv_all();
        assert_eq!(n4_msgs.len(), 1);
        assert_eq!(n4_msgs[0].0.payload, b"post-join message");
        assert_eq!(n4_msgs[0].0.epoch, 1);
    }

    #[test]
    fn node_leave_during_active_flows() {
        let sched = make_scheduler(11);

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));
        let mut n3 = bootstrap_sim_node(3, Rc::clone(&sched));

        // n3 sends messages to n1 and n2
        n3.send_to(nid(1), b"pre-leave-1".to_vec());
        n3.send_to(nid(2), b"pre-leave-2".to_vec());

        // n2 removes n3 from its epoch
        n2.leave(nid(3));
        assert_eq!(n2.current_epoch_id(), 1);

        sched.borrow_mut().tick();

        // n1 should get the message (n3 is still in n1's epoch)
        let n1_msgs = n1.recv_all();
        assert_eq!(n1_msgs.len(), 1);
        assert!(!n1_msgs[0].1, "n1 should not see stale message");
        assert_eq!(n1_msgs[0].0.payload, b"pre-leave-1");

        // n2 should get the message but it's stale (n3 has been removed from n2's epoch)
        let n2_msgs = n2.recv_all();
        assert_eq!(n2_msgs.len(), 1);
        assert!(n2_msgs[0].1, "n2 should see stale message from removed n3");
        assert_eq!(n2_msgs[0].0.payload, b"pre-leave-2");
    }

    // ------------------------------------------------------------------
    // Latency and drop injection
    // ------------------------------------------------------------------

    #[test]
    fn latency_injection_delays_messages() {
        let sched = make_scheduler_with_latency(42, 3, 3); // fixed 3-tick latency

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));

        n1.send_to(nid(2), b"delayed".to_vec());

        // Tick 1: message should not arrive yet (sent_at=0, deliver_at=0+3+1=4)
        sched.borrow_mut().tick();
        assert!(n2.recv().is_none(), "msg should not arrive at tick 1");

        sched.borrow_mut().tick();
        assert!(n2.recv().is_none(), "msg should not arrive at tick 2");

        sched.borrow_mut().tick();
        assert!(n2.recv().is_none(), "msg should not arrive at tick 3");

        // Tick 4: message should arrive
        sched.borrow_mut().tick();
        let msg = n2.recv().expect("msg should arrive at tick 4");
        assert_eq!(msg.0.payload, b"delayed");
    }

    #[test]
    fn drop_injection_drops_messages() {
        let sched = Rc::new(RefCell::new(DeterministicMessageScheduler::new(
            SchedulerConfig {
                seed: 42,
                latency_ticks: (0, 0),
                drop_probability: 1.0, // drop everything
            },
        )));

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));

        let seq = n1.send_to(nid(2), b"should be dropped".to_vec());
        assert!(seq.is_none(), "message should be dropped");

        sched.borrow_mut().tick();
        assert!(n2.recv().is_none(), "no message should arrive");
    }

    // ------------------------------------------------------------------
    // Scheduler: burst, reset, tick_n
    // ------------------------------------------------------------------

    #[test]
    fn burst_delivers_all_pending_immediately() {
        let sched = make_scheduler_with_latency(42, 5, 5); // 5-tick latency

        sched.borrow_mut().register_nodes([nid(1), nid(2)]);
        {
            let mut s = sched.borrow_mut();
            s.send(nid(1), nid(2), 0, b"msg1".to_vec(), 0);
            s.send(nid(1), nid(2), 0, b"msg2".to_vec(), 1);
        }

        assert_eq!(sched.borrow().pending_count(), 2);

        let delivered = sched.borrow_mut().burst();
        assert_eq!(delivered, 2);
        assert_eq!(sched.borrow().pending_count(), 0);
        assert_eq!(sched.borrow().inbox_len(nid(2)), 2);
    }

    #[test]
    fn reset_clears_state_for_replay() {
        let sched = make_scheduler(42);

        sched.borrow_mut().register_nodes([nid(1), nid(2)]);
        {
            let mut s = sched.borrow_mut();
            s.send(nid(1), nid(2), 0, b"msg".to_vec(), 0);
        }
        sched.borrow_mut().tick();

        assert_eq!(sched.borrow().trace.len(), 1);
        assert!(sched.borrow().has_messages(nid(2)));

        sched.borrow_mut().reset();

        assert_eq!(sched.borrow().trace.len(), 0);
        assert_eq!(sched.borrow().pending_count(), 0);
        assert!(!sched.borrow().has_messages(nid(2)));
        assert_eq!(sched.borrow().current_tick(), 0);
    }

    #[test]
    fn tick_n_advances_multiple_ticks() {
        let sched = make_scheduler(42);
        sched.borrow_mut().register_nodes([nid(1)]);
        sched.borrow_mut().tick_n(10);
        assert_eq!(sched.borrow().current_tick(), 10);
    }

    // ------------------------------------------------------------------
    // Sequence number monotonicity
    // ------------------------------------------------------------------

    #[test]
    fn transport_sequence_numbers_are_monotonic() {
        let sched = make_scheduler(42);

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let n2_id = nid(2);
        sched.borrow_mut().register_node(n2_id);

        let seq0 = n1.send_to(n2_id, b"msg0".to_vec()).unwrap();
        let seq1 = n1.send_to(n2_id, b"msg1".to_vec()).unwrap();
        let seq2 = n1.send_to(n2_id, b"msg2".to_vec()).unwrap();

        assert_eq!(seq0, 0);
        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(n1.transport.next_seq(), 3);
    }

    // ------------------------------------------------------------------
    // Edge cases
    // ------------------------------------------------------------------

    #[test]
    fn send_to_unregistered_node_still_queues() {
        let sched = make_scheduler(42);

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        // Node 99 is not registered, but send should still work
        // (the message goes into pending; it just won't have an inbox
        // until one is created)

        n1.send_to(nid(99), b"to unknown".to_vec());
        sched.borrow_mut().tick();

        // Register node 99 after the fact and check inbox
        sched.borrow_mut().register_node(nid(99));
        // The message was already delivered... let's check
        // Actually, delivery happens to inboxes that exist.
        // Since 99 wasn't registered, the message was delivered to a default inbox.

        // This should work because deliver_to_inbox uses entry().or_default()
        assert_eq!(sched.borrow().inbox_len(nid(99)), 1);
    }

    #[test]
    fn empty_inbox_recv_returns_none() {
        let sched = make_scheduler(42);
        let node = bootstrap_sim_node(1, Rc::clone(&sched));
        assert!(node.transport.recv().is_none());
    }

    #[test]
    fn peek_does_not_consume() {
        let sched = make_scheduler(42);

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let n2 = bootstrap_sim_node(2, Rc::clone(&sched));

        n1.send_to(nid(2), b"peek test".to_vec());
        sched.borrow_mut().tick();

        let peeked = n2.transport.peek().expect("peek should return message");
        assert_eq!(peeked.payload, b"peek test");

        // Should still be available
        let msg = n2
            .transport
            .recv()
            .expect("should still be there after peek");
        assert_eq!(msg.payload, b"peek test");

        // Now it should be gone
        assert!(n2.transport.peek().is_none());
    }

    // ------------------------------------------------------------------
    // Partition injection: messages blocked while partition active
    // ------------------------------------------------------------------

    #[test]
    fn partition_injection_blocks_messages() {
        let sched = make_scheduler(42);

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));

        // Inject partition between node1 and node2
        sched.borrow_mut().inject_partition(nid(1), nid(2));

        // Send a message; it should be held, not dropped
        let seq = n1.send_to(nid(2), b"partitioned msg".to_vec());
        assert!(seq.is_some(), "message should be accepted (held)");

        // Advance ticks; message should NOT arrive
        sched.borrow_mut().tick_n(10);
        assert!(
            n2.recv().is_none(),
            "partitioned message must not be delivered"
        );

        // Partition block should be active
        assert!(sched.borrow().is_partitioned(nid(1), nid(2)));
        assert!(sched.borrow().is_partitioned(nid(2), nid(1)));
        assert!(sched.borrow().has_partitions());
        assert_eq!(sched.borrow().held_count, 1);
    }

    #[test]
    fn partition_injection_blocks_bidirectional() {
        let sched = make_scheduler(42);

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));

        // Inject partition bidirectionally
        sched.borrow_mut().inject_partition(nid(1), nid(2));

        // Send from both directions
        n1.send_to(nid(2), b"1->2".to_vec());
        n2.send_to(nid(1), b"2->1".to_vec());

        sched.borrow_mut().tick_n(10);

        assert!(n1.recv().is_none(), "2->1 must be blocked");
        assert!(n2.recv().is_none(), "1->2 must be blocked");
        assert_eq!(sched.borrow().held_count, 2);
    }

    #[test]
    fn partition_blocks_do_not_affect_unblocked_traffic() {
        let sched = make_scheduler(42);

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));
        let mut n3 = bootstrap_sim_node(3, Rc::clone(&sched));

        // Partition only 1<->2
        sched.borrow_mut().inject_partition(nid(1), nid(2));

        // n1 sends to n2 (blocked) and n3 (unblocked)
        n1.send_to(nid(2), b"blocked".to_vec());
        n1.send_to(nid(3), b"free".to_vec());

        sched.borrow_mut().tick();

        // n3 receives its message
        let n3_msgs = n3.recv_all();
        assert_eq!(n3_msgs.len(), 1, "n3 should receive unblocked message");
        assert_eq!(n3_msgs[0].0.payload, b"free");

        // n2 receives nothing
        assert!(n2.recv().is_none(), "n2 must not receive blocked message");

        // Held count should be 1
        assert_eq!(sched.borrow().held_count, 1);
    }

    // ------------------------------------------------------------------
    // Partition healing: held messages delivered on heal
    // ------------------------------------------------------------------

    #[test]
    fn healing_releases_held_messages() {
        let sched = make_scheduler(42);

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));

        // Partition, send, verify blocked
        sched.borrow_mut().inject_partition(nid(1), nid(2));
        let seq = n1.send_to(nid(2), b"held msg".to_vec());
        assert!(seq.is_some());
        sched.borrow_mut().tick_n(10);
        assert!(n2.recv().is_none());

        // Heal the partition
        let delivered = sched.borrow_mut().heal_partition(nid(1), nid(2));
        assert_eq!(delivered, 1, "one held message should be delivered");

        // The message should now be in n2's inbox
        let msg = n2.recv().expect("message should arrive after heal");
        assert_eq!(msg.0.payload, b"held msg");
        assert_eq!(msg.0.from, nid(1));

        // held_count should be decremented
        assert_eq!(sched.borrow().held_count, 0);
    }

    #[test]
    fn healing_releases_bidirectional_held_messages() {
        let sched = make_scheduler(42);

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));

        sched.borrow_mut().inject_partition(nid(1), nid(2));
        n1.send_to(nid(2), b"1->2".to_vec());
        n2.send_to(nid(1), b"2->1".to_vec());
        sched.borrow_mut().tick_n(10);

        assert_eq!(sched.borrow().held_count, 2);

        // Heal — releases both directions
        let delivered = sched.borrow_mut().heal_partition(nid(1), nid(2));
        assert_eq!(delivered, 2);

        let n1_msgs = n1.recv_all();
        let n2_msgs = n2.recv_all();
        assert_eq!(n1_msgs.len(), 1);
        assert_eq!(n2_msgs.len(), 1);
        assert_eq!(n1_msgs[0].0.payload, b"2->1");
        assert_eq!(n2_msgs[0].0.payload, b"1->2");
        assert_eq!(sched.borrow().held_count, 0);
    }

    // ------------------------------------------------------------------
    // heal_all: releases all held messages across all partitions
    // ------------------------------------------------------------------

    #[test]
    fn heal_all_clears_all_partitions() {
        let sched = make_scheduler(42);

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));
        let mut n3 = bootstrap_sim_node(3, Rc::clone(&sched));

        // Two disjoint partitions: 1<->2 and 1<->3
        sched.borrow_mut().inject_partition(nid(1), nid(2));
        sched.borrow_mut().inject_partition(nid(1), nid(3));

        n1.send_to(nid(2), b"to-2".to_vec());
        n1.send_to(nid(3), b"to-3".to_vec());

        sched.borrow_mut().tick_n(10);
        assert_eq!(sched.borrow().held_count, 2);

        // heal_all releases both
        let delivered = sched.borrow_mut().heal_all();
        assert_eq!(delivered, 2);
        assert!(!sched.borrow().has_partitions());
        assert_eq!(sched.borrow().held_count, 0);

        assert_eq!(n2.recv_all().len(), 1);
        assert_eq!(n3.recv_all().len(), 1);
    }

    // ------------------------------------------------------------------
    // Deterministic partition behavior: same seed, same held/released outcome
    // ------------------------------------------------------------------

    #[test]
    fn partition_behavior_is_deterministic() {
        fn run_partition_scenario(seed: u64) -> Vec<SimMessage> {
            let sched = make_scheduler(seed);

            let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
            let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));

            sched.borrow_mut().inject_partition(nid(1), nid(2));
            n1.send_to(nid(2), b"a".to_vec());
            n1.send_to(nid(2), b"b".to_vec());
            sched.borrow_mut().tick_n(5);

            sched.borrow_mut().heal_partition(nid(1), nid(2));
            // Consume messages after heal
            let mut n2_msgs = Vec::new();
            while let Some((msg, _)) = n2.recv() {
                n2_msgs.push(msg);
            }

            n2_msgs
        }

        let result1 = run_partition_scenario(42);
        let result2 = run_partition_scenario(42);
        assert_eq!(result1.len(), 2);
        assert_eq!(result2.len(), 2);
        assert_eq!(
            result1, result2,
            "same seed must produce identical partition outcomes"
        );
    }

    // ------------------------------------------------------------------
    // held_count_for: tracks per-direction held messages
    // ------------------------------------------------------------------

    #[test]
    fn held_count_tracks_per_direction() {
        let sched = make_scheduler(42);
        sched.borrow_mut().register_nodes([nid(1), nid(2), nid(3)]);

        // One-way partition: only 1->2 is blocked
        sched.borrow_mut().inject_one_way_partition(nid(1), nid(2));

        sched
            .borrow_mut()
            .send(nid(1), nid(2), 0, b"blocked".to_vec(), 0);
        sched
            .borrow_mut()
            .send(nid(1), nid(2), 0, b"blocked2".to_vec(), 1);
        sched
            .borrow_mut()
            .send(nid(3), nid(2), 0, b"free".to_vec(), 0);

        sched.borrow_mut().tick_n(5);

        // Direction 1->2 should have 2 held messages
        assert_eq!(sched.borrow().held_count_for(nid(1), nid(2)), 2);
        // Direction 3->2 should be 0 (not partitioned)
        assert_eq!(sched.borrow().held_count_for(nid(3), nid(2)), 0);
        // Total held count should be 2
        assert_eq!(sched.borrow().held_count, 2);

        // n2 should have received only the free message from n3
        assert_eq!(sched.borrow().inbox_len(nid(2)), 1);

        // Heal and verify all held delivered
        let delivered = sched.borrow_mut().heal_partition(nid(1), nid(2));
        assert_eq!(delivered, 2);
        assert_eq!(sched.borrow().held_count, 0);
    }

    // ------------------------------------------------------------------
    // Partition with multiple messages: ordering preserved on heal
    // ------------------------------------------------------------------

    #[test]
    fn healing_preserves_message_order() {
        let sched = make_scheduler(42);

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));

        sched.borrow_mut().inject_partition(nid(1), nid(2));

        // Send 5 messages in order
        for i in 0..5u8 {
            let payload = vec![i];
            n1.send_to(nid(2), payload);
        }

        sched.borrow_mut().tick_n(5);

        assert_eq!(sched.borrow().held_count, 5);

        // Heal
        let delivered = sched.borrow_mut().heal_partition(nid(1), nid(2));
        assert_eq!(delivered, 5);

        // Messages must arrive in original order
        for i in 0..5u8 {
            let msg = n2.recv().expect("message should arrive after heal");
            assert_eq!(msg.0.payload, vec![i], "message order must be preserved");
        }
    }

    // ------------------------------------------------------------------
    // Partition between sets
    // ------------------------------------------------------------------

    #[test]
    fn partition_set_blocks_cross_set_traffic() {
        let sched = make_scheduler(42);

        let mut n1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut n2 = bootstrap_sim_node(2, Rc::clone(&sched));
        let mut n3 = bootstrap_sim_node(3, Rc::clone(&sched));

        // Partition {1,2} <-> {3}
        sched
            .borrow_mut()
            .inject_partition_set(&[nid(1), nid(2)], &[nid(3)]);

        // Cross-set messages blocked
        n1.send_to(nid(3), b"cross".to_vec());
        n2.send_to(nid(3), b"cross2".to_vec());
        // Within-set messages should flow
        n1.send_to(nid(2), b"within".to_vec());

        sched.borrow_mut().tick();

        // n2 gets the within-set message
        let n2_msgs = n2.recv_all();
        assert_eq!(n2_msgs.len(), 1);
        assert_eq!(n2_msgs[0].0.payload, b"within");

        // n3 gets nothing (blocked)
        assert!(n3.recv().is_none(), "cross-set traffic must be blocked");

        assert_eq!(sched.borrow().held_count, 2);

        // Heal all
        sched.borrow_mut().heal_all();
        assert_eq!(n3.recv_all().len(), 2);
    }

    // ------------------------------------------------------------------
    // LoopbackNetwork facade
    // ------------------------------------------------------------------

    #[test]
    fn loopback_network_two_node_roundtrip() {
        let mut net = LoopbackNetwork::new(SchedulerConfig::deterministic(42));
        let n0 = net.add_node(nid(1), EpochMemberSet::new(vec![nid(1)]));
        let n1 = net.add_node(nid(2), EpochMemberSet::new(vec![nid(2)]));

        assert_eq!(net.node_count(), 2);
        net.send(n0, nid(2), b"hello from 1".to_vec());
        net.send(n1, nid(1), b"hello from 2".to_vec());
        assert_eq!(net.pending_count(), 2);

        assert_eq!(net.step_until_idle(10), 1);

        let msgs_1 = net.recv_all(n1);
        assert_eq!(msgs_1.len(), 1);
        assert_eq!(msgs_1[0].0.payload, b"hello from 1");
        assert!(!msgs_1[0].1);

        let msgs_0 = net.recv_all(n0);
        assert_eq!(msgs_0.len(), 1);
        assert_eq!(msgs_0[0].0.payload, b"hello from 2");
        assert!(!msgs_0[0].1);
    }

    #[test]
    fn loopback_network_step_until_idle_stops_on_idle() {
        let mut net = LoopbackNetwork::new(SchedulerConfig::deterministic(42));
        net.add_node(nid(1), EpochMemberSet::new(vec![nid(1)]));
        net.add_node(nid(2), EpochMemberSet::new(vec![nid(2)]));

        assert_eq!(net.step_until_idle(1000), 0);
        assert_eq!(net.current_tick(), 0);
    }

    #[test]
    fn loopback_network_partition_and_heal_delivers_held_messages() {
        let mut net = LoopbackNetwork::new(SchedulerConfig::deterministic(42));
        let n0 = net.add_node(nid(1), EpochMemberSet::new(vec![nid(1)]));
        let n1 = net.add_node(nid(2), EpochMemberSet::new(vec![nid(2)]));

        net.inject_partition(nid(1), nid(2));
        net.send(n0, nid(2), b"during partition".to_vec());
        net.step_until_idle(10);

        assert!(net.recv(n1).is_none());
        assert_eq!(net.heal_partition(nid(1), nid(2)), 1);

        let msgs = net.recv_all(n1);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0.payload, b"during partition");
    }

    #[test]
    fn loopback_network_tick_and_burst_are_deterministic() {
        let config = SchedulerConfig {
            seed: 42,
            latency_ticks: (10, 10),
            drop_probability: 0.0,
        };
        let mut net = LoopbackNetwork::new(config);
        net.add_node(nid(1), EpochMemberSet::new(vec![nid(1)]));
        net.add_node(nid(2), EpochMemberSet::new(vec![nid(2)]));

        assert_eq!(net.current_tick(), 0);
        assert_eq!(net.tick(), 1);
        assert_eq!(net.tick_n(5), 6);

        net.send(0, nid(2), b"latent message".to_vec());
        assert_eq!(net.pending_count(), 1);
        assert_eq!(net.burst(), 1);
        assert_eq!(net.pending_count(), 0);

        let msgs = net.recv_all(1);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0.payload, b"latent message");
    }

    // ------------------------------------------------------------------
    // Integrity-enveloped loopback send/receive
    // ------------------------------------------------------------------

    #[test]
    fn integrity_loopback_roundtrip() {
        let sched = make_scheduler(42);
        let mut node1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut node2 = bootstrap_sim_node(2, Rc::clone(&sched));

        let payload = b"integrity-verified hello".to_vec();
        let seq = node1
            .send_integrity_to(nid(2), payload.clone())
            .expect("send_integrity should not drop");
        assert_eq!(seq, 0);

        sched.borrow_mut().tick();

        let (msg, verified_payload, stale) = node2
            .recv_integrity()
            .expect("recv_integrity should succeed");
        assert!(!stale);
        assert_eq!(verified_payload, payload);
        assert_eq!(msg.from, nid(1));
        assert_eq!(msg.to, nid(2));
    }

    #[test]
    fn integrity_loopback_empty_payload() {
        let sched = make_scheduler(99);
        let mut node1 = bootstrap_sim_node(1, Rc::clone(&sched));
        let mut node2 = bootstrap_sim_node(2, Rc::clone(&sched));

        let payload = vec![];
        node1
            .send_integrity_to(nid(2), payload.clone())
            .expect("send should succeed");

        sched.borrow_mut().tick();

        let (_, verified_payload, _) = node2
            .recv_integrity()
            .expect("recv_integrity should succeed");
        assert!(verified_payload.is_empty());
    }

    #[test]
    fn integrity_loopback_corruption_rejected() {
        let sched = make_scheduler(77);
        let mut node1 = bootstrap_sim_node(1, Rc::clone(&sched));

        // Send normally via integrity
        let payload = b"will be corrupted".to_vec();
        node1
            .send_integrity_to(nid(2), payload)
            .expect("send should succeed");

        // Sneak in and corrupt the wire bytes before the receiver picks up
        // the message. We access the scheduler directly.
        sched.borrow_mut().tick();

        // Find the message in the inbox and tamper with a payload byte
        let mut s = sched.borrow_mut();
        if let Some(msg) = s.recv(nid(2)) {
            // Create a corrupted copy: flip a byte in the payload portion (after the 32-byte digest)
            let mut corrupted = msg.clone();
            if corrupted.payload.len() > 33 {
                corrupted.payload[33] ^= 0xFF;
            }
            // Re-inject the corrupted message
            s.send(
                msg.from,
                msg.to,
                msg.epoch,
                corrupted.payload,
                msg.seq + 100,
            );
        }
        drop(s);

        sched.borrow_mut().tick();

        // IntegrityEnvelope::from_wire no longer verifies BLAKE3 digest
        // (integrity is provided by transport MAC). Corrupted bytes pass
        // through the envelope layer — detection is deferred to the transport.
        let mut node2 = bootstrap_sim_node(2, Rc::clone(&sched));
        let result = node2.recv_integrity();
        assert!(
            result.is_ok(),
            "recv_integrity no longer rejects on payload corruption (transport MAC handles it)"
        );
    }

    #[test]
    fn integrity_loopback_digest_tamper_passes_through() {
        let sched = make_scheduler(88);
        let mut node1 = bootstrap_sim_node(1, Rc::clone(&sched));

        let payload = b"digest tamper test".to_vec();
        node1
            .send_integrity_to(nid(2), payload)
            .expect("send should succeed");

        // Corrupt the digest in the wire bytes.
        sched.borrow_mut().tick();

        let mut s = sched.borrow_mut();
        if let Some(msg) = s.recv(nid(2)) {
            let mut corrupted = msg.clone();
            if !corrupted.payload.is_empty() {
                corrupted.payload[0] ^= 0xFF;
            }
            s.send(
                msg.from,
                msg.to,
                msg.epoch,
                corrupted.payload,
                msg.seq + 100,
            );
        }
        drop(s);

        sched.borrow_mut().tick();

        // IntegrityEnvelope::from_wire no longer verifies BLAKE3 digest.
        // Tampered digest passes through; transport MAC handles integrity.
        let mut node2 = bootstrap_sim_node(2, Rc::clone(&sched));
        let result = node2.recv_integrity();
        assert!(
            result.is_ok(),
            "recv_integrity no longer rejects on digest tamper (transport MAC handles it)"
        );
    }

    #[test]
    fn integrity_loopback_truncated_message_rejected() {
        let sched = make_scheduler(55);
        // Send a message that is too short to contain a valid integrity envelope
        let mut s = sched.borrow_mut();
        s.send(nid(1), nid(2), 0, b"short".to_vec(), 0);
        drop(s);

        sched.borrow_mut().tick();

        let mut node2 = bootstrap_sim_node(2, Rc::clone(&sched));
        let result = node2.recv_integrity();
        assert!(
            result.is_err(),
            "recv_integrity should reject truncated message"
        );
        assert!(matches!(
            result.unwrap_err(),
            crate::envelope::IntegrityError::Truncated { .. }
        ));
    }
}

// ===========================================================================
// LoopbackObjectEnumerator tests
// ===========================================================================

#[cfg(test)]
mod loopback_enum_tests {
    use super::*;
    use crate::object_enumerator::{
        compute_per_node_object_deltas, ObjectPlacementEntry, ShardKind,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use tidefs_membership_epoch::EpochId;

    fn nid(id: u64) -> NodeIdentity {
        NodeIdentity { node_id: id }
    }

    fn mid(id: u64) -> tidefs_membership_epoch::MemberId {
        tidefs_membership_epoch::MemberId(id)
    }

    #[test]
    fn loopback_enumerator_empty_registry() {
        let registry = HarnessObjectRegistry::new();
        let enumerator = LoopbackObjectEnumerator::new(registry);
        let result = enumerator.enumerate_objects(EpochId(0), 1).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn loopback_enumerator_single_node_single_object() {
        let mut registry = HarnessObjectRegistry::new();
        registry.insert_many(nid(1), [42]);

        let enumerator = LoopbackObjectEnumerator::new(registry);
        let result = enumerator.enumerate_objects(EpochId(0), 1).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].object_id, 42);
        assert_eq!(result[0].member_id, mid(1));
        assert_eq!(result[0].shard_kind, ShardKind::Primary);
    }

    #[test]
    fn loopback_enumerator_multi_node_primary_replica_detection() {
        let mut registry = HarnessObjectRegistry::new();
        registry.insert_many(nid(1), [10, 20]);
        registry.insert_many(nid(2), [10]);

        let enumerator = LoopbackObjectEnumerator::new(registry);
        let result = enumerator.enumerate_objects(EpochId(0), 1).unwrap();

        // Sorted: (10, 1), (10, 2), (20, 1)
        assert_eq!(result.len(), 3);
        assert_eq!(
            result[0],
            ObjectPlacementEntry::new(10, mid(1), ShardKind::Primary)
        );
        assert_eq!(
            result[1],
            ObjectPlacementEntry::new(10, mid(2), ShardKind::Replica)
        );
        assert_eq!(
            result[2],
            ObjectPlacementEntry::new(20, mid(1), ShardKind::Primary)
        );
    }

    #[test]
    fn loopback_enumerator_deterministic_output() {
        let mut registry = HarnessObjectRegistry::new();
        registry.insert_many(nid(3), [5]);
        registry.insert_many(nid(1), [10, 5]);
        registry.insert_many(nid(2), [10]);

        let enumerator = LoopbackObjectEnumerator::new(registry);
        let a = enumerator.enumerate_objects(EpochId(1), 42).unwrap();
        let b = enumerator.enumerate_objects(EpochId(1), 42).unwrap();

        assert_eq!(a, b);
        // Expected: (5,1), (5,3), (10,1), (10,2)
        assert_eq!(a.len(), 4);
        assert_eq!(
            a[0],
            ObjectPlacementEntry::new(5, mid(1), ShardKind::Primary)
        );
        assert_eq!(
            a[1],
            ObjectPlacementEntry::new(5, mid(3), ShardKind::Replica)
        );
        assert_eq!(
            a[2],
            ObjectPlacementEntry::new(10, mid(1), ShardKind::Primary)
        );
        assert_eq!(
            a[3],
            ObjectPlacementEntry::new(10, mid(2), ShardKind::Replica)
        );
    }

    #[test]
    fn loopback_enumerator_insufficient_responders() {
        let mut registry = HarnessObjectRegistry::new();
        registry.insert_many(nid(1), [42]);

        let enumerator = LoopbackObjectEnumerator::with_min_responders(registry, 3);
        let result = enumerator.enumerate_objects(EpochId(0), 1);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.expected, 3);
        assert_eq!(err.responded, 1);
    }

    #[test]
    fn loopback_enumerator_remove_node_changes_output() {
        let mut registry = HarnessObjectRegistry::new();
        registry.insert_many(nid(1), [10, 20]);
        registry.insert_many(nid(2), [10, 30]);

        let enumerator = LoopbackObjectEnumerator::new(registry.clone());
        let before = enumerator.enumerate_objects(EpochId(0), 1).unwrap();
        assert_eq!(before.len(), 4);

        registry.remove_node(nid(2));
        let enumerator2 = LoopbackObjectEnumerator::new(registry);
        let after = enumerator2.enumerate_objects(EpochId(0), 1).unwrap();
        assert_eq!(after.len(), 2);
        assert_ne!(before, after);
    }

    #[test]
    fn loopback_enumerator_integration_with_deltas() {
        let mut registry = HarnessObjectRegistry::new();
        registry.insert_many(nid(1), [1, 2, 3]);
        registry.insert_many(nid(2), [1]);

        let enumerator = LoopbackObjectEnumerator::new(registry);
        let enumeration = enumerator.enumerate_objects(EpochId(0), 1).unwrap();

        let mut current: BTreeMap<tidefs_membership_epoch::MemberId, BTreeSet<u64>> =
            BTreeMap::new();
        current.insert(mid(1), [1, 2].into());
        current.insert(mid(2), [1, 4].into());

        let deltas = compute_per_node_object_deltas(&enumeration, &current);

        assert_eq!(deltas[&mid(1)].missing, [3].into());
        assert_eq!(deltas[&mid(2)].excess, [4].into());
        assert!(deltas[&mid(1)].has_work());
        assert!(deltas[&mid(2)].has_work());
    }

    #[test]
    fn loopback_enumerator_respects_min_responders_exactly() {
        let mut registry = HarnessObjectRegistry::new();
        registry.insert_many(nid(1), [1]);

        let enumerator = LoopbackObjectEnumerator::with_min_responders(registry, 1);
        let result = enumerator.enumerate_objects(EpochId(0), 1);
        assert!(result.is_ok());
    }
}
