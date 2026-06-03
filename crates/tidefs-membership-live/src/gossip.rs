#![forbid(unsafe_code)]

//! SWIM-style gossip dissemination protocol for cluster-wide membership state
//! propagation.
//!
//! ## Architecture
//!
//! Membership-live detects liveness locally (via [`FailureDetector`]) and scores
//! suspicion validation via the suspicion accumulator (#5683). This module
//! disseminates those observations cluster-wide through two complementary
//! mechanisms:
//!
//! 1. **Rumor-mongering** — on each outgoing transport message, piggybacks a
//!    bounded set of recent gossip messages. Rumors are selected by age and
//!    state-change priority (Failed > Suspected > Alive).
//! 2. **Anti-entropy exchange** — periodic full-state digest comparison with a
//!    randomly selected peer, exchanging only divergent entries.
//!
//! Together they provide eventual-consistency membership state propagation
//! without requiring a central coordinator.
//!
//! ## Data Integrity
//!
//! Every [`GossipMessage`] carries a BLAKE3-256 digest (`"tidefs-membership-gossip-v1"`)
//! covering member_id, incarnation, state, lamport clock, and originator.
//! Receivers verify this digest via [`verify_full`](GossipMessage::verify_full)
//! before merging the remote observation into their local state.
//!
//! ## Integration
//!
//! - **Input**: consumes suspicion accumulator output (Suspected/Failed scores)
//!   from the failure detector (#5683).
//! - **Output**: feeds disseminated member state into the membership roster
//!   (#5694) for authoritative member-set maintenance.
//! - **Transport**: rumor piggybacking integrates with the transport message
//!   dispatch path; anti-entropy exchanges use direct peer-to-peer messaging.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use tidefs_membership_epoch::{EpochId, MemberId};

// ---------------------------------------------------------------------------
// MemberState — liveness state enum for gossip messages
// ---------------------------------------------------------------------------

/// Liveness state of a cluster member as observed and disseminated.
///
/// Mirrors the SWIM health model: Alive → Suspected → Failed.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum MemberState {
    /// Member is alive and responding to pings.
    Alive = 0,
    /// Member is suspected of failure (unconfirmed).
    Suspected = 1,
    /// Member is confirmed failed by multi-source validation.
    Failed = 2,
}

impl MemberState {
    /// Priority for rumor selection: higher values are selected first.
    #[must_use]
    pub fn rumor_priority(self) -> u8 {
        match self {
            MemberState::Failed => 3,
            MemberState::Suspected => 2,
            MemberState::Alive => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// GossipMessage — a single disseminated liveness observation
// ---------------------------------------------------------------------------

/// A single gossip rumor carrying one member's liveness state observation.
///
/// Each message includes a BLAKE3-256 domain-separated digest for tamper
/// detection. The digest covers the canonical bincode serialization of
/// `(member_id, incarnation, state, lamport_clock, originator)`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GossipMessage {
    /// The member whose state is being reported.
    pub member_id: MemberId,
    /// Monotonically increasing incarnation number. Higher incarnation
    /// always supersedes lower, regardless of state.
    pub incarnation: u64,
    /// Current observed state of the member.
    pub state: MemberState,
    /// Lamport logical clock value. Used to order observations from
    /// different originators about the same member.
    pub lamport_clock: u64,
    /// The node that originated this observation.
    pub originator: MemberId,
    /// Epoch in which this observation was made.
    pub epoch: EpochId,
    /// Timestamp in milliseconds when this message was created.
    pub created_at_millis: u64,
    /// BLAKE3-256 domain-separated digest of the canonical payload.
    pub digest: [u8; 32],
}

/// Domain separation key for gossip message BLAKE3 hashing.
const GOSSIP_DOMAIN: &str = "tidefs-membership-gossip-v1";

impl GossipMessage {
    /// Create a new gossip message and compute its BLAKE3 digest.
    #[must_use]
    pub fn new(
        member_id: MemberId,
        incarnation: u64,
        state: MemberState,
        lamport_clock: u64,
        originator: MemberId,
        epoch: EpochId,
        created_at_millis: u64,
    ) -> Self {
        let digest = Self::compute_digest(
            member_id,
            incarnation,
            state,
            lamport_clock,
            originator,
            epoch,
            created_at_millis,
        );
        Self {
            member_id,
            incarnation,
            state,
            lamport_clock,
            originator,
            epoch,
            created_at_millis,
            digest,
        }
    }

    /// Compute the BLAKE3-256 domain-separated digest for a gossip message
    /// payload.
    fn compute_digest(
        member_id: MemberId,
        incarnation: u64,
        state: MemberState,
        lamport_clock: u64,
        originator: MemberId,
        epoch: EpochId,
        created_at_millis: u64,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(GOSSIP_DOMAIN);
        hasher.update(&member_id.0.to_le_bytes());
        hasher.update(&incarnation.to_le_bytes());
        hasher.update(&[state as u8]);
        hasher.update(&lamport_clock.to_le_bytes());
        hasher.update(&originator.0.to_le_bytes());
        hasher.update(&epoch.0.to_le_bytes());
        hasher.update(&created_at_millis.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verify the stored digest matches the computed digest.
    ///
    /// Returns `true` when the message is authentic and unmodified.
    #[must_use]
    pub fn verify_full(&self) -> bool {
        let computed = Self::compute_digest(
            self.member_id,
            self.incarnation,
            self.state,
            self.lamport_clock,
            self.originator,
            self.epoch,
            self.created_at_millis,
        );
        computed == self.digest
    }

    /// Returns true if `other` supersedes this message.
    ///
    /// Rules (in order):
    /// 1. Higher incarnation always wins.
    /// 2. Equal incarnation, higher lamport clock wins.
    /// 3. Equal clock, but different state: Failed > Suspected > Alive.
    #[must_use]
    pub fn is_superseded_by(&self, other: &GossipMessage) -> bool {
        debug_assert_eq!(
            self.member_id, other.member_id,
            "is_superseded_by should only compare messages for the same member"
        );
        if other.incarnation > self.incarnation {
            return true;
        }
        if other.incarnation < self.incarnation {
            return false;
        }
        // Equal incarnation
        if other.lamport_clock > self.lamport_clock {
            return true;
        }
        if other.lamport_clock < self.lamport_clock {
            return false;
        }
        // Equal lamport clock — escalate by state priority
        other.state.rumor_priority() > self.state.rumor_priority()
    }
}

// ---------------------------------------------------------------------------
// GossipState — per-member tracking for dissemination decisions
// ---------------------------------------------------------------------------

/// Per-member gossip state tracked locally by each node.
///
/// Used to decide whether an incoming rumor carries newer information
/// and should be accepted and re-disseminated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GossipState {
    /// The member being tracked.
    pub member_id: MemberId,
    /// Last known incarnation number.
    pub last_incarnation: u64,
    /// Last known liveness state.
    pub last_state: MemberState,
    /// Last known lamport clock value.
    pub last_lamport_clock: u64,
    /// How many hops this rumor has traversed (for loop detection).
    pub hop_count: u32,
}

impl GossipState {
    /// Create a new gossip state entry with initial values.
    #[must_use]
    pub fn new(
        member_id: MemberId,
        incarnation: u64,
        state: MemberState,
        lamport_clock: u64,
    ) -> Self {
        Self {
            member_id,
            last_incarnation: incarnation,
            last_state: state,
            last_lamport_clock: lamport_clock,
            hop_count: 0,
        }
    }

    /// Try to apply an incoming gossip message, returning `true` if the
    /// state was updated (the rumor carried newer information).
    ///
    /// Updates the stored incarnation, state, and lamport clock when the
    /// incoming message supersedes the current state. Increments the hop
    /// count on successful application.
    pub fn apply(&mut self, msg: &GossipMessage) -> bool {
        debug_assert_eq!(
            self.member_id, msg.member_id,
            "apply should only be called with messages for the same member"
        );

        // Construct a temporary message from current state for comparison.
        let current = GossipMessage {
            member_id: self.member_id,
            incarnation: self.last_incarnation,
            state: self.last_state,
            lamport_clock: self.last_lamport_clock,
            originator: MemberId::new(0), // dummy
            epoch: EpochId::new(0),
            created_at_millis: 0,
            digest: [0u8; 32],
        };

        if current.is_superseded_by(msg) {
            self.last_incarnation = msg.incarnation;
            self.last_state = msg.state;
            self.last_lamport_clock = msg.lamport_clock;
            self.hop_count = self.hop_count.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Returns true if this state has changed (not in initial Alive state).
    #[must_use]
    pub fn has_changed(&self) -> bool {
        self.last_state != MemberState::Alive || self.last_incarnation > 0
    }
}

// ---------------------------------------------------------------------------
// DisseminationConfig — configuration for the gossip protocol
// ---------------------------------------------------------------------------

/// Configuration for the gossip dissemination protocol.
///
/// Uses a builder pattern for ergonomic construction with sensible defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisseminationConfig {
    /// Maximum number of rumors to piggyback on each outgoing message.
    pub piggyback_limit: usize,
    /// Interval in milliseconds between anti-entropy rounds.
    pub anti_entropy_interval_ms: u64,
    /// Maximum number of hops a rumor can traverse before being dropped.
    pub rumor_ttl: u32,
    /// Maximum number of rumors in the rumor-mongering queue. When exceeded,
    /// oldest Alive rumors are evicted first.
    pub max_rumor_queue: usize,
    /// Number of peers to select for anti-entropy exchange each round.
    pub anti_entropy_peer_count: usize,
}

impl Default for DisseminationConfig {
    fn default() -> Self {
        Self {
            piggyback_limit: 3,
            anti_entropy_interval_ms: 1000,
            rumor_ttl: 10,
            max_rumor_queue: 256,
            anti_entropy_peer_count: 1,
        }
    }
}

impl DisseminationConfig {
    /// Create a new config with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of piggybacked rumors per message.
    #[must_use]
    pub fn with_piggyback_limit(mut self, limit: usize) -> Self {
        self.piggyback_limit = limit;
        self
    }

    /// Set the anti-entropy round interval in milliseconds.
    #[must_use]
    pub fn with_anti_entropy_interval_ms(mut self, interval_ms: u64) -> Self {
        self.anti_entropy_interval_ms = interval_ms;
        self
    }

    /// Set the maximum rumor hop count (TTL).
    #[must_use]
    pub fn with_rumor_ttl(mut self, ttl: u32) -> Self {
        self.rumor_ttl = ttl;
        self
    }

    /// Set the maximum rumor queue size.
    #[must_use]
    pub fn with_max_rumor_queue(mut self, max: usize) -> Self {
        self.max_rumor_queue = max;
        self
    }

    /// Set the number of peers for anti-entropy each round.
    #[must_use]
    pub fn with_anti_entropy_peer_count(mut self, count: usize) -> Self {
        self.anti_entropy_peer_count = count;
        self
    }
}
// ---------------------------------------------------------------------------
// QueuedRumor — internal wrapper for a rumor in the piggyback queue
// ---------------------------------------------------------------------------

/// A queued rumor with hop-count tracking for loop detection.
#[derive(Clone, Debug)]
struct QueuedRumor {
    /// The gossip message.
    message: GossipMessage,
    /// Number of hops this rumor has traversed.
    hop_count: u32,
    /// Timestamp when this rumor was enqueued (milliseconds).
    enqueued_at_millis: u64,
}

// ---------------------------------------------------------------------------
// RumorMongerer — piggyback rumor queue with priority selection
// ---------------------------------------------------------------------------

/// Rumor-mongering engine that maintains a bounded queue of gossip messages
/// and selects rumors for piggybacking on outgoing transport messages.
///
/// Selection priority: Failed > Suspected > Alive. Within equal priority,
/// oldest rumors are selected first. Rumors exceeding [`DisseminationConfig::rumor_ttl`]
/// hops are silently dropped during selection. When the queue overflows,
/// the oldest Alive rumor is evicted first.
pub struct RumorMongerer {
    config: DisseminationConfig,
    queue: VecDeque<QueuedRumor>,
    /// Function to obtain current wall-clock time in milliseconds.
    now_fn: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl RumorMongerer {
    /// Create a new rumor-mongerer with the given config and time source.
    #[must_use]
    pub fn new(config: DisseminationConfig, now_fn: Box<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self {
            queue: VecDeque::with_capacity(config.max_rumor_queue),
            config,
            now_fn,
        }
    }

    /// Enqueue a gossip message for dissemination.
    ///
    /// Duplicate suppression: if a rumor for the same member + incarnation
    /// already exists in the queue, the new message is silently dropped.
    ///
    /// When the queue is at capacity, the oldest Alive rumor is evicted.
    /// If no Alive rumor exists, the oldest rumor (any state) is evicted.
    pub fn enqueue(&mut self, msg: GossipMessage, hop_count: u32) {
        let now = (self.now_fn)();

        // Duplicate suppression: same member + incarnation already queued.
        if self.queue.iter().any(|r| {
            r.message.member_id == msg.member_id && r.message.incarnation == msg.incarnation
        }) {
            return;
        }

        if self.queue.len() >= self.config.max_rumor_queue {
            self.evict_one();
        }
        self.queue.push_back(QueuedRumor {
            message: msg,
            hop_count,
            enqueued_at_millis: now,
        });
    }

    /// Evict the oldest Alive rumor, or the oldest rumor if no Alive exists.
    fn evict_one(&mut self) {
        let mut oldest_alive_idx: Option<usize> = None;
        let mut oldest_alive_time = u64::MAX;
        let mut oldest_any_idx: usize = 0;
        let mut oldest_any_time = u64::MAX;

        for (i, rumor) in self.queue.iter().enumerate() {
            if rumor.enqueued_at_millis < oldest_any_time {
                oldest_any_time = rumor.enqueued_at_millis;
                oldest_any_idx = i;
            }
            if rumor.message.state == MemberState::Alive
                && rumor.enqueued_at_millis < oldest_alive_time
            {
                oldest_alive_time = rumor.enqueued_at_millis;
                oldest_alive_idx = Some(i);
            }
        }

        let idx = oldest_alive_idx.unwrap_or(oldest_any_idx);
        self.queue.remove(idx);
    }

    /// Select up to `limit` rumors for piggybacking on an outgoing message.
    ///
    /// Selection rules:
    /// 1. Rumors with `hop_count >= rumor_ttl` are expired and dropped.
    /// 2. Remaining rumors are sorted by state priority (Failed > Suspected > Alive).
    /// 3. Within equal priority, oldest rumors are selected first.
    /// 4. The top `limit` rumors are returned and removed from the queue.
    ///
    /// Returns an empty vec when the queue is empty or all rumors are expired.
    #[must_use]
    pub fn select_piggyback(&mut self, limit: usize) -> Vec<GossipMessage> {
        let ttl = self.config.rumor_ttl;

        // Drop expired rumors.
        self.queue.retain(|r| r.hop_count < ttl);

        if self.queue.is_empty() {
            return Vec::new();
        }

        // Drain all rumors, sort by (priority desc, age asc), split.
        let mut all: Vec<QueuedRumor> = self.queue.drain(..).collect();
        all.sort_by(|a, b| {
            let pa = a.message.state.rumor_priority();
            let pb = b.message.state.rumor_priority();
            pb.cmp(&pa)
                .then_with(|| a.enqueued_at_millis.cmp(&b.enqueued_at_millis))
        });

        let count = limit.min(all.len());
        let selected: Vec<GossipMessage> = all[..count].iter().map(|r| r.message.clone()).collect();

        // Put remaining rumors back into the queue.
        self.queue = all.into_iter().skip(count).collect();

        selected
    }

    /// Number of rumors currently in the queue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

// ---------------------------------------------------------------------------
// AntiEntropyRound — periodic full-state digest exchange
// ---------------------------------------------------------------------------

/// Domain separation key for anti-entropy digest hashing.
const ANTI_ENTROPY_DOMAIN: &str = "tidefs-membership-anti-entropy-v1";

/// Drives periodic full-state digest exchange with a randomly selected peer
/// to detect and reconcile divergent membership state.
///
/// Each round:
/// 1. Compute a BLAKE3-256 digest over local (member_id, incarnation, state) tuples.
/// 2. Exchange digests with the peer.
/// 3. When digests differ, exchange only the divergent entries.
pub struct AntiEntropyRound {
    /// Timestamp of the last completed round (milliseconds).
    last_round_millis: u64,
    /// Minimum interval between rounds (milliseconds).
    interval_ms: u64,
    /// Digest of local state sent during the last completed round.
    last_sent_digest: Option<[u8; 32]>,
}

impl AntiEntropyRound {
    /// Create a new anti-entropy round tracker.
    #[must_use]
    pub fn new(interval_ms: u64) -> Self {
        Self {
            last_round_millis: 0,
            interval_ms,
            last_sent_digest: None,
        }
    }

    /// Returns `true` when enough time has elapsed since the last round.
    #[must_use]
    pub fn should_run(&self, now_millis: u64) -> bool {
        self.last_round_millis == 0
            || now_millis.saturating_sub(self.last_round_millis) >= self.interval_ms
    }

    /// Record that a round completed at the given time, storing the sent digest.
    pub fn record_round(&mut self, now_millis: u64, sent_digest: [u8; 32]) {
        self.last_round_millis = now_millis;
        self.last_sent_digest = Some(sent_digest);
    }

    /// The digest sent during the last completed round, if any.
    #[must_use]
    pub fn last_sent_digest(&self) -> Option<[u8; 32]> {
        self.last_sent_digest
    }

    /// Timestamp of the last completed round.
    #[must_use]
    pub fn last_round_millis(&self) -> u64 {
        self.last_round_millis
    }

    /// Compute a BLAKE3-256 domain-separated digest over the given member
    /// state tuples.
    ///
    /// Tuples are sorted by `member_id` before hashing so that two sets with
    /// the same members in different orders produce identical digests.
    #[must_use]
    pub fn compute_digest(states: &[(MemberId, u64, MemberState)]) -> [u8; 32] {
        let mut sorted: Vec<_> = states.to_vec();
        sorted.sort_by_key(|(id, _, _)| id.0);

        let mut hasher = blake3::Hasher::new_derive_key(ANTI_ENTROPY_DOMAIN);
        for (id, incarnation, state) in &sorted {
            hasher.update(&id.0.to_le_bytes());
            hasher.update(&incarnation.to_le_bytes());
            hasher.update(&[(*state) as u8]);
        }
        hasher.finalize().into()
    }

    /// Find entries in `local` that diverge from `remote`.
    ///
    /// An entry diverges when:
    /// - The member is present in `local` but absent from `remote`, OR
    /// - The member has a different incarnation or state in `remote`.
    ///
    /// Members present only in `remote` are NOT included in the result
    /// (they would be handled by the peer's own divergent-entry computation).
    #[must_use]
    pub fn divergent_entries(
        local: &[(MemberId, u64, MemberState)],
        remote: &[(MemberId, u64, MemberState)],
    ) -> Vec<(MemberId, u64, MemberState)> {
        let remote_map: BTreeMap<MemberId, (u64, MemberState)> = remote
            .iter()
            .map(|&(id, inc, st)| (id, (inc, st)))
            .collect();

        local
            .iter()
            .filter(|&&(id, inc, st)| match remote_map.get(&id) {
                Some(&(r_inc, r_st)) => inc != r_inc || st != r_st,
                None => true,
            })
            .map(|&(id, inc, st)| (id, inc, st))
            .collect()
    }
}
// ---------------------------------------------------------------------------
// GossipConfig — epidemic broadcast configuration
// ---------------------------------------------------------------------------

/// Configuration for epidemic gossip broadcast with fan-out.
///
/// Controls the fan-out factor, retry policy, time-to-live, and
/// deduplication set size for the [`GossipBroadcastEngine`].
#[derive(Clone, Debug)]
pub struct GossipConfig {
    /// Number of peers to fan out each message to. Default 3 gives O(log N)
    /// dissemination with high probability.
    pub fanout: usize,
    /// Number of retry attempts for messages after initial broadcast fails.
    pub retry_count: usize,
    /// Maximum number of hops a gossip message can traverse before being
    /// dropped. Lowers with each re-broadcast; reaches zero at expiry.
    pub ttl: u32,
    /// Maximum capacity of the seen-message deduplication set. When exceeded,
    /// oldest entries are evicted (bounded LRU).
    pub seen_set_capacity: usize,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            fanout: 3,
            retry_count: 2,
            ttl: 10,
            seen_set_capacity: 1024,
        }
    }
}

impl GossipConfig {
    /// Create a new config with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the fan-out factor.
    #[must_use]
    pub fn with_fanout(mut self, fanout: usize) -> Self {
        self.fanout = fanout;
        self
    }

    /// Set the retry count.
    #[must_use]
    pub fn with_retry_count(mut self, retry_count: usize) -> Self {
        self.retry_count = retry_count;
        self
    }

    /// Set the message TTL (hop limit).
    #[must_use]
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    /// Set the seen-set capacity.
    #[must_use]
    pub fn with_seen_set_capacity(mut self, capacity: usize) -> Self {
        self.seen_set_capacity = capacity;
        self
    }
}

// ---------------------------------------------------------------------------
// GossipBroadcastEngine — epidemic fan-out broadcast
// ---------------------------------------------------------------------------

/// Epidemic gossip broadcast engine using fan-out to k random peers.
///
/// Unlike [`RumorMongerer`] which piggybacks rumors passively on outgoing
/// transport messages, this engine proactively fans out epoch transition
/// notifications and peer state deltas to a random subset of peers, achieving
/// O(log N) dissemination rounds with high probability.
///
/// ## Deduplication
///
/// A bounded LRU seen-message set (capacity [`GossipConfig::seen_set_capacity`])
/// prevents redundant processing of already-received messages. Each
/// [`GossipMessage`] carries a BLAKE3-256 digest; the engine uses this digest
/// as the deduplication key.
///
/// ## Integration
///
/// - **Input**: consumes [`crate::event_bridge::MembershipEvent`] (epoch
///   transitions, peer state changes) via [`build_from_event`](Self::build_from_event).
/// - **Output**: fans out resulting [`GossipMessage`]s to selected peers.
/// - **Transport**: use [`crate::transport_wiring::MembershipWireMessage::GossipBroadcast`]
///   to send gossip messages over established sessions.
pub struct GossipBroadcastEngine {
    config: GossipConfig,
    /// LRU-ordered set of message digests already seen. Front = oldest.
    seen: VecDeque<[u8; 32]>,
    /// Function to obtain current wall-clock time in milliseconds.
    now_fn: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl GossipBroadcastEngine {
    /// Create a new broadcast engine with the given config and time source.
    #[must_use]
    pub fn new(config: GossipConfig, now_fn: Box<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self {
            seen: VecDeque::with_capacity(config.seen_set_capacity),
            config,
            now_fn,
        }
    }

    /// Returns `true` if the message digest has already been seen.
    #[must_use]
    pub fn has_seen(&self, digest: &[u8; 32]) -> bool {
        self.seen.contains(digest)
    }

    /// Add a message digest to the seen set, evicting the oldest if at capacity.
    pub fn mark_seen(&mut self, digest: [u8; 32]) {
        // Avoid duplicates.
        if self.seen.contains(&digest) {
            return;
        }
        if self.seen.len() >= self.config.seen_set_capacity {
            self.seen.pop_front();
        }
        self.seen.push_back(digest);
    }

    /// Check whether an incoming gossip message is new (not previously seen).
    ///
    /// Returns `true` if the message should be accepted and processed.
    /// As a side effect, marks the message as seen so it won't be accepted again.
    pub fn accept_message(&mut self, msg: &GossipMessage) -> bool {
        // Reject already-seen messages.
        if self.has_seen(&msg.digest) {
            return false;
        }
        // Reject messages whose age exceeds TTL-based max age.
        let now = (self.now_fn)();
        let age_ms = now.saturating_sub(msg.created_at_millis);
        let max_age_ms = u64::from(self.config.ttl) * 500;
        if age_ms > max_age_ms {
            return false;
        }
        self.mark_seen(msg.digest);
        true
    }

    /// Select up to `fanout` random peers from `all_peers`, excluding any
    /// listed in `exclude`.
    ///
    /// Uses the provided random number generator for deterministic testing.
    /// Returns an empty vec when no eligible peers remain.
    #[must_use]
    pub fn select_fanout_peers(
        &self,
        all_peers: &[MemberId],
        exclude: &[MemberId],
        rng: &mut impl rand::Rng,
    ) -> Vec<MemberId> {
        let eligible: Vec<MemberId> = all_peers
            .iter()
            .filter(|p| !exclude.contains(p))
            .copied()
            .collect();

        if eligible.is_empty() {
            return Vec::new();
        }

        let count = self.config.fanout.min(eligible.len());
        // Use rand 0.7 choose_multiple which returns an iterator.
        use rand::seq::SliceRandom;
        eligible.choose_multiple(rng, count).copied().collect()
    }

    /// Build a [`GossipMessage`] from a [`crate::event_bridge::MembershipEvent`]
    /// for broadcast dissemination.
    ///
    /// Returns `None` when the event does not map to a gossip state.
    /// Uses the incarnation number as the lamport clock for ordering.
    #[must_use]
    pub fn build_from_event(
        event: &crate::event_bridge::MembershipEvent,
        originator: MemberId,
        epoch: EpochId,
        now_millis: u64,
    ) -> Option<GossipMessage> {
        use crate::event_bridge::MembershipEvent;

        let (member_id, incarnation, state) = match event {
            MembershipEvent::MemberJoined {
                member_id,
                incarnation,
                ..
            } => (*member_id, *incarnation, MemberState::Alive),
            MembershipEvent::MemberSuspected {
                member_id,
                incarnation,
                ..
            } => (*member_id, *incarnation, MemberState::Suspected),
            MembershipEvent::MemberFailed {
                member_id,
                incarnation,
                ..
            } => (*member_id, *incarnation, MemberState::Failed),
            MembershipEvent::MemberLeft {
                member_id,
                incarnation,
                ..
            } => (*member_id, *incarnation, MemberState::Failed),
            MembershipEvent::MemberDraining {
                member_id,
                incarnation,
                ..
            } => (*member_id, *incarnation, MemberState::Suspected),
            MembershipEvent::MemberDrained {
                member_id,
                incarnation,
                ..
            } => (*member_id, *incarnation, MemberState::Failed),
        };

        Some(GossipMessage::new(
            member_id,
            incarnation,
            state,
            incarnation, // lamport_clock: use incarnation for ordering
            originator,
            epoch,
            now_millis,
        ))
    }

    /// Number of message digests currently in the seen set.
    #[must_use]
    pub fn seen_count(&self) -> usize {
        self.seen.len()
    }

    /// Clear the seen set. Useful for testing or epoch resets.
    pub fn clear_seen(&mut self) {
        self.seen.clear();
    }

    /// Get the engine's config.
    #[must_use]
    pub fn config(&self) -> &GossipConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    /// Helper: create a basic valid GossipMessage.
    fn mk_msg(
        member_id: u64,
        incarnation: u64,
        state: MemberState,
        lamport: u64,
        originator: u64,
    ) -> GossipMessage {
        GossipMessage::new(
            MemberId::new(member_id),
            incarnation,
            state,
            lamport,
            MemberId::new(originator),
            EpochId::new(1),
            1000,
        )
    }

    // -------------------------------------------------------------------
    // GossipMessage: serialization round-trip and tamper detection
    // -------------------------------------------------------------------

    #[test]
    fn message_bincode_roundtrip() {
        let msg = mk_msg(1, 0, MemberState::Alive, 0, 1);
        let encoded = bincode::serialize(&msg).expect("serialize");
        let decoded: GossipMessage = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(msg, decoded);
        assert!(decoded.verify_full());
    }

    #[test]
    fn message_verify_full_accepts_valid() {
        let msg = mk_msg(1, 0, MemberState::Alive, 0, 1);
        assert!(msg.verify_full());
    }

    #[test]
    fn message_digest_detects_tampered_member_id() {
        let mut msg = mk_msg(1, 0, MemberState::Alive, 0, 1);
        assert!(msg.verify_full());
        msg.member_id = MemberId::new(999);
        assert!(!msg.verify_full());
    }

    #[test]
    fn message_digest_detects_tampered_incarnation() {
        let mut msg = mk_msg(1, 0, MemberState::Alive, 0, 1);
        msg.incarnation = 42;
        assert!(!msg.verify_full());
    }

    #[test]
    fn message_digest_detects_tampered_state() {
        let mut msg = mk_msg(1, 0, MemberState::Alive, 0, 1);
        msg.state = MemberState::Failed;
        assert!(!msg.verify_full());
    }

    #[test]
    fn message_digest_detects_tampered_lamport_clock() {
        let mut msg = mk_msg(1, 0, MemberState::Alive, 0, 1);
        msg.lamport_clock = 777;
        assert!(!msg.verify_full());
    }

    #[test]
    fn message_digest_detects_tampered_originator() {
        let mut msg = mk_msg(1, 0, MemberState::Alive, 0, 1);
        msg.originator = MemberId::new(888);
        assert!(!msg.verify_full());
    }

    #[test]
    fn message_digest_detects_tampered_epoch() {
        let mut msg = mk_msg(1, 0, MemberState::Alive, 0, 1);
        msg.epoch = EpochId::new(999);
        assert!(!msg.verify_full());
    }

    #[test]
    fn message_digest_detects_tampered_timestamp() {
        let mut msg = mk_msg(1, 0, MemberState::Alive, 0, 1);
        msg.created_at_millis = 99999;
        assert!(!msg.verify_full());
    }

    #[test]
    fn message_digest_detects_tampered_digest_byte() {
        let mut msg = mk_msg(1, 0, MemberState::Alive, 0, 1);
        assert!(msg.verify_full());
        msg.digest[0] ^= 0xFF;
        assert!(!msg.verify_full());
    }

    #[test]
    fn message_digests_differ_for_different_members() {
        let a = mk_msg(1, 0, MemberState::Alive, 0, 1);
        let b = mk_msg(2, 0, MemberState::Alive, 0, 1);
        assert_ne!(a.digest, b.digest);
    }

    #[test]
    fn message_digests_differ_for_different_states() {
        let a = mk_msg(1, 0, MemberState::Alive, 0, 1);
        let b = mk_msg(1, 0, MemberState::Suspected, 0, 1);
        assert_ne!(a.digest, b.digest);
    }

    #[test]
    fn message_digests_differ_for_different_incarnation() {
        let a = mk_msg(1, 0, MemberState::Alive, 0, 1);
        let b = mk_msg(1, 1, MemberState::Alive, 0, 1);
        assert_ne!(a.digest, b.digest);
    }

    #[test]
    fn message_digests_differ_for_different_lamport() {
        let a = mk_msg(1, 0, MemberState::Alive, 1, 1);
        let b = mk_msg(1, 0, MemberState::Alive, 2, 1);
        assert_ne!(a.digest, b.digest);
    }

    #[test]
    fn message_digests_differ_for_different_originator() {
        let a = mk_msg(1, 0, MemberState::Alive, 0, 1);
        let b = mk_msg(1, 0, MemberState::Alive, 0, 2);
        assert_ne!(a.digest, b.digest);
    }

    // -------------------------------------------------------------------
    // GossipMessage: supersedes logic (Lamport ordering)
    // -------------------------------------------------------------------

    #[test]
    fn higher_incarnation_supersedes_lower() {
        let old = mk_msg(1, 0, MemberState::Alive, 0, 1);
        let new = mk_msg(1, 1, MemberState::Alive, 0, 1);
        assert!(old.is_superseded_by(&new));
        assert!(!new.is_superseded_by(&old));
    }

    #[test]
    fn equal_incarnation_higher_lamport_wins() {
        let old = mk_msg(1, 0, MemberState::Alive, 5, 1);
        let new = mk_msg(1, 0, MemberState::Alive, 10, 1);
        assert!(old.is_superseded_by(&new));
        assert!(!new.is_superseded_by(&old));
    }

    #[test]
    fn equal_incarnation_and_clock_failed_wins_over_alive() {
        let alive = mk_msg(1, 0, MemberState::Alive, 5, 1);
        let failed = mk_msg(1, 0, MemberState::Failed, 5, 2);
        assert!(alive.is_superseded_by(&failed));
        assert!(!failed.is_superseded_by(&alive));
    }

    #[test]
    fn equal_incarnation_and_clock_suspected_wins_over_alive() {
        let alive = mk_msg(1, 0, MemberState::Alive, 5, 1);
        let suspected = mk_msg(1, 0, MemberState::Suspected, 5, 2);
        assert!(alive.is_superseded_by(&suspected));
        assert!(!suspected.is_superseded_by(&alive));
    }

    #[test]
    fn equal_incarnation_and_clock_failed_wins_over_suspected() {
        let suspected = mk_msg(1, 0, MemberState::Suspected, 5, 1);
        let failed = mk_msg(1, 0, MemberState::Failed, 5, 2);
        assert!(suspected.is_superseded_by(&failed));
        assert!(!failed.is_superseded_by(&suspected));
    }

    #[test]
    fn identical_message_does_not_supersede() {
        let a = mk_msg(1, 0, MemberState::Alive, 0, 1);
        let b = mk_msg(1, 0, MemberState::Alive, 0, 1);
        assert!(!a.is_superseded_by(&b));
        assert!(!b.is_superseded_by(&a));
    }

    #[test]
    fn lower_incarnation_does_not_supersede() {
        let high = mk_msg(1, 5, MemberState::Alive, 0, 1);
        let low = mk_msg(1, 3, MemberState::Failed, 100, 1);
        assert!(!high.is_superseded_by(&low));
        assert!(low.is_superseded_by(&high));
    }

    #[test]
    fn higher_lamport_does_not_override_lower_incarnation() {
        let high_inc = mk_msg(1, 2, MemberState::Alive, 0, 1);
        let high_lamport = mk_msg(1, 1, MemberState::Failed, 100, 2);
        // high_lamport has higher lamport but lower incarnation
        assert!(
            !high_inc.is_superseded_by(&high_lamport),
            "higher incarnation must win over higher lamport clock"
        );
        assert!(
            high_lamport.is_superseded_by(&high_inc),
            "higher incarnation must supersede even if lamport is lower"
        );
    }

    // -------------------------------------------------------------------
    // GossipState: apply logic
    // -------------------------------------------------------------------

    #[test]
    fn gossip_state_apply_newer_message() {
        let mut state = GossipState::new(MemberId::new(1), 0, MemberState::Alive, 0);
        let msg = mk_msg(1, 1, MemberState::Suspected, 5, 2);
        assert!(state.apply(&msg));
        assert_eq!(state.last_incarnation, 1);
        assert_eq!(state.last_state, MemberState::Suspected);
        assert_eq!(state.last_lamport_clock, 5);
        assert_eq!(state.hop_count, 1);
    }

    #[test]
    fn gossip_state_apply_older_message_no_change() {
        let mut state = GossipState::new(MemberId::new(1), 5, MemberState::Failed, 10);
        let initial_hop = state.hop_count;
        let msg = mk_msg(1, 3, MemberState::Alive, 2, 2);
        assert!(!state.apply(&msg));
        assert_eq!(state.last_incarnation, 5);
        assert_eq!(state.last_state, MemberState::Failed);
        assert_eq!(state.last_lamport_clock, 10);
        assert_eq!(
            state.hop_count, initial_hop,
            "hop count should not change on rejected message"
        );
    }

    #[test]
    fn gossip_state_apply_identical_message_no_change() {
        let mut state = GossipState::new(MemberId::new(1), 1, MemberState::Suspected, 5);
        let initial_hop = state.hop_count;
        let msg = mk_msg(1, 1, MemberState::Suspected, 5, 2);
        assert!(!state.apply(&msg));
        assert_eq!(state.hop_count, initial_hop);
    }

    #[test]
    fn gossip_state_apply_equal_incarnation_state_escalation() {
        // Same incarnation and clock, but new state is Failed vs current Alive:
        // Failed should supersede Alive.
        let mut state = GossipState::new(MemberId::new(1), 2, MemberState::Alive, 3);
        let msg = mk_msg(1, 2, MemberState::Failed, 3, 2);
        assert!(state.apply(&msg));
        assert_eq!(state.last_state, MemberState::Failed);
    }

    #[test]
    fn gossip_state_hop_count_accumulates() {
        let mut state = GossipState::new(MemberId::new(1), 0, MemberState::Alive, 0);
        let msg1 = mk_msg(1, 1, MemberState::Suspected, 1, 2);
        let msg2 = mk_msg(1, 2, MemberState::Failed, 2, 3);
        let msg3 = mk_msg(1, 3, MemberState::Failed, 3, 4);

        assert!(state.apply(&msg1));
        assert_eq!(state.hop_count, 1);

        assert!(state.apply(&msg2));
        assert_eq!(state.hop_count, 2);

        assert!(state.apply(&msg3));
        assert_eq!(state.hop_count, 3);
    }

    #[test]
    fn gossip_state_has_changed_detects_non_initial() {
        let initial = GossipState::new(MemberId::new(1), 0, MemberState::Alive, 0);
        assert!(!initial.has_changed());

        let changed_incarnation = GossipState::new(MemberId::new(1), 1, MemberState::Alive, 0);
        assert!(changed_incarnation.has_changed());

        let changed_state = GossipState::new(MemberId::new(1), 0, MemberState::Suspected, 0);
        assert!(changed_state.has_changed());

        let changed_both = GossipState::new(MemberId::new(1), 3, MemberState::Failed, 10);
        assert!(changed_both.has_changed());
    }

    // -------------------------------------------------------------------
    // DisseminationConfig: builder defaults
    // -------------------------------------------------------------------

    #[test]
    fn config_defaults_match_spec() {
        let cfg = DisseminationConfig::default();
        assert_eq!(cfg.piggyback_limit, 3);
        assert_eq!(cfg.anti_entropy_interval_ms, 1000);
        assert_eq!(cfg.rumor_ttl, 10);
        assert_eq!(cfg.max_rumor_queue, 256);
        assert_eq!(cfg.anti_entropy_peer_count, 1);
    }

    #[test]
    fn config_builder_overrides() {
        let cfg = DisseminationConfig::new()
            .with_piggyback_limit(5)
            .with_anti_entropy_interval_ms(500)
            .with_rumor_ttl(15)
            .with_max_rumor_queue(512)
            .with_anti_entropy_peer_count(3);

        assert_eq!(cfg.piggyback_limit, 5);
        assert_eq!(cfg.anti_entropy_interval_ms, 500);
        assert_eq!(cfg.rumor_ttl, 15);
        assert_eq!(cfg.max_rumor_queue, 512);
        assert_eq!(cfg.anti_entropy_peer_count, 3);
    }

    #[test]
    fn config_builder_partial_override() {
        let cfg = DisseminationConfig::new()
            .with_piggyback_limit(7)
            .with_rumor_ttl(20);

        assert_eq!(cfg.piggyback_limit, 7);
        assert_eq!(cfg.rumor_ttl, 20);
        // Others remain default.
        assert_eq!(cfg.anti_entropy_interval_ms, 1000);
        assert_eq!(cfg.max_rumor_queue, 256);
        assert_eq!(cfg.anti_entropy_peer_count, 1);
    }

    // -------------------------------------------------------------------
    // MemberState: rumor priority ordering
    // -------------------------------------------------------------------

    #[test]
    fn member_state_rumor_priority_ordering() {
        assert!(MemberState::Failed.rumor_priority() > MemberState::Suspected.rumor_priority());
        assert!(MemberState::Suspected.rumor_priority() > MemberState::Alive.rumor_priority());
        assert!(MemberState::Failed.rumor_priority() > MemberState::Alive.rumor_priority());
    }

    #[test]
    fn member_state_serde_roundtrip() {
        for state in &[
            MemberState::Alive,
            MemberState::Suspected,
            MemberState::Failed,
        ] {
            let encoded = bincode::serialize(state).expect("serialize");
            let decoded: MemberState = bincode::deserialize(&encoded).expect("deserialize");
            assert_eq!(*state, decoded);
        }
    }

    // -------------------------------------------------------------------
    // Integration: multiple messages, all states, verify_full on all
    // -------------------------------------------------------------------

    #[test]
    fn all_state_variants_roundtrip_with_verify() {
        let states = [
            MemberState::Alive,
            MemberState::Suspected,
            MemberState::Failed,
        ];
        for (i, &state) in states.iter().enumerate() {
            let msg = GossipMessage::new(
                MemberId::new(i as u64 + 1),
                i as u64,
                state,
                i as u64 * 10,
                MemberId::new(42),
                EpochId::new(5),
                2000 + i as u64 * 100,
            );
            assert!(msg.verify_full(), "verify_full failed for {state:?}");

            let encoded = bincode::serialize(&msg).expect("serialize");
            let decoded: GossipMessage = bincode::deserialize(&encoded).expect("deserialize");
            assert_eq!(msg, decoded);
            assert!(decoded.verify_full());
        }
    }

    #[test]
    fn gossip_state_rejects_wrong_member() {
        let mut state = GossipState::new(MemberId::new(1), 0, MemberState::Alive, 0);
        let msg = mk_msg(2, 5, MemberState::Failed, 100, 3);
        // Different member_id: apply panics in debug due to debug_assert.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state.apply(&msg);
        }));
        assert!(
            result.is_err(),
            "applying message for wrong member should trigger debug_assert"
        );
    }

    #[test]
    fn is_superseded_by_wrong_member_panics() {
        let a = mk_msg(1, 0, MemberState::Alive, 0, 1);
        let b = mk_msg(2, 5, MemberState::Failed, 100, 1);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = a.is_superseded_by(&b);
        }));
        assert!(
            result.is_err(),
            "comparing supersede for different members should trigger debug_assert"
        );
    }

    // -------------------------------------------------------------------
    // GossipMessage: bincode edge cases
    // -------------------------------------------------------------------

    #[test]
    fn message_serialized_size_is_reasonable() {
        let msg = mk_msg(1, 0, MemberState::Alive, 0, 1);
        let encoded = bincode::serialize(&msg).expect("serialize");
        // Should be well under 256 bytes for a basic message
        assert!(
            encoded.len() < 256,
            "serialized size {} exceeds 256 bytes",
            encoded.len()
        );
    }

    #[test]
    fn message_large_values_roundtrip() {
        let msg = GossipMessage::new(
            MemberId::new(u64::MAX),
            u64::MAX,
            MemberState::Failed,
            u64::MAX,
            MemberId::new(u64::MAX - 1),
            EpochId::new(u64::MAX),
            u64::MAX,
        );
        assert!(msg.verify_full());
        let encoded = bincode::serialize(&msg).expect("serialize");
        let decoded: GossipMessage = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(msg, decoded);
        assert!(decoded.verify_full());
    }

    #[test]
    fn message_zero_values_roundtrip() {
        let msg = GossipMessage::new(
            MemberId::new(0),
            0,
            MemberState::Alive,
            0,
            MemberId::new(0),
            EpochId::new(0),
            0,
        );
        assert!(msg.verify_full());
        let encoded = bincode::serialize(&msg).expect("serialize");
        let decoded: GossipMessage = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(msg, decoded);
        assert!(decoded.verify_full());
    }

    // -------------------------------------------------------------------
    // RumorMongerer tests
    // -------------------------------------------------------------------

    type TestClock = std::sync::Arc<std::sync::atomic::AtomicU64>;

    fn mk_clock() -> (TestClock, Box<dyn Fn() -> u64 + Send + Sync>) {
        let clock = TestClock::new(std::sync::atomic::AtomicU64::new(0));
        let c = clock.clone();
        (
            clock,
            Box::new(move || c.load(std::sync::atomic::Ordering::SeqCst)),
        )
    }

    fn advance(clock: &TestClock, ms: u64) {
        clock.fetch_add(ms, std::sync::atomic::Ordering::SeqCst);
    }

    fn mk_rumor_mongerer(cap: usize) -> (RumorMongerer, TestClock) {
        let (clock, now_fn) = mk_clock();
        let config = DisseminationConfig::default()
            .with_max_rumor_queue(cap)
            .with_rumor_ttl(10)
            .with_piggyback_limit(3);
        (RumorMongerer::new(config, now_fn), clock)
    }

    #[test]
    fn rumor_mongerer_enqueue_and_select() {
        let (mut rm, clock) = mk_rumor_mongerer(8);
        advance(&clock, 100);

        rm.enqueue(mk_msg(1, 0, MemberState::Alive, 0, 1), 0);
        rm.enqueue(mk_msg(2, 0, MemberState::Suspected, 0, 1), 0);
        rm.enqueue(mk_msg(3, 0, MemberState::Failed, 0, 1), 0);
        rm.enqueue(mk_msg(4, 0, MemberState::Alive, 1, 1), 0);

        assert_eq!(rm.len(), 4);

        let piggyback = rm.select_piggyback(3);
        assert_eq!(piggyback.len(), 3);
        // Failed should be first
        assert_eq!(piggyback[0].member_id, MemberId::new(3));
        assert_eq!(piggyback[0].state, MemberState::Failed);
        // Suspected second
        assert_eq!(piggyback[1].member_id, MemberId::new(2));
        assert_eq!(piggyback[1].state, MemberState::Suspected);
        // One remaining (Alive)
        assert_eq!(rm.len(), 1);
    }

    #[test]
    fn rumor_mongerer_priority_ordering_failed_first() {
        let (mut rm, clock) = mk_rumor_mongerer(10);
        advance(&clock, 100);

        // Enqueue in reverse priority order
        rm.enqueue(mk_msg(1, 0, MemberState::Alive, 0, 1), 0);
        advance(&clock, 10);
        rm.enqueue(mk_msg(2, 0, MemberState::Suspected, 0, 1), 0);
        advance(&clock, 10);
        rm.enqueue(mk_msg(3, 0, MemberState::Failed, 0, 1), 0);

        let piggyback = rm.select_piggyback(3);
        assert_eq!(piggyback.len(), 3);
        assert_eq!(piggyback[0].state, MemberState::Failed);
        assert_eq!(piggyback[1].state, MemberState::Suspected);
        assert_eq!(piggyback[2].state, MemberState::Alive);
    }

    #[test]
    fn rumor_mongerer_same_priority_oldest_first() {
        let (mut rm, clock) = mk_rumor_mongerer(10);
        advance(&clock, 100);
        rm.enqueue(mk_msg(1, 0, MemberState::Failed, 0, 1), 0);
        advance(&clock, 50);
        rm.enqueue(mk_msg(2, 0, MemberState::Failed, 0, 1), 0);
        advance(&clock, 50);
        rm.enqueue(mk_msg(3, 0, MemberState::Failed, 0, 1), 0);

        let piggyback = rm.select_piggyback(3);
        assert_eq!(piggyback.len(), 3);
        // All Failed; oldest first (member_id=1 enqueued first)
        assert_eq!(piggyback[0].member_id, MemberId::new(1));
        assert_eq!(piggyback[1].member_id, MemberId::new(2));
        assert_eq!(piggyback[2].member_id, MemberId::new(3));
    }

    #[test]
    fn rumor_mongerer_ttl_expiration() {
        let (mut rm, _clock) = mk_rumor_mongerer(10);
        rm.enqueue(mk_msg(1, 0, MemberState::Failed, 0, 1), 10); // exactly at TTL
        rm.enqueue(mk_msg(2, 0, MemberState::Failed, 0, 1), 11); // over TTL
        rm.enqueue(mk_msg(3, 0, MemberState::Suspected, 0, 1), 9); // under TTL

        let piggyback = rm.select_piggyback(10);
        // hop_count 10 and 11 are >= TTL=10, dropped. Only member 3 (hop=9) survives.
        assert_eq!(piggyback.len(), 1);
        assert_eq!(piggyback[0].member_id, MemberId::new(3));
    }

    #[test]
    fn rumor_mongerer_ttl_boundary_retained() {
        let (mut rm, _clock) = mk_rumor_mongerer(10);
        rm.enqueue(mk_msg(1, 0, MemberState::Alive, 0, 1), 9); // under TTL=10
        let piggyback = rm.select_piggyback(5);
        assert_eq!(piggyback.len(), 1);
    }

    #[test]
    fn rumor_mongerer_overflow_evicts_oldest_alive() {
        let (mut rm, clock) = mk_rumor_mongerer(3);
        advance(&clock, 100);
        rm.enqueue(mk_msg(1, 0, MemberState::Alive, 0, 1), 0);
        advance(&clock, 10);
        rm.enqueue(mk_msg(2, 0, MemberState::Suspected, 0, 1), 0);
        advance(&clock, 10);
        rm.enqueue(mk_msg(3, 0, MemberState::Failed, 0, 1), 0);

        assert_eq!(rm.len(), 3);

        // Queue is full. Enqueue another Alive -> oldest Alive (member 1) evicted.
        advance(&clock, 10);
        rm.enqueue(mk_msg(4, 0, MemberState::Alive, 1, 1), 0);

        assert_eq!(rm.len(), 3);
        let piggyback = rm.select_piggyback(10);
        // Should not contain member 1
        let ids: Vec<u64> = piggyback.iter().map(|m| m.member_id.0).collect();
        assert!(
            !ids.contains(&1),
            "oldest Alive should be evicted, got {ids:?}"
        );
        assert!(ids.contains(&4), "new Alive should be present");
    }

    #[test]
    fn rumor_mongerer_overflow_no_alive_evicts_oldest_any() {
        let (mut rm, clock) = mk_rumor_mongerer(2);
        advance(&clock, 100);
        rm.enqueue(mk_msg(1, 0, MemberState::Failed, 0, 1), 0);
        advance(&clock, 10);
        rm.enqueue(mk_msg(2, 0, MemberState::Suspected, 0, 1), 0);

        // Queue full, no Alive entries -> oldest (Failed, member 1) evicted.
        advance(&clock, 10);
        rm.enqueue(mk_msg(3, 0, MemberState::Failed, 1, 1), 0);

        let piggyback = rm.select_piggyback(10);
        let ids: Vec<u64> = piggyback.iter().map(|m| m.member_id.0).collect();
        assert!(!ids.contains(&1), "oldest non-Alive should be evicted");
    }

    #[test]
    fn rumor_mongerer_duplicate_suppression() {
        let (mut rm, clock) = mk_rumor_mongerer(10);
        advance(&clock, 100);
        rm.enqueue(mk_msg(1, 0, MemberState::Suspected, 0, 1), 0);

        // Same member_id + incarnation -> suppressed
        rm.enqueue(mk_msg(1, 0, MemberState::Suspected, 0, 2), 0);
        assert_eq!(rm.len(), 1);

        // Different incarnation -> accepted
        rm.enqueue(mk_msg(1, 1, MemberState::Failed, 1, 1), 0);
        assert_eq!(rm.len(), 2);
    }

    #[test]
    fn rumor_mongerer_empty_select_returns_nothing() {
        let (mut rm, _clock) = mk_rumor_mongerer(10);
        let piggyback = rm.select_piggyback(3);
        assert!(piggyback.is_empty());
    }

    #[test]
    fn rumor_mongerer_select_limit_respected() {
        let (mut rm, clock) = mk_rumor_mongerer(10);
        advance(&clock, 100);
        for i in 0..6 {
            rm.enqueue(mk_msg(i, 0, MemberState::Alive, 0, 1), 0);
            advance(&clock, 10);
        }
        let piggyback = rm.select_piggyback(3);
        assert_eq!(piggyback.len(), 3);
        assert_eq!(rm.len(), 3);
    }

    #[test]
    fn rumor_mongerer_all_ttl_expired_returns_empty() {
        let (mut rm, _clock) = mk_rumor_mongerer(10);
        rm.enqueue(mk_msg(1, 0, MemberState::Failed, 0, 1), 15);
        rm.enqueue(mk_msg(2, 0, MemberState::Failed, 0, 1), 20);
        let piggyback = rm.select_piggyback(10);
        assert!(piggyback.is_empty());
        assert!(rm.is_empty(), "expired rumors should be dropped from queue");
    }

    // -------------------------------------------------------------------
    // AntiEntropyRound tests
    // -------------------------------------------------------------------

    #[test]
    fn anti_entropy_should_run_after_interval() {
        // Before any round is recorded, should always run.
        let ae = AntiEntropyRound::new(1000);
        assert!(ae.should_run(0), "should run at time 0 (first round)");
        assert!(
            ae.should_run(500),
            "should run anytime before first round recorded"
        );

        // After recording a round at t=500, check interval semantics.
        let mut ae = AntiEntropyRound::new(1000);
        ae.record_round(500, [0xAAu8; 32]);
        assert!(!ae.should_run(1000), "should not run after only 500ms");
        assert!(
            ae.should_run(1500),
            "should run at interval boundary (500+1000)"
        );
        assert!(ae.should_run(2000), "should run past interval");
    }

    #[test]
    fn anti_entropy_record_round_updates_timestamp() {
        let mut ae = AntiEntropyRound::new(1000);
        let digest = [0xAAu8; 32];
        ae.record_round(500, digest);
        assert_eq!(ae.last_round_millis(), 500);
        assert_eq!(ae.last_sent_digest(), Some(digest));
        assert!(
            !ae.should_run(1000),
            "500ms later, interval is 1000ms: should not run yet"
        );
        assert!(ae.should_run(1500), "1500 >= 500+1000: should run");
    }

    #[test]
    fn anti_entropy_digest_identical_sets() {
        let states = [
            (MemberId::new(1), 0u64, MemberState::Alive),
            (MemberId::new(2), 0u64, MemberState::Alive),
            (MemberId::new(3), 1u64, MemberState::Suspected),
        ];
        let d1 = AntiEntropyRound::compute_digest(&states);
        let d2 = AntiEntropyRound::compute_digest(&states);
        assert_eq!(d1, d2, "identical sets must produce same digest");
    }

    #[test]
    fn anti_entropy_digest_order_independent() {
        let states_a = [
            (MemberId::new(3), 1u64, MemberState::Suspected),
            (MemberId::new(1), 0u64, MemberState::Alive),
            (MemberId::new(2), 0u64, MemberState::Alive),
        ];
        let states_b = [
            (MemberId::new(1), 0u64, MemberState::Alive),
            (MemberId::new(2), 0u64, MemberState::Alive),
            (MemberId::new(3), 1u64, MemberState::Suspected),
        ];
        assert_eq!(
            AntiEntropyRound::compute_digest(&states_a),
            AntiEntropyRound::compute_digest(&states_b),
            "digest must be order-independent (sorted before hashing)"
        );
    }

    #[test]
    fn anti_entropy_digest_differs_for_different_state() {
        let states_a = [(MemberId::new(1), 0u64, MemberState::Alive)];
        let states_b = [(MemberId::new(1), 0u64, MemberState::Failed)];
        assert_ne!(
            AntiEntropyRound::compute_digest(&states_a),
            AntiEntropyRound::compute_digest(&states_b)
        );
    }

    #[test]
    fn anti_entropy_digest_differs_for_different_incarnation() {
        let states_a = [(MemberId::new(1), 0u64, MemberState::Alive)];
        let states_b = [(MemberId::new(1), 1u64, MemberState::Alive)];
        assert_ne!(
            AntiEntropyRound::compute_digest(&states_a),
            AntiEntropyRound::compute_digest(&states_b)
        );
    }

    #[test]
    fn anti_entropy_digest_differs_for_different_member_set() {
        let states_a = [(MemberId::new(1), 0u64, MemberState::Alive)];
        let states_b = [
            (MemberId::new(1), 0u64, MemberState::Alive),
            (MemberId::new(2), 0u64, MemberState::Alive),
        ];
        assert_ne!(
            AntiEntropyRound::compute_digest(&states_a),
            AntiEntropyRound::compute_digest(&states_b)
        );
    }

    #[test]
    fn anti_entropy_empty_set_produces_digest() {
        let states: [(MemberId, u64, MemberState); 0] = [];
        let d1 = AntiEntropyRound::compute_digest(&states);
        let d2 = AntiEntropyRound::compute_digest(&states);
        assert_eq!(d1, d2);
        assert_ne!(
            d1, [0u8; 32],
            "even empty set should produce non-zero digest"
        );
    }

    #[test]
    fn anti_entropy_identical_state_no_divergence() {
        let local = [
            (MemberId::new(1), 0u64, MemberState::Alive),
            (MemberId::new(2), 1u64, MemberState::Suspected),
        ];
        let remote = local;
        let div = AntiEntropyRound::divergent_entries(&local, &remote);
        assert!(div.is_empty(), "identical state should have no divergence");
    }

    #[test]
    fn anti_entropy_single_divergence_by_state() {
        let local = [
            (MemberId::new(1), 0u64, MemberState::Alive),
            (MemberId::new(2), 0u64, MemberState::Alive),
        ];
        let remote = [
            (MemberId::new(1), 0u64, MemberState::Alive),
            (MemberId::new(2), 0u64, MemberState::Failed), // diverged
        ];
        let div = AntiEntropyRound::divergent_entries(&local, &remote);
        assert_eq!(div.len(), 1);
        assert_eq!(div[0].0, MemberId::new(2));
        assert_eq!(div[0].2, MemberState::Alive);
    }

    #[test]
    fn anti_entropy_single_divergence_by_incarnation() {
        let local = [
            (MemberId::new(1), 0u64, MemberState::Alive),
            (MemberId::new(2), 5u64, MemberState::Alive),
        ];
        let remote = [
            (MemberId::new(1), 0u64, MemberState::Alive),
            (MemberId::new(2), 3u64, MemberState::Alive), // lower incarnation
        ];
        let div = AntiEntropyRound::divergent_entries(&local, &remote);
        assert_eq!(div.len(), 1);
        assert_eq!(div[0].0, MemberId::new(2));
        assert_eq!(div[0].1, 5);
    }

    #[test]
    fn anti_entropy_member_only_in_local_is_divergent() {
        let local = [
            (MemberId::new(1), 0u64, MemberState::Alive),
            (MemberId::new(2), 0u64, MemberState::Alive),
        ];
        let remote = [(MemberId::new(1), 0u64, MemberState::Alive)];
        let div = AntiEntropyRound::divergent_entries(&local, &remote);
        assert_eq!(div.len(), 1);
        assert_eq!(div[0].0, MemberId::new(2));
    }

    #[test]
    fn anti_entropy_member_only_in_remote_not_divergent() {
        let local = [(MemberId::new(1), 0u64, MemberState::Alive)];
        let remote = [
            (MemberId::new(1), 0u64, MemberState::Alive),
            (MemberId::new(2), 0u64, MemberState::Alive),
        ];
        let div = AntiEntropyRound::divergent_entries(&local, &remote);
        assert!(
            div.is_empty(),
            "members only in remote are not divergent from local perspective"
        );
    }

    #[test]
    fn anti_entropy_full_divergence_all_entries() {
        let local = [
            (MemberId::new(1), 0u64, MemberState::Failed),
            (MemberId::new(2), 2u64, MemberState::Suspected),
        ];
        let remote = [
            (MemberId::new(1), 0u64, MemberState::Alive),
            (MemberId::new(2), 1u64, MemberState::Alive),
        ];
        let div = AntiEntropyRound::divergent_entries(&local, &remote);
        assert_eq!(div.len(), 2);
    }

    #[test]
    fn anti_entropy_mixed_divergence() {
        let local = [
            (MemberId::new(1), 0u64, MemberState::Alive),
            (MemberId::new(2), 0u64, MemberState::Suspected),
            (MemberId::new(3), 1u64, MemberState::Alive),
        ];
        let remote = [
            (MemberId::new(1), 0u64, MemberState::Alive),  // same
            (MemberId::new(2), 0u64, MemberState::Failed), // different state
        ];
        // member 3 only in local -> divergent
        let div = AntiEntropyRound::divergent_entries(&local, &remote);
        assert_eq!(div.len(), 2);
        let ids: Vec<u64> = div.iter().map(|(id, _, _)| id.0).collect();
        assert!(ids.contains(&2));
        assert!(ids.contains(&3));
    }

    #[test]
    fn anti_entropy_large_set_digest_stable() {
        let mut states: Vec<(MemberId, u64, MemberState)> = Vec::new();
        for i in 0..100 {
            let state = match i % 3 {
                0 => MemberState::Alive,
                1 => MemberState::Suspected,
                _ => MemberState::Failed,
            };
            states.push((MemberId::new(i as u64), (i % 5) as u64, state));
        }
        let d1 = AntiEntropyRound::compute_digest(&states);
        let d2 = AntiEntropyRound::compute_digest(&states);
        assert_eq!(d1, d2);

        // Shuffle and re-check.
        states.reverse();
        let d3 = AntiEntropyRound::compute_digest(&states);
        assert_eq!(d1, d3, "digest must be independent of insertion order");
    }
    // -------------------------------------------------------------------
    // GossipConfig tests
    // -------------------------------------------------------------------

    #[test]
    fn gossip_config_defaults_match_spec() {
        let cfg = GossipConfig::default();
        assert_eq!(cfg.fanout, 3);
        assert_eq!(cfg.retry_count, 2);
        assert_eq!(cfg.ttl, 10);
        assert_eq!(cfg.seen_set_capacity, 1024);
    }

    #[test]
    fn gossip_config_builder_overrides() {
        let cfg = GossipConfig::new()
            .with_fanout(5)
            .with_retry_count(4)
            .with_ttl(15)
            .with_seen_set_capacity(2048);

        assert_eq!(cfg.fanout, 5);
        assert_eq!(cfg.retry_count, 4);
        assert_eq!(cfg.ttl, 15);
        assert_eq!(cfg.seen_set_capacity, 2048);
    }

    #[test]
    fn gossip_config_partial_override() {
        let cfg = GossipConfig::new().with_fanout(7).with_ttl(20);

        assert_eq!(cfg.fanout, 7);
        assert_eq!(cfg.ttl, 20);
        // Others remain default
        assert_eq!(cfg.retry_count, 2);
        assert_eq!(cfg.seen_set_capacity, 1024);
    }

    // -------------------------------------------------------------------
    // GossipBroadcastEngine tests
    // -------------------------------------------------------------------

    fn mk_broadcast_engine(
        fanout: usize,
        ttl: u32,
        cap: usize,
    ) -> (GossipBroadcastEngine, TestClock) {
        let (clock, now_fn) = mk_clock();
        let config = GossipConfig::new()
            .with_fanout(fanout)
            .with_ttl(ttl)
            .with_seen_set_capacity(cap);
        (GossipBroadcastEngine::new(config, now_fn), clock)
    }

    #[test]
    fn broadcast_engine_mark_seen_and_has_seen() {
        let (mut engine, _clock) = mk_broadcast_engine(3, 10, 16);
        let msg = mk_msg(1, 0, MemberState::Alive, 0, 1);

        assert!(!engine.has_seen(&msg.digest));
        engine.mark_seen(msg.digest);
        assert!(engine.has_seen(&msg.digest));
        assert_eq!(engine.seen_count(), 1);
    }

    #[test]
    fn broadcast_engine_mark_seen_idempotent() {
        let (mut engine, _clock) = mk_broadcast_engine(3, 10, 16);
        let msg = mk_msg(1, 0, MemberState::Alive, 0, 1);

        engine.mark_seen(msg.digest);
        engine.mark_seen(msg.digest); // duplicate
        assert_eq!(engine.seen_count(), 1);
    }

    #[test]
    fn broadcast_engine_seen_capacity_lru_eviction() {
        let (mut engine, _clock) = mk_broadcast_engine(3, 10, 3);

        for i in 0..5 {
            let msg = mk_msg(i, 0, MemberState::Alive, 0, 1);
            engine.mark_seen(msg.digest);
        }
        // Capacity 3: only the 3 most recent should remain.
        assert_eq!(engine.seen_count(), 3);
        // First two messages (i=0, i=1) should be evicted.
        let msg0 = mk_msg(0, 0, MemberState::Alive, 0, 1);
        let msg1 = mk_msg(1, 0, MemberState::Alive, 0, 1);
        let msg4 = mk_msg(4, 0, MemberState::Alive, 0, 1);
        assert!(!engine.has_seen(&msg0.digest));
        assert!(!engine.has_seen(&msg1.digest));
        assert!(engine.has_seen(&msg4.digest));
    }

    #[test]
    fn broadcast_engine_accept_message_new() {
        let (mut engine, clock) = mk_broadcast_engine(3, 10, 16);
        advance(&clock, 5000);
        let msg = mk_msg(1, 0, MemberState::Suspected, 0, 1);

        assert!(engine.accept_message(&msg));
        assert!(engine.has_seen(&msg.digest));
    }

    #[test]
    fn broadcast_engine_accept_message_seen_rejected() {
        let (mut engine, clock) = mk_broadcast_engine(3, 10, 16);
        advance(&clock, 5000);
        let msg = mk_msg(1, 0, MemberState::Suspected, 0, 1);

        assert!(engine.accept_message(&msg));
        // Second attempt with same message should be rejected.
        assert!(!engine.accept_message(&msg));
    }

    #[test]
    fn broadcast_engine_accept_message_expired_rejected() {
        let (mut engine, clock) = mk_broadcast_engine(3, 10, 16);
        // TTL=10, max_age_ms = 10 * 500 = 5000ms
        // Create msg at t=0, advance clock to t=6000
        let msg = GossipMessage::new(
            MemberId::new(1),
            0,
            MemberState::Failed,
            0,
            MemberId::new(2),
            EpochId::new(1),
            0, // created_at_millis = 0
        );
        advance(&clock, 6000); // 6000 > 5000 max_age
        assert!(!engine.accept_message(&msg));
        assert!(!engine.has_seen(&msg.digest));
    }

    #[test]
    fn broadcast_engine_accept_message_within_ttl_accepted() {
        let (mut engine, clock) = mk_broadcast_engine(3, 10, 16);
        let msg = GossipMessage::new(
            MemberId::new(1),
            0,
            MemberState::Failed,
            0,
            MemberId::new(2),
            EpochId::new(1),
            0,
        );
        advance(&clock, 4000); // 4000 < 5000 max_age
        assert!(engine.accept_message(&msg));
        assert!(engine.has_seen(&msg.digest));
    }

    #[test]
    fn broadcast_engine_select_fanout_deterministic() {
        let (engine, _clock) = mk_broadcast_engine(3, 10, 16);
        let peers: Vec<MemberId> = (1..=10).map(MemberId::new).collect();

        // Seeded RNG should produce reproducible results.
        let mut rng1 = rand::rngs::StdRng::seed_from_u64(42);
        let mut rng2 = rand::rngs::StdRng::seed_from_u64(42);

        let selected1 = engine.select_fanout_peers(&peers, &[], &mut rng1);
        let selected2 = engine.select_fanout_peers(&peers, &[], &mut rng2);
        assert_eq!(
            selected1, selected2,
            "same seed must produce same selection"
        );
        assert_eq!(selected1.len(), 3, "fanout=3 should select 3 peers");
    }

    #[test]
    fn broadcast_engine_select_fanout_empty_peers() {
        let (engine, _clock) = mk_broadcast_engine(3, 10, 16);
        let peers: Vec<MemberId> = vec![];
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let selected = engine.select_fanout_peers(&peers, &[], &mut rng);
        assert!(selected.is_empty());
    }

    #[test]
    fn broadcast_engine_select_fanout_all_excluded() {
        let (engine, _clock) = mk_broadcast_engine(3, 10, 16);
        let peers: Vec<MemberId> = (1..=5).map(MemberId::new).collect();
        let exclude: Vec<MemberId> = (1..=5).map(MemberId::new).collect();
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let selected = engine.select_fanout_peers(&peers, &exclude, &mut rng);
        assert!(selected.is_empty());
    }

    #[test]
    fn broadcast_engine_select_fanout_excludes_sender() {
        let (engine, _clock) = mk_broadcast_engine(3, 10, 16);
        let peers: Vec<MemberId> = (1..=5).map(MemberId::new).collect();
        let exclude = vec![MemberId::new(1), MemberId::new(3)];
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let selected = engine.select_fanout_peers(&peers, &exclude, &mut rng);
        // Excluded peers must not appear in selection.
        assert!(!selected.contains(&MemberId::new(1)));
        assert!(!selected.contains(&MemberId::new(3)));
        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn broadcast_engine_select_fanout_fewer_than_fanout() {
        let (engine, _clock) = mk_broadcast_engine(5, 10, 16);
        let peers: Vec<MemberId> = (1..=3).map(MemberId::new).collect();
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let selected = engine.select_fanout_peers(&peers, &[], &mut rng);
        // Only 3 peers available, fanout=5, should return all 3.
        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn broadcast_engine_build_from_event_member_joined() {
        use crate::event_bridge::MembershipEvent;

        let event = MembershipEvent::member_joined(MemberId::new(5), 1);
        let msg = GossipBroadcastEngine::build_from_event(
            &event,
            MemberId::new(1),
            EpochId::new(2),
            5000,
        );
        let msg = msg.expect("MemberJoined should produce a message");
        assert_eq!(msg.member_id, MemberId::new(5));
        assert_eq!(msg.incarnation, 1);
        assert_eq!(msg.state, MemberState::Alive);
        assert!(msg.verify_full());
    }

    #[test]
    fn broadcast_engine_build_from_event_member_suspected() {
        use crate::event_bridge::MembershipEvent;

        let event = MembershipEvent::member_suspected(MemberId::new(7), 3);
        let msg = GossipBroadcastEngine::build_from_event(
            &event,
            MemberId::new(1),
            EpochId::new(2),
            5000,
        );
        let msg = msg.expect("MemberSuspected should produce a message");
        assert_eq!(msg.state, MemberState::Suspected);
        assert!(msg.verify_full());
    }

    #[test]
    fn broadcast_engine_build_from_event_member_failed() {
        use crate::event_bridge::MembershipEvent;

        let event = MembershipEvent::member_failed(MemberId::new(9), 2);
        let msg = GossipBroadcastEngine::build_from_event(
            &event,
            MemberId::new(1),
            EpochId::new(3),
            5000,
        );
        let msg = msg.expect("MemberFailed should produce a message");
        assert_eq!(msg.state, MemberState::Failed);
        assert!(msg.verify_full());
    }

    #[test]
    fn broadcast_engine_build_from_event_member_left() {
        use crate::event_bridge::MembershipEvent;

        let event = MembershipEvent::member_left(MemberId::new(11), 1);
        let msg = GossipBroadcastEngine::build_from_event(
            &event,
            MemberId::new(1),
            EpochId::new(2),
            5000,
        );
        let msg = msg.expect("MemberLeft should produce a message");
        assert_eq!(msg.state, MemberState::Failed);
        assert!(msg.verify_full());
    }

    #[test]
    fn broadcast_engine_build_from_event_member_draining() {
        use crate::event_bridge::MembershipEvent;

        let event = MembershipEvent::member_draining(MemberId::new(13), 2);
        let msg = GossipBroadcastEngine::build_from_event(
            &event,
            MemberId::new(1),
            EpochId::new(3),
            5000,
        );
        let msg = msg.expect("MemberDraining should produce a message");
        assert_eq!(msg.state, MemberState::Suspected);
        assert_eq!(msg.member_id, MemberId::new(13));
        assert_eq!(msg.incarnation, 2);
        assert!(msg.verify_full());
    }

    #[test]
    fn broadcast_engine_build_from_event_member_drained() {
        use crate::event_bridge::MembershipEvent;

        let event = MembershipEvent::member_drained(MemberId::new(15), 3);
        let msg = GossipBroadcastEngine::build_from_event(
            &event,
            MemberId::new(1),
            EpochId::new(3),
            5000,
        );
        let msg = msg.expect("MemberDrained should produce a message");
        assert_eq!(msg.state, MemberState::Failed);
        assert_eq!(msg.member_id, MemberId::new(15));
        assert_eq!(msg.incarnation, 3);
        assert!(msg.verify_full());
    }
    #[test]
    fn broadcast_engine_clear_seen() {
        let (mut engine, _clock) = mk_broadcast_engine(3, 10, 16);
        for i in 0..5 {
            let msg = mk_msg(i, 0, MemberState::Alive, 0, 1);
            engine.mark_seen(msg.digest);
        }
        assert!(engine.seen_count() > 0);
        engine.clear_seen();
        assert_eq!(engine.seen_count(), 0);
    }

    // -------------------------------------------------------------------
    // 5-node simulated cluster: epidemic dissemination
    // -------------------------------------------------------------------

    /// Simulate a 5-node cluster where node 0 originates a gossip message
    /// and epidemic fan-out propagates it to all nodes.
    ///
    /// Each node has a GossipBroadcastEngine with fanout=2 and TTL=8.
    /// In each round, every node that has received a new message fans out
    /// to fanout peers (selected deterministically via seeded RNG).
    /// Assert that all 5 nodes receive the message within 3 rounds
    /// (expected: O(log N) = ceil(log2(5)) = 3 rounds with high probability).
    #[test]
    fn five_node_epidemic_dissemination() {
        let num_nodes: u64 = 5;
        let fanout = 2;
        let ttl = 8u32;

        // Build all peer lists and engines.
        let all_peers: Vec<MemberId> = (0..num_nodes).map(MemberId::new).collect();

        let mut engines: Vec<(GossipBroadcastEngine, TestClock)> = (0..num_nodes)
            .map(|_| mk_broadcast_engine(fanout, ttl, 64))
            .collect();

        // Originate a gossip message from node 0 (member 0 is reported as Failed).
        let origin_msg = GossipMessage::new(
            MemberId::new(0),
            1,
            MemberState::Failed,
            1,
            MemberId::new(0),
            EpochId::new(1),
            1000,
        );

        // Each node's per-round incoming message queue: Vec<(GossipMessage, Vec<MemberId>)>
        // where the Vec<MemberId> is the exclude list (who already sent it to us).
        let mut inboxes: Vec<Vec<(GossipMessage, Vec<MemberId>)>> =
            vec![Vec::new(); num_nodes as usize];

        // Seed node 0: it accepts its own message and fans out.
        {
            // Use direct indexing.
            advance(&engines[0].1, 1500);
            assert!(engines[0].0.accept_message(&origin_msg));
            // Build exclude list: the originator (node 0 itself).
            let exclude = vec![MemberId::new(0)];
            let mut rng = rand::rngs::StdRng::seed_from_u64(12345);
            let selected = engines[0]
                .0
                .select_fanout_peers(&all_peers, &exclude, &mut rng);
            for peer in &selected {
                inboxes[peer.0 as usize].push((origin_msg.clone(), vec![MemberId::new(0)]));
            }
        }

        let mut nodes_with_msg: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        nodes_with_msg.insert(0);

        let max_rounds = 5;
        let mut rounds_taken = 0;

        for round in 0..max_rounds {
            // Snapshot current inboxes before processing (to avoid borrowing issues).
            let snapshots: Vec<Vec<(GossipMessage, Vec<MemberId>)>> = inboxes.clone();
            inboxes = vec![Vec::new(); num_nodes as usize];

            let mut new_recipients = 0;

            for node_id in 0..num_nodes {
                let incoming = &snapshots[node_id as usize];
                if incoming.is_empty() {
                    continue;
                }

                // Accept first new message (skip if already seen).
                // Use direct indexing for mutable access.
                let mut accepted = false;
                for (msg, _prev_hops) in incoming {
                    if engines[node_id as usize].0.has_seen(&msg.digest) {
                        continue;
                    }
                    // Simulate time passing; message must be within TTL age.
                    advance(&engines[node_id as usize].1, 2000 + (node_id * 100));
                    if engines[node_id as usize].0.accept_message(msg) {
                        accepted = true;
                        nodes_with_msg.insert(node_id);
                        new_recipients += 1;
                        break;
                    }
                }

                if accepted && nodes_with_msg.len() < num_nodes as usize {
                    // Fan out to peers, excluding self and whoever sent to us.
                    let mut exclude: Vec<MemberId> =
                        incoming.iter().flat_map(|(_, hops)| hops.clone()).collect();
                    exclude.push(MemberId::new(node_id));
                    // Also exclude nodes we know already have the message.
                    for &n in &nodes_with_msg {
                        let mid = MemberId::new(n);
                        if !exclude.contains(&mid) {
                            exclude.push(mid);
                        }
                    }
                    // Use direct indexing for fanout selection.
                    let mut rng = rand::rngs::StdRng::seed_from_u64(12345 + node_id + round as u64);
                    let selected = engines[0]
                        .0
                        .select_fanout_peers(&all_peers, &exclude, &mut rng);
                    let new_exclude = exclude.clone();
                    for peer in &selected {
                        inboxes[peer.0 as usize].push((origin_msg.clone(), new_exclude.clone()));
                    }
                }
            }

            if new_recipients == 0 && nodes_with_msg.len() < num_nodes as usize {
                // No progress — epidemic stalled (should not happen with enough fanout).
                break;
            }

            rounds_taken = round + 1;
            if nodes_with_msg.len() >= num_nodes as usize {
                break;
            }
        }

        assert_eq!(
            nodes_with_msg.len(),
            num_nodes as usize,
            "all {num_nodes} nodes should receive gossip within {max_rounds} rounds; got {nodes_with_msg:?}"
        );
        assert!(
            rounds_taken <= 3,
            "epidemic should complete in O(log N)=3 rounds with fanout=2; took {rounds_taken} rounds"
        );
    }
}
