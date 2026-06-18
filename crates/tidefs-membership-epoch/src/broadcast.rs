// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BLAKE3-verified membership epoch configuration broadcast protocol.
//!
//! This module implements per-peer delivery of committed [`EpochConfig`]
//! values with acknowledgment tracking, configurable retry, and duplicate
//! suppression. When an epoch transition commits, the resulting configuration
//! is broadcast to all connected transport peers; each peer acknowledges
//! receipt, and unacknowledged configs are retried up to a configurable limit.
//!
//! ## Protocol Overview
//!
//! 1. [`EpochConfigBroadcast::broadcast`] enqueues the config into every
//!    known peer's per-peer delivery queue.
//! 2. Duplicate suppression rejects a config whose epoch number and hash
//!    have already been delivered.
//! 3. [`EpochConfigBroadcast::deliver_pending`] drains each peer queue,
//!    calling the caller-supplied send function for each pending config.
//! 4. [`EpochConfigBroadcast::record_ack`] records a peer's acknowledgment
//!    and removes the config from the pending-ack set.
//! 5. If a peer has not acked within `max_retries` delivery attempts,
//!    the config is left in the pending-ack set for the caller to observe.
//!
//! ## Wire Format
//!
//! The [`EpochConfig`] wire type carries a BLAKE3-256 domain-separated hash
//! (domain `tidefs-membership-epoch-config-v1`) covering the member set hash,
//! epoch number, leader identity, and predecessor epoch hash. Any consumer
//! can call [`EpochConfig::verify_full`] to detect tampering.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

/// A BLAKE3-verified epoch configuration delivered during broadcast.
///
/// Binds the member set hash, epoch number, leader identity, and
/// predecessor epoch hash into a single tamper-evident payload.
/// The domain-separated hash covers all four fields so any receiver
/// can independently verify correctness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochConfig {
    /// BLAKE3-256 hash of the sorted member set for this epoch.
    pub member_set_hash: [u8; 32],
    /// Monotonic epoch sequence number.
    pub epoch_number: u64,
    /// Node identity of the epoch leader.
    pub leader_id: u64,
    /// BLAKE3-256 hash of the predecessor epoch config.
    pub predecessor_epoch_hash: [u8; 32],
    /// BLAKE3-256 domain-separated hash covering all fields.
    pub blake3_hash: [u8; 32],
}

impl EpochConfig {
    /// Domain separation tag for epoch-config hashing.
    pub const DOMAIN_TAG: &[u8] = b"tidefs-membership-epoch-config-v1";

    /// Compute the BLAKE3-256 hash for an epoch configuration.
    ///
    /// Covers `member_set_hash`, `epoch_number`, `leader_id`, and
    /// `predecessor_epoch_hash` in order with domain separation.
    pub fn compute_hash(
        member_set_hash: &[u8; 32],
        epoch_number: u64,
        leader_id: u64,
        predecessor_epoch_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_TAG);
        hasher.update(member_set_hash);
        hasher.update(&epoch_number.to_le_bytes());
        hasher.update(&leader_id.to_le_bytes());
        hasher.update(predecessor_epoch_hash);
        hasher.finalize().into()
    }

    /// Create a new `EpochConfig` with a computed BLAKE3 hash.
    pub fn new(
        member_set_hash: [u8; 32],
        epoch_number: u64,
        leader_id: u64,
        predecessor_epoch_hash: [u8; 32],
    ) -> Self {
        let blake3_hash = Self::compute_hash(
            &member_set_hash,
            epoch_number,
            leader_id,
            &predecessor_epoch_hash,
        );
        Self {
            member_set_hash,
            epoch_number,
            leader_id,
            predecessor_epoch_hash,
            blake3_hash,
        }
    }

    /// Verify that `self.blake3_hash` matches the computed hash over
    /// all four payload fields.
    pub fn verify_full(&self) -> bool {
        Self::compute_hash(
            &self.member_set_hash,
            self.epoch_number,
            self.leader_id,
            &self.predecessor_epoch_hash,
        ) == self.blake3_hash
    }

    /// Return the config hash for acknowledgment tracking.
    pub fn config_hash(&self) -> &[u8; 32] {
        &self.blake3_hash
    }
}

/// Holds a single peer's delivery state during broadcast.
#[derive(Clone, Debug)]
struct PeerDeliveryState {
    /// Configs queued for this peer (oldest-first).
    queue: VecDeque<EpochConfig>,
    /// Number of delivery attempts for the current head-of-line config.
    attempts: usize,
}

impl PeerDeliveryState {
    fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            attempts: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// Error conditions during epoch config broadcast.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BroadcastError {
    /// The config was suppressed because an identical (epoch_number,
    /// config_hash) pair was already broadcast.
    DuplicateConfig {
        epoch_number: u64,
        config_hash: [u8; 32],
    },
    /// A peer has exhausted retries for the head-of-line config.
    PeerRetriesExhausted {
        peer_id: u64,
        config_hash: [u8; 32],
        attempts: usize,
    },
    /// The peer is not known to this broadcast instance.
    UnknownPeer(u64),
}

impl fmt::Display for BroadcastError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateConfig { epoch_number, .. } => {
                write!(
                    f,
                    "duplicate config: epoch {epoch_number} already broadcast"
                )
            }
            Self::PeerRetriesExhausted {
                peer_id, attempts, ..
            } => {
                write!(
                    f,
                    "peer {peer_id} exhausted retries after {attempts} attempts"
                )
            }
            Self::UnknownPeer(id) => write!(f, "unknown peer {id}"),
        }
    }
}

impl std::error::Error for BroadcastError {}

/// Manages epoch configuration broadcast to a set of transport peers.
///
/// Each peer has an independent delivery queue (oldest-first) and
/// acknowledgment state. Configs are enqueued via [`broadcast`] and
/// delivered via [`deliver_pending`]. Acknowledgments are recorded
/// via [`record_ack`].
///
/// Duplicate suppression: a config with the same `(epoch_number,
/// config_hash)` pair that has already been enqueued is silently
/// skipped (returns `Ok(())` without enqueuing).
///
/// Retry: each head-of-line config is retried up to `max_retries`
/// times. If retries are exhausted, the caller can observe the
/// stuck peer via [`pending_peers`].
///
/// [`broadcast`]: EpochConfigBroadcast::broadcast
/// [`deliver_pending`]: EpochConfigBroadcast::deliver_pending
/// [`record_ack`]: EpochConfigBroadcast::record_ack
/// [`pending_peers`]: EpochConfigBroadcast::pending_peers
#[derive(Clone, Debug)]
pub struct EpochConfigBroadcast {
    /// Per-peer delivery state keyed by peer node id.
    peers: BTreeMap<u64, PeerDeliveryState>,
    /// Set of (epoch_number, config_hash) already delivered for
    /// duplicate suppression.
    delivered: BTreeSet<(u64, [u8; 32])>,
    /// Maximum retry attempts per head-of-line config per peer.
    max_retries: usize,
}

impl EpochConfigBroadcast {
    /// Create a new broadcast manager with the given retry limit.
    pub fn new(max_retries: usize) -> Self {
        Self {
            peers: BTreeMap::new(),
            delivered: BTreeSet::new(),
            max_retries,
        }
    }

    /// Register a peer for future broadcasts.
    ///
    /// Idempotent: if the peer is already registered, this is a no-op.
    pub fn register_peer(&mut self, peer_id: u64) {
        self.peers
            .entry(peer_id)
            .or_insert_with(PeerDeliveryState::new);
    }

    /// Remove a peer and discard its pending queue.
    ///
    /// After removal, any pending acks for this peer are implicitly
    /// dropped (they will never be acked).
    pub fn unregister_peer(&mut self, peer_id: u64) {
        self.peers.remove(&peer_id);
    }

    /// Number of registered peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Enqueue an epoch config for delivery to every registered peer.
    ///
    /// Returns `Ok(())` when the config is enqueued for all peers.
    /// Returns `BroadcastError::DuplicateConfig` when an identical
    /// (epoch_number, config_hash) pair has already been broadcast.
    pub fn broadcast(&mut self, config: EpochConfig) -> Result<(), BroadcastError> {
        let key = (config.epoch_number, config.blake3_hash);
        if !self.delivered.insert(key) {
            return Err(BroadcastError::DuplicateConfig {
                epoch_number: config.epoch_number,
                config_hash: config.blake3_hash,
            });
        }

        for state in self.peers.values_mut() {
            state.queue.push_back(config.clone());
        }
        Ok(())
    }

    /// Deliver the head-of-line pending config to each peer by calling
    /// the supplied `send_fn`.
    ///
    /// For each peer with a non-empty queue, `send_fn(peer_id, &config)`
    /// is called once. If `send_fn` returns `true`, the peer's retry
    /// counter is reset and the caller should later call [`record_ack`].
    /// If `send_fn` returns `false` or the `max_retries` limit is
    /// exceeded, the config stays pending and the retry counter is
    /// incremented.
    ///
    /// Returns the set of peer ids whose retries were exhausted on
    /// this delivery round.
    ///
    /// [`record_ack`]: EpochConfigBroadcast::record_ack
    pub fn deliver_pending<F>(&mut self, mut send_fn: F) -> Vec<u64>
    where
        F: FnMut(u64, &EpochConfig) -> bool,
    {
        let mut exhausted = Vec::new();

        for (&peer_id, state) in self.peers.iter_mut() {
            if state.queue.is_empty() {
                continue;
            }

            if state.attempts >= self.max_retries {
                // Already exhausted — skip delivery but report
                exhausted.push(peer_id);
                continue;
            }

            let config = state.queue.front().expect("queue non-empty");
            if send_fn(peer_id, config) {
                // Delivery succeeded — reset attempts; caller will ack
                state.attempts = 0;
            } else {
                state.attempts += 1;
                if state.attempts >= self.max_retries {
                    exhausted.push(peer_id);
                }
            }
        }

        exhausted
    }

    /// Record that a peer acknowledged receipt of a config.
    ///
    /// Pops the head-of-line config from the peer's queue. If the
    /// peer has more configs queued, the retry counter is reset for
    /// the next head-of-line entry.
    ///
    /// Returns `BroadcastError::UnknownPeer` if the peer is not
    /// registered.
    pub fn record_ack(&mut self, peer_id: u64) -> Result<(), BroadcastError> {
        let state = self
            .peers
            .get_mut(&peer_id)
            .ok_or(BroadcastError::UnknownPeer(peer_id))?;

        state.queue.pop_front();
        // Reset attempts for the next config in queue (if any)
        state.attempts = 0;
        Ok(())
    }

    /// Return the peer ids that have pending (unacked) configs.
    pub fn pending_peers(&self) -> Vec<u64> {
        self.peers
            .iter()
            .filter(|(_, s)| !s.is_empty())
            .map(|(&id, _)| id)
            .collect()
    }

    /// Return the number of pending configs for a specific peer.
    pub fn pending_count(&self, peer_id: u64) -> usize {
        self.peers.get(&peer_id).map_or(0, |s| s.queue.len())
    }

    /// Total number of pending deliveries across all peers.
    pub fn total_pending(&self) -> usize {
        self.peers.values().map(|s| s.queue.len()).sum()
    }

    /// Whether a config with the given (epoch_number, hash) has
    /// already been broadcast (duplicate suppression).
    pub fn is_delivered(&self, epoch_number: u64, config_hash: &[u8; 32]) -> bool {
        self.delivered.contains(&(epoch_number, *config_hash))
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EpochConfig ───────────────────────────────────────────────────

    fn test_config(
        member_set_hash: [u8; 32],
        epoch_number: u64,
        leader_id: u64,
        predecessor_hash: [u8; 32],
    ) -> EpochConfig {
        EpochConfig::new(member_set_hash, epoch_number, leader_id, predecessor_hash)
    }

    fn hash_from_u8(v: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = v;
        h
    }

    #[test]
    fn epoch_config_verify_full_accepts_valid() {
        let ms = hash_from_u8(0xAA);
        let prev = hash_from_u8(0xBB);
        let cfg = test_config(ms, 5, 42, prev);
        assert!(cfg.verify_full());
    }

    #[test]
    fn epoch_config_verify_rejects_tampered_member_set_hash() {
        let ms = hash_from_u8(0xAA);
        let prev = hash_from_u8(0xBB);
        let mut cfg = test_config(ms, 5, 42, prev);
        cfg.member_set_hash[0] ^= 0xFF;
        assert!(!cfg.verify_full());
    }

    #[test]
    fn epoch_config_verify_rejects_tampered_epoch_number() {
        let ms = hash_from_u8(0xAA);
        let prev = hash_from_u8(0xBB);
        let mut cfg = test_config(ms, 5, 42, prev);
        cfg.epoch_number = 99;
        assert!(!cfg.verify_full());
    }

    #[test]
    fn epoch_config_verify_rejects_tampered_leader_id() {
        let ms = hash_from_u8(0xAA);
        let prev = hash_from_u8(0xBB);
        let mut cfg = test_config(ms, 5, 42, prev);
        cfg.leader_id = 7;
        assert!(!cfg.verify_full());
    }

    #[test]
    fn epoch_config_verify_rejects_tampered_predecessor_hash() {
        let ms = hash_from_u8(0xAA);
        let prev = hash_from_u8(0xBB);
        let mut cfg = test_config(ms, 5, 42, prev);
        cfg.predecessor_epoch_hash[0] ^= 0xFF;
        assert!(!cfg.verify_full());
    }

    #[test]
    fn epoch_config_verify_rejects_tampered_blake3_hash() {
        let ms = hash_from_u8(0xAA);
        let prev = hash_from_u8(0xBB);
        let mut cfg = test_config(ms, 5, 42, prev);
        cfg.blake3_hash[0] ^= 0x01;
        assert!(!cfg.verify_full());
    }

    #[test]
    fn epoch_config_hash_deterministic() {
        let ms = hash_from_u8(0xAA);
        let prev = hash_from_u8(0xBB);
        let c1 = test_config(ms, 5, 42, prev);
        let c2 = test_config(ms, 5, 42, prev);
        assert_eq!(c1.blake3_hash, c2.blake3_hash);
    }

    #[test]
    fn epoch_config_hash_differs_by_member_set_hash() {
        let prev = hash_from_u8(0xBB);
        let c1 = test_config(hash_from_u8(0xAA), 5, 42, prev);
        let c2 = test_config(hash_from_u8(0xCC), 5, 42, prev);
        assert_ne!(c1.blake3_hash, c2.blake3_hash);
    }

    #[test]
    fn epoch_config_hash_differs_by_epoch_number() {
        let ms = hash_from_u8(0xAA);
        let prev = hash_from_u8(0xBB);
        let c1 = test_config(ms, 5, 42, prev);
        let c2 = test_config(ms, 6, 42, prev);
        assert_ne!(c1.blake3_hash, c2.blake3_hash);
    }

    #[test]
    fn epoch_config_hash_differs_by_leader_id() {
        let ms = hash_from_u8(0xAA);
        let prev = hash_from_u8(0xBB);
        let c1 = test_config(ms, 5, 42, prev);
        let c2 = test_config(ms, 5, 99, prev);
        assert_ne!(c1.blake3_hash, c2.blake3_hash);
    }

    #[test]
    fn epoch_config_hash_differs_by_predecessor_hash() {
        let ms = hash_from_u8(0xAA);
        let c1 = test_config(ms, 5, 42, hash_from_u8(0xBB));
        let c2 = test_config(ms, 5, 42, hash_from_u8(0xDD));
        assert_ne!(c1.blake3_hash, c2.blake3_hash);
    }

    #[test]
    fn epoch_config_domain_separation_cross_check() {
        // Hashing the same data with a different domain tag produces
        // a different hash.
        let ms = hash_from_u8(0xAA);
        let prev = hash_from_u8(0xBB);
        let cfg = test_config(ms, 5, 42, prev);

        // Re-compute with a different domain tag
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tidefs-membership-epoch-config-v2"); // different domain
        hasher.update(&cfg.member_set_hash);
        hasher.update(&cfg.epoch_number.to_le_bytes());
        hasher.update(&cfg.leader_id.to_le_bytes());
        hasher.update(&cfg.predecessor_epoch_hash);
        let cross_hash: [u8; 32] = hasher.finalize().into();
        assert_ne!(cross_hash, cfg.blake3_hash);
    }

    #[test]
    fn epoch_config_serde_roundtrip() {
        let ms = hash_from_u8(0xAA);
        let prev = hash_from_u8(0xBB);
        let cfg = test_config(ms, 5, 42, prev);
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: EpochConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, cfg);
        assert!(restored.verify_full());
    }

    // ── EpochConfigBroadcast ──────────────────────────────────────────

    fn config_for_epoch(epoch: u64) -> EpochConfig {
        let ms = hash_from_u8(epoch as u8);
        let prev = hash_from_u8(epoch.saturating_sub(1) as u8);
        EpochConfig::new(ms, epoch, 1, prev)
    }

    #[test]
    fn broadcast_delivers_to_all_registered_peers() {
        let mut bc = EpochConfigBroadcast::new(3);
        bc.register_peer(1);
        bc.register_peer(2);
        bc.register_peer(3);

        let cfg = config_for_epoch(1);
        bc.broadcast(cfg.clone()).unwrap();

        // All three peers have the config queued
        assert_eq!(bc.pending_count(1), 1);
        assert_eq!(bc.pending_count(2), 1);
        assert_eq!(bc.pending_count(3), 1);
        assert_eq!(bc.pending_peers().len(), 3);
        assert_eq!(bc.total_pending(), 3);
    }

    #[test]
    fn broadcast_with_empty_peer_set_is_noop() {
        let mut bc = EpochConfigBroadcast::new(3);
        let cfg = config_for_epoch(1);
        // No peers registered — broadcast should succeed but enqueue nothing
        bc.broadcast(cfg).unwrap();
        assert_eq!(bc.total_pending(), 0);
    }

    #[test]
    fn duplicate_config_suppression() {
        let mut bc = EpochConfigBroadcast::new(3);
        bc.register_peer(1);

        let cfg = config_for_epoch(1);
        bc.broadcast(cfg.clone()).unwrap();

        // Same epoch number and config hash → suppressed
        let result = bc.broadcast(cfg.clone());
        assert!(matches!(
            result,
            Err(BroadcastError::DuplicateConfig { .. })
        ));
        assert_eq!(bc.pending_count(1), 1); // still only one queued
    }

    #[test]
    fn different_epoch_not_suppressed() {
        let mut bc = EpochConfigBroadcast::new(3);
        bc.register_peer(1);

        bc.broadcast(config_for_epoch(1)).unwrap();
        bc.broadcast(config_for_epoch(2)).unwrap();

        // Two distinct configs queued in FIFO order
        assert_eq!(bc.pending_count(1), 2);
    }

    #[test]
    fn same_epoch_different_config_not_suppressed() {
        let mut bc = EpochConfigBroadcast::new(3);
        bc.register_peer(1);

        let c1 = EpochConfig::new(hash_from_u8(0xAA), 1, 1, hash_from_u8(0x00));
        let c2 = EpochConfig::new(hash_from_u8(0xBB), 1, 1, hash_from_u8(0x00));
        // Different member_set_hash → different config_hash → not suppressed
        assert_ne!(c1.blake3_hash, c2.blake3_hash);

        bc.broadcast(c1).unwrap();
        bc.broadcast(c2).unwrap();
        assert_eq!(bc.pending_count(1), 2);
    }

    #[test]
    fn record_ack_pops_head_of_line() {
        let mut bc = EpochConfigBroadcast::new(3);
        bc.register_peer(1);

        bc.broadcast(config_for_epoch(1)).unwrap();
        bc.broadcast(config_for_epoch(2)).unwrap();
        assert_eq!(bc.pending_count(1), 2);

        bc.record_ack(1).unwrap();
        assert_eq!(bc.pending_count(1), 1); // one remains

        bc.record_ack(1).unwrap();
        assert_eq!(bc.pending_count(1), 0); // queue drained
    }

    #[test]
    fn record_ack_unknown_peer() {
        let mut bc = EpochConfigBroadcast::new(3);
        let result = bc.record_ack(999);
        assert!(matches!(result, Err(BroadcastError::UnknownPeer(999))));
    }

    #[test]
    fn deliver_pending_calls_send_fn_per_peer() {
        let mut bc = EpochConfigBroadcast::new(3);
        bc.register_peer(1);
        bc.register_peer(2);

        let cfg = config_for_epoch(1);
        bc.broadcast(cfg.clone()).unwrap();

        let mut delivered = Vec::new();
        let exhausted = bc.deliver_pending(|peer_id, config| {
            delivered.push((peer_id, config.clone()));
            true // delivery succeeded
        });

        assert!(exhausted.is_empty());
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0].0, 1);
        assert_eq!(delivered[1].0, 2);
        // Both peers still have config queued (ack not yet recorded)
        assert_eq!(bc.pending_count(1), 1);
        assert_eq!(bc.pending_count(2), 1);
    }

    #[test]
    fn deliver_pending_skips_empty_queues() {
        let mut bc = EpochConfigBroadcast::new(3);
        bc.register_peer(1);
        bc.register_peer(2);

        bc.broadcast(config_for_epoch(1)).unwrap();
        // Ack peer 1 to drain its queue
        bc.record_ack(1).unwrap();

        let mut delivered = Vec::new();
        bc.deliver_pending(|peer_id, config| {
            delivered.push((peer_id, config.clone()));
            true
        });

        // Only peer 2 still has pending
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].0, 2);
    }

    #[test]
    fn retry_exhaustion_after_max_retries() {
        let mut bc = EpochConfigBroadcast::new(2); // max_retries = 2
        bc.register_peer(1);

        bc.broadcast(config_for_epoch(1)).unwrap();

        // First delivery round — send_fn returns false (failure)
        let exhausted = bc.deliver_pending(|_, _| false);
        assert!(exhausted.is_empty()); // 1 attempt, not yet exhausted
        assert_eq!(bc.pending_count(1), 1);

        // Second delivery round — still failing
        let exhausted = bc.deliver_pending(|_, _| false);
        assert_eq!(exhausted, vec![1]); // 2 attempts = max_retries → exhausted
        assert_eq!(bc.pending_count(1), 1); // config remains queued
    }

    #[test]
    fn retry_counter_resets_after_ack() {
        let mut bc = EpochConfigBroadcast::new(2);
        bc.register_peer(1);

        bc.broadcast(config_for_epoch(1)).unwrap();
        bc.broadcast(config_for_epoch(2)).unwrap();

        // Fail first delivery, then succeed
        bc.deliver_pending(|_, _| false); // attempt 1 for epoch 1
        bc.deliver_pending(|_, config| {
            // Verify we're still on epoch 1 (head of line)
            assert_eq!(config.epoch_number, 1);
            true // success
        });

        // Ack head of line (epoch 1)
        bc.record_ack(1).unwrap();
        assert_eq!(bc.pending_count(1), 1); // epoch 2 remains

        // Now deliver epoch 2 — attempts should be reset
        let exhausted = bc.deliver_pending(|_, c| {
            assert_eq!(c.epoch_number, 2);
            false // fail
        });
        assert!(exhausted.is_empty()); // only 1 attempt, not exhausted
    }

    #[test]
    fn unregister_peer_discards_pending() {
        let mut bc = EpochConfigBroadcast::new(3);
        bc.register_peer(1);
        bc.register_peer(2);

        bc.broadcast(config_for_epoch(1)).unwrap();
        assert_eq!(bc.pending_peers().len(), 2);

        bc.unregister_peer(1);
        assert_eq!(bc.pending_peers().len(), 1);
        assert_eq!(bc.pending_count(1), 0);
        assert_eq!(bc.pending_count(2), 1);
    }

    #[test]
    fn register_peer_idempotent() {
        let mut bc = EpochConfigBroadcast::new(3);
        bc.register_peer(1);
        bc.register_peer(1);
        assert_eq!(bc.peer_count(), 1);
    }

    #[test]
    fn is_delivered_tracks_suppression() {
        let mut bc = EpochConfigBroadcast::new(3);
        bc.register_peer(1);

        let cfg = config_for_epoch(5);
        assert!(!bc.is_delivered(5, &cfg.blake3_hash));

        bc.broadcast(cfg.clone()).unwrap();
        assert!(bc.is_delivered(5, &cfg.blake3_hash));
    }

    #[test]
    fn full_broadcast_lifecycle() {
        let mut bc = EpochConfigBroadcast::new(3);
        bc.register_peer(10);
        bc.register_peer(20);
        bc.register_peer(30);

        // Broadcast epoch 1
        let cfg1 = config_for_epoch(1);
        bc.broadcast(cfg1).unwrap();
        assert_eq!(bc.total_pending(), 3);

        // Deliver to all peers
        let mut delivered = Vec::new();
        bc.deliver_pending(|peer_id, config| {
            delivered.push((peer_id, config.epoch_number));
            true
        });
        assert_eq!(delivered.len(), 3);

        // Ack peers 10 and 20
        bc.record_ack(10).unwrap();
        bc.record_ack(20).unwrap();
        assert_eq!(bc.pending_peers(), vec![30]);
        assert_eq!(bc.total_pending(), 1);

        // Ack peer 30
        bc.record_ack(30).unwrap();
        assert!(bc.pending_peers().is_empty());
        assert_eq!(bc.total_pending(), 0);

        // Broadcast epoch 2
        let cfg2 = config_for_epoch(2);
        let cfg2_hash = *cfg2.config_hash();
        bc.broadcast(cfg2).unwrap();
        assert_eq!(bc.total_pending(), 3);
        assert!(bc.is_delivered(2, &cfg2_hash));

        // Duplicate epoch 2 is suppressed
        let result = bc.broadcast(config_for_epoch(2));
        assert!(matches!(
            result,
            Err(BroadcastError::DuplicateConfig { .. })
        ));
    }

    #[test]
    fn partial_delivery_failure_with_retry_recovery() {
        let mut bc = EpochConfigBroadcast::new(3);
        bc.register_peer(1);
        bc.register_peer(2);
        bc.register_peer(3);

        bc.broadcast(config_for_epoch(1)).unwrap();

        // First round: peer 2 fails, others succeed
        let exhausted = bc.deliver_pending(|peer_id, _| peer_id != 2);
        assert!(exhausted.is_empty());

        // Second round: peer 2 succeeds
        let exhausted = bc.deliver_pending(|peer_id, _| peer_id == 2);
        assert!(exhausted.is_empty());

        // Ack all
        bc.record_ack(1).unwrap();
        bc.record_ack(2).unwrap();
        bc.record_ack(3).unwrap();
        assert_eq!(bc.total_pending(), 0);
    }

    #[test]
    fn retry_exhaustion_reported_across_rounds() {
        let mut bc = EpochConfigBroadcast::new(2);
        bc.register_peer(1);
        bc.register_peer(2);

        bc.broadcast(config_for_epoch(1)).unwrap();

        // Round 1: both fail
        let exhausted = bc.deliver_pending(|_, _| false);
        assert!(exhausted.is_empty());

        // Round 2: peer 1 fails again (exhausted), peer 2 succeeds
        let exhausted = bc.deliver_pending(|peer_id, _| peer_id == 2);
        assert_eq!(exhausted, vec![1]);

        // Peer 1 is stuck; peer 2 can ack
        bc.record_ack(2).unwrap();
        assert_eq!(bc.pending_count(2), 0);
        assert_eq!(bc.pending_count(1), 1);
    }

    #[test]
    fn pending_peers_returns_sorted() {
        let mut bc = EpochConfigBroadcast::new(3);
        bc.register_peer(30);
        bc.register_peer(10);
        bc.register_peer(20);

        bc.broadcast(config_for_epoch(1)).unwrap();
        bc.record_ack(20).unwrap();

        // BTreeMap iteration order → keys are sorted
        assert_eq!(bc.pending_peers(), vec![10, 30]);
    }
}
