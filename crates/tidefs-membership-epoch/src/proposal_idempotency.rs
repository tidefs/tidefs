//! Proposal idempotency-key deduplication for safe coordinator retransmission.
//!
//! When a subsystem resubmits a proposal after coordinator failover, the
//! idempotency tracker short-circuits duplicate proposals before they enter
//! a quorum round, preventing double-commits and wasted transport bandwidth.
//!
//! ## Caller Contract
//!
//! The caller generates a deterministic [`ProposalIdempotencyKey`] for each
//! logical proposal intent. Before entering quorum, the caller consults
//! [`IdempotencyTracker::check_and_insert`]: a duplicate key returns
//! [`ProposalOutcome::AlreadyCommitted`] and the caller must skip quorum.
//!
//! ## Retention
//!
//! Keys are retained for `retention_epochs` epochs after commit. After that
//! window, they are pruned on the next `check_and_insert` call. An LRU cap
//! (`max_tracked_keys`) evicts the oldest entry when capacity is exceeded.

use std::collections::{HashMap, VecDeque};
use std::fmt;

// ── ProposalIdempotencyKey ──────────────────────────────────────────────

/// An opaque caller-chosen idempotency key for a proposal.
///
/// The caller must ensure that identical logical proposals produce identical
/// keys (e.g. via BLAKE3 hash of the proposal intent). Keys are scoped to
/// the proposer — different proposers with the same key bytes are tracked
/// independently.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProposalIdempotencyKey(pub [u8; 32]);

impl ProposalIdempotencyKey {
    /// Create a key from a 32-byte array.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a key from a BLAKE3 hash of proposal-intent bytes.
    #[must_use]
    pub fn from_intent(intent_bytes: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tidefs-membership-proposal-idempotency-v1");
        hasher.update(intent_bytes);
        Self(hasher.finalize().into())
    }

    /// View the key as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ProposalIdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProposalIdempotencyKey({:02x}{:02x}..)",
            self.0[0], self.0[1]
        )
    }
}

// ── IdempotencyConfig ───────────────────────────────────────────────────

/// Configuration for the [`IdempotencyTracker`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdempotencyConfig {
    /// Number of committed epochs to retain keys before pruning.
    pub retention_epochs: u64,
    /// Maximum number of tracked keys before LRU eviction.
    pub max_tracked_keys: usize,
}

impl Default for IdempotencyConfig {
    fn default() -> Self {
        Self {
            retention_epochs: 8,
            max_tracked_keys: 4096,
        }
    }
}

impl IdempotencyConfig {
    /// Create a new config with the given retention window and capacity.
    #[must_use]
    pub const fn new(retention_epochs: u64, max_tracked_keys: usize) -> Self {
        Self {
            retention_epochs,
            max_tracked_keys,
        }
    }
}

// ── ProposalOutcome ─────────────────────────────────────────────────────

/// The outcome of consulting the idempotency tracker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalOutcome {
    /// This proposal-key pair is new; proceed to quorum.
    PassThrough,
    /// This proposal-key pair was already committed at the given epoch.
    AlreadyCommitted {
        /// The epoch at which the original proposal was committed.
        epoch: u64,
    },
}

// ── IdempotencyTracker ──────────────────────────────────────────────────

/// Bounded-LRU tracker for proposal idempotency deduplication.
///
/// Keyed by `(proposer_id, ProposalIdempotencyKey)`. On each
/// [`Self::check_and_insert`] call:
///
/// 1. Prunes entries older than `current_epoch - retention_epochs`.
/// 2. Checks if the key already exists → returns [`ProposalOutcome::AlreadyCommitted`].
/// 3. Inserts the key with the current epoch.
/// 4. If the LRU cap is exceeded, evicts the oldest entry.
#[derive(Clone, Debug)]
pub struct IdempotencyTracker {
    config: IdempotencyConfig,
    /// Maps (proposer_id, key) → committed epoch.
    entries: HashMap<(u64, ProposalIdempotencyKey), u64>,
    /// Insertion-order queue for LRU eviction. Front = oldest.
    lru_order: VecDeque<(u64, ProposalIdempotencyKey)>,
}

impl IdempotencyTracker {
    /// Create a new empty tracker with the given config.
    #[must_use]
    pub fn new(config: IdempotencyConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            lru_order: VecDeque::new(),
        }
    }

    /// Create a new tracker with default config (8 epochs, 4096 keys).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(IdempotencyConfig::default())
    }

    /// Check whether a proposal key has already been committed, and insert
    /// it if not.
    pub fn check_and_insert(
        &mut self,
        proposer_id: u64,
        key: ProposalIdempotencyKey,
        current_epoch: u64,
    ) -> ProposalOutcome {
        self.prune_epoch_window(current_epoch);

        if let Some(&committed_epoch) = self.entries.get(&(proposer_id, key)) {
            return ProposalOutcome::AlreadyCommitted {
                epoch: committed_epoch,
            };
        }

        let entry_key = (proposer_id, key);
        self.entries.insert(entry_key, current_epoch);
        self.lru_order.push_back(entry_key);

        while self.entries.len() > self.config.max_tracked_keys {
            if let Some(oldest) = self.lru_order.pop_front() {
                self.entries.remove(&oldest);
            }
        }

        ProposalOutcome::PassThrough
    }

    /// Prune entries whose commit epoch is below the retention window.
    fn prune_epoch_window(&mut self, current_epoch: u64) {
        let cutoff = current_epoch.saturating_sub(self.config.retention_epochs);
        if self.config.retention_epochs == 0 || cutoff == 0 {
            return;
        }

        let mut i = 0;
        while i < self.lru_order.len() {
            let entry_key = self.lru_order[i];
            if let Some(&epoch) = self.entries.get(&entry_key) {
                if epoch < cutoff {
                    self.entries.remove(&entry_key);
                    self.lru_order.remove(i);
                    continue;
                }
            } else {
                self.lru_order.remove(i);
                continue;
            }
            i += 1;
        }
    }

    /// Record a commit for a key at a given epoch.
    pub fn record_commit(
        &mut self,
        proposer_id: u64,
        key: ProposalIdempotencyKey,
        committed_epoch: u64,
    ) {
        self.entries.insert((proposer_id, key), committed_epoch);
    }

    /// Return the number of currently tracked entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the tracker is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the configured retention window.
    #[must_use]
    pub fn retention_epochs(&self) -> u64 {
        self.config.retention_epochs
    }

    /// Return the configured max key capacity.
    #[must_use]
    pub fn max_tracked_keys(&self) -> usize {
        self.config.max_tracked_keys
    }

    /// Clear all tracked entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.lru_order.clear();
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(seed: u8) -> ProposalIdempotencyKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        ProposalIdempotencyKey(bytes)
    }

    // ── Basic duplicate detection ────────────────────────────────────

    #[test]
    fn duplicate_key_returns_already_committed() {
        let mut tracker = IdempotencyTracker::with_defaults();
        let key = make_key(1);
        assert_eq!(
            tracker.check_and_insert(42, key, 10),
            ProposalOutcome::PassThrough
        );
        assert_eq!(
            tracker.check_and_insert(42, key, 10),
            ProposalOutcome::AlreadyCommitted { epoch: 10 }
        );
    }

    #[test]
    fn non_duplicate_key_passes_through() {
        let mut tracker = IdempotencyTracker::with_defaults();
        assert_eq!(
            tracker.check_and_insert(42, make_key(1), 10),
            ProposalOutcome::PassThrough
        );
        assert_eq!(
            tracker.check_and_insert(42, make_key(2), 10),
            ProposalOutcome::PassThrough
        );
    }

    // ── Different proposers are independent ──────────────────────────

    #[test]
    fn different_proposers_same_key_are_independent() {
        let mut tracker = IdempotencyTracker::with_defaults();
        let key = make_key(1);
        assert_eq!(
            tracker.check_and_insert(1, key, 10),
            ProposalOutcome::PassThrough
        );
        assert_eq!(
            tracker.check_and_insert(2, key, 10),
            ProposalOutcome::PassThrough
        );
    }

    #[test]
    fn same_proposer_different_key_are_independent() {
        let mut tracker = IdempotencyTracker::with_defaults();
        assert_eq!(
            tracker.check_and_insert(42, make_key(1), 10),
            ProposalOutcome::PassThrough
        );
        assert_eq!(
            tracker.check_and_insert(42, make_key(2), 10),
            ProposalOutcome::PassThrough
        );
    }

    // ── Duplicate detection across epochs ────────────────────────────

    #[test]
    fn duplicate_persists_across_epochs() {
        let mut tracker = IdempotencyTracker::with_defaults();
        let key = make_key(1);
        tracker.check_and_insert(42, key, 5);
        assert_eq!(
            tracker.check_and_insert(42, key, 10),
            ProposalOutcome::AlreadyCommitted { epoch: 5 }
        );
    }

    // ── LRU capacity eviction ────────────────────────────────────────

    #[test]
    fn lru_eviction_when_capacity_exceeded() {
        let config = IdempotencyConfig {
            retention_epochs: 100,
            max_tracked_keys: 3,
        };
        let mut tracker = IdempotencyTracker::new(config);

        tracker.check_and_insert(1, make_key(1), 10);
        tracker.check_and_insert(1, make_key(2), 10);
        tracker.check_and_insert(1, make_key(3), 10);
        assert_eq!(tracker.len(), 3);

        // 4th key evicts key1 (oldest)
        tracker.check_and_insert(1, make_key(4), 10);
        assert_eq!(tracker.len(), 3);

        // Still-present keys return AlreadyCommitted without side effects
        assert!(matches!(
            tracker.check_and_insert(1, make_key(2), 10),
            ProposalOutcome::AlreadyCommitted { .. }
        ));
        assert!(matches!(
            tracker.check_and_insert(1, make_key(3), 10),
            ProposalOutcome::AlreadyCommitted { .. }
        ));
        assert!(matches!(
            tracker.check_and_insert(1, make_key(4), 10),
            ProposalOutcome::AlreadyCommitted { .. }
        ));
        // Evicted key passes through
        assert_eq!(
            tracker.check_and_insert(1, make_key(1), 10),
            ProposalOutcome::PassThrough
        );
    }

    #[test]
    fn lru_eviction_evicts_oldest_by_insertion_order() {
        let config = IdempotencyConfig {
            retention_epochs: 100,
            max_tracked_keys: 2,
        };
        let mut tracker = IdempotencyTracker::new(config);

        tracker.check_and_insert(1, make_key(1), 10);
        tracker.check_and_insert(1, make_key(2), 10);

        // key3 evicts key1 (oldest)
        tracker.check_and_insert(1, make_key(3), 10);

        // Still-present keys
        assert!(matches!(
            tracker.check_and_insert(1, make_key(2), 10),
            ProposalOutcome::AlreadyCommitted { .. }
        ));
        assert!(matches!(
            tracker.check_and_insert(1, make_key(3), 10),
            ProposalOutcome::AlreadyCommitted { .. }
        ));
        // Evicted key
        assert_eq!(
            tracker.check_and_insert(1, make_key(1), 10),
            ProposalOutcome::PassThrough
        );
    }

    // ── Epoch-window pruning ─────────────────────────────────────────

    #[test]
    fn epoch_window_pruning_removes_old_entries() {
        let config = IdempotencyConfig {
            retention_epochs: 5,
            max_tracked_keys: 100,
        };
        let mut tracker = IdempotencyTracker::new(config);

        tracker.check_and_insert(1, make_key(1), 10);
        tracker.check_and_insert(1, make_key(2), 15);
        assert_eq!(tracker.len(), 2);

        // cutoff = 21 - 5 = 16; epoch 10 and 15 both < 16, both pruned
        tracker.check_and_insert(1, make_key(3), 21);
        assert_eq!(
            tracker.check_and_insert(1, make_key(1), 21),
            ProposalOutcome::PassThrough
        );
        assert_eq!(
            tracker.check_and_insert(1, make_key(2), 21),
            ProposalOutcome::PassThrough
        );
    }

    #[test]
    fn epoch_window_pruning_preserves_recent_entries() {
        let config = IdempotencyConfig {
            retention_epochs: 5,
            max_tracked_keys: 100,
        };
        let mut tracker = IdempotencyTracker::new(config);

        tracker.check_and_insert(1, make_key(1), 10);
        tracker.check_and_insert(1, make_key(2), 16);

        // cutoff = 17 - 5 = 12; epoch 10 < 12 pruned, epoch 16 >= 12 preserved
        tracker.check_and_insert(1, make_key(3), 17);

        assert_eq!(
            tracker.check_and_insert(1, make_key(1), 17),
            ProposalOutcome::PassThrough
        );
        assert!(matches!(
            tracker.check_and_insert(1, make_key(2), 17),
            ProposalOutcome::AlreadyCommitted { .. }
        ));
    }

    #[test]
    fn epoch_pruning_at_exact_boundary() {
        let config = IdempotencyConfig {
            retention_epochs: 3,
            max_tracked_keys: 100,
        };
        let mut tracker = IdempotencyTracker::new(config);

        tracker.check_and_insert(1, make_key(1), 7);
        // cutoff = 10 - 3 = 7; epoch 7 < 7 is false, preserved
        tracker.check_and_insert(1, make_key(2), 10);

        assert_eq!(
            tracker.check_and_insert(1, make_key(1), 10),
            ProposalOutcome::AlreadyCommitted { epoch: 7 }
        );
    }

    #[test]
    fn zero_retention_disables_pruning() {
        let config = IdempotencyConfig {
            retention_epochs: 0,
            max_tracked_keys: 100,
        };
        let mut tracker = IdempotencyTracker::new(config);

        tracker.check_and_insert(1, make_key(1), 10);
        assert_eq!(
            tracker.check_and_insert(1, make_key(1), 1000),
            ProposalOutcome::AlreadyCommitted { epoch: 10 }
        );
    }

    // ── Empty and single-entry edge cases ────────────────────────────

    #[test]
    fn empty_tracker_is_empty() {
        let tracker = IdempotencyTracker::with_defaults();
        assert!(tracker.is_empty());
        assert_eq!(tracker.len(), 0);
    }

    #[test]
    fn single_entry_behavior() {
        let mut tracker = IdempotencyTracker::with_defaults();
        assert_eq!(
            tracker.check_and_insert(42, make_key(1), 10),
            ProposalOutcome::PassThrough
        );
        assert_eq!(tracker.len(), 1);
        assert!(!tracker.is_empty());
    }

    // ── Clear ────────────────────────────────────────────────────────

    #[test]
    fn clear_removes_all_entries() {
        let mut tracker = IdempotencyTracker::with_defaults();
        tracker.check_and_insert(1, make_key(1), 10);
        tracker.check_and_insert(1, make_key(2), 10);
        tracker.check_and_insert(2, make_key(1), 10);
        assert_eq!(tracker.len(), 3);

        tracker.clear();
        assert!(tracker.is_empty());
        assert_eq!(
            tracker.check_and_insert(1, make_key(1), 10),
            ProposalOutcome::PassThrough
        );
    }

    // ── Record commit ────────────────────────────────────────────────

    #[test]
    fn record_commit_updates_epoch() {
        let mut tracker = IdempotencyTracker::with_defaults();
        let key = make_key(1);

        tracker.check_and_insert(1, key, 5);
        tracker.record_commit(1, key, 7);

        assert_eq!(
            tracker.check_and_insert(1, key, 10),
            ProposalOutcome::AlreadyCommitted { epoch: 7 }
        );
    }

    #[test]
    fn record_commit_for_untracked_key_adds_entry() {
        let mut tracker = IdempotencyTracker::with_defaults();
        let key = make_key(1);

        tracker.record_commit(1, key, 7);
        assert_eq!(
            tracker.check_and_insert(1, key, 10),
            ProposalOutcome::AlreadyCommitted { epoch: 7 }
        );
    }

    // ── ProposalIdempotencyKey ───────────────────────────────────────

    #[test]
    fn key_from_intent_is_deterministic() {
        let k1 = ProposalIdempotencyKey::from_intent(b"hello");
        let k2 = ProposalIdempotencyKey::from_intent(b"hello");
        assert_eq!(k1, k2);
    }

    #[test]
    fn key_from_intent_differs_by_input() {
        let k1 = ProposalIdempotencyKey::from_intent(b"hello");
        let k2 = ProposalIdempotencyKey::from_intent(b"world");
        assert_ne!(k1, k2);
    }

    #[test]
    fn key_as_bytes_roundtrips() {
        let key = ProposalIdempotencyKey::new([0x42; 32]);
        assert_eq!(key.as_bytes(), &[0x42u8; 32]);
    }

    #[test]
    fn key_display_is_readable() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xAB;
        bytes[1] = 0xCD;
        let key = ProposalIdempotencyKey::new(bytes);
        let s = format!("{key}");
        assert!(s.contains("abcd"));
    }

    // ── Config defaults ──────────────────────────────────────────────

    #[test]
    fn default_config_matches_spec() {
        let cfg = IdempotencyConfig::default();
        assert_eq!(cfg.retention_epochs, 8);
        assert_eq!(cfg.max_tracked_keys, 4096);
    }

    #[test]
    fn custom_config_persists() {
        let cfg = IdempotencyConfig::new(20, 1024);
        assert_eq!(cfg.retention_epochs, 20);
        assert_eq!(cfg.max_tracked_keys, 1024);
    }

    // ── ProposalOutcome equality ─────────────────────────────────────

    #[test]
    fn outcome_equality() {
        assert_eq!(
            ProposalOutcome::AlreadyCommitted { epoch: 5 },
            ProposalOutcome::AlreadyCommitted { epoch: 5 }
        );
        assert_ne!(
            ProposalOutcome::AlreadyCommitted { epoch: 5 },
            ProposalOutcome::AlreadyCommitted { epoch: 6 }
        );
        assert_ne!(
            ProposalOutcome::AlreadyCommitted { epoch: 5 },
            ProposalOutcome::PassThrough
        );
    }

    // ── Large-scale stress: many keys, LRU + pruning ─────────────────

    #[test]
    fn many_keys_lru_and_pruning_interaction() {
        let config = IdempotencyConfig {
            retention_epochs: 10,
            max_tracked_keys: 50,
        };
        let mut tracker = IdempotencyTracker::new(config);

        for i in 0..100u64 {
            tracker.check_and_insert(i % 3, make_key(i as u8), 0);
        }

        assert!(tracker.len() <= 50);

        tracker.check_and_insert(0, make_key(200), 20);
        assert_eq!(tracker.len(), 1);
    }

    // ── Max capacity boundary ────────────────────────────────────────

    #[test]
    fn capacity_of_one() {
        let config = IdempotencyConfig {
            retention_epochs: 100,
            max_tracked_keys: 1,
        };
        let mut tracker = IdempotencyTracker::new(config);

        tracker.check_and_insert(1, make_key(1), 10);
        assert_eq!(tracker.len(), 1);

        // key2 evicts key1
        tracker.check_and_insert(1, make_key(2), 10);
        assert_eq!(tracker.len(), 1);

        // key2 still present
        assert!(matches!(
            tracker.check_and_insert(1, make_key(2), 10),
            ProposalOutcome::AlreadyCommitted { .. }
        ));
        // key1 evicted, passes through
        assert_eq!(
            tracker.check_and_insert(1, make_key(1), 10),
            ProposalOutcome::PassThrough
        );
    }
}
