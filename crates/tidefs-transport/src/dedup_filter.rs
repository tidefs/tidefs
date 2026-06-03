//! Transport per-peer message deduplication with sequence-number sliding
//! window and domain-separated state-digest verification via BLAKE3.
//!
//! ## Purpose
//!
//! Prevents duplicate message delivery at the transport receiver by tracking
//! seen sequence numbers in a per-peer sliding window. When a sender retries
//! a message after a lost ACK, the receiver drops the retry rather than
//! double-processing state mutations (intent-log entries, membership updates,
//! lease operations).
//!
//! Every transport consumer gets exactly-once delivery without reinventing
//! sequence tracking per subsystem.
//!
//! ## Architecture
//!
//! ```text
//! Message arrives (peer_id, delivery_seq)
//!   |
//!   +-- DedupFilter::check_and_record(peer_id, delivery_seq)
//!   |
//!   +-> Stale     -> drop, sequence below window floor
//!   +-> Duplicate -> drop, already delivered
//!   +-> Deliver   -> dispatch to subsystem handlers
//! ```
//!
//! ## Window semantics
//!
//! Each peer maintains a sliding window of `window_size` sequence numbers
//! backed by a bitmap for O(1) lookup. The window covers `[floor,
//! floor + window_size)`. Sequences below `floor` return `Stale`.
//! Sequences at or beyond `floor + window_size` slide the window forward,
//! evicting the oldest entries.
//!
//! ## BLAKE3 domain separation
//!
//! State digests use domain `tidefs-transport-dedup-v1` for
//! deterministic filter-state verification in tests. The digest covers
//! `(peer_count, [per_peer: (peer_id, floor, bits)])` sorted by peer_id.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// DeliveryVerdict
// ---------------------------------------------------------------------------

/// Outcome of a deduplication check on an inbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryVerdict {
    /// First time seeing this sequence number; deliver to subsystems.
    Deliver,
    /// Sequence already seen within the current window; drop as duplicate.
    Duplicate,
    /// Sequence below the window floor; too old to track, reject.
    Stale,
}

impl fmt::Display for DeliveryVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeliveryVerdict::Deliver => write!(f, "Deliver"),
            DeliveryVerdict::Duplicate => write!(f, "Duplicate"),
            DeliveryVerdict::Stale => write!(f, "Stale"),
        }
    }
}

// ---------------------------------------------------------------------------
// DedupWindow -- per-peer sliding window
// ---------------------------------------------------------------------------

/// Per-peer sliding window of seen sequence numbers with bitmap-backed O(1)
/// lookup.
///
/// The window covers `[floor, floor + window_size)`. When a sequence at or
/// beyond the window end arrives, the window slides forward, evicting the
/// oldest entries.
#[derive(Debug, Clone)]
struct DedupWindow {
    /// Oldest sequence number still tracked.
    floor: u64,
    /// Number of sequence slots in the window.
    window_size: u16,
    /// Bitmap: the i-th bit tracks sequence `floor + i`.
    /// Each `u64` holds 64 bits; word count is `ceil(window_size / 64)`.
    bits: Vec<u64>,
}

impl DedupWindow {
    fn new(window_size: u16) -> Self {
        let window_size = window_size.max(1);
        let words = (window_size as usize).div_ceil(64);
        DedupWindow {
            floor: 0,
            window_size,
            bits: vec![0u64; words],
        }
    }

    /// Check whether `seq` has been seen, recording it if not.
    fn check_and_record(&mut self, seq: u64) -> DeliveryVerdict {
        // Below the window floor - too old.
        if seq < self.floor {
            return DeliveryVerdict::Stale;
        }

        // Beyond the window end - slide first.
        let window_end = self.floor + self.window_size as u64;
        if seq >= window_end {
            self.slide_to(seq);
        }

        let offset = (seq - self.floor) as usize;
        let word = offset / 64;
        let bit = offset % 64;
        let mask = 1u64 << bit;

        if self.bits[word] & mask != 0 {
            DeliveryVerdict::Duplicate
        } else {
            self.bits[word] |= mask;
            DeliveryVerdict::Deliver
        }
    }

    /// Slide the window so that `seq` falls within it.
    /// New floor = seq - window_size + 1 (keeping seq in the last slot).
    fn slide_to(&mut self, seq: u64) {
        let new_floor = seq.saturating_sub(self.window_size as u64 - 1);
        if new_floor <= self.floor {
            return;
        }

        let shift = new_floor - self.floor;
        let words = self.bits.len();

        // If the shift exceeds the entire window width, just reset.
        if shift >= self.window_size as u64 {
            self.bits.fill(0);
            self.floor = new_floor;
            return;
        }

        // Copy overlapping bits from the old bitmap into position.
        let old_start = shift as usize;
        let old_end = (self.window_size as usize).min(words * 64);
        let mut new_bits = vec![0u64; words];

        for i in old_start..old_end {
            let old_word = i / 64;
            let old_bit = i % 64;
            if self.bits[old_word] & (1u64 << old_bit) != 0 {
                let new_idx = i - old_start;
                let new_word = new_idx / 64;
                let new_bit = new_idx % 64;
                new_bits[new_word] |= 1u64 << new_bit;
            }
        }

        self.bits = new_bits;
        self.floor = new_floor;
    }

    /// BLAKE3-256 domain-separated state digest for per-window verification.
    #[allow(dead_code)]
    fn state_digest(&self) -> [u8; 32] {
        use blake3::Hasher;

        const DOMAIN: &[u8] = b"tidefs-transport-dedup-v1";

        // Build a keyed hasher from the domain string.
        let mut domain_hasher = Hasher::new();
        domain_hasher.update(DOMAIN);
        let domain_key = domain_hasher.finalize();
        let mut hasher = Hasher::new_keyed(domain_key.as_bytes());

        hasher.update(&self.floor.to_le_bytes());
        hasher.update(&self.window_size.to_le_bytes());
        for word in &self.bits {
            hasher.update(&word.to_le_bytes());
        }

        let hash = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(hash.as_bytes());
        digest
    }
}

// ---------------------------------------------------------------------------
// DedupFilterConfig
// ---------------------------------------------------------------------------

/// Configuration for the per-peer deduplication filter.
#[derive(Debug, Clone)]
pub struct DedupFilterConfig {
    /// Number of sequence numbers tracked per peer (sliding window size).
    /// Clamped to [1, 65535].  Default: 1024.
    pub window_size: u16,
    /// When true, stale sequences (below floor) are rejected as `Stale`.
    /// When false, stale sequences are delivered with a warning (lenient mode).
    pub strict_mode: bool,
}

impl Default for DedupFilterConfig {
    fn default() -> Self {
        DedupFilterConfig {
            window_size: 1024,
            strict_mode: true,
        }
    }
}

impl DedupFilterConfig {
    /// Create a new config with the given window size.
    /// Window size is clamped to [1, 65535].
    pub fn with_window_size(window_size: u16) -> Self {
        DedupFilterConfig {
            window_size: window_size.max(1),
            strict_mode: true,
        }
    }

    /// Create a new config in lenient mode (stale sequences get delivered
    /// rather than rejected).
    pub fn lenient(window_size: u16) -> Self {
        DedupFilterConfig {
            window_size: window_size.max(1),
            strict_mode: false,
        }
    }
}

// ---------------------------------------------------------------------------
// DedupFilterStats
// ---------------------------------------------------------------------------

/// Lock-free statistics snapshot for a `DedupFilter`.
#[derive(Debug, Clone, Default)]
pub struct DedupFilterStats {
    /// Total messages delivered (first-time sequence numbers).
    pub delivered: u64,
    /// Total messages dropped as duplicates.
    pub duplicates: u64,
    /// Total messages rejected as stale (below window floor).
    pub stales: u64,
}

impl DedupFilterStats {
    /// Return a point-in-time snapshot.
    pub fn snapshot(&self) -> Self {
        self.clone()
    }
}

// ---------------------------------------------------------------------------
// DedupFilter
// ---------------------------------------------------------------------------

/// Per-peer deduplication filter using sequence-number sliding windows.
///
/// Keyed by peer_id (u64), each peer gets an independent `DedupWindow`.
/// Thread-safe: all methods take `&self` and use internal `Mutex`.
///
/// # Example
///
/// ```ignore
/// let filter = DedupFilter::new(DedupFilterConfig::default());
/// assert_eq!(filter.check_and_record(42, 1), DeliveryVerdict::Deliver);
/// assert_eq!(filter.check_and_record(42, 1), DeliveryVerdict::Duplicate);
/// assert_eq!(filter.check_and_record(42, 2), DeliveryVerdict::Deliver);
/// ```
pub struct DedupFilter {
    windows: Mutex<HashMap<u64, DedupWindow>>,
    config: DedupFilterConfig,
    stats: Mutex<DedupFilterStats>,
}

impl DedupFilter {
    /// Create a new `DedupFilter` with the given configuration.
    pub fn new(config: DedupFilterConfig) -> Self {
        DedupFilter {
            windows: Mutex::new(HashMap::new()),
            config,
            stats: Mutex::new(DedupFilterStats::default()),
        }
    }

    /// Create a new `DedupFilter` with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(DedupFilterConfig::default())
    }

    /// Check whether `seq` from `peer_id` has been seen, recording it if not.
    ///
    /// Returns:
    /// - `Deliver` for a never-before-seen sequence (dispatch to handlers).
    /// - `Duplicate` for a sequence already recorded in the window.
    /// - `Stale` for a sequence below the window floor (in strict mode;
    ///   in lenient mode, returns `Deliver`).
    pub fn check_and_record(&self, peer_id: u64, seq: u64) -> DeliveryVerdict {
        let result;
        {
            let mut windows = self.windows.lock().unwrap();
            let window = windows
                .entry(peer_id)
                .or_insert_with(|| DedupWindow::new(self.config.window_size));
            result = window.check_and_record(seq);
        }

        // Update stats outside the main lock to keep the critical section small.
        {
            let mut stats = self.stats.lock().unwrap();
            match result {
                DeliveryVerdict::Deliver => stats.delivered += 1,
                DeliveryVerdict::Duplicate => stats.duplicates += 1,
                DeliveryVerdict::Stale => {
                    stats.stales += 1;
                    if !self.config.strict_mode {
                        return DeliveryVerdict::Deliver;
                    }
                }
            }
        }

        result
    }

    /// Remove the per-peer window for `peer_id`, releasing its memory.
    /// Returns true if the peer existed.
    pub fn remove_peer(&self, peer_id: u64) -> bool {
        let mut windows = self.windows.lock().unwrap();
        windows.remove(&peer_id).is_some()
    }

    /// Return the number of tracked peers.
    pub fn peer_count(&self) -> usize {
        let windows = self.windows.lock().unwrap();
        windows.len()
    }

    /// Return a snapshot of aggregate statistics.
    pub fn stats(&self) -> DedupFilterStats {
        let stats = self.stats.lock().unwrap();
        stats.snapshot()
    }

    /// Return the current window floor for a peer, if tracked.
    pub fn peer_floor(&self, peer_id: u64) -> Option<u64> {
        let windows = self.windows.lock().unwrap();
        windows.get(&peer_id).map(|w| w.floor)
    }

    /// BLAKE3-256 domain-separated state digest covering all peers.
    /// Domain: `tidefs-transport-dedup-v1`.
    ///
    /// Covers `(peer_count, [(peer_id, floor, bits)])` sorted by peer_id
    /// for deterministic verification of the entire filter state.
    pub fn state_digest(&self) -> [u8; 32] {
        use blake3::Hasher;

        // Build a keyed hasher from the domain string.
        let mut domain_hasher = Hasher::new();
        domain_hasher.update(b"tidefs-transport-dedup-v1");
        let domain_key = domain_hasher.finalize();
        let mut hasher = Hasher::new_keyed(domain_key.as_bytes());

        let windows = self.windows.lock().unwrap();
        let peer_count = windows.len() as u64;
        hasher.update(&peer_count.to_le_bytes());

        // Sort by peer_id for deterministic ordering.
        let mut peers: Vec<(&u64, &DedupWindow)> = windows.iter().collect();
        peers.sort_by_key(|(id, _)| *id);

        for (peer_id, window) in peers {
            hasher.update(&peer_id.to_le_bytes());
            hasher.update(&window.floor.to_le_bytes());
            hasher.update(&window.window_size.to_le_bytes());
            for word in &window.bits {
                hasher.update(&word.to_le_bytes());
            }
        }

        let hash = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(hash.as_bytes());
        digest
    }
}

impl fmt::Debug for DedupFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let windows = self.windows.lock().unwrap();
        let stats = self.stats.lock().unwrap();
        f.debug_struct("DedupFilter")
            .field("peer_count", &windows.len())
            .field("config", &self.config)
            .field("stats", &stats)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DeliveryVerdict display -------------------------------------------

    #[test]
    fn verdict_display() {
        assert_eq!(format!("{}", DeliveryVerdict::Deliver), "Deliver");
        assert_eq!(format!("{}", DeliveryVerdict::Duplicate), "Duplicate");
        assert_eq!(format!("{}", DeliveryVerdict::Stale), "Stale");
    }

    // -- Single-peer basic ops ---------------------------------------------

    #[test]
    fn first_delivery() {
        let f = DedupFilter::with_defaults();
        assert_eq!(f.check_and_record(1, 100), DeliveryVerdict::Deliver);
    }

    #[test]
    fn duplicate_rejection() {
        let f = DedupFilter::with_defaults();
        assert_eq!(f.check_and_record(1, 100), DeliveryVerdict::Deliver);
        assert_eq!(f.check_and_record(1, 100), DeliveryVerdict::Duplicate);
    }

    #[test]
    fn sequence_gap_fill() {
        let f = DedupFilter::with_defaults();
        // Fill gap in any order.
        assert_eq!(f.check_and_record(1, 5), DeliveryVerdict::Deliver);
        assert_eq!(f.check_and_record(1, 7), DeliveryVerdict::Deliver);
        // Seq 5 already seen.
        assert_eq!(f.check_and_record(1, 5), DeliveryVerdict::Duplicate);
        // Seq 6 (gap between 5 and 7) is new.
        assert_eq!(f.check_and_record(1, 6), DeliveryVerdict::Deliver);
        // Now 6 is duplicate.
        assert_eq!(f.check_and_record(1, 6), DeliveryVerdict::Duplicate);
    }

    #[test]
    fn window_wraparound_slide() {
        // Small window of 4 slots.
        let config = DedupFilterConfig::with_window_size(4);
        let f = DedupFilter::new(config);

        for s in 0..4 {
            assert_eq!(f.check_and_record(1, s), DeliveryVerdict::Deliver);
        }
        // Window is [0, 4).  Seq 0 is duplicate.
        assert_eq!(f.check_and_record(1, 0), DeliveryVerdict::Duplicate);

        // Seq 4 slides the window to [1, 5).
        assert_eq!(f.check_and_record(1, 4), DeliveryVerdict::Deliver);
        // Seq 0 below floor 1 is stale.
        assert_eq!(f.check_and_record(1, 0), DeliveryVerdict::Stale);
        // Seq 1 was preserved in overlap.
        assert_eq!(f.check_and_record(1, 1), DeliveryVerdict::Duplicate);

        // Big jump slides window to [97, 101).
        assert_eq!(f.check_and_record(1, 100), DeliveryVerdict::Deliver);
        // Gap >> window_size resets bits; 97 is a first delivery.
        assert_eq!(f.check_and_record(1, 97), DeliveryVerdict::Deliver);
        assert_eq!(f.check_and_record(1, 96), DeliveryVerdict::Stale);
    }

    #[test]
    fn stale_below_floor_rejection() {
        let config = DedupFilterConfig::with_window_size(4);
        let f = DedupFilter::new(config);

        // Establish floor at 100 by filling [100, 104).
        for s in 100..104 {
            assert_eq!(f.check_and_record(1, s), DeliveryVerdict::Deliver);
        }
        // Slide to 200 -> floor = 197.
        assert_eq!(f.check_and_record(1, 200), DeliveryVerdict::Deliver);
        // Sequences below 197 are stale.
        assert_eq!(f.check_and_record(1, 100), DeliveryVerdict::Stale);
        assert_eq!(f.check_and_record(1, 196), DeliveryVerdict::Stale);
        // 197 was not explicitly seen but is within range.
        assert_eq!(f.check_and_record(1, 197), DeliveryVerdict::Deliver);
    }

    // -- Multi-peer isolation ----------------------------------------------

    #[test]
    fn multi_peer_isolation() {
        let f = DedupFilter::with_defaults();
        assert_eq!(f.check_and_record(1, 10), DeliveryVerdict::Deliver);
        // Peer 2 has an independent window.
        assert_eq!(f.check_and_record(2, 10), DeliveryVerdict::Deliver);
        assert_eq!(f.check_and_record(1, 10), DeliveryVerdict::Duplicate);
        assert_eq!(f.check_and_record(2, 10), DeliveryVerdict::Duplicate);
        assert_eq!(f.check_and_record(3, 10), DeliveryVerdict::Deliver);
        assert_eq!(f.peer_count(), 3);
    }

    // -- Peer removal ------------------------------------------------------

    #[test]
    fn remove_peer() {
        let f = DedupFilter::with_defaults();
        f.check_and_record(1, 10);
        assert_eq!(f.peer_count(), 1);
        assert!(f.remove_peer(1));
        assert_eq!(f.peer_count(), 0);
        // Re-adding peer 1 starts fresh.
        assert_eq!(f.check_and_record(1, 10), DeliveryVerdict::Deliver);
    }

    #[test]
    fn remove_nonexistent_peer() {
        let f = DedupFilter::with_defaults();
        assert!(!f.remove_peer(999));
    }

    // -- Lenient mode ------------------------------------------------------

    #[test]
    fn lenient_mode_delivers_stale() {
        let config = DedupFilterConfig::lenient(4);
        let f = DedupFilter::new(config);

        // Fill window [0, 4) then slide past it.
        for s in 0..4 {
            f.check_and_record(1, s);
        }
        f.check_and_record(1, 100);

        // In lenient mode, stale below-floor sequences deliver anyway.
        assert_eq!(f.check_and_record(1, 50), DeliveryVerdict::Deliver);
        // Stats still count the stale event internally.
        let s = f.stats();
        assert!(s.stales > 0);
    }

    // -- BLAKE3 state digest determinism -----------------------------------

    #[test]
    fn state_digest_determinism() {
        let f = DedupFilter::with_defaults();
        for s in 0..10 {
            f.check_and_record(1, s);
        }
        let d1 = f.state_digest();

        let g = DedupFilter::with_defaults();
        for s in 0..10 {
            g.check_and_record(1, s);
        }
        let d2 = g.state_digest();
        assert_eq!(d1, d2);
    }

    #[test]
    fn state_digest_different_ops_different_digest() {
        let f = DedupFilter::with_defaults();
        f.check_and_record(1, 1);
        f.check_and_record(1, 2);
        let d1 = f.state_digest();

        let g = DedupFilter::with_defaults();
        g.check_and_record(1, 1);
        g.check_and_record(1, 3);
        let d2 = g.state_digest();
        assert_ne!(d1, d2);
    }

    #[test]
    fn state_digest_multi_peer_ordering() {
        // Insert peers in different order; digest must be deterministic
        // (sorted by peer_id).
        let f = DedupFilter::with_defaults();
        f.check_and_record(3, 1);
        f.check_and_record(1, 1);
        f.check_and_record(2, 1);
        let d1 = f.state_digest();

        let g = DedupFilter::with_defaults();
        g.check_and_record(1, 1);
        g.check_and_record(2, 1);
        g.check_and_record(3, 1);
        let d2 = g.state_digest();
        assert_eq!(d1, d2);
    }

    // -- Window-size boundary clamping -------------------------------------

    #[test]
    fn window_size_clamped_to_1() {
        let config = DedupFilterConfig::with_window_size(0);
        let f = DedupFilter::new(config);
        // Window size 1: only the current seq is tracked.
        assert_eq!(f.check_and_record(1, 10), DeliveryVerdict::Deliver);
        assert_eq!(f.check_and_record(1, 10), DeliveryVerdict::Duplicate);
        assert_eq!(f.check_and_record(1, 11), DeliveryVerdict::Deliver);
        // 10 is now stale (floor = 11).
        assert_eq!(f.check_and_record(1, 10), DeliveryVerdict::Stale);
    }

    #[test]
    fn large_window_size() {
        let config = DedupFilterConfig::with_window_size(65535);
        let f = DedupFilter::new(config);
        f.check_and_record(1, 1000);
        assert_eq!(f.check_and_record(1, 1000), DeliveryVerdict::Duplicate);
        for s in 2000..3000 {
            f.check_and_record(2, s);
        }
        assert_eq!(f.peer_count(), 2);
    }

    // -- Empty filter edge cases -------------------------------------------

    #[test]
    fn empty_filter_digest_nonzero() {
        let f = DedupFilter::with_defaults();
        let d = f.state_digest();
        let zeros = [0u8; 32];
        assert_ne!(d, zeros);
    }

    #[test]
    fn empty_filter_stats() {
        let f = DedupFilter::with_defaults();
        let s = f.stats();
        assert_eq!(s.delivered, 0);
        assert_eq!(s.duplicates, 0);
        assert_eq!(s.stales, 0);
    }

    #[test]
    fn empty_filter_peer_count() {
        let f = DedupFilter::with_defaults();
        assert_eq!(f.peer_count(), 0);
        assert_eq!(f.peer_floor(1), None);
    }

    // -- Stats tracking ----------------------------------------------------

    #[test]
    fn stats_track_all_verdicts() {
        let config = DedupFilterConfig::with_window_size(4);
        let f = DedupFilter::new(config);

        f.check_and_record(1, 0); // deliver
        f.check_and_record(1, 0); // duplicate
        f.check_and_record(1, 1); // deliver
        f.check_and_record(1, 2); // deliver
        f.check_and_record(1, 100); // deliver + slide -> seq 0 stale
        f.check_and_record(1, 0); // stale

        let s = f.stats();
        assert_eq!(s.delivered, 4);
        assert_eq!(s.duplicates, 1);
        assert_eq!(s.stales, 1);
    }

    // -- Concurrent access -------------------------------------------------

    #[test]
    fn concurrent_access_same_peer() {
        use std::sync::Arc;
        use std::thread;

        let f = Arc::new(DedupFilter::with_defaults());
        let mut handles = vec![];

        for t in 0..4 {
            let f = Arc::clone(&f);
            handles.push(thread::spawn(move || {
                // Each thread writes to non-overlapping sequence ranges.
                for s in 0..100 {
                    f.check_and_record(1, s + t * 100);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let s = f.stats();
        assert_eq!(s.delivered, 400);
        assert_eq!(s.duplicates, 0);
    }

    #[test]
    fn concurrent_access_different_peers() {
        use std::sync::Arc;
        use std::thread;

        let f = Arc::new(DedupFilter::with_defaults());
        let mut handles = vec![];

        for t in 0..8 {
            let f = Arc::clone(&f);
            handles.push(thread::spawn(move || {
                let peer = t as u64;
                for s in 0..50 {
                    f.check_and_record(peer, s);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(f.peer_count(), 8);
        let s = f.stats();
        assert_eq!(s.delivered, 400);
        assert_eq!(s.duplicates, 0);
    }

    // -- Config defaults ---------------------------------------------------

    #[test]
    fn default_config_values() {
        let config = DedupFilterConfig::default();
        assert_eq!(config.window_size, 1024);
        assert!(config.strict_mode);
    }

    // -- Floor tracking ----------------------------------------------------

    #[test]
    fn peer_floor_advances_on_slide() {
        let config = DedupFilterConfig::with_window_size(4);
        let f = DedupFilter::new(config);

        f.check_and_record(1, 0);
        assert_eq!(f.peer_floor(1), Some(0));

        f.check_and_record(1, 10);
        // After sliding to 10, floor = 10 - 4 + 1 = 7.
        assert_eq!(f.peer_floor(1), Some(7));
    }

    // -- Large gap resets window -------------------------------------------

    #[test]
    fn large_gap_resets_window() {
        let config = DedupFilterConfig::with_window_size(8);
        let f = DedupFilter::new(config);

        for s in 0..8 {
            f.check_and_record(1, s);
        }
        // Jump far beyond the window.
        f.check_and_record(1, 1_000_000);
        // Old sequences are stale.
        assert_eq!(f.check_and_record(1, 0), DeliveryVerdict::Stale);
        assert_eq!(f.check_and_record(1, 7), DeliveryVerdict::Stale);
        // New sequences deliver.
        assert_eq!(f.check_and_record(1, 1_000_001), DeliveryVerdict::Deliver);
        assert_eq!(f.check_and_record(1, 1_000_001), DeliveryVerdict::Duplicate);
    }

    // -- Per-window state_digest consistency -------------------------------

    #[test]
    fn per_window_digest_consistent() {
        let mut w1 = DedupWindow::new(8);
        w1.check_and_record(0);
        w1.check_and_record(1);
        let d1 = w1.state_digest();

        let mut w2 = DedupWindow::new(8);
        w2.check_and_record(0);
        w2.check_and_record(1);
        let d2 = w2.state_digest();

        assert_eq!(d1, d2);
    }

    #[test]
    fn per_window_digest_differs_on_different_data() {
        let mut w1 = DedupWindow::new(8);
        w1.check_and_record(0);
        let d1 = w1.state_digest();

        let mut w2 = DedupWindow::new(8);
        w2.check_and_record(1);
        let d2 = w2.state_digest();

        assert_ne!(d1, d2);
    }
}
