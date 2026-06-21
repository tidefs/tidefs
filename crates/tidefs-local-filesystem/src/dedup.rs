// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeMap;

use tidefs_dedup::DedupHash;
use tidefs_local_object_store::ObjectKey;

use crate::types::ContentFingerprint;

/// Deduplication statistics accumulated during a filesystem session.
///
/// Reset on mount; not persisted across sessions.
///
/// # Canonical object lifetime (#6167)
///
/// The durable `DedupRefCount` authority (crate::dedup_refcount) owns
/// canonical dedup object lifetime. Each canonical chunk object has a
/// sibling refcount object that tracks the number of live per-inode chunk
/// redirects pointing to it. When the refcount reaches zero, the canonical
/// object is reclaimed through the standard reclaim queue drain.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DedupStats {
    /// Number of chunk writes that were avoided because a duplicate chunk
    /// (same content fingerprint) already existed in the canonical store.
    pub dedup_hits: u64,
    /// Cumulative bytes saved by dedup redirects (chunk_size × dedup_hits).
    pub dedup_bytes_saved: u64,
    /// Total number of chunks written (including redirects and inline writes).
    pub total_chunks: u64,
}

impl DedupStats {
    /// Dedup ratio: total_chunks / (total_chunks - dedup_hits), or 0.0 if
    /// no chunks have been written.
    pub fn dedup_ratio(&self) -> f64 {
        let unique = self.total_chunks.saturating_sub(self.dedup_hits);
        if unique == 0 {
            0.0
        } else {
            self.total_chunks as f64 / unique as f64
        }
    }
}

/// In-memory deduplication index mapping content fingerprints to canonical
/// object keys.
///
/// Session-local lookup cache. The durable refcount authority
/// (`DedupRefCount`) owns canonical object lifetime across
/// sessions; this index accelerates same-session dedup hits only.
#[derive(Clone, Debug, Default)]
pub struct DedupIndex {
    map: BTreeMap<DedupHash, (ObjectKey, u64)>,
    stats: DedupStats,
}

impl DedupIndex {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            stats: DedupStats::default(),
        }
    }

    pub fn lookup_hash(&self, hash: &DedupHash) -> Option<ObjectKey> {
        self.map.get(hash).map(|(key, _)| *key)
    }

    pub fn insert(&mut self, fingerprint: ContentFingerprint, canonical_key: ObjectKey) {
        let hash = fingerprint.as_dedup_hash();
        self.map
            .entry(hash)
            .and_modify(|(_key, count)| *count += 1)
            .or_insert((canonical_key, 1));
    }

    /// Decrement the reference count for a fingerprint.
    /// Removes the entry when the count reaches zero.
    pub fn remove(&mut self, fingerprint: &ContentFingerprint) {
        use std::collections::btree_map::Entry;
        if let Entry::Occupied(mut entry) = self.map.entry(fingerprint.as_dedup_hash()) {
            let (_key, count) = entry.get_mut();
            *count = count.saturating_sub(1);
            if *count == 0 {
                entry.remove();
            }
        }
    }

    pub fn record_dedup_hit(&mut self, bytes: u64) {
        self.stats.dedup_hits += 1;
        self.stats.dedup_bytes_saved += bytes;
    }

    pub fn record_chunk_written(&mut self) {
        self.stats.total_chunks += 1;
    }

    pub fn stats(&self) -> DedupStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(bytes: [u8; 32]) -> ContentFingerprint {
        ContentFingerprint::from_bytes32(bytes)
    }

    fn object_key(_bytes: [u8; 32]) -> ObjectKey {
        ObjectKey::default()
    }

    #[test]
    fn dedup_stats_defaults_to_zero() {
        let stats = DedupStats::default();
        assert_eq!(stats.dedup_hits, 0);
        assert_eq!(stats.dedup_bytes_saved, 0);
        assert_eq!(stats.total_chunks, 0);
    }

    #[test]
    fn dedup_ratio_zero_when_no_chunks() {
        let stats = DedupStats {
            total_chunks: 0,
            ..Default::default()
        };
        assert!((stats.dedup_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn dedup_ratio_one_when_no_hits() {
        let stats = DedupStats {
            total_chunks: 100,
            dedup_hits: 0,
            ..Default::default()
        };
        assert!((stats.dedup_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn dedup_ratio_two_when_half_hits() {
        let stats = DedupStats {
            total_chunks: 100,
            dedup_hits: 50,
            ..Default::default()
        };
        assert!((stats.dedup_ratio() - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn dedup_ratio_handles_hits_eq_chunks() {
        let stats = DedupStats {
            total_chunks: 100,
            dedup_hits: 100,
            ..Default::default()
        };
        let r = stats.dedup_ratio();
        assert!(r == 0.0 || r.is_infinite());
    }

    #[test]
    fn record_dedup_hit_increments_stats() {
        let mut idx = DedupIndex::new();
        idx.record_dedup_hit(4096);
        assert_eq!(idx.stats().dedup_hits, 1);
        assert_eq!(idx.stats().dedup_bytes_saved, 4096);
    }

    #[test]
    fn record_chunk_written_increments_total() {
        let mut idx = DedupIndex::new();
        idx.record_chunk_written();
        idx.record_chunk_written();
        assert_eq!(idx.stats().total_chunks, 2);
    }

    #[test]
    fn stats_reflects_combined_operations() {
        let mut idx = DedupIndex::new();
        for _ in 0..5 {
            idx.record_chunk_written();
        }
        idx.record_dedup_hit(4096);
        idx.record_dedup_hit(4096);
        let s = idx.stats();
        assert_eq!(s.total_chunks, 5);
        assert_eq!(s.dedup_hits, 2);
        assert_eq!(s.dedup_bytes_saved, 8192);
        assert!((s.dedup_ratio() - 5.0 / 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn lookup_returns_none_for_missing_fingerprint() {
        let idx = DedupIndex::new();
        let fp = fingerprint([1u8; 32]);
        assert!(idx.lookup_hash(&fp.as_dedup_hash()).is_none());
    }

    #[test]
    fn insert_and_lookup_roundtrip() {
        let mut idx = DedupIndex::new();
        let fp = fingerprint([1u8; 32]);
        let key = object_key([2u8; 32]);
        idx.insert(fp, key);
        assert_eq!(idx.lookup_hash(&fp.as_dedup_hash()), Some(key));
    }

    #[test]
    fn lookup_hash_uses_dedup_crate_identity() {
        let mut idx = DedupIndex::new();
        let hash = tidefs_dedup::DedupHash::compute_domain_separated(b"tidefs-test", b"payload");
        let fp = ContentFingerprint::from_dedup_hash(hash);
        let key = object_key([2u8; 32]);

        idx.insert(fp, key);

        assert_eq!(idx.lookup_hash(&hash), Some(key));
    }

    #[test]
    fn remove_decrements_and_removes_at_zero() {
        let mut idx = DedupIndex::new();
        let fp = fingerprint([1u8; 32]);
        idx.insert(fp, object_key([2u8; 32]));
        assert!(idx.lookup_hash(&fp.as_dedup_hash()).is_some());
        idx.remove(&fp);
        assert!(idx.lookup_hash(&fp.as_dedup_hash()).is_none());
    }

    #[test]
    fn remove_stays_after_multiple_inserts() {
        let mut idx = DedupIndex::new();
        let fp = fingerprint([1u8; 32]);
        idx.insert(fp, object_key([2u8; 32]));
        idx.insert(fp, object_key([3u8; 32]));
        idx.remove(&fp);
        assert!(idx.lookup_hash(&fp.as_dedup_hash()).is_some());
        idx.remove(&fp);
        assert!(idx.lookup_hash(&fp.as_dedup_hash()).is_none());
    }

    #[test]
    fn stats_independent_of_insert_remove() {
        let mut idx = DedupIndex::new();
        idx.insert(fingerprint([1u8; 32]), object_key([2u8; 32]));
        idx.remove(&fingerprint([1u8; 32]));
        let s = idx.stats();
        assert_eq!(s.dedup_hits, 0);
        assert_eq!(s.total_chunks, 0);
    }
}
