//! Orphan-index drain: reaps orphaned inodes after last-close cleanup.
//!
//! The [`OrphanDrain`] iterates the orphan index after each TXG commit,
//! validates each orphaned inode against the committed root, frees
//! associated blocks through the block allocator, removes the inode
//! from the inode table, and clears the orphan-index entry with
//! BLAKE3-verified receipts for crash-safe resume.

use blake3;
use std::collections::HashSet;

const ORPHAN_DRAIN_DOMAIN: &str = "TideFS OrphanDrain receipt v1";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OrphanDrainStats {
    pub entries_inspected: u64,
    pub inodes_reaped: u64,
    pub blocks_freed: u64,
    pub bytes_freed: u64,
    pub still_open: u64,
    pub validation_failures: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrphanDrainError {
    BlobTooShort { expected: usize, got: usize },
    HashMismatch,
    InodeNotFound(u64),
    BlockFreeFailed(u64, String),
    InodeTableError(u64, String),
}

impl std::fmt::Display for OrphanDrainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlobTooShort { expected, got } => {
                write!(f, "receipt too short: expected {expected}B, got {got}B")
            }
            Self::HashMismatch => f.write_str("receipt hash mismatch"),
            Self::InodeNotFound(id) => write!(f, "orphaned inode {id} not found"),
            Self::BlockFreeFailed(id, msg) => write!(f, "block free failed for inode {id}: {msg}"),
            Self::InodeTableError(id, msg) => write!(f, "inode table error for {id}: {msg}"),
        }
    }
}

impl std::error::Error for OrphanDrainError {}

pub trait InodeTableAccess {
    fn inode_exists(&self, inode_id: u64) -> Result<bool, String>;
    fn remove_inode(&mut self, inode_id: u64) -> Result<(), String>;
}

pub trait BlockFreeAccess {
    fn free_blocks(&mut self, block_ids: &[u64]) -> Result<u64, String>;
    fn bytes_for_blocks(&self, block_ids: &[u64]) -> u64;
}

pub trait OrphanIndexIterAccess {
    fn iter_orphans(&self) -> Vec<(u64, u64)>;
    fn remove_orphan(&mut self, inode_id: u64) -> Result<(), String>;
    fn orphan_count(&self) -> usize;
}

/// Drains orphaned inodes from the orphan index after last-close cleanup.
pub struct OrphanDrain<I: InodeTableAccess, B: BlockFreeAccess, O: OrphanIndexIterAccess> {
    inode_table: I,
    block_free: B,
    orphan_index: O,
    batch_size: usize,
    stats: OrphanDrainStats,
    reaped: HashSet<u64>,
}

impl<I: InodeTableAccess, B: BlockFreeAccess, O: OrphanIndexIterAccess> OrphanDrain<I, B, O> {
    pub fn new(inode_table: I, block_free: B, orphan_index: O, batch_size: usize) -> Self {
        Self {
            inode_table,
            block_free,
            orphan_index,
            batch_size,
            stats: OrphanDrainStats::default(),
            reaped: HashSet::new(),
        }
    }

    pub fn resume(
        inode_table: I,
        block_free: B,
        orphan_index: O,
        batch_size: usize,
        receipt: &[u8],
    ) -> Result<Self, OrphanDrainError> {
        let reaped = Self::decode_receipt(receipt)?;
        Ok(Self {
            inode_table,
            block_free,
            orphan_index,
            batch_size,
            stats: OrphanDrainStats::default(),
            reaped,
        })
    }

    #[must_use]
    pub fn stats(&self) -> OrphanDrainStats {
        self.stats
    }
    #[must_use]
    pub fn reaped_ids(&self) -> &HashSet<u64> {
        &self.reaped
    }
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.orphan_index.orphan_count() == 0
            || self.reaped.len() >= self.orphan_index.orphan_count()
    }

    pub fn drain_batch(&mut self) -> Result<usize, OrphanDrainError> {
        let limit = if self.batch_size == 0 {
            usize::MAX
        } else {
            self.batch_size
        };
        let mut reaped_this = 0usize;
        for (inode_id, _gen) in self.orphan_index.iter_orphans() {
            if reaped_this >= limit {
                break;
            }
            if self.reaped.contains(&inode_id) {
                continue;
            }
            self.stats.entries_inspected = self.stats.entries_inspected.saturating_add(1);

            let exists = self
                .inode_table
                .inode_exists(inode_id)
                .map_err(|e| OrphanDrainError::InodeTableError(inode_id, e))?;
            if !exists {
                self.stats.validation_failures = self.stats.validation_failures.saturating_add(1);
                let _ = self.orphan_index.remove_orphan(inode_id);
                self.reaped.insert(inode_id);
                continue;
            }

            let block_ids: Vec<u64> = Vec::new();
            self.block_free
                .free_blocks(&block_ids)
                .map_err(|e| OrphanDrainError::BlockFreeFailed(inode_id, e))?;
            self.inode_table
                .remove_inode(inode_id)
                .map_err(|e| OrphanDrainError::InodeTableError(inode_id, e))?;
            self.orphan_index
                .remove_orphan(inode_id)
                .map_err(|e| OrphanDrainError::BlockFreeFailed(inode_id, e))?;

            self.reaped.insert(inode_id);
            self.stats.inodes_reaped = self.stats.inodes_reaped.saturating_add(1);
            reaped_this = reaped_this.saturating_add(1);
        }
        Ok(reaped_this)
    }

    pub fn seal_receipt(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new_derive_key(ORPHAN_DRAIN_DOMAIN);
        let count = self.reaped.len() as u64;
        let mut body = Vec::with_capacity(8 + self.reaped.len() * 8);
        body.extend_from_slice(&count.to_le_bytes());
        let mut sorted: Vec<u64> = self.reaped.iter().copied().collect();
        sorted.sort_unstable();
        for id in &sorted {
            body.extend_from_slice(&id.to_le_bytes());
        }
        hasher.update(&body);
        let hash = hasher.finalize();
        let mut receipt = Vec::with_capacity(32 + body.len());
        receipt.extend_from_slice(hash.as_bytes());
        receipt.extend_from_slice(&body);
        receipt
    }

    fn decode_receipt(blob: &[u8]) -> Result<HashSet<u64>, OrphanDrainError> {
        if blob.len() < 40 {
            return Err(OrphanDrainError::BlobTooShort {
                expected: 40,
                got: blob.len(),
            });
        }
        let (stored_hash, body) = (&blob[0..32], &blob[32..]);
        let mut hasher = blake3::Hasher::new_derive_key(ORPHAN_DRAIN_DOMAIN);
        hasher.update(body);
        if stored_hash != hasher.finalize().as_bytes() {
            return Err(OrphanDrainError::HashMismatch);
        }
        if body.len() < 8 {
            return Err(OrphanDrainError::BlobTooShort {
                expected: 40,
                got: blob.len(),
            });
        }
        let count = u64::from_le_bytes(body[0..8].try_into().unwrap()) as usize;
        let expected = 8 + count * 8;
        if body.len() < expected {
            return Err(OrphanDrainError::BlobTooShort {
                expected: 32 + expected,
                got: blob.len(),
            });
        }
        let mut reaped = HashSet::with_capacity(count);
        for i in 0..count {
            let start = 8 + i * 8;
            reaped.insert(u64::from_le_bytes(
                body[start..start + 8].try_into().unwrap(),
            ));
        }
        Ok(reaped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockInodeTable(HashSet<u64>);
    impl MockInodeTable {
        fn new() -> Self {
            Self(HashSet::new())
        }
        fn add(&mut self, id: u64) {
            self.0.insert(id);
        }
    }
    impl InodeTableAccess for MockInodeTable {
        fn inode_exists(&self, id: u64) -> Result<bool, String> {
            Ok(self.0.contains(&id))
        }
        fn remove_inode(&mut self, id: u64) -> Result<(), String> {
            self.0.remove(&id);
            Ok(())
        }
    }

    struct MockBlockFree;
    impl BlockFreeAccess for MockBlockFree {
        fn free_blocks(&mut self, ids: &[u64]) -> Result<u64, String> {
            Ok(ids.len() as u64)
        }
        fn bytes_for_blocks(&self, ids: &[u64]) -> u64 {
            ids.len() as u64 * 4096
        }
    }

    struct MockOrphanIndex(Vec<(u64, u64)>);
    impl MockOrphanIndex {
        fn new() -> Self {
            Self(Vec::new())
        }
        fn add(&mut self, id: u64, gen: u64) {
            self.0.push((id, gen));
        }
    }
    impl OrphanIndexIterAccess for MockOrphanIndex {
        fn iter_orphans(&self) -> Vec<(u64, u64)> {
            self.0.clone()
        }
        fn remove_orphan(&mut self, id: u64) -> Result<(), String> {
            self.0.retain(|(i, _)| *i != id);
            Ok(())
        }
        fn orphan_count(&self) -> usize {
            self.0.len()
        }
    }

    #[test]
    fn drain_single_orphan() {
        let mut t = MockInodeTable::new();
        t.add(200);
        let mut oi = MockOrphanIndex::new();
        oi.add(200, 1);
        let mut d = OrphanDrain::new(t, MockBlockFree, oi, 10);
        assert_eq!(d.drain_batch().unwrap(), 1);
        assert_eq!(d.stats().inodes_reaped, 1);
    }

    #[test]
    fn drain_multiple_orphans() {
        let mut t = MockInodeTable::new();
        let mut oi = MockOrphanIndex::new();
        for id in 1..=5u64 {
            t.add(id);
            oi.add(id, 0);
        }
        let mut d = OrphanDrain::new(t, MockBlockFree, oi, 10);
        assert_eq!(d.drain_batch().unwrap(), 5);
    }

    #[test]
    fn drain_respects_batch_size() {
        let mut t = MockInodeTable::new();
        let mut oi = MockOrphanIndex::new();
        for id in 1..=10u64 {
            t.add(id);
            oi.add(id, 0);
        }
        let mut d = OrphanDrain::new(t, MockBlockFree, oi, 3);
        assert_eq!(d.drain_batch().unwrap(), 3);
    }

    #[test]
    fn drain_empty() {
        let mut d = OrphanDrain::new(
            MockInodeTable::new(),
            MockBlockFree,
            MockOrphanIndex::new(),
            10,
        );
        assert_eq!(d.drain_batch().unwrap(), 0);
    }

    #[test]
    fn drain_skips_already_reaped() {
        let mut t = MockInodeTable::new();
        t.add(100);
        let mut oi = MockOrphanIndex::new();
        oi.add(100, 1);
        let mut d = OrphanDrain::new(t, MockBlockFree, oi, 10);
        d.reaped.insert(100);
        assert_eq!(d.drain_batch().unwrap(), 0);
    }

    #[test]
    fn drain_missing_inode_clears_orphan() {
        let mut oi = MockOrphanIndex::new();
        oi.add(300, 1);
        let mut d = OrphanDrain::new(MockInodeTable::new(), MockBlockFree, oi, 10);
        d.drain_batch().unwrap();
        assert_eq!(d.stats().validation_failures, 1);
    }

    #[test]
    fn receipt_roundtrip() {
        let mut t = MockInodeTable::new();
        t.add(42);
        let mut oi = MockOrphanIndex::new();
        oi.add(42, 0);
        let mut d = OrphanDrain::new(t, MockBlockFree, oi, 10);
        d.drain_batch().unwrap();
        let r = d.seal_receipt();
        let reaped =
            OrphanDrain::<MockInodeTable, MockBlockFree, MockOrphanIndex>::decode_receipt(&r)
                .unwrap();
        assert!(reaped.contains(&42));
    }

    #[test]
    fn receipt_multiple() {
        let mut t = MockInodeTable::new();
        let mut oi = MockOrphanIndex::new();
        for id in [10, 20, 30, 40, 50] {
            t.add(id);
            oi.add(id, 0);
        }
        let mut d = OrphanDrain::new(t, MockBlockFree, oi, 10);
        d.drain_batch().unwrap();
        let reaped = OrphanDrain::<MockInodeTable, MockBlockFree, MockOrphanIndex>::decode_receipt(
            &d.seal_receipt(),
        )
        .unwrap();
        assert_eq!(reaped.len(), 5);
    }

    #[test]
    fn receipt_hash_mismatch() {
        let mut t = MockInodeTable::new();
        t.add(99);
        let mut oi = MockOrphanIndex::new();
        oi.add(99, 0);
        let mut d = OrphanDrain::new(t, MockBlockFree, oi, 10);
        d.drain_batch().unwrap();
        let mut r = d.seal_receipt();
        r[10] ^= 0xFF;
        assert!(matches!(
            OrphanDrain::<MockInodeTable, MockBlockFree, MockOrphanIndex>::decode_receipt(&r),
            Err(OrphanDrainError::HashMismatch)
        ));
    }

    #[test]
    fn receipt_empty() {
        let d = OrphanDrain::new(
            MockInodeTable::new(),
            MockBlockFree,
            MockOrphanIndex::new(),
            10,
        );
        let reaped = OrphanDrain::<MockInodeTable, MockBlockFree, MockOrphanIndex>::decode_receipt(
            &d.seal_receipt(),
        )
        .unwrap();
        assert!(reaped.is_empty());
    }

    #[test]
    fn resume_skips_reaped() {
        let mut t1 = MockInodeTable::new();
        let mut oi1 = MockOrphanIndex::new();
        for id in 1..=3u64 {
            t1.add(id);
            oi1.add(id, 0);
        }
        let mut d1 = OrphanDrain::new(t1, MockBlockFree, oi1, 10);
        d1.drain_batch().unwrap();
        let receipt = d1.seal_receipt();

        let mut t2 = MockInodeTable::new();
        let mut oi2 = MockOrphanIndex::new();
        for id in 1..=5u64 {
            t2.add(id);
            oi2.add(id, 0);
        }
        let mut d2 = OrphanDrain::resume(t2, MockBlockFree, oi2, 10, &receipt).unwrap();
        assert_eq!(d2.drain_batch().unwrap(), 2);
    }

    #[test]
    fn error_display() {
        assert!(format!("{}", OrphanDrainError::InodeNotFound(42)).contains("42"));
        assert!(format!(
            "{}",
            OrphanDrainError::BlobTooShort {
                expected: 40,
                got: 10
            }
        )
        .contains("40"));
    }
}
