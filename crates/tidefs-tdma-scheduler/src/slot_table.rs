//! Active-slot lifecycle table with insert, lookup, and epoch-gated expiry.
//!
//! Tracks currently-active TDMA slots keyed by `(node_id, write_txg)`. Slots
//! are inserted when allocated, looked up during write dispatch, and expired
//! en masse when their epoch falls before the current epoch.

use std::collections::HashMap;

use tidefs_membership_epoch::EpochId;

/// Errors from slot-table operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SlotTableError {
    /// A slot with this key already exists and is still active.
    #[error("slot already active for (node={node}, txg={txg})")]
    SlotAlreadyActive { node: u64, txg: u64 },

    /// The slot table is at capacity.
    #[error("slot table full: capacity {capacity}")]
    TableFull { capacity: usize },

    /// No active slot found for the given key.
    #[error("no active slot for (node={node}, txg={txg})")]
    SlotNotFound { node: u64, txg: u64 },
}

/// A stored active-slot entry carried inside [`SlotTable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotEntry {
    /// Epoch this slot was allocated in.
    pub epoch: EpochId,
    /// Node that holds this slot.
    pub node_id: u64,
    /// Write transaction-group identifier.
    pub write_txg: u64,
    /// Slot index within the epoch.
    pub slot_index: u64,
    /// Slot start wall-clock time in milliseconds.
    pub slot_start_ms: u64,
    /// Slot end wall-clock time in milliseconds.
    pub slot_end_ms: u64,
}

impl SlotEntry {
    /// Create a new slot entry.
    pub fn new(
        epoch: EpochId,
        node_id: u64,
        write_txg: u64,
        slot_index: u64,
        slot_start_ms: u64,
        slot_end_ms: u64,
    ) -> Self {
        Self {
            epoch,
            node_id,
            write_txg,
            slot_index,
            slot_start_ms,
            slot_end_ms,
        }
    }

    /// Whether this slot has expired at the given wall-clock time.
    pub fn is_expired_at(&self, now_ms: u64) -> bool {
        now_ms >= self.slot_end_ms
    }
}

/// Slot-table key: `(node_id, write_txg)`.
type SlotKey = (u64, u64);

// ---------------------------------------------------------------------------
// SlotTable
// ---------------------------------------------------------------------------

/// Active-slot lifecycle table.
///
/// Tracks currently-active TDMA slots. Supports insert, lookup, individual
/// removal, and bulk expiry of slots whose epoch is behind the current epoch.
///
/// Capacity is bounded; insertions at capacity return
/// [`SlotTableError::TableFull`].
pub struct SlotTable {
    /// Maximum number of active slots.
    capacity: usize,
    /// Active slots indexed by (node_id, write_txg).
    slots: HashMap<SlotKey, SlotEntry>,
}

impl SlotTable {
    /// Create a new slot table with the given capacity.
    ///
    /// Returns `None` if `capacity` is zero.
    pub fn new(capacity: usize) -> Option<Self> {
        if capacity == 0 {
            return None;
        }
        Some(Self {
            capacity,
            slots: HashMap::new(),
        })
    }

    /// Maximum number of active slots.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Current number of active slots.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// True when no active slots are tracked.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// True when the table is at capacity.
    pub fn is_full(&self) -> bool {
        self.slots.len() >= self.capacity
    }

    /// Number of free slots remaining.
    pub fn remaining(&self) -> usize {
        self.capacity.saturating_sub(self.slots.len())
    }

    // ------------------------------------------------------------------
    // Insert
    // ------------------------------------------------------------------

    /// Insert an active slot into the table.
    ///
    /// Returns [`SlotTableError::SlotAlreadyActive`] if the same
    /// (node_id, write_txg) already has an active slot.
    /// Returns [`SlotTableError::TableFull`] when the table is at capacity.
    pub fn insert(&mut self, entry: SlotEntry) -> Result<(), SlotTableError> {
        let key = (entry.node_id, entry.write_txg);

        if self.slots.contains_key(&key) {
            return Err(SlotTableError::SlotAlreadyActive {
                node: entry.node_id,
                txg: entry.write_txg,
            });
        }

        if self.is_full() {
            return Err(SlotTableError::TableFull {
                capacity: self.capacity,
            });
        }

        self.slots.insert(key, entry);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    /// Look up an active slot by (node_id, write_txg).
    pub fn lookup(&self, node_id: u64, write_txg: u64) -> Option<&SlotEntry> {
        self.slots.get(&(node_id, write_txg))
    }

    /// Look up a mutable reference to an active slot.
    pub fn lookup_mut(&mut self, node_id: u64, write_txg: u64) -> Option<&mut SlotEntry> {
        self.slots.get_mut(&(node_id, write_txg))
    }

    // ------------------------------------------------------------------
    // Removal
    // ------------------------------------------------------------------

    /// Remove and return a slot by key.
    pub fn remove(&mut self, node_id: u64, write_txg: u64) -> Option<SlotEntry> {
        self.slots.remove(&(node_id, write_txg))
    }

    // ------------------------------------------------------------------
    // Expiry
    // ------------------------------------------------------------------

    /// Expire all slots whose epoch is strictly less than `current_epoch`.
    ///
    /// Returns the removed entries.
    pub fn expire_epoch(&mut self, current_epoch: EpochId) -> Vec<SlotEntry> {
        let expired_keys: Vec<SlotKey> = self
            .slots
            .iter()
            .filter(|(_, entry)| entry.epoch < current_epoch)
            .map(|(k, _)| *k)
            .collect();

        let mut removed = Vec::with_capacity(expired_keys.len());
        for key in expired_keys {
            if let Some(entry) = self.slots.remove(&key) {
                removed.push(entry);
            }
        }
        removed
    }

    /// Expire all slots whose `slot_end_ms` is at or before `now_ms`.
    ///
    /// Returns the removed entries.
    pub fn expire_by_time(&mut self, now_ms: u64) -> Vec<SlotEntry> {
        let expired_keys: Vec<SlotKey> = self
            .slots
            .iter()
            .filter(|(_, entry)| entry.slot_end_ms <= now_ms)
            .map(|(k, _)| *k)
            .collect();

        let mut removed = Vec::with_capacity(expired_keys.len());
        for key in expired_keys {
            if let Some(entry) = self.slots.remove(&key) {
                removed.push(entry);
            }
        }
        removed
    }

    /// Iterate over all active slot entries.
    pub fn iter(&self) -> impl Iterator<Item = &SlotEntry> {
        self.slots.values()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> EpochId {
        EpochId(1)
    }

    fn test_entry(node_id: u64, txg: u64, slot_index: u64) -> SlotEntry {
        SlotEntry::new(test_epoch(), node_id, txg, slot_index, 1000, 1100)
    }

    fn test_table() -> SlotTable {
        SlotTable::new(64).unwrap()
    }

    #[test]
    fn rejects_zero_capacity() {
        assert!(SlotTable::new(0).is_none());
    }

    #[test]
    fn new_table_empty() {
        let t = test_table();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert_eq!(t.capacity(), 64);
        assert_eq!(t.remaining(), 64);
    }

    #[test]
    fn insert_and_lookup() {
        let mut t = test_table();
        let e = test_entry(10, 1, 5);
        t.insert(e.clone()).unwrap();

        let found = t.lookup(10, 1).unwrap();
        assert_eq!(found.node_id, 10);
        assert_eq!(found.write_txg, 1);
        assert_eq!(found.slot_index, 5);
        assert_eq!(found.epoch, test_epoch());
    }

    #[test]
    fn insert_duplicate_rejected() {
        let mut t = test_table();
        t.insert(test_entry(10, 1, 5)).unwrap();
        let err = t.insert(test_entry(10, 1, 7)).unwrap_err();
        assert!(matches!(
            err,
            SlotTableError::SlotAlreadyActive { node: 10, txg: 1 }
        ));
    }

    #[test]
    fn insert_at_capacity_rejected() {
        let mut t = SlotTable::new(3).unwrap();
        t.insert(test_entry(1, 0, 0)).unwrap();
        t.insert(test_entry(2, 0, 0)).unwrap();
        t.insert(test_entry(3, 0, 0)).unwrap();
        assert!(t.is_full());

        let err = t.insert(test_entry(4, 0, 0)).unwrap_err();
        assert!(matches!(err, SlotTableError::TableFull { capacity: 3 }));
    }

    #[test]
    fn lookup_missing_returns_none() {
        let t = test_table();
        assert!(t.lookup(99, 99).is_none());
    }

    #[test]
    fn lookup_mut_allows_update() {
        let mut t = test_table();
        t.insert(test_entry(10, 1, 5)).unwrap();
        t.lookup_mut(10, 1).unwrap().slot_index = 99;
        assert_eq!(t.lookup(10, 1).unwrap().slot_index, 99);
    }

    #[test]
    fn remove_returns_and_deletes() {
        let mut t = test_table();
        t.insert(test_entry(10, 1, 5)).unwrap();
        let removed = t.remove(10, 1).unwrap();
        assert_eq!(removed.slot_index, 5);
        assert!(t.lookup(10, 1).is_none());
        assert!(t.is_empty());
    }

    #[test]
    fn remove_missing_returns_none() {
        let mut t = test_table();
        assert!(t.remove(99, 99).is_none());
    }

    #[test]
    fn expire_epoch_removes_old_epochs() {
        let mut t = test_table();

        // Epoch 1 slots
        t.insert(SlotEntry::new(EpochId(1), 10, 1, 0, 0, 100))
            .unwrap();
        t.insert(SlotEntry::new(EpochId(1), 20, 1, 0, 0, 100))
            .unwrap();

        // Epoch 3 slot (current)
        t.insert(SlotEntry::new(EpochId(3), 30, 1, 0, 0, 100))
            .unwrap();

        let removed = t.expire_epoch(EpochId(2));
        assert_eq!(removed.len(), 2);

        // Epoch 3 slot remains
        assert!(t.lookup(30, 1).is_some());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn expire_epoch_keeps_current_epoch() {
        let mut t = test_table();
        t.insert(SlotEntry::new(EpochId(5), 10, 1, 0, 0, 100))
            .unwrap();

        let removed = t.expire_epoch(EpochId(5)); // slots with epoch < 5
        assert!(removed.is_empty());
        assert!(t.lookup(10, 1).is_some());
    }

    #[test]
    fn expire_by_time_removes_ended_slots() {
        let mut t = test_table();
        t.insert(SlotEntry::new(EpochId(1), 10, 1, 0, 1000, 1100))
            .unwrap();
        t.insert(SlotEntry::new(EpochId(1), 20, 1, 0, 2000, 2100))
            .unwrap();

        // At t=1100, slot 10 expires (end=1100), slot 20 stays.
        let removed = t.expire_by_time(1100);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].node_id, 10);
        assert!(t.lookup(20, 1).is_some());

        // At t=2100, slot 20 also expires.
        let removed = t.expire_by_time(2100);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].node_id, 20);
        assert!(t.is_empty());
    }

    #[test]
    fn is_expired_at_bounds() {
        let e = SlotEntry::new(EpochId(1), 10, 1, 0, 1000, 1100);
        assert!(!e.is_expired_at(0));
        assert!(!e.is_expired_at(1099));
        assert!(e.is_expired_at(1100));
        assert!(e.is_expired_at(1101));
    }

    #[test]
    fn iter_yields_all_entries() {
        let mut t = test_table();
        t.insert(test_entry(10, 1, 0)).unwrap();
        t.insert(test_entry(20, 1, 0)).unwrap();
        t.insert(test_entry(30, 1, 0)).unwrap();

        let mut ids: Vec<u64> = t.iter().map(|e| e.node_id).collect();
        ids.sort();
        assert_eq!(ids, vec![10, 20, 30]);
    }

    #[test]
    fn remaining_tracks_free_capacity() {
        let mut t = SlotTable::new(5).unwrap();
        assert_eq!(t.remaining(), 5);
        t.insert(test_entry(1, 0, 0)).unwrap();
        assert_eq!(t.remaining(), 4);
        t.insert(test_entry(2, 0, 0)).unwrap();
        assert_eq!(t.remaining(), 3);
    }

    #[test]
    fn remove_then_insert_allows_reinsert() {
        let mut t = test_table();
        t.insert(test_entry(10, 1, 5)).unwrap();
        t.remove(10, 1);
        // Should succeed: key is no longer present.
        t.insert(test_entry(10, 1, 7)).unwrap();
        assert_eq!(t.lookup(10, 1).unwrap().slot_index, 7);
    }
}
