//! Inode lifecycle management for the VFS engine.
//!
//! Provides [`InodeHandle`] for tracking active inodes through allocation,
//! reference counting, and reclaim, with pin-set integration preventing
//! reclamation of inodes held by datasets or snapshots.
//!
//! [`InodeTable`] is the central registry mapping [`InodeId`] to handles,
//! supporting bulk reclaim collection for the dead-object reclamation path.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::{Errno, InodeAttr, InodeId};

/// State machine for an inode handle tracked by the VFS engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InodeState {
    /// Inode is allocated and active; may have outstanding references.
    Allocated,
    /// Inode is pinned by a dataset root, snapshot, or open directory
    /// cursor — preventing reclamation even when refcount is zero.
    Pinned,
    /// Inode has been marked for reclamation; no references remain and
    /// it is not pinned. The dead-object reclamation path will remove it.
    Reclaiming,
}

/// Handle tracking a live inode's lifecycle within the VFS engine.
///
/// Each handle carries a reference count. A fresh allocation or lookup
/// sets it to 1. Open file handles increment it, and `release`/`close`
/// decrement it. When the reference count reaches zero and the inode is
/// not pinned, it becomes eligible for reclamation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InodeHandle {
    /// The inode identifier.
    pub inode_id: InodeId,
    /// Current attributes for this inode.
    pub attr: InodeAttr,
    /// Lifecycle state.
    pub state: InodeState,
    refcount: u64,
}

impl InodeHandle {
    /// Create a freshly-allocated handle with reference count 1.
    #[must_use]
    pub fn new(inode_id: InodeId, attr: InodeAttr) -> Self {
        Self {
            inode_id,
            attr,
            state: InodeState::Allocated,
            refcount: 1,
        }
    }

    /// Current reference count.
    #[must_use]
    pub fn refcount(&self) -> u64 {
        self.refcount
    }

    /// Increment the reference count, returning the new value.
    pub fn inc_ref(&mut self) -> u64 {
        self.refcount = self.refcount.saturating_add(1);
        self.refcount
    }

    /// Decrement the reference count, returning the new value.
    ///
    /// Returns `Err(Errno::EINVAL)` if the count is already zero.
    pub fn dec_ref(&mut self) -> Result<u64, Errno> {
        if self.refcount == 0 {
            return Err(Errno::EINVAL);
        }
        self.refcount -= 1;
        Ok(self.refcount)
    }

    /// Pin the inode, preventing reclamation even at refcount zero.
    pub fn pin(&mut self) {
        self.state = InodeState::Pinned;
    }

    /// Remove the pin. Falls back to `Allocated` if currently pinned.
    pub fn unpin(&mut self) {
        if self.state == InodeState::Pinned {
            self.state = InodeState::Allocated;
        }
    }

    /// Whether the inode is eligible for reclamation.
    ///
    /// An inode is reclaimable when its reference count is zero and it
    /// is not pinned.
    #[must_use]
    pub fn is_reclaimable(&self) -> bool {
        self.refcount == 0 && self.state != InodeState::Pinned
    }

    /// Mark the inode as reclaiming.
    ///
    /// Returns `Err(Errno::EBUSY)` if the inode still has references or
    /// is pinned.
    pub fn mark_reclaiming(&mut self) -> Result<(), Errno> {
        if !self.is_reclaimable() {
            return Err(Errno::EBUSY);
        }
        self.state = InodeState::Reclaiming;
        Ok(())
    }
}

/// Registry of inode handles, supporting allocation, lookup, ref-count
/// management, pinning, and bulk reclamation.
#[derive(Clone, Debug)]
pub struct InodeTable {
    handles: BTreeMap<u64, InodeHandle>,
}

impl InodeTable {
    /// Create an empty inode table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handles: BTreeMap::new(),
        }
    }

    /// Insert a new handle. If an entry with the same inode id already
    /// exists it is replaced, and the old handle is returned.
    pub fn allocate(&mut self, attr: InodeAttr) -> InodeHandle {
        let inode_id = attr.inode_id;
        let handle = InodeHandle::new(inode_id, attr);
        self.handles.insert(inode_id.get(), handle.clone());
        handle
    }

    /// Look up a handle by inode id.
    #[must_use]
    pub fn lookup(&self, inode_id: InodeId) -> Option<&InodeHandle> {
        self.handles.get(&inode_id.get())
    }

    /// Look up a mutable handle by inode id.
    #[must_use]
    pub fn lookup_mut(&mut self, inode_id: InodeId) -> Option<&mut InodeHandle> {
        self.handles.get_mut(&inode_id.get())
    }

    /// Increment the reference count on `inode_id`.
    ///
    /// Returns the new count, or `Err(Errno::ENOENT)` if the inode is
    /// not in the table.
    pub fn inc_ref(&mut self, inode_id: InodeId) -> Result<u64, Errno> {
        let handle = self.handles.get_mut(&inode_id.get()).ok_or(Errno::ENOENT)?;
        Ok(handle.inc_ref())
    }

    /// Decrement the reference count on `inode_id`.
    ///
    /// Returns the new count, or `Err(Errno::ENOENT)` if the inode is
    /// not in the table.
    pub fn dec_ref(&mut self, inode_id: InodeId) -> Result<u64, Errno> {
        let handle = self.handles.get_mut(&inode_id.get()).ok_or(Errno::ENOENT)?;
        handle.dec_ref()
    }

    /// Pin an inode, preventing reclamation.
    pub fn pin(&mut self, inode_id: InodeId) -> Result<(), Errno> {
        self.handles
            .get_mut(&inode_id.get())
            .ok_or(Errno::ENOENT)?
            .pin();
        Ok(())
    }

    /// Unpin an inode.
    pub fn unpin(&mut self, inode_id: InodeId) -> Result<(), Errno> {
        self.handles
            .get_mut(&inode_id.get())
            .ok_or(Errno::ENOENT)?
            .unpin();
        Ok(())
    }

    /// Collect ids of all inodes currently eligible for reclamation.
    #[must_use]
    pub fn collect_reclaimable(&self) -> Vec<InodeId> {
        self.handles
            .iter()
            .filter(|(_, h)| h.is_reclaimable())
            .map(|(_, h)| h.inode_id)
            .collect()
    }

    /// Reclaim an inode: remove it from the table and return the handle.
    ///
    /// Returns `Err(Errno::EBUSY)` if the inode still has references or
    /// is pinned, and `Err(Errno::ENOENT)` if it is not in the table.
    pub fn reclaim(&mut self, inode_id: InodeId) -> Result<InodeHandle, Errno> {
        {
            let handle = self.handles.get(&inode_id.get()).ok_or(Errno::ENOENT)?;
            if !handle.is_reclaimable() {
                return Err(Errno::EBUSY);
            }
        }
        self.handles.remove(&inode_id.get()).ok_or(Errno::ENOENT)
    }

    /// Number of handles in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Iterate over all handles in the table.
    pub fn iter(&self) -> impl Iterator<Item = &InodeHandle> {
        self.handles.values()
    }
}

impl Default for InodeTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Generation, InodeFlags, NodeKind, PosixAttrs};

    fn test_attr(inode_id: u64, kind: NodeKind) -> InodeAttr {
        InodeAttr::new(
            InodeId::new(inode_id),
            Generation::new(1),
            kind,
            PosixAttrs {
                mode: crate::S_IFREG | 0o644,
                uid: 1000,
                gid: 1000,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            InodeFlags::default(),
            0,
            0,
        )
    }

    // ── InodeHandle lifecycle ──────────────────────────────────────────

    #[test]
    fn handle_new_starts_refcount_1_allocated() {
        let h = InodeHandle::new(InodeId::new(10), test_attr(10, NodeKind::File));
        assert_eq!(h.refcount(), 1);
        assert_eq!(h.state, InodeState::Allocated);
    }

    #[test]
    fn handle_inc_dec_ref() {
        let mut h = InodeHandle::new(InodeId::new(10), test_attr(10, NodeKind::File));
        assert_eq!(h.inc_ref(), 2);
        assert_eq!(h.inc_ref(), 3);
        assert_eq!(h.dec_ref(), Ok(2));
        assert_eq!(h.dec_ref(), Ok(1));
        assert_eq!(h.dec_ref(), Ok(0));
        assert_eq!(h.dec_ref(), Err(Errno::EINVAL));
    }

    #[test]
    fn handle_pin_unpin() {
        let mut h = InodeHandle::new(InodeId::new(10), test_attr(10, NodeKind::File));
        assert_eq!(h.state, InodeState::Allocated);
        h.pin();
        assert_eq!(h.state, InodeState::Pinned);
        h.unpin();
        assert_eq!(h.state, InodeState::Allocated);
    }

    #[test]
    fn handle_reclaimable_only_when_refcount_zero_and_not_pinned() {
        let mut h = InodeHandle::new(InodeId::new(10), test_attr(10, NodeKind::File));
        assert!(!h.is_reclaimable());
        h.dec_ref().unwrap();
        assert!(h.is_reclaimable());
        h.pin();
        assert!(!h.is_reclaimable());
        h.unpin();
        assert!(h.is_reclaimable());
    }

    #[test]
    fn handle_mark_reclaiming_rejected_when_referenced() {
        let mut h = InodeHandle::new(InodeId::new(10), test_attr(10, NodeKind::File));
        assert_eq!(h.mark_reclaiming(), Err(Errno::EBUSY));
    }

    #[test]
    fn handle_mark_reclaiming_succeeds_when_eligible() {
        let mut h = InodeHandle::new(InodeId::new(10), test_attr(10, NodeKind::File));
        h.dec_ref().unwrap();
        h.mark_reclaiming().unwrap();
        assert_eq!(h.state, InodeState::Reclaiming);
    }

    // ── InodeTable allocate / lookup ───────────────────────────────────

    #[test]
    fn table_allocate_and_lookup() {
        let mut t = InodeTable::new();
        t.allocate(test_attr(100, NodeKind::File));
        let found = t.lookup(InodeId::new(100)).expect("should find");
        assert_eq!(found.inode_id, InodeId::new(100));
        assert_eq!(found.refcount(), 1);
    }

    #[test]
    fn table_lookup_missing_returns_none() {
        let t = InodeTable::new();
        assert!(t.lookup(InodeId::new(999)).is_none());
    }

    #[test]
    fn table_allocate_replace_existing() {
        let mut t = InodeTable::new();
        t.allocate(test_attr(100, NodeKind::File));
        t.allocate(test_attr(100, NodeKind::Dir));
        let found = t.lookup(InodeId::new(100)).unwrap();
        assert_eq!(found.attr.kind, NodeKind::Dir);
    }

    // ── InodeTable ref counting ────────────────────────────────────────

    #[test]
    fn table_inc_dec_ref() {
        let mut t = InodeTable::new();
        t.allocate(test_attr(100, NodeKind::File));
        assert_eq!(t.inc_ref(InodeId::new(100)), Ok(2));
        assert_eq!(t.dec_ref(InodeId::new(100)), Ok(1));
    }

    #[test]
    fn table_ref_ops_on_missing() {
        let mut t = InodeTable::new();
        assert_eq!(t.inc_ref(InodeId::new(1)), Err(Errno::ENOENT));
        assert_eq!(t.dec_ref(InodeId::new(1)), Err(Errno::ENOENT));
    }

    // ── InodeTable pin / unpin ─────────────────────────────────────────

    #[test]
    fn table_pin_unpin() {
        let mut t = InodeTable::new();
        t.allocate(test_attr(100, NodeKind::File));
        t.pin(InodeId::new(100)).unwrap();
        assert_eq!(
            t.lookup(InodeId::new(100)).unwrap().state,
            InodeState::Pinned
        );
        t.unpin(InodeId::new(100)).unwrap();
        assert_eq!(
            t.lookup(InodeId::new(100)).unwrap().state,
            InodeState::Allocated
        );
    }

    #[test]
    fn table_pin_missing() {
        let mut t = InodeTable::new();
        assert_eq!(t.pin(InodeId::new(1)), Err(Errno::ENOENT));
    }

    // ── InodeTable reclaim ─────────────────────────────────────────────

    #[test]
    fn table_reclaim_success() {
        let mut t = InodeTable::new();
        t.allocate(test_attr(100, NodeKind::File));
        t.dec_ref(InodeId::new(100)).unwrap();

        let reclaimable = t.collect_reclaimable();
        assert_eq!(reclaimable.len(), 1);
        assert_eq!(reclaimable[0], InodeId::new(100));

        let reclaimed = t.reclaim(InodeId::new(100)).unwrap();
        assert_eq!(reclaimed.inode_id, InodeId::new(100));
        assert!(t.lookup(InodeId::new(100)).is_none());
    }

    #[test]
    fn table_reclaim_fails_when_refcount_nonzero() {
        let mut t = InodeTable::new();
        t.allocate(test_attr(100, NodeKind::File));
        assert_eq!(t.reclaim(InodeId::new(100)), Err(Errno::EBUSY));
    }

    #[test]
    fn table_reclaim_fails_when_pinned() {
        let mut t = InodeTable::new();
        t.allocate(test_attr(100, NodeKind::File));
        t.dec_ref(InodeId::new(100)).unwrap();
        t.pin(InodeId::new(100)).unwrap();
        assert_eq!(t.reclaim(InodeId::new(100)), Err(Errno::EBUSY));
    }

    #[test]
    fn table_reclaim_missing() {
        let mut t = InodeTable::new();
        assert_eq!(t.reclaim(InodeId::new(1)), Err(Errno::ENOENT));
    }

    // ── InodeTable iteration ───────────────────────────────────────────

    #[test]
    fn table_iter_and_len() {
        let mut t = InodeTable::new();
        for i in 0..5 {
            t.allocate(test_attr(100 + i, NodeKind::File));
        }
        assert_eq!(t.len(), 5);
        assert!(!t.is_empty());
        let ids: Vec<u64> = t.iter().map(|h| h.inode_id.get()).collect();
        assert_eq!(ids, alloc::vec![100, 101, 102, 103, 104]);
    }

    #[test]
    fn table_default_is_empty() {
        let t = InodeTable::default();
        assert!(t.is_empty());
    }

    // ── Integration: full lifecycle ────────────────────────────────────

    #[test]
    fn full_lifecycle_create_open_close_reclaim() {
        let mut t = InodeTable::new();
        t.allocate(test_attr(42, NodeKind::File));
        assert_eq!(t.lookup(InodeId::new(42)).unwrap().refcount(), 1);

        t.inc_ref(InodeId::new(42)).unwrap();
        assert_eq!(t.lookup(InodeId::new(42)).unwrap().refcount(), 2);

        t.dec_ref(InodeId::new(42)).unwrap();
        assert_eq!(t.lookup(InodeId::new(42)).unwrap().refcount(), 1);

        t.dec_ref(InodeId::new(42)).unwrap();
        assert!(t.collect_reclaimable().contains(&InodeId::new(42)));

        t.reclaim(InodeId::new(42)).unwrap();
        assert!(t.lookup(InodeId::new(42)).is_none());
    }

    #[test]
    fn full_lifecycle_pin_prevents_reclaim() {
        let mut t = InodeTable::new();
        t.allocate(test_attr(42, NodeKind::File));
        t.dec_ref(InodeId::new(42)).unwrap();
        t.pin(InodeId::new(42)).unwrap();
        assert!(t.collect_reclaimable().is_empty());
        assert_eq!(t.reclaim(InodeId::new(42)), Err(Errno::EBUSY));
    }
}
