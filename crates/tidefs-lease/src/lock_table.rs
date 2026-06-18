//! LockTable: the in-memory authoritative lock state on the lock service leader.
//!
//! Design spec §3.4: maintains active lease grants indexed by lease_id,
//! per-dataset subtree index, per-inode index, per-inode byte-range interval
//! tree, blocking lock wait queues, and owner reverse index.

use crate::types::*;
use std::collections::{BTreeMap, VecDeque};
use tidefs_membership_epoch::{EpochId, MemberId};

// ---------------------------------------------------------------------------
// Interval tree implementation (design spec §3.6)
// ---------------------------------------------------------------------------

/// An entry in a per-inode byte-range interval tree.
#[derive(Clone, Debug)]
struct IntervalEntry {
    start: u64,
    end: u64,
    lease_id: u64,
    lease_class: LeaseClass,
}

/// Byte-range interval tree for per-inode lock conflict detection.
///
/// Supports insert, remove, query_overlap, and query_conflict operations.
/// The design spec targets O(log n) for production R-B tree; this
/// implementation uses a sorted vector for correctness.
#[derive(Clone, Debug, Default)]
pub struct IntervalTree {
    entries: Vec<IntervalEntry>,
}

impl IntervalTree {
    pub fn new() -> Self {
        Self { entries: vec![] }
    }

    pub fn insert(
        &mut self,
        start: u64,
        end: u64,
        lease_id: u64,
        lease_class: LeaseClass,
    ) -> Result<(), IntervalError> {
        for entry in &self.entries {
            if intervals_overlap(entry.start, entry.end, start, end)
                && locks_conflict(entry.lease_class, lease_class)
            {
                return Err(IntervalError::Overlap {
                    existing_lease_id: entry.lease_id,
                });
            }
        }
        self.entries.push(IntervalEntry {
            start,
            end,
            lease_id,
            lease_class,
        });
        self.entries.sort_by_key(|e| e.start);
        Ok(())
    }

    pub fn remove(&mut self, lease_id: u64) -> bool {
        let len_before = self.entries.len();
        self.entries.retain(|e| e.lease_id != lease_id);
        self.entries.len() < len_before
    }

    pub fn query_overlap(&self, start: u64, end: u64) -> Vec<(u64, u64, u64, LeaseClass)> {
        self.entries
            .iter()
            .filter(|e| intervals_overlap(e.start, e.end, start, end))
            .map(|e| (e.start, e.end, e.lease_id, e.lease_class))
            .collect()
    }

    pub fn query_conflict(
        &self,
        start: u64,
        end: u64,
        lock_type: RangeLockType,
    ) -> Option<(u64, u64, u64)> {
        for entry in &self.entries {
            if intervals_overlap(entry.start, entry.end, start, end) {
                let entry_type = class_to_range_type(entry.lease_class);
                if range_locks_conflict(entry_type, lock_type) {
                    return Some((entry.start, entry.end, entry.lease_id));
                }
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntervalError {
    Overlap { existing_lease_id: u64 },
}

fn intervals_overlap(a1: u64, b1: u64, a2: u64, b2: u64) -> bool {
    a1 < b2 && a2 < b1
}

fn locks_conflict(a: LeaseClass, b: LeaseClass) -> bool {
    a.is_exclusive() || b.is_exclusive()
}

fn class_to_range_type(c: LeaseClass) -> RangeLockType {
    match c {
        LeaseClass::Exclusive => RangeLockType::Write,
        LeaseClass::Shared | LeaseClass::Staging => RangeLockType::Read,
    }
}

fn range_locks_conflict(a: RangeLockType, b: RangeLockType) -> bool {
    matches!(a, RangeLockType::Write) || matches!(b, RangeLockType::Write)
}

// ---------------------------------------------------------------------------
// LockTable (design spec §3.4)
// ---------------------------------------------------------------------------

/// The authoritative in-memory lock state on the lock service leader.
#[derive(Clone, Debug)]
pub struct LockTable {
    grants: BTreeMap<u64, LeaseGrant>,
    subtree_index: BTreeMap<(u64, String), u64>,
    inode_index: BTreeMap<(u64, u64), Vec<u64>>,
    range_index: BTreeMap<(u64, u64), IntervalTree>,
    pending_locks: BTreeMap<(u64, u64), VecDeque<PendingLockRequest>>,
    owner_index: BTreeMap<LockOwner, Vec<u64>>,
    current_term: u64,
    current_epoch: EpochId,
    last_applied: u64,
    max_pending_per_inode: usize,
}

impl LockTable {
    pub fn new(current_term: u64, current_epoch: EpochId) -> Self {
        Self {
            grants: BTreeMap::new(),
            subtree_index: BTreeMap::new(),
            inode_index: BTreeMap::new(),
            range_index: BTreeMap::new(),
            pending_locks: BTreeMap::new(),
            owner_index: BTreeMap::new(),
            current_term,
            current_epoch,
            last_applied: 0,
            max_pending_per_inode: 1024,
        }
    }

    pub fn current_term(&self) -> u64 {
        self.current_term
    }
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }
    pub fn last_applied(&self) -> u64 {
        self.last_applied
    }
    pub fn grant_count(&self) -> usize {
        self.grants.len()
    }
    pub fn get_grant(&self, lease_id: u64) -> Option<&LeaseGrant> {
        self.grants.get(&lease_id)
    }
    pub fn grants_iter(&self) -> impl Iterator<Item = &LeaseGrant> {
        self.grants.values()
    }

    pub fn validate_fencing(&self, term: u64, epoch: EpochId) -> bool {
        term == self.current_term && epoch == self.current_epoch
    }

    // -- Raft apply (design spec §5.3) --

    pub fn apply(&mut self, cmd: &RaftCommand) {
        match cmd {
            RaftCommand::Grant { grant } => self.insert_grant(grant.clone()),
            RaftCommand::Renew {
                lease_id,
                new_expires_at_millis,
                version,
            } => {
                if let Some(g) = self.grants.get_mut(lease_id) {
                    g.expires_at_millis = *new_expires_at_millis;
                    g.renew_by_millis = new_expires_at_millis.saturating_sub(g.term_millis / 4);
                    g.version = *version;
                    g.lifecycle = LeaseLifecycle::Granted;
                }
            }
            RaftCommand::Release { lease_id } => {
                self.remove_grant(*lease_id);
            }
            RaftCommand::Break { lease_id } => {
                if let Some(g) = self.grants.get_mut(lease_id) {
                    g.lifecycle = LeaseLifecycle::Fenced;
                }
            }
            RaftCommand::Upgrade { lease_id } => {
                if let Some(g) = self.grants.get_mut(lease_id) {
                    g.lease_class = LeaseClass::Exclusive;
                    g.version += 1;
                }
            }
            RaftCommand::Downgrade { lease_id } => {
                if let Some(g) = self.grants.get_mut(lease_id) {
                    g.lease_class = LeaseClass::Shared;
                    g.version += 1;
                }
            }
            RaftCommand::Snapshot {
                grants,
                last_applied,
            } => {
                self.grants.clear();
                self.clear_all_indexes();
                for g in grants {
                    self.insert_grant(g.clone());
                }
                self.last_applied = *last_applied;
            }
        }
    }

    // -- Conflict detection (design spec §5.1) --

    pub fn check_conflict(&self, domain: &LeaseDomain, lease_class: LeaseClass) -> Option<u64> {
        use LeaseDomain::*;
        match domain {
            Subtree { dataset_id, prefix } => {
                for ((ds_id, existing_pfx), &existing_id) in &self.subtree_index {
                    if ds_id != dataset_id {
                        continue;
                    }
                    if let Some(grant) = self.grants.get(&existing_id) {
                        if grant.lifecycle.is_terminal() {
                            continue;
                        }
                        if crate::types::subtree_overlap(prefix, existing_pfx)
                            && (grant.lease_class.is_exclusive() || lease_class.is_exclusive())
                        {
                            return Some(existing_id);
                        }
                    }
                }
                if lease_class.is_exclusive() {
                    for ((ds_id, _ino), lease_ids) in &self.inode_index {
                        if ds_id != dataset_id {
                            continue;
                        }
                        for &lid in lease_ids {
                            if let Some(grant) = self.grants.get(&lid) {
                                if !grant.lifecycle.is_terminal() {
                                    return Some(lid);
                                }
                            }
                        }
                    }
                }
                None
            }
            Inode { dataset_id, ino } => {
                for ((ds_id, _pfx), &existing_id) in &self.subtree_index {
                    if ds_id != dataset_id {
                        continue;
                    }
                    if let Some(grant) = self.grants.get(&existing_id) {
                        if grant.lifecycle.is_terminal() {
                            continue;
                        }
                        if grant.lease_class.is_exclusive() || lease_class.is_exclusive() {
                            return Some(existing_id);
                        }
                    }
                }
                if let Some(lease_ids) = self.inode_index.get(&(*dataset_id, *ino)) {
                    for &lid in lease_ids {
                        if let Some(grant) = self.grants.get(&lid) {
                            if grant.lifecycle.is_terminal() {
                                continue;
                            }
                            if grant.lease_class.is_exclusive() || lease_class.is_exclusive() {
                                return Some(lid);
                            }
                        }
                    }
                }
                None
            }
            ByteRange {
                dataset_id,
                ino,
                start,
                end,
            } => {
                for ((ds_id, _pfx), &existing_id) in &self.subtree_index {
                    if ds_id != dataset_id {
                        continue;
                    }
                    if let Some(grant) = self.grants.get(&existing_id) {
                        if grant.lifecycle.is_terminal() {
                            continue;
                        }
                        if grant.lease_class.is_exclusive() || lease_class.is_exclusive() {
                            return Some(existing_id);
                        }
                    }
                }
                if let Some(lease_ids) = self.inode_index.get(&(*dataset_id, *ino)) {
                    for &lid in lease_ids {
                        if let Some(grant) = self.grants.get(&lid) {
                            if grant.lifecycle.is_terminal() {
                                continue;
                            }
                            if matches!(grant.domain, LeaseDomain::ByteRange { .. }) {
                                continue;
                            }
                            if grant.lease_class.is_exclusive() || lease_class.is_exclusive() {
                                return Some(lid);
                            }
                        }
                    }
                }
                if let Some(tree) = self.range_index.get(&(*dataset_id, *ino)) {
                    let lock_type = match lease_class {
                        LeaseClass::Exclusive => RangeLockType::Write,
                        LeaseClass::Shared | LeaseClass::Staging => RangeLockType::Read,
                    };
                    if let Some((_s, _e, existing_id)) =
                        tree.query_conflict(*start, *end, lock_type)
                    {
                        if let Some(grant) = self.grants.get(&existing_id) {
                            if !grant.lifecycle.is_terminal() {
                                return Some(existing_id);
                            }
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    // -- Pending lock queue --

    pub fn enqueue_pending(
        &mut self,
        dataset_id: u64,
        ino: u64,
        req: PendingLockRequest,
    ) -> Result<(), LockQueueError> {
        let queue = self.pending_locks.entry((dataset_id, ino)).or_default();
        if queue.len() >= self.max_pending_per_inode {
            return Err(LockQueueError::QueueFull);
        }
        queue.push_back(req);
        Ok(())
    }

    pub fn dequeue_pending(&mut self, dataset_id: u64, ino: u64) -> Option<PendingLockRequest> {
        self.pending_locks.get_mut(&(dataset_id, ino))?.pop_front()
    }

    pub fn peek_pending(&self, dataset_id: u64, ino: u64) -> Option<&PendingLockRequest> {
        self.pending_locks.get(&(dataset_id, ino))?.front()
    }

    pub fn sweep_pending(&mut self, now_millis: u64) -> Vec<(u64, u64, MemberId, u64)> {
        let mut timeouts = Vec::new();
        let keys: Vec<(u64, u64)> = self.pending_locks.keys().cloned().collect();
        for key in keys {
            if let Some(queue) = self.pending_locks.get_mut(&key) {
                while let Some(req) = queue.front() {
                    if req.is_timed_out(now_millis) {
                        let r = queue.pop_front().unwrap();
                        timeouts.push((key.0, key.1, r.callback_node_id, r.callback_opaque));
                    } else {
                        break;
                    }
                }
                if queue.is_empty() {
                    self.pending_locks.remove(&key);
                }
            }
        }
        timeouts
    }

    // -- Leader failover (design spec §5.4) --

    pub fn leader_failover(&mut self) {
        self.current_term += 1;
        for grant in self.grants.values_mut() {
            // Use LeaseGrant::fence() for proper transition validation
            let _ = grant.fence();
        }
        self.pending_locks.clear();
    }

    // -- Owner lookup --

    pub fn owner_lease_ids(&self, owner: &LockOwner) -> Vec<u64> {
        self.owner_index.get(owner).cloned().unwrap_or_default()
    }

    // -- Internal --

    fn insert_grant(&mut self, grant: LeaseGrant) {
        let lease_id = grant.lease_id;
        let owner = LockOwner {
            node_id: grant.holder_id,
            pid: 0,
            owner_key: 0,
        };
        self.grants.insert(lease_id, grant.clone());
        match &grant.domain {
            LeaseDomain::Subtree { dataset_id, prefix } => {
                self.subtree_index
                    .insert((*dataset_id, prefix.clone()), lease_id);
            }
            LeaseDomain::Inode { dataset_id, ino } => {
                self.inode_index
                    .entry((*dataset_id, *ino))
                    .or_default()
                    .push(lease_id);
            }
            LeaseDomain::ByteRange {
                dataset_id,
                ino,
                start,
                end,
            } => {
                self.inode_index
                    .entry((*dataset_id, *ino))
                    .or_default()
                    .push(lease_id);
                let tree = self.range_index.entry((*dataset_id, *ino)).or_default();
                let _ = tree.insert(*start, *end, lease_id, grant.lease_class);
            }
            _ => {}
        }
        self.owner_index.entry(owner).or_default().push(lease_id);
    }

    fn remove_grant(&mut self, lease_id: u64) {
        if let Some(grant) = self.grants.remove(&lease_id) {
            match &grant.domain {
                LeaseDomain::Subtree { dataset_id, prefix } => {
                    self.subtree_index.remove(&(*dataset_id, prefix.clone()));
                }
                LeaseDomain::Inode { dataset_id, ino } => {
                    Self::remove_from_inode_index(
                        &mut self.inode_index,
                        *dataset_id,
                        *ino,
                        lease_id,
                    );
                }
                LeaseDomain::ByteRange {
                    dataset_id, ino, ..
                } => {
                    if let Some(tree) = self.range_index.get_mut(&(*dataset_id, *ino)) {
                        tree.remove(lease_id);
                        if tree.is_empty() {
                            self.range_index.remove(&(*dataset_id, *ino));
                        }
                    }
                    Self::remove_from_inode_index(
                        &mut self.inode_index,
                        *dataset_id,
                        *ino,
                        lease_id,
                    );
                }
                _ => {}
            }
            let owner = LockOwner {
                node_id: grant.holder_id,
                pid: 0,
                owner_key: 0,
            };
            if let Some(v) = self.owner_index.get_mut(&owner) {
                v.retain(|&id| id != lease_id);
                if v.is_empty() {
                    self.owner_index.remove(&owner);
                }
            }
        }
    }

    fn remove_from_inode_index(
        idx: &mut BTreeMap<(u64, u64), Vec<u64>>,
        ds: u64,
        ino: u64,
        lid: u64,
    ) {
        if let Some(v) = idx.get_mut(&(ds, ino)) {
            v.retain(|&id| id != lid);
            if v.is_empty() {
                idx.remove(&(ds, ino));
            }
        }
    }

    fn clear_all_indexes(&mut self) {
        self.subtree_index.clear();
        self.inode_index.clear();
        self.range_index.clear();
        self.owner_index.clear();
        self.pending_locks.clear();
    }

    /// Release every lease associated with a dataset mount identity.
    /// Returns the count of leases released.
    pub fn release_by_mount(&mut self, dataset_mount_id: u64, epoch: EpochId) -> u32 {
        let ids: Vec<u64> = self
            .grants
            .values()
            .filter(|g| g.dataset_mount_id == dataset_mount_id && g.epoch == epoch)
            .map(|g| g.lease_id)
            .collect();
        let count = ids.len() as u32;
        for lease_id in ids {
            self.remove_grant(lease_id);
        }
        count
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockQueueError {
    QueueFull,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::EpochId;

    fn mid(v: u64) -> MemberId {
        MemberId::new(v)
    }

    #[test]
    fn test_lock_table_empty() {
        let table = LockTable::new(1, EpochId::new(1));
        assert_eq!(table.grant_count(), 0);
        assert_eq!(table.current_term(), 1);
    }

    #[test]
    fn test_grant_release() {
        let mut table = LockTable::new(1, EpochId::new(1));
        let g = LeaseGrant::request(
            100,
            LeaseClass::Exclusive,
            LeaseDomain::Inode {
                dataset_id: 1,
                ino: 42,
            },
            mid(5),
            1u64,
            30_000,
            1_000_000,
            EpochId::new(1),
            100,
            3,
            3,
        );
        table.apply(&RaftCommand::Grant { grant: g });
        assert_eq!(table.grant_count(), 1);
        table.apply(&RaftCommand::Release { lease_id: 100 });
        assert_eq!(table.grant_count(), 0);
    }

    #[test]
    fn test_break_then_release() {
        let mut table = LockTable::new(1, EpochId::new(1));
        let g = LeaseGrant::request(
            200,
            LeaseClass::Shared,
            LeaseDomain::Inode {
                dataset_id: 2,
                ino: 7,
            },
            mid(3),
            1u64,
            30_000,
            1_000_000,
            EpochId::new(1),
            200,
            3,
            3,
        );
        table.apply(&RaftCommand::Grant { grant: g });
        table.apply(&RaftCommand::Break { lease_id: 200 });
        assert_eq!(
            table.get_grant(200).unwrap().lifecycle,
            LeaseLifecycle::Fenced
        );
        table.apply(&RaftCommand::Release { lease_id: 200 });
        assert_eq!(table.grant_count(), 0);
    }

    #[test]
    fn test_upgrade_downgrade() {
        let mut table = LockTable::new(1, EpochId::new(1));
        let g = LeaseGrant::request(
            300,
            LeaseClass::Shared,
            LeaseDomain::Inode {
                dataset_id: 3,
                ino: 10,
            },
            mid(2),
            1u64,
            30_000,
            800_000,
            EpochId::new(1),
            300,
            3,
            3,
        );
        table.apply(&RaftCommand::Grant { grant: g });
        assert_eq!(
            table.get_grant(300).unwrap().lease_class,
            LeaseClass::Shared
        );
        table.apply(&RaftCommand::Upgrade { lease_id: 300 });
        assert_eq!(
            table.get_grant(300).unwrap().lease_class,
            LeaseClass::Exclusive
        );
        table.apply(&RaftCommand::Downgrade { lease_id: 300 });
        assert_eq!(
            table.get_grant(300).unwrap().lease_class,
            LeaseClass::Shared
        );
    }

    #[test]
    fn test_snapshot() {
        let mut table = LockTable::new(1, EpochId::new(1));
        let g1 = LeaseGrant::request(
            1,
            LeaseClass::Shared,
            LeaseDomain::Inode {
                dataset_id: 1,
                ino: 1,
            },
            mid(1),
            1u64,
            30_000,
            100_000,
            EpochId::new(1),
            1,
            3,
            3,
        );
        let g2 = LeaseGrant::request(
            2,
            LeaseClass::Exclusive,
            LeaseDomain::ByteRange {
                dataset_id: 1,
                ino: 1,
                start: 0,
                end: 4096,
            },
            mid(2),
            1u64,
            30_000,
            200_000,
            EpochId::new(1),
            2,
            3,
            3,
        );
        table.apply(&RaftCommand::Grant { grant: g1.clone() });
        table.apply(&RaftCommand::Grant { grant: g2.clone() });
        assert_eq!(table.grant_count(), 2);
        table.apply(&RaftCommand::Snapshot {
            grants: vec![g1, g2],
            last_applied: 2,
        });
        assert_eq!(table.grant_count(), 2);
        assert_eq!(table.last_applied(), 2);
    }

    #[test]
    fn test_leader_failover() {
        let mut table = LockTable::new(1, EpochId::new(1));
        let g = LeaseGrant::request(
            400,
            LeaseClass::Exclusive,
            LeaseDomain::Inode {
                dataset_id: 4,
                ino: 99,
            },
            mid(4),
            1u64,
            30_000,
            500_000,
            EpochId::new(1),
            400,
            3,
            3,
        );
        table.apply(&RaftCommand::Grant { grant: g });
        table.leader_failover();
        assert_eq!(table.current_term(), 2);
        assert_eq!(
            table.get_grant(400).unwrap().lifecycle,
            LeaseLifecycle::Fenced
        );
    }

    #[test]
    fn test_subtree_conflict() {
        let mut table = LockTable::new(1, EpochId::new(1));
        let g = LeaseGrant::request(
            1,
            LeaseClass::Exclusive,
            LeaseDomain::Subtree {
                dataset_id: 1,
                prefix: "/a/".into(),
            },
            mid(1),
            1u64,
            30_000,
            100_000,
            EpochId::new(1),
            1,
            3,
            3,
        );
        table.apply(&RaftCommand::Grant { grant: g });
        assert!(table
            .check_conflict(
                &LeaseDomain::Subtree {
                    dataset_id: 1,
                    prefix: "/a/b/".into()
                },
                LeaseClass::Shared
            )
            .is_some());
        assert!(table
            .check_conflict(
                &LeaseDomain::Subtree {
                    dataset_id: 1,
                    prefix: "/other/".into()
                },
                LeaseClass::Shared
            )
            .is_none());
    }

    #[test]
    fn test_subtree_overlap_fn() {
        assert!(crate::types::subtree_overlap("/", "/a/b/"));
        assert!(crate::types::subtree_overlap("/a/b/", "/a/b/c/"));
        assert!(!crate::types::subtree_overlap("/a/b/", "/a/c/"));
        assert!(crate::types::subtree_overlap("/a/b/", "/a/b/"));
    }

    #[test]
    fn test_byte_range_non_overlapping_no_conflict() {
        // Regression test: ByteRange entries in inode_index must not
        // cause false-positive conflicts for non-overlapping ranges.
        // Only range_index.query_conflict decides ByteRange-vs-ByteRange.
        let mut table = LockTable::new(1, EpochId::new(1));
        let g1 = LeaseGrant::request(
            10,
            LeaseClass::Exclusive,
            LeaseDomain::ByteRange {
                dataset_id: 1,
                ino: 100,
                start: 0,
                end: 4095,
            },
            mid(1),
            1u64,
            30_000,
            100_000,
            EpochId::new(1),
            10,
            3,
            3,
        );
        table.apply(&RaftCommand::Grant { grant: g1 });
        // Non-overlapping range should NOT conflict
        assert!(table
            .check_conflict(
                &LeaseDomain::ByteRange {
                    dataset_id: 1,
                    ino: 100,
                    start: 4096,
                    end: 8191
                },
                LeaseClass::Shared
            )
            .is_none());
        // Overlapping range SHOULD conflict
        assert!(table
            .check_conflict(
                &LeaseDomain::ByteRange {
                    dataset_id: 1,
                    ino: 100,
                    start: 2048,
                    end: 6143
                },
                LeaseClass::Shared
            )
            .is_some());
        // Same non-overlapping range with exclusive SHOULD conflict
        // (existing exclusive blocks any overlapping byte-range)
        assert!(table
            .check_conflict(
                &LeaseDomain::ByteRange {
                    dataset_id: 1,
                    ino: 100,
                    start: 0,
                    end: 4095
                },
                LeaseClass::Exclusive
            )
            .is_some());
        // Non-overlapping exclusive should conflict with existing exclusive
        // because exclusive ByteRange blocks all byte ranges on that inode
        // (range_index handles this via query_conflict)
    }
    #[test]
    fn test_interval_tree_basic() {
        let mut tree = IntervalTree::new();
        assert!(tree.insert(0, 4096, 1, LeaseClass::Exclusive).is_ok());
        assert!(tree.insert(2048, 6144, 2, LeaseClass::Exclusive).is_err());
        assert!(tree.insert(0, 1024, 2, LeaseClass::Shared).is_err());
        assert!(tree.insert(4096, 8192, 3, LeaseClass::Shared).is_ok());
        assert_eq!(tree.len(), 2);
        let c = tree.query_conflict(0, 512, RangeLockType::Read);
        assert!(c.is_some());
        assert!(tree.remove(1));
        assert_eq!(tree.len(), 1);
        assert!(tree.query_conflict(0, 512, RangeLockType::Read).is_none());
    }

    #[test]
    fn test_pending_queue() {
        let mut table = LockTable::new(1, EpochId::new(1));
        let req = PendingLockRequest {
            request_id: 1,
            owner: LockOwner::new(mid(10), 100, 1),
            domain: LeaseDomain::ByteRange {
                dataset_id: 1,
                ino: 5,
                start: 0,
                end: 1024,
            },
            lease_class: LeaseClass::Exclusive,
            enqueued_at_millis: 1000,
            timeout_millis: 30_000,
            callback_node_id: mid(10),
            callback_opaque: 0xDEAD,
        };
        assert!(table.enqueue_pending(1, 5, req.clone()).is_ok());
        assert!(table.peek_pending(1, 5).is_some());
        assert!(table.dequeue_pending(1, 5).is_some());
        assert!(table.peek_pending(1, 5).is_none());
    }

    #[test]
    fn test_lease_domain_covers() {
        let subtree = LeaseDomain::Subtree {
            dataset_id: 1,
            prefix: "/home/".into(),
        };
        let inode = LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        };
        let range = LeaseDomain::ByteRange {
            dataset_id: 1,
            ino: 42,
            start: 0,
            end: 4096,
        };
        let other = LeaseDomain::Inode {
            dataset_id: 99,
            ino: 42,
        };
        assert!(subtree.covers(&inode));
        assert!(subtree.covers(&range));
        assert!(!inode.covers(&subtree));
        assert!(inode.covers(&range));
        assert!(!range.covers(&inode));
        assert!(!subtree.covers(&other));
    }

    #[test]
    fn test_tier() {
        assert_eq!(
            LeaseDomain::Subtree {
                dataset_id: 1,
                prefix: "/".into()
            }
            .tier(),
            LeaseLevel::Subtree
        );
        assert_eq!(
            LeaseDomain::Inode {
                dataset_id: 1,
                ino: 5
            }
            .tier(),
            LeaseLevel::Inode
        );
    }

    #[test]
    fn test_lock_method_constants() {
        assert_eq!(LockMethod::SERVICE_ID, 0x0A);
        assert_eq!(LockMethod::Acquire.to_u8(), 0x00);
        assert_eq!(LockMethod::RecallAllAck.to_u8(), 0x11);
        assert_eq!(LockMethod::from_u8(0x00), Some(LockMethod::Acquire));
        assert_eq!(LockMethod::from_u8(0x12), None); // first reserved slot
        assert_eq!(LockMethod::from_u8(0xFF), None);
    }

    #[test]
    fn test_lock_owner_serde() {
        let owner = LockOwner::new(mid(10), 1234, 0xABCD);
        let json = serde_json::to_string(&owner).unwrap();
        let owner2: LockOwner = serde_json::from_str(&json).unwrap();
        assert_eq!(owner, owner2);
    


}
}
