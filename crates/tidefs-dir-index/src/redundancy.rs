//! Metadata redundancy: directory B-tree page replication, failover, and
//! automatic repair.
//!
//! Directory B-tree pages are replicated across multiple devices so that
//! loss of a single device doesn't render the namespace inaccessible.
//!
//! ## Design
//!
//! - [`MetadataRedundancyPolicy`] configures the replication factor per pool.
//!   Default is 2 (primary + 1 replica).
//! - [`replicated_put`] writes page data to the primary store and all replicas.
//! - [`replicated_get`] reads from the primary; on failure (key missing or
//!   checksum mismatch), tries each replica in order.
//! - [`repair_primary`] rewrites the primary copy from healthy replica data
//!   after a successful failover read.

use alloc::vec::Vec;
use tidefs_local_object_store::{LocalObjectStore, ObjectKey};

// ---------------------------------------------------------------------------
// MetadataRedundancyPolicy
// ---------------------------------------------------------------------------

/// Per-pool configuration for metadata replication.
///
/// Controls how many copies of directory B-tree pages are maintained.
/// A replication factor of 1 means no redundancy (primary only).
/// The default of 2 provides single-device fault tolerance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataRedundancyPolicy {
    /// Total number of copies (primary + replicas). Minimum 1, default 2.
    pub replication_factor: u8,
}

impl Default for MetadataRedundancyPolicy {
    fn default() -> Self {
        Self {
            replication_factor: 2,
        }
    }
}

impl MetadataRedundancyPolicy {
    /// Create a policy with the given replication factor (clamped to >= 1).
    #[must_use]
    pub const fn new(replication_factor: u8) -> Self {
        Self {
            replication_factor: if replication_factor < 1 {
                1
            } else {
                replication_factor
            },
        }
    }

    /// Whether redundancy is enabled (factor > 1).
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.replication_factor > 1
    }

    /// Number of replica copies (total copies minus primary).
    #[must_use]
    pub const fn replica_count(self) -> usize {
        self.replication_factor.saturating_sub(1) as usize
    }
}

// ---------------------------------------------------------------------------
// ReplicatedReadResult
// ---------------------------------------------------------------------------

/// Outcome of a replicated read with failover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplicatedReadResult {
    /// Read from primary store succeeded.
    Primary(Vec<u8>),
    /// Primary failed; read succeeded from replica at the given index.
    Replica(Vec<u8>, usize),
    /// All copies failed -- data is unavailable.
    Unavailable,
}

impl ReplicatedReadResult {
    /// Extract the payload bytes, regardless of source.
    #[must_use]
    pub fn into_payload(self) -> Option<Vec<u8>> {
        match self {
            ReplicatedReadResult::Primary(p) | ReplicatedReadResult::Replica(p, _) => Some(p),
            ReplicatedReadResult::Unavailable => None,
        }
    }

    /// Whether the primary needs repair (read succeeded from a replica).
    #[must_use]
    pub const fn primary_needs_repair(&self) -> bool {
        matches!(self, ReplicatedReadResult::Replica(_, _))
    }

    /// Whether any copy was found (primary or replica).
    #[must_use]
    pub const fn is_available(&self) -> bool {
        !matches!(self, ReplicatedReadResult::Unavailable)
    }
}

// ---------------------------------------------------------------------------
// Core replication operations
// ---------------------------------------------------------------------------

/// Write page data to the primary store and all replicas.
///
/// Returns an error if any write fails. Callers should treat a partial
/// write (some replicas succeeded, some failed) as an error and retry or
/// mark the failed replicas as suspect.
pub fn replicated_put(
    primary: &mut LocalObjectStore,
    replicas: &mut [&mut LocalObjectStore],
    key: &ObjectKey,
    data: &[u8],
) -> tidefs_local_object_store::Result<()> {
    primary.put(*key, data)?;
    for replica in replicas.iter_mut() {
        replica.put(*key, data)?;
    }
    Ok(())
}

/// Read page data with automatic failover.
///
/// Tries the primary store first. If the key is missing or the read fails,
/// tries each replica in order. Returns [`ReplicatedReadResult::Unavailable`]
/// only when all copies are missing.
///
/// # Automatic repair
///
/// When this function returns [`ReplicatedReadResult::Replica`], the caller
/// should invoke [`repair_primary`] to restore the primary copy.
pub fn replicated_get(
    primary: &LocalObjectStore,
    replicas: &[&LocalObjectStore],
    key: &ObjectKey,
) -> tidefs_local_object_store::Result<ReplicatedReadResult> {
    if let Some(data) = primary.get(*key)? {
        return Ok(ReplicatedReadResult::Primary(data));
    }

    for (i, replica) in replicas.iter().enumerate() {
        match replica.get(*key)? {
            Some(data) => return Ok(ReplicatedReadResult::Replica(data, i)),
            None => continue,
        }
    }

    Ok(ReplicatedReadResult::Unavailable)
}

/// Repair the primary copy by rewriting it from known-good replica data.
///
/// Called after [`replicated_get`] returns [`ReplicatedReadResult::Replica`]
/// to restore the primary to a healthy state.
pub fn repair_primary(
    primary: &mut LocalObjectStore,
    key: &ObjectKey,
    data: &[u8],
) -> tidefs_local_object_store::Result<()> {
    primary.put(*key, data)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// ReplicatedDirPageIndex -- convenience wrapper
// ---------------------------------------------------------------------------

/// A directory page index with automatic replication and failover.
///
/// Wraps the underlying page data and transparently replicates writes
/// to replica stores. On reads, failover is attempted automatically
/// with automatic primary repair.
///
/// The caller is responsible for opening the [`LocalObjectStore`]
/// instances (primary and replicas) and passing them in.
pub struct ReplicatedDirPageIndex {
    policy: MetadataRedundancyPolicy,
    primary: LocalObjectStore,
    replicas: Vec<LocalObjectStore>,
    repair_count: u64,
    failover_count: u64,
}

impl ReplicatedDirPageIndex {
    /// Create a new replicated index with the given policy.
    ///
    /// `primary` is the primary object store. `replicas` are the replica
    /// stores. The number of replicas must match `policy.replica_count()`
    /// when `policy.is_enabled()`, or be empty when redundancy is disabled.
    ///
    /// # Panics
    ///
    /// Panics if the number of replicas does not match the policy.
    pub fn new(
        policy: MetadataRedundancyPolicy,
        primary: LocalObjectStore,
        replicas: Vec<LocalObjectStore>,
    ) -> Self {
        assert_eq!(
            replicas.len(),
            policy.replica_count(),
            "replica count must match policy replica_count"
        );

        ReplicatedDirPageIndex {
            policy,
            primary,
            replicas,
            repair_count: 0,
            failover_count: 0,
        }
    }

    /// Return a reference to the primary store.
    #[must_use]
    pub fn primary(&self) -> &LocalObjectStore {
        &self.primary
    }

    /// Return a mutable reference to the primary store.
    #[must_use]
    pub fn primary_mut(&mut self) -> &mut LocalObjectStore {
        &mut self.primary
    }

    /// Return a slice of replica stores (immutable).
    #[must_use]
    pub fn replicas(&self) -> &[LocalObjectStore] {
        &self.replicas
    }

    /// Return mutable references to replica stores.
    #[must_use]
    pub fn replicas_mut(&mut self) -> &mut [LocalObjectStore] {
        &mut self.replicas
    }

    /// Return the redundancy policy.
    #[must_use]
    pub const fn policy(&self) -> MetadataRedundancyPolicy {
        self.policy
    }

    /// Number of times automatic primary repair was performed.
    #[must_use]
    pub const fn repair_count(&self) -> u64 {
        self.repair_count
    }

    /// Number of times failover (replica read) was used.
    #[must_use]
    pub const fn failover_count(&self) -> u64 {
        self.failover_count
    }

    /// Put a page with replication to all stores.
    pub fn put(&mut self, key: ObjectKey, data: &[u8]) -> tidefs_local_object_store::Result<()> {
        if !self.policy.is_enabled() {
            return self.primary.put(key, data).map(|_| ());
        }

        let mut replica_refs: Vec<&mut LocalObjectStore> = self.replicas.iter_mut().collect();
        replicated_put(&mut self.primary, &mut replica_refs, &key, data)
    }

    /// Get a page with automatic failover and repair.
    ///
    /// If the primary is missing and a replica has the data, the primary
    /// is automatically repaired before returning.
    pub fn get(&mut self, key: ObjectKey) -> tidefs_local_object_store::Result<Option<Vec<u8>>> {
        if !self.policy.is_enabled() {
            return self.primary.get(key);
        }

        let replica_refs: Vec<&LocalObjectStore> = self.replicas.iter().collect();
        let result = replicated_get(&self.primary, &replica_refs, &key)?;

        match result {
            ReplicatedReadResult::Primary(data) => Ok(Some(data)),
            ReplicatedReadResult::Replica(data, _replica_idx) => {
                self.failover_count += 1;
                // Automatic repair: rewrite primary from replica data
                repair_primary(&mut self.primary, &key, &data)?;
                self.repair_count += 1;
                Ok(Some(data))
            }
            ReplicatedReadResult::Unavailable => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_store_at(dir: &tempfile::TempDir) -> LocalObjectStore {
        LocalObjectStore::open(dir.path()).unwrap()
    }

    fn temp_dir() -> tempfile::TempDir {
        tempfile::TempDir::new().unwrap()
    }

    fn dummy_key(id: u64) -> ObjectKey {
        ObjectKey::from_name(alloc::format!("test:page:{id:08x}"))
    }

    fn dummy_data(seed: u8) -> Vec<u8> {
        (0..64u8).map(|i| seed.wrapping_add(i)).collect()
    }

    // -- MetadataRedundancyPolicy --

    #[test]
    fn policy_default_is_replication_factor_2() {
        let p = MetadataRedundancyPolicy::default();
        assert_eq!(p.replication_factor, 2);
        assert!(p.is_enabled());
        assert_eq!(p.replica_count(), 1);
    }

    #[test]
    fn policy_factor_1_means_no_redundancy() {
        let p = MetadataRedundancyPolicy::new(1);
        assert_eq!(p.replication_factor, 1);
        assert!(!p.is_enabled());
        assert_eq!(p.replica_count(), 0);
    }

    #[test]
    fn policy_factor_0_clamped_to_1() {
        let p = MetadataRedundancyPolicy::new(0);
        assert_eq!(p.replication_factor, 1);
    }

    #[test]
    fn policy_factor_3_has_two_replicas() {
        let p = MetadataRedundancyPolicy::new(3);
        assert_eq!(p.replication_factor, 3);
        assert!(p.is_enabled());
        assert_eq!(p.replica_count(), 2);
    }

    // -- replicated_put / replicated_get --

    #[test]
    fn replicated_put_write_to_primary_and_replica() {
        let p1 = temp_dir();
        let p2 = temp_dir();
        let mut primary = open_store_at(&p1);
        let mut replica = open_store_at(&p2);
        let key = dummy_key(1);
        let data = dummy_data(42);

        replicated_put(&mut primary, &mut [&mut replica], &key, &data).unwrap();

        assert!(primary.get(key).unwrap().is_some());
        assert!(replica.get(key).unwrap().is_some());
    }

    #[test]
    fn replicated_get_returns_from_primary_when_present() {
        let p1 = temp_dir();
        let p2 = temp_dir();
        let mut primary = open_store_at(&p1);
        let mut replica = open_store_at(&p2);
        let key = dummy_key(2);
        let data = dummy_data(7);

        replicated_put(&mut primary, &mut [&mut replica], &key, &data).unwrap();

        let replica_refs: Vec<&LocalObjectStore> = vec![&replica];
        let result = replicated_get(&primary, &replica_refs, &key).unwrap();
        assert_eq!(result, ReplicatedReadResult::Primary(data));
    }

    #[test]
    fn replicated_get_failover_to_replica_when_primary_missing() {
        let p1 = temp_dir();
        let p2 = temp_dir();
        let primary = open_store_at(&p1);
        let mut replica = open_store_at(&p2);
        let key = dummy_key(3);
        let data = dummy_data(99);

        // Write only to replica (simulate primary loss)
        replica.put(key, &data).unwrap();

        let replica_refs: Vec<&LocalObjectStore> = vec![&replica];
        let result = replicated_get(&primary, &replica_refs, &key).unwrap();
        assert_eq!(result, ReplicatedReadResult::Replica(data, 0));
    }

    #[test]
    fn replicated_get_failover_to_second_replica() {
        let p1 = temp_dir();
        let p2 = temp_dir();
        let p3 = temp_dir();
        let primary = open_store_at(&p1);
        let replica1 = open_store_at(&p2);
        let mut replica2 = open_store_at(&p3);
        let key = dummy_key(4);
        let data = dummy_data(55);

        // Write only to second replica (replica1 empty)
        replica2.put(key, &data).unwrap();

        let replica_refs: Vec<&LocalObjectStore> = vec![&replica1, &replica2];
        let result = replicated_get(&primary, &replica_refs, &key).unwrap();
        assert_eq!(result, ReplicatedReadResult::Replica(data, 1));
    }

    #[test]
    fn replicated_get_unavailable_when_all_copies_missing() {
        let p1 = temp_dir();
        let p2 = temp_dir();
        let primary = open_store_at(&p1);
        let replica = open_store_at(&p2);
        let key = dummy_key(5);

        let replica_refs: Vec<&LocalObjectStore> = vec![&replica];
        let result = replicated_get(&primary, &replica_refs, &key).unwrap();
        assert_eq!(result, ReplicatedReadResult::Unavailable);
    }

    // -- repair_primary --

    #[test]
    fn repair_primary_restores_missing_copy() {
        let p1 = temp_dir();
        let p2 = temp_dir();
        let mut primary = open_store_at(&p1);
        let _replica = open_store_at(&p2);
        let key = dummy_key(6);
        let data = dummy_data(77);

        // Primary is missing the key
        assert!(primary.get(key).unwrap().is_none());

        // Repair from replica data
        repair_primary(&mut primary, &key, &data).unwrap();

        // Primary now has the data
        let restored = primary.get(key).unwrap();
        assert_eq!(restored, Some(data));
    }

    // -- ReplicatedReadResult helpers --

    #[test]
    fn result_into_payload_primary() {
        let data = vec![1u8, 2, 3];
        let r = ReplicatedReadResult::Primary(data.clone());
        assert_eq!(r.into_payload(), Some(data));
    }

    #[test]
    fn result_into_payload_replica() {
        let data = vec![4u8, 5, 6];
        let r = ReplicatedReadResult::Replica(data.clone(), 0);
        assert_eq!(r.into_payload(), Some(data));
    }

    #[test]
    fn result_into_payload_unavailable() {
        assert_eq!(ReplicatedReadResult::Unavailable.into_payload(), None);
    }

    #[test]
    fn result_primary_needs_repair() {
        assert!(!ReplicatedReadResult::Primary(vec![1]).primary_needs_repair());
        assert!(ReplicatedReadResult::Replica(vec![1], 0).primary_needs_repair());
        assert!(!ReplicatedReadResult::Unavailable.primary_needs_repair());
    }

    #[test]
    fn result_is_available() {
        assert!(ReplicatedReadResult::Primary(vec![1]).is_available());
        assert!(ReplicatedReadResult::Replica(vec![1], 0).is_available());
        assert!(!ReplicatedReadResult::Unavailable.is_available());
    }

    // -- ReplicatedDirPageIndex --

    #[test]
    fn replicated_index_put_get_roundtrip() {
        let p1 = temp_dir();
        let p2 = temp_dir();
        let primary = open_store_at(&p1);
        let replica = open_store_at(&p2);
        let policy = MetadataRedundancyPolicy::default();
        let mut idx = ReplicatedDirPageIndex::new(policy, primary, vec![replica]);
        let key = dummy_key(10);
        let data = dummy_data(33);

        idx.put(key, &data).unwrap();

        let result = idx.get(key).unwrap();
        assert_eq!(result, Some(data));
        assert_eq!(idx.failover_count(), 0);
        assert_eq!(idx.repair_count(), 0);
    }

    #[test]
    fn replicated_index_failover_and_auto_repair() {
        let p1 = temp_dir();
        let p2 = temp_dir();
        let primary = open_store_at(&p1);
        let replica = open_store_at(&p2);
        let policy = MetadataRedundancyPolicy::default();
        let mut idx = ReplicatedDirPageIndex::new(policy, primary, vec![replica]);
        let key = dummy_key(99);
        let data = dummy_data(88);

        // Write to replica directly, bypass primary (simulate device loss)
        idx.replicas_mut()[0].put(key, &data).unwrap();

        // Read through index: primary missing, failover to replica, auto-repair
        let result = idx.get(key).unwrap();
        assert_eq!(result, Some(data.clone()));
        assert_eq!(idx.failover_count(), 1);
        assert_eq!(idx.repair_count(), 1);

        // Primary now has the data (auto-repaired)
        let primary_has = idx.primary().get(key).unwrap();
        assert_eq!(primary_has, Some(data));
    }

    #[test]
    fn replicated_index_no_redundancy_disables_replication() {
        let p1 = temp_dir();
        let primary = open_store_at(&p1);
        let policy = MetadataRedundancyPolicy::new(1);
        let mut idx = ReplicatedDirPageIndex::new(policy, primary, vec![]);
        let key = dummy_key(12);
        let data = dummy_data(55);

        idx.put(key, &data).unwrap();

        let result = idx.get(key).unwrap();
        assert_eq!(result, Some(data));
        assert_eq!(idx.failover_count(), 0);
    }

    #[test]
    fn replicated_index_double_failure_all_copies_missing() {
        let p1 = temp_dir();
        let p2 = temp_dir();
        let primary = open_store_at(&p1);
        let replica = open_store_at(&p2);
        let policy = MetadataRedundancyPolicy::default();
        let mut idx = ReplicatedDirPageIndex::new(policy, primary, vec![replica]);
        let key = dummy_key(13);

        // Neither primary nor replica has the data
        let result = idx.get(key).unwrap();
        assert_eq!(result, None);
        assert_eq!(idx.failover_count(), 0);
    }

    #[test]
    fn replicated_index_cross_store_isolation() {
        let p1 = temp_dir();
        let p2 = temp_dir();
        let p3 = temp_dir();
        let p4 = temp_dir();

        let policy = MetadataRedundancyPolicy::default();
        let mut idx_a =
            ReplicatedDirPageIndex::new(policy, open_store_at(&p1), vec![open_store_at(&p2)]);
        let mut idx_b =
            ReplicatedDirPageIndex::new(policy, open_store_at(&p3), vec![open_store_at(&p4)]);

        let key = dummy_key(20);
        let data_a = dummy_data(10);
        let data_b = dummy_data(20);

        idx_a.put(key, &data_a).unwrap();
        idx_b.put(key, &data_b).unwrap();

        assert_eq!(idx_a.get(key).unwrap(), Some(data_a));
        assert_eq!(idx_b.get(key).unwrap(), Some(data_b));
    }

    #[test]
    fn replicated_index_replica_count_3() {
        let p1 = temp_dir();
        let p2 = temp_dir();
        let p3 = temp_dir();

        let policy = MetadataRedundancyPolicy::new(3);
        let mut idx = ReplicatedDirPageIndex::new(
            policy,
            open_store_at(&p1),
            vec![open_store_at(&p2), open_store_at(&p3)],
        );

        assert_eq!(idx.policy().replica_count(), 2);
        assert_eq!(idx.replicas().len(), 2);

        let key = dummy_key(30);
        let data = dummy_data(99);
        idx.put(key, &data).unwrap();

        // All three copies exist
        assert!(idx.primary().get(key).unwrap().is_some());
        assert!(idx.replicas()[0].get(key).unwrap().is_some());
        assert!(idx.replicas()[1].get(key).unwrap().is_some());
    }

    #[test]
    fn replicated_index_failover_counts_across_multiple_reads() {
        let p1 = temp_dir();
        let p2 = temp_dir();
        let policy = MetadataRedundancyPolicy::default();
        let mut idx =
            ReplicatedDirPageIndex::new(policy, open_store_at(&p1), vec![open_store_at(&p2)]);

        // Write several keys only to replica
        for i in 0..5u64 {
            let key = dummy_key(100 + i);
            let data = dummy_data(i as u8);
            idx.replicas_mut()[0].put(key, &data).unwrap();
            let result = idx.get(key).unwrap();
            assert_eq!(result, Some(data));
        }

        assert_eq!(idx.failover_count(), 5);
        assert_eq!(idx.repair_count(), 5);
    }

    #[test]
    fn replicated_index_put_then_get_primary_intact_no_failover() {
        let p1 = temp_dir();
        let p2 = temp_dir();
        let policy = MetadataRedundancyPolicy::default();
        let mut idx =
            ReplicatedDirPageIndex::new(policy, open_store_at(&p1), vec![open_store_at(&p2)]);

        for i in 0..10u64 {
            let key = dummy_key(200 + i);
            let data = dummy_data(i as u8);
            idx.put(key, &data).unwrap();
        }

        for i in 0..10u64 {
            let key = dummy_key(200 + i);
            let result = idx.get(key).unwrap();
            assert!(result.is_some());
        }

        // Primary was never missing; no failover
        assert_eq!(idx.failover_count(), 0);
        assert_eq!(idx.repair_count(), 0);
    }
}

// ---------------------------------------------------------------------------
// DirBTreeReplicator — write-side replication for B-tree pages
// ---------------------------------------------------------------------------

/// Replicates B-tree page writes to replica stores.
///
/// When a directory B-tree page is flushed to the primary store,
/// [`DirBTreeReplicator::replicate`] writes the same page data to all
/// configured replica [`LocalObjectStore`] instances.
///
/// The caller is responsible for writing to the primary store first;
/// this replicator only handles the replica copies.
#[derive(Debug)]
pub struct DirBTreeReplicator {
    policy: MetadataRedundancyPolicy,
    replicas: Vec<LocalObjectStore>,
}

impl DirBTreeReplicator {
    /// Create a replicator with the given redundancy policy.
    ///
    /// The number of replicas must equal `policy.replica_count()`.
    /// An empty replica set is valid for a policy with factor 1.
    ///
    /// # Panics
    ///
    /// Panics if `replicas.len()` does not match `policy.replica_count()`.
    #[must_use]
    pub fn new(policy: MetadataRedundancyPolicy, replicas: Vec<LocalObjectStore>) -> Self {
        assert_eq!(
            replicas.len(),
            policy.replica_count(),
            "DirBTreeReplicator: replica count ({}) must match policy replica_count ({})",
            replicas.len(),
            policy.replica_count(),
        );
        DirBTreeReplicator { policy, replicas }
    }

    /// Replicate a page write to all configured replica stores.
    ///
    /// The primary store must have already received the write. This method
    /// only touches the replicas. Returns an error if any replica write
    /// fails.
    pub fn replicate(
        &mut self,
        key: &ObjectKey,
        data: &[u8],
    ) -> tidefs_local_object_store::Result<()> {
        for replica in &mut self.replicas {
            replica.put(*key, data)?;
        }
        Ok(())
    }

    /// Return the redundancy policy.
    #[must_use]
    pub const fn policy(&self) -> MetadataRedundancyPolicy {
        self.policy
    }
}

// ---------------------------------------------------------------------------
// DirBTreeFailover — read-side failover with automatic primary repair
// ---------------------------------------------------------------------------

/// Reads directory B-tree pages with automatic replica failover and repair.
///
/// On read, tries the primary store first. If the key is missing, each
/// replica is tried in order. When a replica succeeds, the primary is
/// automatically repaired (the data is rewritten to the primary store)
/// before returning.
///
/// Counters track how many times failover and repair occurred.
#[derive(Debug)]
pub struct DirBTreeFailover {
    policy: MetadataRedundancyPolicy,
    primary: LocalObjectStore,
    replicas: Vec<LocalObjectStore>,
    failover_count: u64,
    repair_count: u64,
}

impl DirBTreeFailover {
    /// Create a failover reader with the given redundancy policy.
    ///
    /// # Panics
    ///
    /// Panics if `replicas.len()` does not match `policy.replica_count()`.
    #[must_use]
    pub fn new(
        policy: MetadataRedundancyPolicy,
        primary: LocalObjectStore,
        replicas: Vec<LocalObjectStore>,
    ) -> Self {
        assert_eq!(
            replicas.len(),
            policy.replica_count(),
            "DirBTreeFailover: replica count must match policy replica_count"
        );
        DirBTreeFailover {
            policy,
            primary,
            replicas,
            failover_count: 0,
            repair_count: 0,
        }
    }

    /// Read a page with automatic failover.
    ///
    /// If the primary has the data, returns it. Otherwise, tries each
    /// replica in order. When a replica supplies the data, the primary
    /// is automatically repaired before returning.
    ///
    /// Returns `Ok(None)` only when all copies (primary + replicas) are
    /// missing.
    pub fn read(&mut self, key: ObjectKey) -> tidefs_local_object_store::Result<Option<Vec<u8>>> {
        if !self.policy.is_enabled() {
            return self.primary.get(key);
        }

        let replica_refs: Vec<&LocalObjectStore> = self.replicas.iter().collect();
        let result = replicated_get(&self.primary, &replica_refs, &key)?;

        match result {
            ReplicatedReadResult::Primary(data) => Ok(Some(data)),
            ReplicatedReadResult::Replica(data, _replica_idx) => {
                self.failover_count += 1;
                repair_primary(&mut self.primary, &key, &data)?;
                self.repair_count += 1;
                Ok(Some(data))
            }
            ReplicatedReadResult::Unavailable => Ok(None),
        }
    }

    /// Return the redundancy policy.
    #[must_use]
    pub const fn policy(&self) -> MetadataRedundancyPolicy {
        self.policy
    }

    /// Return a reference to the primary store.
    #[must_use]
    pub fn primary(&self) -> &LocalObjectStore {
        &self.primary
    }

    /// Number of times automatic failover (replica read) was triggered.
    #[must_use]
    pub const fn failover_count(&self) -> u64 {
        self.failover_count
    }

    /// Number of times the primary was automatically repaired.
    #[must_use]
    pub const fn repair_count(&self) -> u64 {
        self.repair_count
    }
}
