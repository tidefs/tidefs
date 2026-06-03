//! Deterministic object enumeration protocol for rebuild state transfer.
//!
//! Defines the [`PlacementMap`] -- a versioned, immutable snapshot of the
//! placement table -- plus the [`ObjectEnumerator`] trait and
//! [`ObjectPlacementEntry`] type used to produce a total-ordered stream of
//! (object, node, shard) tuples across a membership epoch.
//!
//! Enumerations are deterministic given a fixed [`PlacementMap`] version,
//! so two nodes independently enumerating the same namespace arrive at
//! identical object lists.
//!
//! This is consumed by `tidefs-rebuild-planner` to compute per-node object
//! delta sets (objects a node should hold vs. objects it currently holds).
//!
//! # Placement map versioning
//!
//! Each [`PlacementMap`] carries a monotonically increasing `version` and a
//! membership `epoch`. Clients observe one consistent map version, and
//! rebalance moves data deterministically by computing the delta between
//! two versioned maps. The version increments when the placement table
//! changes (membership join/leave, rebalance completion).

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use tidefs_membership_epoch::{EpochId, MemberId};

// ── ShardKind ────────────────────────────────────────────────────────

/// Classifies the role of a shard within a durability layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ShardKind {
    /// Primary shard — the authoritative copy for read/write fast path.
    Primary,
    /// Secondary replica shard — full copy of the object data.
    Replica,
}

// ── ObjectPlacementEntry ─────────────────────────────────────────────

/// A single entry in the deterministic enumeration: an object placed on a
/// specific node with a given shard role.
///
/// Sorted by `(object_id, member_id)` to guarantee identical output across
/// independent enumerations of the same namespace.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ObjectPlacementEntry {
    /// The object identifier.
    pub object_id: u64,
    /// The member (node) that holds this object.
    pub member_id: MemberId,
    /// The shard role (primary vs replica).
    pub shard_kind: ShardKind,
}

impl ObjectPlacementEntry {
    /// Create a new placement entry.
    #[must_use]
    pub fn new(object_id: u64, member_id: MemberId, shard_kind: ShardKind) -> Self {
        Self {
            object_id,
            member_id,
            shard_kind,
        }
    }
}

// ── ObjectEnumerator trait ───────────────────────────────────────────

/// Deterministic object enumerator: iterates placed objects across a
/// membership epoch, producing a total-ordered list of placement entries.
///
/// Implementations vary by transport: loopback-network enumeration uses
/// in-process placement tables; real transport enumeration queries remote
/// nodes over session channels.
pub trait ObjectEnumerator {
    /// Error type for enumeration failures.
    type Error: std::fmt::Debug;

    /// Enumerate all placed objects for a given membership epoch and
    /// placement table version.
    ///
    /// Returns a `Vec` sorted deterministically by `(object_id, member_id)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the enumeration cannot complete (e.g., a remote
    /// node is unreachable and the placement state is not locally cached).
    fn enumerate_objects(
        &self,
        membership_epoch: EpochId,
        placement_version: u64,
    ) -> Result<Vec<ObjectPlacementEntry>, Self::Error>;
}

// ── PlacementTableObjectEnumerator ──────────────────────────────────

/// An [`ObjectEnumerator`] that reads directly from an in-memory placement
/// table without contacting remote nodes.
///
/// Suitable for tests and for nodes that already hold a complete placement
/// state in local memory.
pub struct PlacementTableObjectEnumerator {
    /// Maps `object_id -> set of member_ids` that hold the object.
    placement: BTreeMap<u64, BTreeSet<MemberId>>,
}

impl PlacementTableObjectEnumerator {
    /// Create an enumerator from an existing placement map.
    ///
    /// Each entry `(object_id, members)` records which members hold the
    /// object. The first member listed is treated as primary; subsequent
    /// members are replicas.
    #[must_use]
    pub fn new(placement: BTreeMap<u64, BTreeSet<MemberId>>) -> Self {
        Self { placement }
    }

    /// Build from a flat set of `(object_id, member_id)` pairs.
    #[must_use]
    pub fn from_pairs(pairs: &[(u64, MemberId)]) -> Self {
        let mut placement: BTreeMap<u64, BTreeSet<MemberId>> = BTreeMap::new();
        for &(obj_id, member_id) in pairs {
            placement.entry(obj_id).or_default().insert(member_id);
        }
        Self { placement }
    }

    /// Add a single object placement.
    pub fn add_placement(&mut self, object_id: u64, member_id: MemberId) {
        self.placement
            .entry(object_id)
            .or_default()
            .insert(member_id);
    }
}

impl ObjectEnumerator for PlacementTableObjectEnumerator {
    type Error = std::convert::Infallible;

    fn enumerate_objects(
        &self,
        _membership_epoch: EpochId,
        _placement_version: u64,
    ) -> Result<Vec<ObjectPlacementEntry>, Self::Error> {
        let mut entries = Vec::new();
        for (&object_id, members) in &self.placement {
            let mut sorted_members: Vec<MemberId> = members.iter().copied().collect();
            sorted_members.sort();
            for (idx, member_id) in sorted_members.iter().enumerate() {
                let shard_kind = if idx == 0 {
                    ShardKind::Primary
                } else {
                    ShardKind::Replica
                };
                entries.push(ObjectPlacementEntry::new(object_id, *member_id, shard_kind));
            }
        }
        // Deterministic: sort by (object_id, member_id)
        entries.sort();
        Ok(entries)
    }
}

// ── PlacementMap ─────────────────────────────────────────────────────

/// A versioned, immutable snapshot of the placement table.
///
/// Each [`PlacementMap`] binds a membership [`EpochId`] and a monotonically
/// increasing `version` to a deterministic object-to-node mapping. Two nodes
/// with the same `version` observe identical placement; a version mismatch
/// signals that a rebalance is needed.
///
/// # Versioning semantics
///
/// - `version` starts at 1 and increments on every placement change
///   (membership join/leave or rebalance completion).
/// - Version 0 is reserved as "uninitialized" / "no placement yet".
/// - The mapping is immutable after construction -- a new version requires
///   a new [`PlacementMap`] instance.
///
/// # Rebalance stability
///
/// Rebalance determinism follows from the versioned snapshot: computing the
/// delta between two [`PlacementMap`] instances (via [`enumerate`]) yields
/// the exact set of objects that must move. No object moves between two
/// identical versions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementMap {
    /// Monotonically increasing placement version (1..).
    pub version: u64,
    /// Membership epoch this map was computed for.
    pub epoch: EpochId,
    /// Immutable object-to-member mapping.
    mapping: BTreeMap<u64, BTreeSet<MemberId>>,
}

impl PlacementMap {
    /// Create a new placement map with the given version, epoch, and mapping.
    ///
    /// # Panics
    ///
    /// Panics if `version` is 0 (reserved for "uninitialized").
    #[must_use]
    pub fn new(version: u64, epoch: EpochId, mapping: BTreeMap<u64, BTreeSet<MemberId>>) -> Self {
        assert!(version > 0, "PlacementMap version 0 is reserved");
        Self {
            version,
            epoch,
            mapping,
        }
    }

    /// Create the zero-version sentinel: no placement yet.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            version: 0,
            epoch: EpochId(0),
            mapping: BTreeMap::new(),
        }
    }

    /// Whether this map has a real placement (version > 0).
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.version > 0
    }

    /// Number of objects in the placement map.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.mapping.len()
    }

    /// Total number of (object, member) placement entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.mapping.values().map(|m| m.len()).sum()
    }

    /// Return the set of member IDs that hold the given object.
    #[must_use]
    pub fn members_for(&self, object_id: u64) -> Option<&BTreeSet<MemberId>> {
        self.mapping.get(&object_id)
    }

    /// Whether this map's version is strictly newer than another.
    #[must_use]
    pub fn is_newer_than(&self, other: &PlacementMap) -> bool {
        self.version > other.version
    }

    /// Whether two maps share the same version (and thus placement).
    #[must_use]
    pub fn same_version_as(&self, other: &PlacementMap) -> bool {
        self.version == other.version
    }

    /// Produce a deterministic, total-ordered enumeration of all placed
    /// objects. Equivalent to what [`PlacementTableObjectEnumerator`]
    /// would return for this map.
    ///
    /// Entries are sorted by `(object_id, member_id)`, with the first
    /// member per object as Primary and subsequent members as Replica.
    #[must_use]
    pub fn enumerate(&self) -> Vec<ObjectPlacementEntry> {
        let mut entries = Vec::with_capacity(self.entry_count());
        for (&object_id, members) in &self.mapping {
            let mut sorted_members: Vec<MemberId> = members.iter().copied().collect();
            sorted_members.sort();
            for (idx, member_id) in sorted_members.iter().enumerate() {
                let shard_kind = if idx == 0 {
                    ShardKind::Primary
                } else {
                    ShardKind::Replica
                };
                entries.push(ObjectPlacementEntry::new(object_id, *member_id, shard_kind));
            }
        }
        entries.sort();
        entries
    }

    /// Return a reference to the immutable mapping.
    #[must_use]
    pub fn mapping(&self) -> &BTreeMap<u64, BTreeSet<MemberId>> {
        &self.mapping
    }

    /// Consume self and return the inner mapping.
    #[must_use]
    pub fn into_mapping(self) -> BTreeMap<u64, BTreeSet<MemberId>> {
        self.mapping
    }
}

// ── Per-node object delta computation ───────────────────────────────

/// Delta between what a node should hold and what it currently holds.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PerNodeObjectDelta {
    /// Objects the node should hold but currently does not (need transfer).
    pub missing: BTreeSet<u64>,
    /// Objects the node holds but should not (can be retired).
    pub excess: BTreeSet<u64>,
    /// Objects the node holds and should hold (no change needed).
    pub current: BTreeSet<u64>,
}

impl PerNodeObjectDelta {
    /// Whether any objects need transfer or retirement.
    #[must_use]
    pub fn has_work(&self) -> bool {
        !self.missing.is_empty() || !self.excess.is_empty()
    }

    /// Total number of objects that need to be transferred.
    #[must_use]
    pub fn missing_count(&self) -> usize {
        self.missing.len()
    }

    /// Total number of objects that can be retired.
    #[must_use]
    pub fn excess_count(&self) -> usize {
        self.excess.len()
    }
}

/// Compute per-node object deltas from a full enumeration and per-node
/// current-object sets.
///
/// For each node in the enumeration, computes:
/// - `missing`: objects in the enumeration for this node that the node
///   does not currently hold.
/// - `excess`: objects the node currently holds that are not in the
///   enumeration for this node.
/// - `current`: objects in both sets (no change needed).
#[must_use]
pub fn compute_per_node_object_deltas(
    enumeration: &[ObjectPlacementEntry],
    current_node_objects: &BTreeMap<MemberId, BTreeSet<u64>>,
) -> BTreeMap<MemberId, PerNodeObjectDelta> {
    // Build the desired set from enumeration: member_id -> set of object_ids
    let mut desired: BTreeMap<MemberId, BTreeSet<u64>> = BTreeMap::new();
    for entry in enumeration {
        desired
            .entry(entry.member_id)
            .or_default()
            .insert(entry.object_id);
    }

    // Collect all member ids from both desired and current
    let mut all_members: BTreeSet<MemberId> = BTreeSet::new();
    for m in desired.keys() {
        all_members.insert(*m);
    }
    for m in current_node_objects.keys() {
        all_members.insert(*m);
    }

    let mut deltas: BTreeMap<MemberId, PerNodeObjectDelta> = BTreeMap::new();
    for member_id in all_members {
        let desired_objects = desired.get(&member_id).cloned().unwrap_or_default();
        let current_objects = current_node_objects
            .get(&member_id)
            .cloned()
            .unwrap_or_default();

        let mut delta = PerNodeObjectDelta::default();
        for obj in &desired_objects {
            if current_objects.contains(obj) {
                delta.current.insert(*obj);
            } else {
                delta.missing.insert(*obj);
            }
        }
        for obj in &current_objects {
            if !desired_objects.contains(obj) {
                delta.excess.insert(*obj);
            }
        }
        deltas.insert(member_id, delta);
    }
    deltas
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(id: u64) -> MemberId {
        MemberId(id)
    }

    #[test]
    fn empty_enumeration_produces_empty_deltas() {
        let enumeration = vec![];
        let current: BTreeMap<MemberId, BTreeSet<u64>> = BTreeMap::new();
        let deltas = compute_per_node_object_deltas(&enumeration, &current);
        assert!(deltas.is_empty());
    }

    #[test]
    fn all_current_no_deltas() {
        let enumeration = vec![
            ObjectPlacementEntry::new(1, mid(10), ShardKind::Primary),
            ObjectPlacementEntry::new(1, mid(20), ShardKind::Replica),
        ];
        let mut current: BTreeMap<MemberId, BTreeSet<u64>> = BTreeMap::new();
        current.insert(mid(10), [1].into());
        current.insert(mid(20), [1].into());

        let deltas = compute_per_node_object_deltas(&enumeration, &current);

        assert!(!deltas[&mid(10)].has_work());
        assert!(!deltas[&mid(20)].has_work());
        assert_eq!(deltas[&mid(10)].current.len(), 1);
    }

    #[test]
    fn missing_object_generates_transfer() {
        let enumeration = vec![ObjectPlacementEntry::new(42, mid(10), ShardKind::Primary)];
        let current: BTreeMap<MemberId, BTreeSet<u64>> = BTreeMap::new();
        // node 10 holds nothing

        let deltas = compute_per_node_object_deltas(&enumeration, &current);
        assert!(deltas[&mid(10)].has_work());
        assert_eq!(deltas[&mid(10)].missing, [42].into());
        assert!(deltas[&mid(10)].excess.is_empty());
    }

    #[test]
    fn excess_object_generates_retirement() {
        let enumeration = vec![];
        let mut current: BTreeMap<MemberId, BTreeSet<u64>> = BTreeMap::new();
        current.insert(mid(10), [99].into());

        let deltas = compute_per_node_object_deltas(&enumeration, &current);
        assert!(deltas[&mid(10)].has_work());
        assert!(deltas[&mid(10)].missing.is_empty());
        assert_eq!(deltas[&mid(10)].excess, [99].into());
    }

    #[test]
    fn mixed_missing_and_excess() {
        let enumeration = vec![
            ObjectPlacementEntry::new(10, mid(1), ShardKind::Primary),
            ObjectPlacementEntry::new(20, mid(1), ShardKind::Replica),
            ObjectPlacementEntry::new(20, mid(2), ShardKind::Primary),
        ];
        let mut current: BTreeMap<MemberId, BTreeSet<u64>> = BTreeMap::new();
        current.insert(mid(1), [20, 30].into()); // has 20 (ok), has 30 (excess), missing 10
        current.insert(mid(2), [50].into()); // has 50 (excess), missing 20

        let deltas = compute_per_node_object_deltas(&enumeration, &current);

        // Node 1: missing {10}, excess {30}, current {20}
        assert_eq!(deltas[&mid(1)].missing, [10].into());
        assert_eq!(deltas[&mid(1)].excess, [30].into());
        assert_eq!(deltas[&mid(1)].current, [20].into());
        assert!(deltas[&mid(1)].has_work());

        // Node 2: missing {20}, excess {50}, current {}
        assert_eq!(deltas[&mid(2)].missing, [20].into());
        assert_eq!(deltas[&mid(2)].excess, [50].into());
        assert!(deltas[&mid(2)].current.is_empty());
        assert!(deltas[&mid(2)].has_work());
    }

    // ── PlacementMap tests ────────────────────────────────────────

    #[test]
    fn placement_map_new_creates_initialized_map() {
        let mut mapping = BTreeMap::new();
        mapping.insert(42, [mid(1)].into());
        let map = PlacementMap::new(1, EpochId(7), mapping);

        assert!(map.is_initialized());
        assert_eq!(map.version, 1);
        assert_eq!(map.epoch, EpochId(7));
        assert_eq!(map.object_count(), 1);
    }

    #[test]
    fn placement_map_empty_is_uninitialized() {
        let map = PlacementMap::empty();
        assert!(!map.is_initialized());
        assert_eq!(map.version, 0);
        assert_eq!(map.object_count(), 0);
    }

    #[test]
    #[should_panic(expected = "version 0 is reserved")]
    fn placement_map_rejects_version_zero() {
        let _ = PlacementMap::new(0, EpochId(1), BTreeMap::new());
    }

    #[test]
    fn placement_map_version_comparison() {
        let map_v1 = PlacementMap::new(1, EpochId(1), BTreeMap::new());
        let map_v2 = PlacementMap::new(2, EpochId(2), BTreeMap::new());
        let map_v1_dup = PlacementMap::new(1, EpochId(3), BTreeMap::new());

        assert!(map_v2.is_newer_than(&map_v1));
        assert!(!map_v1.is_newer_than(&map_v2));
        assert!(map_v1.same_version_as(&map_v1_dup));
        assert!(!map_v1.same_version_as(&map_v2));
    }

    #[test]
    fn placement_map_enumerate_empty() {
        let map = PlacementMap::new(1, EpochId(0), BTreeMap::new());
        let entries = map.enumerate();
        assert!(entries.is_empty());
    }

    #[test]
    fn placement_map_enumerate_single_object() {
        let mut mapping = BTreeMap::new();
        mapping.insert(42, [mid(1)].into());
        let map = PlacementMap::new(1, EpochId(0), mapping);

        let entries = map.enumerate();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0],
            ObjectPlacementEntry::new(42, mid(1), ShardKind::Primary)
        );
    }

    #[test]
    fn placement_map_enumerate_multi_object_multi_replica() {
        let mut mapping = BTreeMap::new();
        mapping.insert(10, [mid(1), mid(2)].into());
        mapping.insert(20, [mid(3)].into());
        let map = PlacementMap::new(2, EpochId(5), mapping);

        let entries = map.enumerate();
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0],
            ObjectPlacementEntry::new(10, mid(1), ShardKind::Primary)
        );
        assert_eq!(
            entries[1],
            ObjectPlacementEntry::new(10, mid(2), ShardKind::Replica)
        );
        assert_eq!(
            entries[2],
            ObjectPlacementEntry::new(20, mid(3), ShardKind::Primary)
        );
    }

    #[test]
    fn placement_map_enumerate_deterministic() {
        let mut mapping = BTreeMap::new();
        mapping.insert(5, [mid(3), mid(1)].into()); // unordered insertion
        mapping.insert(3, [mid(2)].into());
        let map = PlacementMap::new(7, EpochId(42), mapping);

        let a = map.enumerate();
        let b = map.enumerate();
        assert_eq!(a, b);
        // (3,2), (5,1), (5,3) -- object_id first, then member_id
        assert_eq!(
            a[0],
            ObjectPlacementEntry::new(3, mid(2), ShardKind::Primary)
        );
        assert_eq!(
            a[1],
            ObjectPlacementEntry::new(5, mid(1), ShardKind::Primary)
        );
        assert_eq!(
            a[2],
            ObjectPlacementEntry::new(5, mid(3), ShardKind::Replica)
        );
    }

    #[test]
    fn placement_map_members_for() {
        let mut mapping = BTreeMap::new();
        mapping.insert(100, [mid(1), mid(2), mid(3)].into());
        let map = PlacementMap::new(1, EpochId(0), mapping);

        let members = map.members_for(100).unwrap();
        assert!(members.contains(&mid(1)));
        assert!(members.contains(&mid(2)));
        assert!(members.contains(&mid(3)));
        assert_eq!(members.len(), 3);

        assert!(map.members_for(999).is_none());
    }

    #[test]
    fn placement_map_entry_count() {
        let mut mapping = BTreeMap::new();
        mapping.insert(1, [mid(10), mid(20)].into());
        mapping.insert(2, [mid(30)].into());
        let map = PlacementMap::new(1, EpochId(0), mapping);

        assert_eq!(map.object_count(), 2);
        assert_eq!(map.entry_count(), 3);
    }

    #[test]
    fn placement_map_into_mapping() {
        let mut mapping = BTreeMap::new();
        mapping.insert(1, [mid(10)].into());
        let map = PlacementMap::new(1, EpochId(0), mapping.clone());
        let inner = map.into_mapping();
        assert_eq!(inner, mapping);
    }

    // ── PlacementTableObjectEnumerator tests ──────────────────────

    #[test]
    fn placement_table_enumerator_empty() {
        let enumerator = PlacementTableObjectEnumerator::new(BTreeMap::new());
        let result = enumerator.enumerate_objects(EpochId(0), 1).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn placement_table_enumerator_single_object() {
        let mut placement: BTreeMap<u64, BTreeSet<MemberId>> = BTreeMap::new();
        placement.insert(42, [mid(1)].into());

        let enumerator = PlacementTableObjectEnumerator::new(placement);
        let result = enumerator.enumerate_objects(EpochId(0), 1).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].object_id, 42);
        assert_eq!(result[0].member_id, mid(1));
        assert_eq!(result[0].shard_kind, ShardKind::Primary);
    }

    #[test]
    fn placement_table_enumerator_multi_object_multi_replica() {
        let mut placement: BTreeMap<u64, BTreeSet<MemberId>> = BTreeMap::new();
        placement.insert(10, [mid(1), mid(2)].into());
        placement.insert(20, [mid(3)].into());

        let enumerator = PlacementTableObjectEnumerator::new(placement);
        let result = enumerator.enumerate_objects(EpochId(0), 1).unwrap();

        // Sorted by (object_id, member_id): (10, 1), (10, 2), (20, 3)
        assert_eq!(result.len(), 3);
        assert_eq!(
            result[0],
            ObjectPlacementEntry::new(10, mid(1), ShardKind::Primary)
        );
        assert_eq!(
            result[1],
            ObjectPlacementEntry::new(10, mid(2), ShardKind::Replica)
        );
        assert_eq!(
            result[2],
            ObjectPlacementEntry::new(20, mid(3), ShardKind::Primary)
        );
    }

    #[test]
    fn placement_table_enumerator_deterministic() {
        let mut placement: BTreeMap<u64, BTreeSet<MemberId>> = BTreeMap::new();
        placement.insert(5, [mid(3), mid(1)].into()); // unordered insertion
        placement.insert(3, [mid(2)].into());

        let enumerator = PlacementTableObjectEnumerator::new(placement);
        let a = enumerator.enumerate_objects(EpochId(42), 7).unwrap();
        let b = enumerator.enumerate_objects(EpochId(42), 7).unwrap();

        assert_eq!(a, b, "same inputs must produce identical outputs");
        // (3,2), (5,1), (5,3) — object_id first, then member_id
        assert_eq!(a[0].object_id, 3);
        assert_eq!(a[1].object_id, 5);
        assert_eq!(a[1].member_id, mid(1));
        assert_eq!(a[2].member_id, mid(3));
    }

    #[test]
    fn placement_table_enumerator_from_pairs() {
        let pairs = [(42, mid(1)), (42, mid(2)), (99, mid(1))];
        let enumerator = PlacementTableObjectEnumerator::from_pairs(&pairs);
        let result = enumerator.enumerate_objects(EpochId(0), 0).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(
            result[0],
            ObjectPlacementEntry::new(42, mid(1), ShardKind::Primary)
        );
        assert_eq!(
            result[1],
            ObjectPlacementEntry::new(42, mid(2), ShardKind::Replica)
        );
        assert_eq!(
            result[2],
            ObjectPlacementEntry::new(99, mid(1), ShardKind::Primary)
        );
    }
}
