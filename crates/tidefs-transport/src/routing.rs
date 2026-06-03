//! Message routing table with membership-driven next-hop resolution.
//!
//! [`RoutingTable`] computes shortest-path routes through the known peer
//! adjacency graph derived from the membership roster and peer-manager
//! connection state.  Routes are recomputed on every `update()` call and
//! carry BLAKE3-256 domain-separated state digests for integrity
//! verification.
//!
//! # BFS shortest-path routing
//!
//! Routes are computed via breadth-first search over the adjacency graph.
//! Directly-connected peers get `path_length = 1`; relay destinations get
//! `path_length >= 2`.  Unreachable destinations resolve to `None`.
//! Tie-breaking between equal-length paths is deterministic (lowest
//! `MemberId` for next-hop).
//!
//! # BLAKE3 integrity
//!
//! Domain: `tidefs-transport-routing-v1`

use blake3::Hasher;
use std::collections::{BTreeMap, VecDeque};
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// BLAKE3 domain separator
// ---------------------------------------------------------------------------

const ROUTING_DOMAIN: &str = "tidefs-transport-routing-v1";

// ---------------------------------------------------------------------------
// RouteEntry
// ---------------------------------------------------------------------------

/// A resolved route entry for a single destination node.
///
/// Carries the immediate next-hop peer, path length (hop count),
/// and a BLAKE3-256 domain-separated digest covering the route
/// preimage: `(destination, next_hop, path_length)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    /// The immediate next-hop peer to which messages for `destination`
    /// should be forwarded.
    pub next_hop: MemberId,
    /// Number of hops from the local node to the destination.
    /// 1 = direct peer; >= 2 = relay route.
    pub path_length: u32,
    /// BLAKE3-256 digest of this route entry.
    /// Covers `(destination.0, next_hop.0, path_length)` with domain
    /// separation `tidefs-transport-routing-v1`.
    pub digest: [u8; 32],
}

impl RouteEntry {
    fn new(destination: MemberId, next_hop: MemberId, path_length: u32) -> Self {
        let digest = Self::compute_digest(destination, next_hop, path_length);
        Self {
            next_hop,
            path_length,
            digest,
        }
    }

    fn compute_digest(destination: MemberId, next_hop: MemberId, path_length: u32) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(ROUTING_DOMAIN);
        hasher.update(&destination.0.to_le_bytes());
        hasher.update(&next_hop.0.to_le_bytes());
        hasher.update(&path_length.to_le_bytes());
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// RoutingTable
// ---------------------------------------------------------------------------

/// Membership-driven routing table that resolves next-hop peers for
/// destination nodes.
///
/// The table is updated from an active-member set and a peer adjacency
/// graph (typically sourced from the membership roster and peer-manager
/// connection state).  Shortest-path routes are computed via BFS and
/// cached until the next update.
///
/// # Invariants
///
/// - Routes to `self_id` are never present (self-route exclusion).
/// - Routes are invalidated and recomputed on every `update()`.
/// - The table digest covers all route entries in canonical
///   destination order, providing deterministic integrity verification
///   for identical inputs.
pub struct RoutingTable {
    /// The local node identifier.  Routes to this node are excluded.
    self_id: Option<MemberId>,
    /// Known direct adjacencies: for each node, the set of nodes it is
    /// directly connected to.  The graph is undirected -- if A is adjacent
    /// to B, the caller must provide the symmetric entry.
    adjacencies: BTreeMap<MemberId, Vec<MemberId>>,
    /// Cached routes keyed by destination.
    routes: BTreeMap<MemberId, RouteEntry>,
    /// BLAKE3-256 digest covering the full routing table state.
    table_digest: [u8; 32],
    /// Whether routes need recomputation.
    dirty: bool,
}

impl RoutingTable {
    /// Create an empty routing table.
    pub fn new() -> Self {
        Self {
            self_id: None,
            adjacencies: BTreeMap::new(),
            routes: BTreeMap::new(),
            table_digest: Self::compute_empty_digest(),
            dirty: false,
        }
    }

    /// Set the local node identifier.
    ///
    /// Changing `self_id` invalidates all routes.
    pub fn set_self(&mut self, self_id: MemberId) {
        if self.self_id != Some(self_id) {
            self.self_id = Some(self_id);
            self.dirty = true;
        }
    }

    /// Update the routing table with fresh membership and adjacency data.
    ///
    /// `active_members` is the set of node identifiers that are currently
    /// active (typically Active and Suspected states from the roster).
    /// `adjacencies` is the undirected peer adjacency graph -- if node A
    /// has a direct transport session to node B, both `A -> [B]` and
    /// `B -> [A]` must be included.
    ///
    /// Routes are fully recomputed on every call.  This is a cheap
    /// operation for typical cluster sizes (hundreds of nodes).
    pub fn update(
        &mut self,
        active_members: &[MemberId],
        adjacencies: BTreeMap<MemberId, Vec<MemberId>>,
    ) {
        self.adjacencies = adjacencies;
        self.dirty = true;
        self.recompute_routes(active_members);
    }

    /// Resolve the route to a destination node.
    ///
    /// Returns `None` when:
    /// - `destination` is the local node (`self_id`)
    /// - No path exists to `destination` in the adjacency graph
    /// - The table has not been updated with any data
    pub fn resolve_route(&self, destination: MemberId) -> Option<&RouteEntry> {
        // Never route to self.
        if self.self_id == Some(destination) {
            return None;
        }
        self.routes.get(&destination)
    }

    /// Return the BLAKE3-256 state digest covering the full routing table.
    ///
    /// Two tables with identical self-id, adjacencies, and active members
    /// will produce identical digests.
    pub fn table_digest(&self) -> [u8; 32] {
        self.table_digest
    }

    /// Return the number of cached routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Return true if the routing table has no routes.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Return an iterator over (destination, route) pairs in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = (&MemberId, &RouteEntry)> {
        self.routes.iter()
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    /// Recompute shortest-path routes for all active members via BFS.
    fn recompute_routes(&mut self, active_members: &[MemberId]) {
        let self_id = match self.self_id {
            Some(id) => id,
            None => {
                self.routes.clear();
                self.table_digest = Self::compute_empty_digest();
                self.dirty = false;
                return;
            }
        };

        // Build a list of active member IDs (excluding self).
        let active_set: Vec<MemberId> = active_members
            .iter()
            .filter(|m| **m != self_id)
            .copied()
            .collect();

        self.routes.clear();

        if active_set.is_empty() {
            self.table_digest = Self::compute_empty_digest();
            self.dirty = false;
            return;
        }

        // BFS from self: maps node -> distance-from-self.
        // Use u64 as key (Ord + Hash) since MemberId lacks Hash but has Ord.
        let mut visited: BTreeMap<MemberId, u32> = BTreeMap::new();
        let mut queue: VecDeque<MemberId> = VecDeque::new();

        // Seed: direct neighbors of self.
        if let Some(neighbors) = self.adjacencies.get(&self_id) {
            for &neighbor in neighbors {
                if let std::collections::btree_map::Entry::Vacant(e) = visited.entry(neighbor) {
                    e.insert(1);
                    queue.push_back(neighbor);
                }
            }
        }

        // BFS traversal.
        while let Some(current) = queue.pop_front() {
            let dist = visited[&current];

            if let Some(neighbors) = self.adjacencies.get(&current) {
                for &neighbor in neighbors {
                    if neighbor == self_id {
                        continue;
                    }
                    if let std::collections::btree_map::Entry::Vacant(e) = visited.entry(neighbor) {
                        e.insert(dist + 1);
                        queue.push_back(neighbor);
                    }
                }
            }
        }

        // For each reachable destination, determine next-hop.
        let self_neighbors: Vec<MemberId> =
            self.adjacencies.get(&self_id).cloned().unwrap_or_default();

        for &dest in &active_set {
            let dist = match visited.get(&dest) {
                Some(d) => *d,
                None => continue, // unreachable
            };

            let next_hop = if dist == 1 {
                // Direct peer: next_hop is the destination itself.
                Some(dest)
            } else {
                // Relay: find a neighbor of self with distance = dist - 1
                // that can reach dest.  Among ties, pick the lowest MemberId.
                self_neighbors
                    .iter()
                    .filter(|&&n| {
                        visited.get(&n) == Some(&1)
                            && Self::can_reach(&self.adjacencies, n, dest, dist - 1)
                    })
                    .min_by_key(|&&n| n.0)
                    .copied()
            };

            if let Some(hop) = next_hop {
                self.routes.insert(dest, RouteEntry::new(dest, hop, dist));
            }
        }

        self.table_digest = self.compute_table_digest();
        self.dirty = false;
    }

    /// Check whether `from` can reach `target` in at most `max_dist` hops
    /// in the adjacency graph (BFS search limited to `max_dist`).
    fn can_reach(
        adj: &BTreeMap<MemberId, Vec<MemberId>>,
        from: MemberId,
        target: MemberId,
        max_dist: u32,
    ) -> bool {
        if from == target {
            return true;
        }
        if max_dist == 0 {
            return false;
        }
        let mut visited: BTreeMap<MemberId, u32> = BTreeMap::new();
        let mut queue: VecDeque<MemberId> = VecDeque::new();
        visited.insert(from, 0);
        queue.push_back(from);

        while let Some(current) = queue.pop_front() {
            let cur_dist = visited[&current];
            if cur_dist >= max_dist {
                continue;
            }
            if let Some(neighbors) = adj.get(&current) {
                for &neighbor in neighbors {
                    if neighbor == target {
                        return true;
                    }
                    if let std::collections::btree_map::Entry::Vacant(e) = visited.entry(neighbor) {
                        e.insert(cur_dist + 1);
                        queue.push_back(neighbor);
                    }
                }
            }
        }
        false
    }

    /// Compute the BLAKE3-256 table digest over all routes in canonical
    /// destination order.
    fn compute_table_digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(ROUTING_DOMAIN);
        // Feed self_id into digest so different self nodes produce
        // different digests.
        if let Some(id) = self.self_id {
            hasher.update(&id.0.to_le_bytes());
        } else {
            hasher.update(&[0u8; 8]); // sentinel for None
        }
        for route in self.routes.values() {
            hasher.update(&route.digest);
        }
        hasher.finalize().into()
    }

    /// Compute the digest for an empty routing table.
    fn compute_empty_digest() -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(ROUTING_DOMAIN);
        hasher.update(&[0u8; 8]); // sentinel for no self_id
        hasher.finalize().into()
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(n: u64) -> MemberId {
        MemberId(n)
    }

    // Helper: build a simple adjacency map.
    // Edges are undirected -- both directions are inserted.
    fn build_adj(edges: &[(u64, u64)]) -> BTreeMap<MemberId, Vec<MemberId>> {
        let mut adj: BTreeMap<MemberId, Vec<MemberId>> = BTreeMap::new();
        for &(a, b) in edges {
            adj.entry(mid(a)).or_default().push(mid(b));
            adj.entry(mid(b)).or_default().push(mid(a));
        }
        // Deduplicate and sort for determinism.
        for neighbors in adj.values_mut() {
            neighbors.sort_by_key(|n| n.0);
            neighbors.dedup_by_key(|n| n.0);
        }
        adj
    }

    // ----- single-hop direct route -----

    #[test]
    fn direct_peer_route() {
        let mut table = RoutingTable::new();
        table.set_self(mid(1));
        let adj = build_adj(&[(1, 2), (1, 3)]);
        let active = vec![mid(2), mid(3)];
        table.update(&active, adj);

        let r2 = table.resolve_route(mid(2)).expect("direct peer 2");
        assert_eq!(r2.next_hop, mid(2));
        assert_eq!(r2.path_length, 1);

        let r3 = table.resolve_route(mid(3)).expect("direct peer 3");
        assert_eq!(r3.next_hop, mid(3));
        assert_eq!(r3.path_length, 1);
    }

    // ----- two-hop relay route -----

    #[test]
    fn two_hop_relay_route() {
        let mut table = RoutingTable::new();
        table.set_self(mid(1));
        // Topology: 1 -- 2 -- 3
        let adj = build_adj(&[(1, 2), (2, 3)]);
        let active = vec![mid(2), mid(3)];
        table.update(&active, adj);

        let r3 = table.resolve_route(mid(3)).expect("two-hop to 3");
        assert_eq!(r3.next_hop, mid(2));
        assert_eq!(r3.path_length, 2);
    }

    // ----- unreachable destination -----

    #[test]
    fn unreachable_destination() {
        let mut table = RoutingTable::new();
        table.set_self(mid(1));
        // 1 connected to 2, but 4 is an island with no path.
        let adj = build_adj(&[(1, 2)]);
        let active = vec![mid(2), mid(4)];
        table.update(&active, adj);

        assert!(table.resolve_route(mid(2)).is_some());
        assert!(table.resolve_route(mid(4)).is_none());
    }

    // ----- update invalidates and recomputes -----

    #[test]
    fn update_recomputes_routes() {
        let mut table = RoutingTable::new();
        table.set_self(mid(1));

        // Initial: 1 -- 2
        let adj = build_adj(&[(1, 2)]);
        let active = vec![mid(2)];
        table.update(&active, adj);
        assert!(table.resolve_route(mid(2)).is_some());
        assert_eq!(table.len(), 1);

        // Update: add 3 as new member (but no adjacency to 3)
        let active2 = vec![mid(2), mid(3)];
        let adj2 = build_adj(&[(1, 2)]);
        table.update(&active2, adj2);
        assert_eq!(table.len(), 1);
        assert!(table.resolve_route(mid(2)).is_some());
        assert!(table.resolve_route(mid(3)).is_none()); // unreachable

        // Update: connect 3 via 2
        let adj3 = build_adj(&[(1, 2), (2, 3)]);
        table.update(&active2, adj3);
        assert_eq!(table.len(), 2);
        let r3 = table.resolve_route(mid(3)).expect("now reachable");
        assert_eq!(r3.next_hop, mid(2));
        assert_eq!(r3.path_length, 2);

        // Update: 2 removed, 3 now unreachable
        let adj4 = build_adj(&[]);
        let active3 = vec![mid(3)];
        table.update(&active3, adj4);
        assert!(table.resolve_route(mid(3)).is_none());
        assert_eq!(table.len(), 0);
    }

    // ----- empty roster -----

    #[test]
    fn empty_roster_yields_no_routes() {
        let mut table = RoutingTable::new();
        table.set_self(mid(1));
        let adj = build_adj(&[(1, 2)]);
        table.update(&[], adj);
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    // ----- self-route exclusion -----

    #[test]
    fn self_route_exclusion() {
        let mut table = RoutingTable::new();
        table.set_self(mid(1));
        let adj = build_adj(&[(1, 2)]);
        table.update(&[mid(1), mid(2)], adj);
        assert!(table.resolve_route(mid(1)).is_none());
    }

    // ----- multi-path tie-breaking determinism -----

    #[test]
    fn multi_path_tie_breaking() {
        let mut table = RoutingTable::new();
        table.set_self(mid(1));
        // Topology: 1 connected to 2 and 3, both connect to 4.
        // Two equal-length paths: 1->2->4 and 1->3->4 (both length 2).
        // Tie-break: lower MemberId next-hop wins (2 < 3).
        let adj = build_adj(&[(1, 2), (1, 3), (2, 4), (3, 4)]);
        let active = vec![mid(2), mid(3), mid(4)];
        table.update(&active, adj);

        let r4 = table.resolve_route(mid(4)).expect("reachable via either");
        assert_eq!(r4.next_hop, mid(2), "tie-break to lower MemberId");
        assert_eq!(r4.path_length, 2);
    }

    // ----- routing table digest determinism -----

    #[test]
    fn table_digest_determinism() {
        let mut t1 = RoutingTable::new();
        t1.set_self(mid(1));
        let adj = build_adj(&[(1, 2), (2, 3)]);
        t1.update(&[mid(2), mid(3)], adj.clone());

        let mut t2 = RoutingTable::new();
        t2.set_self(mid(1));
        t2.update(&[mid(2), mid(3)], adj);

        assert_eq!(t1.table_digest(), t2.table_digest());
    }

    #[test]
    fn table_digest_differs_for_different_topology() {
        let mut t1 = RoutingTable::new();
        t1.set_self(mid(1));
        let adj1 = build_adj(&[(1, 2)]);
        t1.update(&[mid(2)], adj1);

        let mut t2 = RoutingTable::new();
        t2.set_self(mid(1));
        let adj2 = build_adj(&[(1, 3)]);
        t2.update(&[mid(3)], adj2);

        assert_ne!(t1.table_digest(), t2.table_digest());
    }

    #[test]
    fn table_digest_empty_tables_equal() {
        let t1 = RoutingTable::new();
        let t2 = RoutingTable::new();
        assert_eq!(t1.table_digest(), t2.table_digest());
    }

    // ----- no self_id set -----

    #[test]
    fn no_self_id_yields_no_routes() {
        let mut table = RoutingTable::new();
        let adj = build_adj(&[(1, 2), (2, 3)]);
        table.update(&[mid(1), mid(2), mid(3)], adj);
        assert!(table.is_empty());
    }

    // ----- RouteEntry digest stability -----

    #[test]
    fn route_entry_digest_stable() {
        let d1 = RouteEntry::compute_digest(mid(42), mid(10), 2);
        let d2 = RouteEntry::compute_digest(mid(42), mid(10), 2);
        assert_eq!(d1, d2);
    }

    #[test]
    fn route_entry_digest_differs_by_destination() {
        let d1 = RouteEntry::compute_digest(mid(42), mid(10), 2);
        let d2 = RouteEntry::compute_digest(mid(43), mid(10), 2);
        assert_ne!(d1, d2);
    }

    #[test]
    fn route_entry_digest_differs_by_next_hop() {
        let d1 = RouteEntry::compute_digest(mid(42), mid(10), 2);
        let d2 = RouteEntry::compute_digest(mid(42), mid(11), 2);
        assert_ne!(d1, d2);
    }

    #[test]
    fn route_entry_digest_differs_by_path_length() {
        let d1 = RouteEntry::compute_digest(mid(42), mid(10), 2);
        let d2 = RouteEntry::compute_digest(mid(42), mid(10), 3);
        assert_ne!(d1, d2);
    }

    // ----- self_id change invalidates -----

    #[test]
    fn self_id_change_invalidates() {
        let mut table = RoutingTable::new();
        table.set_self(mid(1));
        let adj = build_adj(&[(1, 2)]);
        table.update(&[mid(2)], adj.clone());
        assert_eq!(table.len(), 1);

        // Change self to 2 (now 1 is a peer)
        table.set_self(mid(2));
        let adj2 = build_adj(&[(2, 1)]);
        table.update(&[mid(1)], adj2);
        assert_eq!(table.len(), 1);
        assert!(table.resolve_route(mid(2)).is_none()); // self
        assert!(table.resolve_route(mid(1)).is_some()); // peer
    }

    // ----- three-hop relay -----

    #[test]
    fn three_hop_relay_route() {
        let mut table = RoutingTable::new();
        table.set_self(mid(1));
        // Topology: 1 -- 2 -- 3 -- 4
        let adj = build_adj(&[(1, 2), (2, 3), (3, 4)]);
        let active = vec![mid(2), mid(3), mid(4)];
        table.update(&active, adj);

        let r4 = table.resolve_route(mid(4)).expect("three-hop to 4");
        assert_eq!(r4.next_hop, mid(2));
        assert_eq!(r4.path_length, 3);
    }

    // ----- diamond topology: prefer shorter path -----

    #[test]
    fn diamond_topology_prefers_shorter_path() {
        let mut table = RoutingTable::new();
        table.set_self(mid(1));
        // Topology: 1 -- 2 -- 4
        //          1 -- 3 -- 4
        //          1 -- 4 (direct, shorter)
        let adj = build_adj(&[(1, 2), (2, 4), (1, 3), (3, 4), (1, 4)]);
        let active = vec![mid(2), mid(3), mid(4)];
        table.update(&active, adj);

        let r4 = table.resolve_route(mid(4)).expect("reachable");
        assert_eq!(r4.path_length, 1, "direct path wins");
        assert_eq!(r4.next_hop, mid(4));
    }

    // ----- iteration order -----

    #[test]
    fn iteration_is_canonical_order() {
        let mut table = RoutingTable::new();
        table.set_self(mid(1));
        let adj = build_adj(&[(1, 3), (1, 2)]);
        table.update(&[mid(2), mid(3)], adj);

        let ids: Vec<u64> = table.iter().map(|(mid, _)| mid.0).collect();
        assert_eq!(ids, vec![2, 3], "BTreeMap canonical order");
    }

    // ----- default impl -----

    #[test]
    fn default_is_empty() {
        let table = RoutingTable::default();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }
}
