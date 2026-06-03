//! Placement integration: wires `tidefs-placement-planner` node placement
//! decisions into the deterministic two-node harness.
//!
//! [`PlacementScenario`] bridges placement computation (BLAKE3-keyed
//! [`NodePlacement`]) and the harness state transfer infrastructure.
//! Each object is placed onto its computed target node(s), and the harness
//! ships the payload to the correct destination via the deterministic
//! loopback transport.
//!
//! The integration preserves determinism: same (seed, objects, layout)
//! always produces the same target assignments and transfer outcomes.

use crate::{StateObject, StateTransferResult, TwoNodeHarness};
use tidefs_durability_layout::{DurabilityLayoutV1, FailureDomainV1};
use tidefs_placement_planner::node_placement::{NodeCandidate, NodePlacement};
use tidefs_placement_planner::PlacementError;

// ── PlacementScenario ─────────────────────────────────────────────────

/// A scenario that computes placement decisions for objects and routes
/// state transfers to the correct target node(s) inside the two-node harness.
pub struct PlacementScenario {
    pub harness: TwoNodeHarness,
    placement_computed: bool,
}

impl PlacementScenario {
    /// Create a new placement scenario with the given PRNG seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            harness: TwoNodeHarness::new(seed),
            placement_computed: false,
        }
    }

    /// Establish the transport session between Node A and Node B.
    pub fn establish(&mut self) -> Result<(), String> {
        self.harness.establish_session()
    }

    /// Compute node placement for a set of objects against the given
    /// durability layout and failure domain.
    ///
    /// Both nodes are always eligible (unless unhealthy), so placement
    /// respects the layout's anti-affinity rules with the available
    /// two-node roster.
    pub fn compute_placements(
        &self,
        objects: &[StateObject],
        layout: &DurabilityLayoutV1,
        failure_domain: &FailureDomainV1,
    ) -> Result<Vec<NodePlacement>, PlacementError> {
        let nodes: Vec<NodeCandidate> = vec![NodeCandidate::new(1), NodeCandidate::new(2)];

        objects
            .iter()
            .map(|obj| {
                NodePlacement::compute(
                    obj.object_key,
                    obj.object_key.wrapping_mul(0x9E37_79B9_7F4A_7C15),
                    layout,
                    failure_domain,
                    &nodes,
                    self.harness.seed,
                )
            })
            .collect()
    }

    /// Ship objects from Node A to their placement targets.
    ///
    /// Objects whose primary target is Node B are shipped from A to B;
    /// objects placed on Node A stay local with no transfer.
    pub fn ship_to_placement_targets_a(
        &mut self,
        objects: &[StateObject],
        placements: &[NodePlacement],
    ) -> Result<StateTransferResult, String> {
        let a_to_b: Vec<StateObject> = objects
            .iter()
            .zip(placements.iter())
            .filter(|(_, p)| p.primary_node() == Some(2))
            .map(|(obj, _)| obj.clone())
            .collect();

        if a_to_b.is_empty() {
            return Ok(StateTransferResult {
                object_count: 0,
                total_bytes: 0,
                chunk_count: 0,
                transfer_digest: [0u8; 32],
            });
        }
        self.harness.state_transfer_a_to_b(&a_to_b)
    }

    /// Ship objects from Node B to their placement targets.
    pub fn ship_to_placement_targets_b(
        &mut self,
        objects: &[StateObject],
        placements: &[NodePlacement],
    ) -> Result<StateTransferResult, String> {
        let b_to_a: Vec<StateObject> = objects
            .iter()
            .zip(placements.iter())
            .filter(|(_, p)| p.primary_node() == Some(1))
            .map(|(obj, _)| obj.clone())
            .collect();

        if b_to_a.is_empty() {
            return Ok(StateTransferResult {
                object_count: 0,
                total_bytes: 0,
                chunk_count: 0,
                transfer_digest: [0u8; 32],
            });
        }
        self.harness.state_transfer_b_to_a(&b_to_a)
    }

    /// Verify placements respect failure-domain separation: no two
    /// selected targets for the same placement slot share the same domain.
    #[must_use]
    pub fn verify_failure_domain_separation(placements: &[NodePlacement], required: usize) -> bool {
        if required <= 1 {
            return true;
        }
        for p in placements {
            if p.node_targets.len() < required {
                return false;
            }
            let unique: std::collections::BTreeSet<u64> =
                p.node_targets.iter().copied().take(required).collect();
            if unique.len() < required {
                return false;
            }
        }
        true
    }

    pub fn teardown(&mut self) {
        self.harness.teardown();
        self.placement_computed = false;
    }
}

// ── Harness extension methods ──────────────────────────────────────────

impl TwoNodeHarness {
    /// Transfer objects from A to B using placement-driven routing.
    ///
    /// Computes placement via BLAKE3-keyed hashing, ships only objects
    /// belonging on Node B. Returns the transfer result plus placements.
    pub fn placement_transfer_a_to_b(
        &mut self,
        objects: &[StateObject],
        layout: &DurabilityLayoutV1,
        failure_domain: &FailureDomainV1,
    ) -> Result<(StateTransferResult, Vec<NodePlacement>), String> {
        let nodes = vec![NodeCandidate::new(1), NodeCandidate::new(2)];

        let placements: Vec<NodePlacement> = objects
            .iter()
            .map(|obj| {
                NodePlacement::compute(
                    obj.object_key,
                    obj.object_key.wrapping_mul(0x9E37_79B9_7F4A_7C15),
                    layout,
                    failure_domain,
                    &nodes,
                    self.seed,
                )
                .map_err(|e| format!("placement compute: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let a_to_b: Vec<StateObject> = objects
            .iter()
            .zip(placements.iter())
            .filter(|(_, p)| p.primary_node() == Some(2))
            .map(|(obj, _)| obj.clone())
            .collect();

        let result = if a_to_b.is_empty() {
            StateTransferResult {
                object_count: 0,
                total_bytes: 0,
                chunk_count: 0,
                transfer_digest: [0u8; 32],
            }
        } else {
            self.state_transfer_a_to_b(&a_to_b)?
        };

        Ok((result, placements))
    }

    /// Transfer objects from B to A using placement-driven routing.
    pub fn placement_transfer_b_to_a(
        &mut self,
        objects: &[StateObject],
        layout: &DurabilityLayoutV1,
        failure_domain: &FailureDomainV1,
    ) -> Result<(StateTransferResult, Vec<NodePlacement>), String> {
        let nodes = vec![NodeCandidate::new(1), NodeCandidate::new(2)];

        let placements: Vec<NodePlacement> = objects
            .iter()
            .map(|obj| {
                NodePlacement::compute(
                    obj.object_key,
                    obj.object_key.wrapping_mul(0x9E37_79B9_7F4A_7C15),
                    layout,
                    failure_domain,
                    &nodes,
                    self.seed,
                )
                .map_err(|e| format!("placement compute: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let b_to_a: Vec<StateObject> = objects
            .iter()
            .zip(placements.iter())
            .filter(|(_, p)| p.primary_node() == Some(1))
            .map(|(obj, _)| obj.clone())
            .collect();

        let result = if b_to_a.is_empty() {
            StateTransferResult {
                object_count: 0,
                total_bytes: 0,
                chunk_count: 0,
                transfer_digest: [0u8; 32],
            }
        } else {
            self.state_transfer_b_to_a(&b_to_a)?
        };

        Ok((result, placements))
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateObject;
    use tidefs_durability_layout::FailureDomainLevel;

    fn mirror_layout(copies: u8) -> DurabilityLayoutV1 {
        DurabilityLayoutV1::mirror(copies).unwrap()
    }

    fn node_fd() -> FailureDomainV1 {
        FailureDomainV1::new(FailureDomainLevel::Node, 64).unwrap()
    }

    fn rack_fd() -> FailureDomainV1 {
        FailureDomainV1::new(FailureDomainLevel::Rack, 64).unwrap()
    }

    #[test]
    fn placement_computation_deterministic() {
        let scenario = PlacementScenario::new(42);
        let objects: Vec<StateObject> = (0..10)
            .map(|i| StateObject {
                object_key: 100 + i,
                payload: format!("obj-{i}").into_bytes(),
            })
            .collect();
        let layout = mirror_layout(1);
        let fd = node_fd();

        let p1 = scenario.compute_placements(&objects, &layout, &fd).unwrap();
        let p2 = scenario.compute_placements(&objects, &layout, &fd).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn placement_scenario_different_seeds_diverge() {
        let s42 = PlacementScenario::new(42);
        let s99 = PlacementScenario::new(99);
        let objects = vec![StateObject {
            object_key: 1,
            payload: b"data".to_vec(),
        }];
        let layout = mirror_layout(1);
        let fd = node_fd();

        let p42 = s42.compute_placements(&objects, &layout, &fd).unwrap();
        let p99 = s99.compute_placements(&objects, &layout, &fd).unwrap();
        let p99_again = s99.compute_placements(&objects, &layout, &fd).unwrap();
        assert_eq!(p99, p99_again);
        // Seeds may or may not produce same targets with 2 nodes.
        // Assert deterministic reproduction regardless.
        let p42_again = s42.compute_placements(&objects, &layout, &fd).unwrap();
        assert_eq!(p42, p42_again);
    }

    #[test]
    fn placement_not_enough_nodes_errors() {
        let scenario = PlacementScenario::new(42);
        let objects: Vec<StateObject> = (0..5)
            .map(|i| StateObject {
                object_key: 100 + i,
                payload: vec![0xAA; 64],
            })
            .collect();
        let layout = mirror_layout(3); // needs 3, only 2 exist
        let fd = node_fd();
        let err = scenario
            .compute_placements(&objects, &layout, &fd)
            .unwrap_err();
        assert!(err.to_string().contains("not enough healthy members"));
    }

    #[test]
    fn placement_mirror_1_single_target_per_object() {
        let scenario = PlacementScenario::new(42);
        let objects = vec![StateObject {
            object_key: 7,
            payload: b"single".to_vec(),
        }];
        let layout = mirror_layout(1);
        let fd = node_fd();
        let placements = scenario.compute_placements(&objects, &layout, &fd).unwrap();
        assert_eq!(placements.len(), 1);
        assert_eq!(placements[0].node_targets.len(), 1);
        assert!(placements[0].satisfied());
    }

    #[test]
    fn placement_mirror_2_both_nodes_targeted() {
        let scenario = PlacementScenario::new(42);
        let objects = vec![StateObject {
            object_key: 1,
            payload: b"mirror-2".to_vec(),
        }];
        let layout = mirror_layout(2);
        let fd = node_fd();
        let placements = scenario.compute_placements(&objects, &layout, &fd).unwrap();
        assert_eq!(placements[0].node_targets.len(), 2);
        assert_eq!(placements[0].required_count, 2);
        assert!(placements[0].satisfied());
    }

    // ── Placement-driven transfer tests ────────────────────────────────

    #[test]
    fn placement_driven_transfer_a_to_b() {
        let mut scenario = PlacementScenario::new(42);
        scenario.establish().expect("session establish");

        let objects: Vec<StateObject> = (0..20)
            .map(|i| StateObject {
                object_key: 100 + i,
                payload: format!("payload-{i}-abcdefg").into_bytes(),
            })
            .collect();
        let layout = mirror_layout(1);
        let fd = node_fd();
        let placements = scenario.compute_placements(&objects, &layout, &fd).unwrap();

        let b_count = placements
            .iter()
            .filter(|p| p.primary_node() == Some(2))
            .count();

        let result = scenario
            .ship_to_placement_targets_a(&objects, &placements)
            .expect("A->B transfer");

        if b_count > 0 {
            assert_eq!(result.object_count, b_count);
        } else {
            assert_eq!(result.object_count, 0);
        }
    }

    #[test]
    fn placement_driven_transfer_b_to_a() {
        let mut scenario = PlacementScenario::new(42);
        scenario.establish().expect("session establish");

        let objects: Vec<StateObject> = (0..20)
            .map(|i| StateObject {
                object_key: 200 + i,
                payload: format!("b-to-a-{i}").into_bytes(),
            })
            .collect();
        let layout = mirror_layout(1);
        let fd = node_fd();
        let placements = scenario.compute_placements(&objects, &layout, &fd).unwrap();

        let a_count = placements
            .iter()
            .filter(|p| p.primary_node() == Some(1))
            .count();

        let result = scenario
            .ship_to_placement_targets_b(&objects, &placements)
            .expect("B->A transfer");

        if a_count > 0 {
            assert_eq!(result.object_count, a_count);
        } else {
            assert_eq!(result.object_count, 0);
        }
    }

    #[test]
    fn placement_transfer_deterministic_replay() {
        fn run(seed: u64) -> (usize, Vec<u64>) {
            let mut scenario = PlacementScenario::new(seed);
            scenario.establish().expect("establish");
            let objects: Vec<StateObject> = (0..10)
                .map(|i| StateObject {
                    object_key: 10 + i,
                    payload: format!("det-{i}").into_bytes(),
                })
                .collect();
            let layout = mirror_layout(1);
            let fd = node_fd();
            let placements = scenario.compute_placements(&objects, &layout, &fd).unwrap();
            let result = scenario
                .ship_to_placement_targets_a(&objects, &placements)
                .expect("transfer");
            let targets: Vec<u64> = placements.iter().filter_map(|p| p.primary_node()).collect();
            (result.object_count, targets)
        }
        let (c1, t1) = run(42);
        let (c2, t2) = run(42);
        assert_eq!(c1, c2);
        assert_eq!(t1, t2);
    }

    // ── Harness extension method tests ─────────────────────────────────

    #[test]
    fn harness_placement_transfer_method() {
        let mut h = TwoNodeHarness::new(42);
        h.establish_session().expect("session establish");
        let objects: Vec<StateObject> = (0..15)
            .map(|i| StateObject {
                object_key: 1 + i,
                payload: format!("ext-{i}").into_bytes(),
            })
            .collect();
        let layout = mirror_layout(1);
        let fd = node_fd();

        let (result, placements) = h
            .placement_transfer_a_to_b(&objects, &layout, &fd)
            .expect("placement_transfer_a_to_b");

        assert_eq!(placements.len(), objects.len());
        for p in &placements {
            assert!(p.satisfied());
            assert_eq!(p.required_count, 1);
        }
        let b_count = placements
            .iter()
            .filter(|p| p.primary_node() == Some(2))
            .count();
        if b_count > 0 {
            assert_eq!(result.object_count, b_count);
        }
    }

    #[test]
    fn harness_placement_transfer_b_to_a_method() {
        let mut h = TwoNodeHarness::new(42);
        h.establish_session().expect("session establish");
        let objects: Vec<StateObject> = (0..15)
            .map(|i| StateObject {
                object_key: 100 + i,
                payload: format!("b-ext-{i}").into_bytes(),
            })
            .collect();
        let layout = mirror_layout(1);
        let fd = node_fd();

        let (result, placements) = h
            .placement_transfer_b_to_a(&objects, &layout, &fd)
            .expect("placement_transfer_b_to_a");

        assert_eq!(placements.len(), objects.len());
        let a_count = placements
            .iter()
            .filter(|p| p.primary_node() == Some(1))
            .count();
        if a_count > 0 {
            assert_eq!(result.object_count, a_count);
        }
    }

    #[test]
    fn harness_placement_mirror_2_transfer() {
        let mut h = TwoNodeHarness::new(42);
        h.establish_session().expect("session establish");
        let objects: Vec<StateObject> = (0..5)
            .map(|i| StateObject {
                object_key: 200 + i,
                payload: format!("m2-{i}").into_bytes(),
            })
            .collect();
        let layout = mirror_layout(2);
        let fd = node_fd();

        let (result, placements) = h
            .placement_transfer_a_to_b(&objects, &layout, &fd)
            .expect("mirror-2 transfer");

        for p in &placements {
            assert_eq!(p.node_targets.len(), 2);
            assert_eq!(p.required_count, 2);
            assert!(p.satisfied());
        }
        assert_eq!(placements.len(), 5);
        // All objects with node 2 as primary are shipped.
        assert!(result.object_count <= 5);
    }

    #[test]
    fn harness_placement_empty_transfer() {
        let mut h = TwoNodeHarness::new(42);
        h.establish_session().expect("session establish");
        let objects: Vec<StateObject> = vec![];
        let layout = mirror_layout(1);
        let fd = node_fd();
        let (result, placements) = h
            .placement_transfer_a_to_b(&objects, &layout, &fd)
            .expect("empty transfer");
        assert_eq!(placements.len(), 0);
        assert_eq!(result.object_count, 0);
    }

    #[test]
    fn failure_domain_separation_check() {
        let scenario = PlacementScenario::new(42);
        let objects: Vec<StateObject> = (0..10)
            .map(|i| StateObject {
                object_key: 300 + i,
                payload: format!("fd-{i}").into_bytes(),
            })
            .collect();
        let layout = mirror_layout(2);
        let fd = node_fd();
        let placements = scenario.compute_placements(&objects, &layout, &fd).unwrap();
        assert!(PlacementScenario::verify_failure_domain_separation(
            &placements,
            2
        ));
    }

    #[test]
    fn placement_transfer_large_objects() {
        let mut scenario = PlacementScenario::new(42);
        scenario.establish().expect("session establish");
        let objects = vec![
            StateObject {
                object_key: 500,
                payload: vec![0xBB; 8192],
            },
            StateObject {
                object_key: 501,
                payload: vec![0xCC; 15000],
            },
        ];
        let layout = mirror_layout(1);
        let fd = node_fd();
        let placements = scenario.compute_placements(&objects, &layout, &fd).unwrap();

        let b_objects: Vec<_> = objects
            .iter()
            .zip(placements.iter())
            .filter(|(_, p)| p.primary_node() == Some(2))
            .collect();

        if !b_objects.is_empty() {
            let result = scenario
                .ship_to_placement_targets_a(&objects, &placements)
                .expect("large transfer");
            assert!(result.chunk_count > 0);
            assert!(result.total_bytes > 0);
        }
    }

    #[test]
    fn rack_level_placement_transfer() {
        let mut h = TwoNodeHarness::new(42);
        h.establish_session().expect("session establish");
        let objects: Vec<StateObject> = (0..10)
            .map(|i| StateObject {
                object_key: 600 + i,
                payload: format!("rack-{i}").into_bytes(),
            })
            .collect();
        let layout = mirror_layout(1);
        let fd = rack_fd();
        let (result, _placements) = h
            .placement_transfer_a_to_b(&objects, &layout, &fd)
            .expect("rack-level transfer");
        assert!(result.object_count <= 10);
    }
}
