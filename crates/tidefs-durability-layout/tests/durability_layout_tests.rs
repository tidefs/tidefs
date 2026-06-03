//! Integration tests for durability-layout validation against failure-domain topologies.
//!
//! Tests cover the full validation pipeline: topology construction, layout
//! validation, failure scenario simulation, sealed persistence round-trip,
//! and edge cases.

use tidefs_durability_layout::failure_domain::FailureDomainTopology;
use tidefs_durability_layout::layout_validator::{
    LayoutValidationError, LayoutValidator, ValidationWarning,
};
use tidefs_durability_layout::DurabilityLayoutV1;
use tidefs_durability_layout::DurabilityPolicy;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a 3-node, 2-rack topology with 4 devices per node.
fn three_node_two_rack_12dev() -> FailureDomainTopology {
    let mut topo = FailureDomainTopology::new();
    topo.add_node(1, 10, 100);
    topo.add_node(2, 10, 100);
    topo.add_node(3, 20, 200);
    for node_id in 1..=3 {
        for dev in 0..4 {
            topo.add_device(node_id * 100 + dev, node_id);
        }
    }
    topo
}

/// Build a 2-node, 1-rack topology with 2 devices per node.
fn two_node_single_rack() -> FailureDomainTopology {
    let mut topo = FailureDomainTopology::new();
    topo.add_node(1, 10, 100);
    topo.add_node(2, 10, 100);
    topo.add_device(101, 1);
    topo.add_device(102, 1);
    topo.add_device(201, 2);
    topo.add_device(202, 2);
    topo
}

// ---------------------------------------------------------------------------
// Single-node failure tests
// ---------------------------------------------------------------------------

#[test]
fn mirror3_three_nodes_accepts_single_node_failure() {
    let topo = three_node_two_rack_12dev();
    let layout = DurabilityLayoutV1::mirror(3).unwrap();
    let validator = LayoutValidator::new(layout);
    let result = validator.validate(&topo);
    assert!(
        result.valid,
        "mirror-3 on 3 nodes should survive single-node failure"
    );
}

#[test]
fn mirror2_single_node_rejects() {
    let mut topo = FailureDomainTopology::new();
    topo.add_node(1, 10, 100);
    topo.add_device(101, 1);
    topo.add_device(102, 1);
    let layout = DurabilityLayoutV1::mirror(2).unwrap();
    let validator = LayoutValidator::new(layout);
    let result = validator.validate(&topo);
    assert!(!result.valid, "mirror-2 on 1 node must be rejected");
    assert!(result
        .errors
        .iter()
        .any(|e| matches!(e, LayoutValidationError::SingleNodeFailureRisk { .. })));
}

#[test]
fn mirror3_two_nodes_accepts() {
    let topo = two_node_single_rack();
    let layout = DurabilityLayoutV1::mirror(3).unwrap();
    let validator = LayoutValidator::new(layout);
    let result = validator.validate(&topo);
    assert!(
        result.valid,
        "mirror-3 on 2 nodes survives (2+1 distribution)"
    );
    assert!(result
        .warnings
        .iter()
        .any(|w| matches!(w, ValidationWarning::ReplicasShareNodes { .. })));
}

#[test]
fn mirror1_rejects_any_failure() {
    let topo = three_node_two_rack_12dev();
    let layout = DurabilityLayoutV1::mirror(1).unwrap();
    let validator = LayoutValidator::new(layout);
    let result = validator.validate(&topo);
    assert!(!result.valid, "mirror-1 cannot survive any failure");
}

// ---------------------------------------------------------------------------
// Multi-node failure tests
// ---------------------------------------------------------------------------

#[test]
fn mirror3_two_node_failure_scenario() {
    let topo = three_node_two_rack_12dev();
    let layout = DurabilityLayoutV1::mirror(3).unwrap();
    let validator = LayoutValidator::new(layout);
    // 2 of 3 nodes fail: ceil(3/3)=1 per node, losing 2 loses 2 -> 1 survives
    assert!(validator.validate_failure_scenario(&topo, &[1, 2]).is_ok());
}

#[test]
fn mirror3_all_nodes_fail_rejected() {
    let topo = three_node_two_rack_12dev();
    let layout = DurabilityLayoutV1::mirror(3).unwrap();
    let validator = LayoutValidator::new(layout);
    assert!(validator
        .validate_failure_scenario(&topo, &[1, 2, 3])
        .is_err());
}

#[test]
fn mirror4_two_nodes_one_failure_survives() {
    let topo = two_node_single_rack();
    let layout = DurabilityLayoutV1::mirror(4).unwrap();
    let validator = LayoutValidator::new(layout);
    // ceil(4/2)=2 per node, losing 1 node loses <=2 -> 2 survive
    assert!(validator.validate_failure_scenario(&topo, &[1]).is_ok());
}

// ---------------------------------------------------------------------------
// Rack-aware placement validation
// ---------------------------------------------------------------------------

#[test]
fn mirror3_two_racks_accepts_rack_failure() {
    let topo = three_node_two_rack_12dev();
    let layout = DurabilityLayoutV1::mirror(3).unwrap();
    let validator = LayoutValidator::new(layout);
    let result = validator.validate(&topo);
    assert!(result.valid);
}

#[test]
fn mirror2_two_racks_single_rack_topology_warns() {
    let topo = two_node_single_rack(); // 1 rack
    let layout = DurabilityLayoutV1::mirror(2).unwrap();
    let validator = LayoutValidator::new(layout);
    let result = validator.validate(&topo);
    assert!(
        result.valid,
        "mirror-2 on 2 nodes in 1 rack is valid with warning"
    );
    assert!(result
        .warnings
        .iter()
        .any(|w| matches!(w, ValidationWarning::SingleRackTopology)));
}

// ---------------------------------------------------------------------------
// Layout hash verification tests
// ---------------------------------------------------------------------------

#[test]
fn seal_and_verify_mirror_round_trip() {
    let layout = DurabilityLayoutV1::mirror(3).unwrap();
    let sealed = tidefs_durability_layout::seal_layout(&layout);
    let verified = tidefs_durability_layout::verify_layout(&sealed).unwrap();
    assert_eq!(verified, layout);
}

#[test]
fn seal_different_layouts_different_output() {
    let a = DurabilityLayoutV1::mirror(2).unwrap();
    let b = DurabilityLayoutV1::mirror(3).unwrap();
    assert_ne!(
        tidefs_durability_layout::seal_layout(&a),
        tidefs_durability_layout::seal_layout(&b)
    );
}

#[test]
fn verify_rejects_tampered_seal() {
    let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
    let mut sealed = tidefs_durability_layout::seal_layout(&layout);
    // Flip a byte in the seal hash
    {
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
    }
    assert!(tidefs_durability_layout::verify_layout(&sealed).is_err());
}

#[test]
fn verify_rejects_truncated() {
    let layout = DurabilityLayoutV1::mirror(1).unwrap();
    let sealed = tidefs_durability_layout::seal_layout(&layout);
    assert!(tidefs_durability_layout::verify_layout(&sealed[..10]).is_err());
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

#[test]
fn empty_topology_rejected() {
    let topo = FailureDomainTopology::new();
    let layout = DurabilityLayoutV1::mirror(3).unwrap();
    let validator = LayoutValidator::new(layout);
    let result = validator.validate(&topo);
    assert!(!result.valid);
    assert!(result
        .errors
        .iter()
        .any(|e| matches!(e, LayoutValidationError::EmptyTopology)));
}

#[test]
fn zero_copies_rejected() {
    let topo = three_node_two_rack_12dev();
    let layout = DurabilityLayoutV1 {
        policy: DurabilityPolicy::Mirror { copies: 0 },
    };
    let validator = LayoutValidator::new(layout);
    let result = validator.validate(&topo);
    assert!(!result.valid);
    assert!(result
        .errors
        .iter()
        .any(|e| matches!(e, LayoutValidationError::ZeroCopies)));
}

#[test]
fn insufficient_devices_rejected() {
    let mut topo = FailureDomainTopology::new();
    topo.add_node(1, 10, 100);
    topo.add_node(2, 10, 100);
    topo.add_device(101, 1); // only 1 device for mirror-3
    let layout = DurabilityLayoutV1::mirror(3).unwrap();
    let validator = LayoutValidator::new(layout);
    let result = validator.validate(&topo);
    assert!(!result.valid);
    assert!(result
        .errors
        .iter()
        .any(|e| matches!(e, LayoutValidationError::InsufficientDevices { .. })));
}

#[test]
fn erasure_4_2_valid_on_12_devices() {
    let topo = three_node_two_rack_12dev();
    let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
    let validator = LayoutValidator::new(layout);
    let result = validator.validate(&topo);
    assert!(result.valid);
}

#[test]
fn overprovisioned_topology_warns() {
    let mut topo = FailureDomainTopology::new();
    for node_id in 1..=10 {
        topo.add_node(node_id, node_id / 3, node_id / 5);
        topo.add_device(node_id * 100, node_id);
    }
    let layout = DurabilityLayoutV1::mirror(3).unwrap();
    let validator = LayoutValidator::new(layout);
    let result = validator.validate(&topo);
    assert!(result.valid);
    assert!(result
        .warnings
        .iter()
        .any(|w| matches!(w, ValidationWarning::OverProvisioned { .. })));
}
