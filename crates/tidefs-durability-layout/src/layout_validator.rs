//! Layout validator with failure-domain simulation.
//!
//! [`LayoutValidator`] takes a [`crate::DurabilityLayoutV1`] and a
//! [`crate::failure_domain::FailureDomainTopology`] and determines whether
//! the durability layout guarantees survive specific failure scenarios:
//! single-node, multi-node, rack-level, and datacenter-level failures.

use crate::failure_domain::FailureDomainTopology;
use crate::{DurabilityLayoutV1, DurabilityPolicy};

// ---------------------------------------------------------------------------
// LayoutValidationError
// ---------------------------------------------------------------------------

/// Errors returned by layout validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutValidationError {
    /// The topology cannot satisfy the policy's replica count.
    InsufficientNodes { required: usize, available: usize },
    /// The policy cannot survive a single-node failure.
    SingleNodeFailureRisk { copies: u8, nodes: usize },
    /// The policy cannot survive a single-rack failure.
    SingleRackFailureRisk { copies: u8, racks: usize },
    /// The policy cannot survive failure of N nodes.
    MultiNodeFailureRisk {
        failed_nodes: usize,
        copies: u8,
        total_nodes: usize,
    },
    /// The topology is empty.
    EmptyTopology,
    /// The policy's shard count exceeds the device count.
    InsufficientDevices { required: usize, available: usize },
    /// Mirror policy with copies=0.
    ZeroCopies,
    /// Erasure policy with data_shards=0.
    ZeroDataShards,
}

// ---------------------------------------------------------------------------
// ValidationResult
// ---------------------------------------------------------------------------

/// Result of a layout validation pass against a topology.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationResult {
    /// Whether the layout is valid for this topology.
    pub valid: bool,
    /// List of validation errors found.
    pub errors: Vec<LayoutValidationError>,
    /// Warnings about suboptimal configurations.
    pub warnings: Vec<ValidationWarning>,
}

/// Non-fatal warnings about a layout configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationWarning {
    /// Topology has more failure domains than the policy requires.
    OverProvisioned {
        policy_requires: usize,
        topology_provides: usize,
    },
    /// Replicas must share nodes because replicas > nodes.
    ReplicasShareNodes { copies: u8, nodes: usize },
    /// All nodes are in a single rack.
    SingleRackTopology,
    /// All nodes are in a single datacenter.
    SingleDatacenterTopology,
}

impl ValidationResult {
    /// Create a successful result.
    pub fn valid() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Create a failed result with a single error.
    pub fn invalid(error: LayoutValidationError) -> Self {
        Self {
            valid: false,
            errors: vec![error],
            warnings: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// LayoutValidator
// ---------------------------------------------------------------------------

/// Validates a durability layout against a failure-domain topology.
#[derive(Clone, Debug)]
pub struct LayoutValidator {
    layout: DurabilityLayoutV1,
}

impl LayoutValidator {
    /// Create a new validator for the given durability layout.
    pub fn new(layout: DurabilityLayoutV1) -> Self {
        Self { layout }
    }

    /// Return the layout being validated.
    pub fn layout(&self) -> &DurabilityLayoutV1 {
        &self.layout
    }

    /// Run all standard validation checks against a topology.
    pub fn validate(&self, topology: &FailureDomainTopology) -> ValidationResult {
        let mut result = ValidationResult::valid();

        if topology.node_count() == 0 && topology.device_count() == 0 {
            result.valid = false;
            result.errors.push(LayoutValidationError::EmptyTopology);
            return result;
        }

        match &self.layout.policy {
            DurabilityPolicy::Mirror { copies } => {
                self.validate_mirror(*copies, topology, &mut result);
            }
            DurabilityPolicy::ErasureStyle {
                data_shards,
                parity_shards,
            } => {
                self.validate_erasure(*data_shards, *parity_shards, topology, &mut result);
            }
            DurabilityPolicy::Hybrid {
                mirror_copies,
                data_shards,
                parity_shards: _,
            } => {
                self.validate_hybrid(*mirror_copies, *data_shards, topology, &mut result);
            }
        }

        // Warnings
        let total_shards = self.layout.policy.total_shards();
        if topology.node_count() > total_shards {
            result.warnings.push(ValidationWarning::OverProvisioned {
                policy_requires: total_shards,
                topology_provides: topology.node_count(),
            });
        }
        if topology.rack_count() == 1 && topology.node_count() > 1 {
            result.warnings.push(ValidationWarning::SingleRackTopology);
        }
        if topology.dc_count() == 1 && topology.node_count() > 1 {
            result
                .warnings
                .push(ValidationWarning::SingleDatacenterTopology);
        }

        result
    }

    /// Validate a specific failure scenario: the given nodes fail.
    pub fn validate_failure_scenario(
        &self,
        topology: &FailureDomainTopology,
        failed_nodes: &[u64],
    ) -> Result<(), LayoutValidationError> {
        let (total_replicas, min_required) = self.policy_requirements();
        let sim = topology.simulate_node_failure(failed_nodes, total_replicas, min_required);
        if sim.survives {
            Ok(())
        } else {
            Err(LayoutValidationError::MultiNodeFailureRisk {
                failed_nodes: failed_nodes.len(),
                copies: total_replicas as u8,
                total_nodes: topology.node_count(),
            })
        }
    }

    /// Return (total_replicas, min_required) for the current policy.
    fn policy_requirements(&self) -> (usize, usize) {
        match &self.layout.policy {
            DurabilityPolicy::Mirror { copies } => (*copies as usize, 1),
            DurabilityPolicy::ErasureStyle {
                data_shards,
                parity_shards,
            } => {
                let total = (*data_shards + *parity_shards) as usize;
                (total, *data_shards as usize)
            }
            DurabilityPolicy::Hybrid {
                mirror_copies: _,
                data_shards,
                parity_shards: _,
            } => {
                let total = *data_shards as usize;
                (total, total)
            }
        }
    }

    fn validate_mirror(
        &self,
        copies: u8,
        topology: &FailureDomainTopology,
        result: &mut ValidationResult,
    ) {
        if copies == 0 {
            result.valid = false;
            result.errors.push(LayoutValidationError::ZeroCopies);
            return;
        }

        let device_count = topology.device_count();
        if device_count < copies as usize {
            result.valid = false;
            result
                .errors
                .push(LayoutValidationError::InsufficientDevices {
                    required: copies as usize,
                    available: device_count,
                });
        }

        if topology.node_count() > 0 && (copies as usize) > topology.node_count() {
            result.warnings.push(ValidationWarning::ReplicasShareNodes {
                copies,
                nodes: topology.node_count(),
            });
        }

        if !topology.can_survive_any_single_node_failure(copies) {
            result.valid = false;
            result
                .errors
                .push(LayoutValidationError::SingleNodeFailureRisk {
                    copies,
                    nodes: topology.node_count(),
                });
        }

        if topology.rack_count() >= 2 && !topology.can_survive_any_single_rack_failure(copies) {
            result.valid = false;
            result
                .errors
                .push(LayoutValidationError::SingleRackFailureRisk {
                    copies,
                    racks: topology.rack_count(),
                });
        }
    }

    fn validate_erasure(
        &self,
        data_shards: u8,
        parity_shards: u8,
        topology: &FailureDomainTopology,
        result: &mut ValidationResult,
    ) {
        if data_shards == 0 {
            result.valid = false;
            result.errors.push(LayoutValidationError::ZeroDataShards);
            return;
        }

        let device_count = topology.device_count();
        let total_shards = (data_shards + parity_shards) as usize;
        if device_count < total_shards {
            result.valid = false;
            result
                .errors
                .push(LayoutValidationError::InsufficientDevices {
                    required: total_shards,
                    available: device_count,
                });
        }
    }

    fn validate_hybrid(
        &self,
        mirror_copies: u8,
        data_shards: u8,
        topology: &FailureDomainTopology,
        result: &mut ValidationResult,
    ) {
        self.validate_mirror(mirror_copies, topology, result);

        if data_shards == 0 {
            result.valid = false;
            result.errors.push(LayoutValidationError::ZeroDataShards);
        }

        let total_shards = self.layout.policy.total_shards();
        if topology.device_count() < total_shards {
            result.valid = false;
            result
                .errors
                .push(LayoutValidationError::InsufficientDevices {
                    required: total_shards,
                    available: topology.device_count(),
                });
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failure_domain::FailureDomainTopology;
    use crate::DurabilityLayoutV1;

    fn three_node_two_rack_topology() -> FailureDomainTopology {
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

    #[test]
    fn mirror3_three_nodes_valid() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let validator = LayoutValidator::new(layout);
        let result = validator.validate(&three_node_two_rack_topology());
        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn mirror3_survives_one_node_failure() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let validator = LayoutValidator::new(layout);
        assert!(validator
            .validate_failure_scenario(&three_node_two_rack_topology(), &[1])
            .is_ok());
    }

    #[test]
    fn mirror2_two_nodes_valid() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_node(2, 10, 100);
        topo.add_device(101, 1);
        topo.add_device(201, 2);
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let validator = LayoutValidator::new(layout);
        assert!(validator.validate(&topo).valid);
    }

    #[test]
    fn mirror2_one_node_rejects() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_device(101, 1);
        topo.add_device(102, 1);
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let validator = LayoutValidator::new(layout);
        let result = validator.validate(&topo);
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, LayoutValidationError::SingleNodeFailureRisk { .. })));
    }

    #[test]
    fn mirror1_rejects_node_failure() {
        let layout = DurabilityLayoutV1::mirror(1).unwrap();
        let validator = LayoutValidator::new(layout);
        let result = validator.validate(&three_node_two_rack_topology());
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| matches!(
            e,
            LayoutValidationError::SingleNodeFailureRisk { copies: 1, .. }
        )));
    }

    #[test]
    fn empty_topology_rejected() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let validator = LayoutValidator::new(layout);
        let result = validator.validate(&FailureDomainTopology::new());
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, LayoutValidationError::EmptyTopology)));
    }

    #[test]
    fn mirror3_insufficient_devices() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_node(2, 10, 100);
        topo.add_node(3, 20, 200);
        topo.add_device(101, 1);
        topo.add_device(201, 2);
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let validator = LayoutValidator::new(layout);
        let result = validator.validate(&topo);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| matches!(
            e,
            LayoutValidationError::InsufficientDevices {
                required: 3,
                available: 2
            }
        )));
    }

    #[test]
    fn mirror3_single_rack_warns() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_node(2, 10, 100);
        topo.add_node(3, 10, 100);
        for node_id in 1..=3 {
            for dev in 0..4 {
                topo.add_device(node_id * 100 + dev, node_id);
            }
        }
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let validator = LayoutValidator::new(layout);
        let result = validator.validate(&topo);
        assert!(result.valid);
        assert!(result
            .warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::SingleRackTopology)));
    }

    #[test]
    fn mirror3_two_nodes_fails_two_node_failure() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_node(2, 10, 100);
        topo.add_device(101, 1);
        topo.add_device(102, 1);
        topo.add_device(201, 2);
        topo.add_device(202, 2);
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let validator = LayoutValidator::new(layout);
        let result = validator.validate_failure_scenario(&topo, &[1, 2]);
        assert!(result.is_err());
    }

    #[test]
    fn erasure_4_2_valid_on_6_devices() {
        let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
        let validator = LayoutValidator::new(layout);
        let result = validator.validate(&three_node_two_rack_topology());
        assert!(result.valid);
    }

    #[test]
    fn erasure_4_2_four_devices_requires_six_targets() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_node(2, 10, 100);
        for device_id in 0..4 {
            let node_id = if device_id % 2 == 0 { 1 } else { 2 };
            topo.add_device(100 + device_id, node_id);
        }
        let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
        let validator = LayoutValidator::new(layout);
        let result = validator.validate(&topo);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| matches!(
            e,
            LayoutValidationError::InsufficientDevices {
                required: 6,
                available: 4
            }
        )));
    }

    #[test]
    fn erasure_4_2_failure_scenario_uses_full_width() {
        let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
        let validator = LayoutValidator::new(layout);
        assert!(validator
            .validate_failure_scenario(&three_node_two_rack_topology(), &[1])
            .is_ok());
    }

    #[test]
    fn hybrid_2_4_2_valid() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_node(2, 10, 100);
        topo.add_node(3, 20, 200);
        for node_id in 1..=3 {
            for dev in 0..6 {
                topo.add_device(node_id * 100 + dev, node_id);
            }
        }
        let layout = DurabilityLayoutV1 {
            policy: DurabilityPolicy::hybrid(2, 4, 2).unwrap(),
        };
        let validator = LayoutValidator::new(layout);
        assert!(validator.validate(&topo).valid);
    }

    #[test]
    fn hybrid_2_4_2_single_rack_warns() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_node(2, 10, 100);
        for node_id in 1..=2 {
            for dev in 0..6 {
                topo.add_device(node_id * 100 + dev, node_id);
            }
        }
        let layout = DurabilityLayoutV1 {
            policy: DurabilityPolicy::hybrid(2, 4, 2).unwrap(),
        };
        let validator = LayoutValidator::new(layout);
        let result = validator.validate(&topo);
        assert!(
            result.valid,
            "hybrid with 2 nodes on 1 rack is valid (node-level isolation)"
        );
        assert!(result
            .warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::SingleRackTopology)));
    }

    #[test]
    fn overprovisioned_warning() {
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

    #[test]
    fn replicas_share_nodes_warning() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_node(2, 10, 100);
        for node_id in 1..=2 {
            for dev in 0..3 {
                topo.add_device(node_id * 100 + dev, node_id);
            }
        }
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let validator = LayoutValidator::new(layout);
        let result = validator.validate(&topo);
        assert!(result.valid);
        assert!(result.warnings.iter().any(|w| matches!(
            w,
            ValidationWarning::ReplicasShareNodes {
                copies: 3,
                nodes: 2
            }
        )));
    }

    #[test]
    fn single_datacenter_warning() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_node(2, 20, 100);
        for node_id in 1..=2 {
            for dev in 0..3 {
                topo.add_device(node_id * 100 + dev, node_id);
            }
        }
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let validator = LayoutValidator::new(layout);
        let result = validator.validate(&topo);
        assert!(result.valid);
        assert!(result
            .warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::SingleDatacenterTopology)));
    }
}
