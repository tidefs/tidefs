// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Cluster pool orchestration: request builders for multi-node pool
//! creation and import.
//!
//! **Prototype boundary note**: the [`ClusterPoolOrchestrator`] builds per-node
//! protocol messages ([ClusterPoolCreateRequest], [ClusterPoolImportRequest])
//! from a [ClusterPoolConfig] and provides aggregation helpers for
//! responses.  It does **not** send or collect messages itself — callers
//! are responsible for transport dispatch.
//!
//! The [`PoolTransport`] trait is a transport-neutral abstraction for
//! prototype message dispatch.  `tidefsctl cluster pool create` may provide a
//! `tidefs-transport` adapter, while the in-memory [ChannelPoolTransport]
//! remains a unit-test transport.  Neither path makes this orchestrator a
//! final distributed operator UAPI or a cluster status authority.
//!
//! Do not close any clustered-pool runtime gate with SourceModel,
//! CargoUnit, in-memory channel, or scaffolding-only validation.

use std::collections::BTreeMap;

use crate::pool_config::{ClusterPlacementPolicy, ClusterPoolConfig};
use crate::pool_protocol::{
    ClusterPoolCreateRequest, ClusterPoolCreateResponse, ClusterPoolImportRequest,
    ClusterPoolImportResponse, ClusterPoolMessage, NodeDeviceSpec,
};

// ---------------------------------------------------------------------------
// PoolTransport — abstract transport for pool protocol messages
// ---------------------------------------------------------------------------

/// Trait for sending and receiving cluster pool prototype messages.
///
/// Implementations may use tidefs-transport sessions, in-memory channels
/// for testing, or any other reliable delivery mechanism.  The transport
/// is responsible for authenticity and integrity; this protocol layer
/// does not add per-message cryptographic verification and does not define
/// final distributed operator UAPI.
pub trait PoolTransport {
    /// The error type returned by send/receive operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Send a pool protocol message to a target node.
    fn send(&self, target_node_id: u64, message: ClusterPoolMessage) -> Result<(), Self::Error>;

    /// Receive a pool protocol message (blocking or async wrapper).
    /// Returns `None` if no message is available within a timeout.
    fn recv(&self) -> Result<Option<(u64, ClusterPoolMessage)>, Self::Error>;
}

// ---------------------------------------------------------------------------
// Orchestration errors
// ---------------------------------------------------------------------------

/// Errors that can occur during cluster pool orchestration.
#[derive(Clone, Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error("no devices configured for node {node_id}")]
    NoDevicesForNode { node_id: u64 },

    #[error("node {node_id} failed pool creation: {reason}")]
    NodeCreateFailed { node_id: u64, reason: String },

    #[error("node {node_id} failed pool import: {reason}")]
    NodeImportFailed { node_id: u64, reason: String },

    #[error("quorum not reached: {succeeded}/{total} nodes succeeded")]
    QuorumNotReached {
        succeeded: usize,
        total: usize,
        outcome: Option<CreateOutcome>,
    },

    #[error("response from unknown node {node_id}")]
    UnknownNode { node_id: u64 },

    #[error("transport error: {0}")]
    Transport(String),

    #[error("timeout waiting for response from {pending} node(s)")]
    Timeout { pending: usize },
}

// ---------------------------------------------------------------------------
// CreateOutcome — aggregate result of multi-node pool creation
// ---------------------------------------------------------------------------

/// Aggregate result of a multi-node pool creation.
#[derive(Clone, Debug)]
pub struct CreateOutcome {
    /// Pool GUID assigned to the pool.
    pub pool_guid: [u8; 16],
    /// Pool name.
    pub pool_name: String,
    /// Total number of nodes targeted.
    pub total_nodes: usize,
    /// Number of nodes that succeeded.
    pub succeeded: usize,
    /// Per-node results (node_id -> per-node device GUIDs).
    pub node_results: BTreeMap<u64, NodeCreateResult>,
}

/// Result for a single node during pool creation.
#[derive(Clone, Debug)]
pub struct NodeCreateResult {
    /// Whether creation succeeded on this node.
    pub success: bool,
    /// Per-device GUIDs assigned during label creation.
    pub device_guids: Vec<[u8; 16]>,
    /// Error message if creation failed.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// ImportOutcome — aggregate result of multi-node pool import
// ---------------------------------------------------------------------------

/// Aggregate result of a multi-node pool import.
#[derive(Clone, Debug)]
pub struct ImportOutcome {
    /// Pool GUID that was imported.
    pub pool_guid: [u8; 16],
    /// Total number of nodes targeted.
    pub total_nodes: usize,
    /// Number of nodes that succeeded.
    pub succeeded: usize,
    /// Per-node results.
    pub node_results: BTreeMap<u64, NodeImportResult>,
}

/// Result for a single node during pool import.
#[derive(Clone, Debug)]
pub struct NodeImportResult {
    /// Whether import succeeded on this node.
    pub success: bool,
    /// Committed root epoch recovered during import.
    pub committed_root_epoch: Option<u64>,
    /// Number of intent log records replayed.
    pub intent_log_replayed: Option<u64>,
    /// Error message if import failed.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// ClusterPoolOrchestrator
// ---------------------------------------------------------------------------

/// Coordinates multi-node pool lifecycle operations.
///
/// The orchestrator builds per-node protocol messages from a
/// [`ClusterPoolConfig`] and dispatches them through a [`PoolTransport`].
pub struct ClusterPoolOrchestrator;

impl ClusterPoolOrchestrator {
    /// Build the set of per-node create requests from a config.
    ///
    /// Returns a map from node_id to the create request for that node.
    /// The caller is responsible for sending these requests through
    /// the transport and collecting responses.
    pub fn build_create_requests(
        config: &ClusterPoolConfig,
        request_id: u64,
    ) -> BTreeMap<u64, ClusterPoolCreateRequest> {
        let mut map = BTreeMap::new();
        for &node_id in &config.node_ids {
            let node_devices: Vec<NodeDeviceSpec> = config
                .devices_for_node(node_id)
                .into_iter()
                .map(NodeDeviceSpec::from)
                .collect();

            if node_devices.is_empty() {
                continue;
            }

            map.insert(
                node_id,
                ClusterPoolCreateRequest {
                    request_id,
                    pool_guid: config.pool_guid,
                    pool_name: config.pool_name.clone(),
                    target_node_id: node_id,
                    node_devices,
                    redundancy: config.redundancy,
                    placement: ClusterPlacementPolicy::from_redundancy(config.redundancy),
                    allow_file_devices: config.allow_file_devices,
                },
            );
        }
        map
    }

    /// Build the set of per-node import requests from a config.
    pub fn build_import_requests(
        config: &ClusterPoolConfig,
        request_id: u64,
        read_only: bool,
    ) -> BTreeMap<u64, ClusterPoolImportRequest> {
        let mut map = BTreeMap::new();
        for &node_id in &config.node_ids {
            let device_paths: Vec<String> = config
                .devices_for_node(node_id)
                .into_iter()
                .map(|nd| nd.device_path.to_string_lossy().to_string())
                .collect();

            map.insert(
                node_id,
                ClusterPoolImportRequest {
                    request_id,
                    pool_guid: config.pool_guid,
                    target_node_id: node_id,
                    device_paths,
                    read_only,
                },
            );
        }
        map
    }

    /// Aggregate create responses into a [`CreateOutcome`].
    ///
    /// `responses` is a map from node_id to the response received from
    /// that node.  Any node in `expected_nodes` that does not have a
    /// response is treated as failed.
    pub fn aggregate_create_responses(
        pool_guid: [u8; 16],
        pool_name: &str,
        expected_nodes: &[u64],
        responses: &BTreeMap<u64, ClusterPoolCreateResponse>,
    ) -> CreateOutcome {
        let total = expected_nodes.len();
        let mut node_results = BTreeMap::new();
        let mut succeeded = 0usize;

        for &node_id in expected_nodes {
            if let Some(resp) = responses.get(&node_id) {
                node_results.insert(
                    node_id,
                    NodeCreateResult {
                        success: resp.success,
                        device_guids: resp.device_guids.clone(),
                        error: resp.error.clone(),
                    },
                );
                if resp.success {
                    succeeded += 1;
                }
            } else {
                node_results.insert(
                    node_id,
                    NodeCreateResult {
                        success: false,
                        device_guids: vec![],
                        error: Some("no response received".to_string()),
                    },
                );
            }
        }

        CreateOutcome {
            pool_guid,
            pool_name: pool_name.to_string(),
            total_nodes: total,
            succeeded,
            node_results,
        }
    }

    /// Aggregate import responses into an [`ImportOutcome`].
    pub fn aggregate_import_responses(
        pool_guid: [u8; 16],
        expected_nodes: &[u64],
        responses: &BTreeMap<u64, ClusterPoolImportResponse>,
    ) -> ImportOutcome {
        let total = expected_nodes.len();
        let mut node_results = BTreeMap::new();
        let mut succeeded = 0usize;

        for &node_id in expected_nodes {
            if let Some(resp) = responses.get(&node_id) {
                node_results.insert(
                    node_id,
                    NodeImportResult {
                        success: resp.success,
                        committed_root_epoch: resp.committed_root_epoch,
                        intent_log_replayed: resp.intent_log_replayed,
                        error: resp.error.clone(),
                    },
                );
                if resp.success {
                    succeeded += 1;
                }
            } else {
                node_results.insert(
                    node_id,
                    NodeImportResult {
                        success: false,
                        committed_root_epoch: None,
                        intent_log_replayed: None,
                        error: Some("no response received".to_string()),
                    },
                );
            }
        }

        ImportOutcome {
            pool_guid,
            total_nodes: total,
            succeeded,
            node_results,
        }
    }
    /// Dispatch per-node create requests through a [`PoolTransport`],
    /// collect responses, aggregate results, and validate quorum.
    ///
    /// Returns `Ok(CreateOutcome)` when all nodes respond with success.
    /// Returns `Err(OrchestratorError::QuorumNotReached)` when one or more
    /// nodes fail or time out.  Partial results are preserved in the
    /// outcome for prototype diagnostics.
    ///
    /// The caller is responsible for providing a transport already
    /// connected to all target nodes.
    pub fn dispatch_create(
        config: &ClusterPoolConfig,
        request_id: u64,
        transport: &dyn PoolTransport<Error = OrchestratorError>,
        timeout_iterations: usize,
    ) -> Result<CreateOutcome, OrchestratorError> {
        // 1. Build per-node requests.
        let requests = Self::build_create_requests(config, request_id);
        if requests.is_empty() {
            return Err(OrchestratorError::NoDevicesForNode { node_id: 0 });
        }

        let expected_nodes: Vec<u64> = requests.keys().copied().collect();

        // 2. Send all requests.
        for (&node_id, req) in &requests {
            transport
                .send(node_id, ClusterPoolMessage::CreateRequest(req.clone()))
                .map_err(|e| {
                    OrchestratorError::Transport(format!("send to node {node_id}: {e}"))
                })?;
        }

        // 3. Collect responses with a spin-timeout loop.
        let mut responses: BTreeMap<u64, ClusterPoolCreateResponse> = BTreeMap::new();
        let mut remaining = expected_nodes.len();

        for _iter in 0..timeout_iterations {
            if remaining == 0 {
                break;
            }
            match transport.recv() {
                Ok(Some((node_id, msg))) => match msg {
                    ClusterPoolMessage::CreateResponse(resp) => {
                        if !responses.contains_key(&node_id) {
                            remaining -= 1;
                            responses.insert(node_id, resp);
                        }
                    }
                    other => {
                        eprintln!(
                            "tidefsctl: unexpected response type from node {node_id}: {:?}",
                            std::mem::discriminant(&other)
                        );
                    }
                },
                Ok(None) => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => {
                    return Err(OrchestratorError::Transport(format!("recv: {e}")));
                }
            }
        }

        // 4. Aggregate and validate.
        let outcome = Self::aggregate_create_responses(
            config.pool_guid,
            &config.pool_name,
            &expected_nodes,
            &responses,
        );
        let outcome = Self::check_create_quorum(outcome)?;
        Ok(outcome)
    }

    /// Validate that a create outcome has full quorum (all nodes succeeded).
    ///
    /// Returns `Ok(())` if all nodes succeeded, or
    /// `Err(OrchestratorError::QuorumNotReached)` otherwise.
    pub fn check_create_quorum(outcome: CreateOutcome) -> Result<CreateOutcome, OrchestratorError> {
        if outcome.succeeded == outcome.total_nodes {
            return Ok(outcome);
        }

        // Capture counts before moving outcome. Per-node failure details are
        // preserved in the outcome carried by the error for prototype
        // diagnostics.
        let succeeded = outcome.succeeded;
        let total = outcome.total_nodes;

        Err(OrchestratorError::QuorumNotReached {
            outcome: Some(outcome),
            succeeded,
            total,
        })
    }

    /// Validate that an import outcome has full quorum.
    pub fn check_import_quorum(outcome: &ImportOutcome) -> Result<(), OrchestratorError> {
        if outcome.succeeded == outcome.total_nodes {
            return Ok(());
        }
        Err(OrchestratorError::QuorumNotReached {
            outcome: None,
            succeeded: outcome.succeeded,
            total: outcome.total_nodes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool_config::{
        ClusterPlacementPolicy, ClusterRedundancy, FailureDomain, NodeDevice,
    };
    use std::path::PathBuf;

    fn make_test_device(node_id: u64, local_idx: u32, global_idx: u32) -> NodeDevice {
        NodeDevice::new(
            PathBuf::from(format!("/dev/node{node_id}-disk{local_idx}")),
            [local_idx as u8; 16],
            local_idx,
            global_idx,
            1024 * 1024 * 1024,
            node_id,
            FailureDomain::for_node(node_id),
        )
    }

    fn make_three_node_config() -> ClusterPoolConfig {
        let devices = vec![
            make_test_device(1, 0, 0),
            make_test_device(2, 0, 1),
            make_test_device(3, 0, 2),
        ];
        ClusterPoolConfig::new(
            [0xAB; 16],
            "clustertest".into(),
            devices,
            ClusterPlacementPolicy::Stripe,
        )
    }

    // -- build_create_requests tests --

    #[test]
    fn build_create_requests_three_nodes() {
        let config = make_three_node_config();
        let requests = ClusterPoolOrchestrator::build_create_requests(&config, 42);

        assert_eq!(requests.len(), 3);
        assert!(requests.contains_key(&1));
        assert!(requests.contains_key(&2));
        assert!(requests.contains_key(&3));

        for (node_id, req) in &requests {
            assert_eq!(req.request_id, 42);
            assert_eq!(req.pool_guid, [0xAB; 16]);
            assert_eq!(req.pool_name, "clustertest");
            assert_eq!(req.target_node_id, *node_id);
            assert_eq!(req.node_devices.len(), 1);
            assert_eq!(req.redundancy, ClusterRedundancy::None);
            assert_eq!(req.placement, ClusterPlacementPolicy::Stripe);
        }
    }

    #[test]
    fn build_create_requests_two_nodes_four_devices() {
        let devices = vec![
            make_test_device(10, 0, 0),
            make_test_device(10, 1, 1),
            make_test_device(20, 0, 2),
            make_test_device(20, 1, 3),
        ];
        let config = ClusterPoolConfig::new(
            [0xCD; 16],
            "fourdisk".into(),
            devices,
            ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 },
        );
        let requests = ClusterPoolOrchestrator::build_create_requests(&config, 1);

        assert_eq!(requests.len(), 2);
        assert_eq!(requests[&10].node_devices.len(), 2);
        assert_eq!(requests[&20].node_devices.len(), 2);
        assert_eq!(requests[&10].target_node_id, 10);
        assert_eq!(requests[&20].target_node_id, 20);
        assert_eq!(
            requests[&10].redundancy,
            ClusterRedundancy::MirrorAcrossNodes { copies: 2 }
        );
        assert_eq!(
            requests[&20].redundancy,
            ClusterRedundancy::MirrorAcrossNodes { copies: 2 }
        );
    }

    #[test]
    fn build_create_requests_derive_placement_from_redundancy() {
        let mut config = make_three_node_config();
        config.redundancy = ClusterRedundancy::ErasureCoded {
            data_shards: 2,
            parity_shards: 1,
        };
        config.placement = ClusterPlacementPolicy::Stripe;

        let requests = ClusterPoolOrchestrator::build_create_requests(&config, 5);

        assert_eq!(requests.len(), 3);
        for req in requests.values() {
            assert_eq!(
                req.redundancy,
                ClusterRedundancy::ErasureCoded {
                    data_shards: 2,
                    parity_shards: 1,
                }
            );
            assert_eq!(
                req.placement,
                ClusterPlacementPolicy::ErasureCoded { data: 2, parity: 1 }
            );
        }
    }

    #[test]
    fn build_create_requests_preserves_file_device_opt_in() {
        let config = make_three_node_config().with_file_devices_for_development(true);
        let requests = ClusterPoolOrchestrator::build_create_requests(&config, 7);

        assert!(requests.values().all(|req| req.allow_file_devices));
    }

    // -- build_import_requests tests --

    #[test]
    fn build_import_requests_three_nodes() {
        let config = make_three_node_config();
        let requests = ClusterPoolOrchestrator::build_import_requests(&config, 99, false);

        assert_eq!(requests.len(), 3);
        for (node_id, req) in &requests {
            assert_eq!(req.request_id, 99);
            assert_eq!(req.pool_guid, [0xAB; 16]);
            assert_eq!(req.target_node_id, *node_id);
            assert_eq!(req.device_paths.len(), 1);
            assert!(!req.read_only);
        }
    }

    #[test]
    fn build_import_requests_readonly() {
        let config = make_three_node_config();
        let requests = ClusterPoolOrchestrator::build_import_requests(&config, 1, true);

        for req in requests.values() {
            assert!(req.read_only);
        }
    }

    // -- aggregate_create_responses tests --

    #[test]
    fn aggregate_create_all_success() {
        let mut responses = BTreeMap::new();
        responses.insert(
            1,
            ClusterPoolCreateResponse {
                request_id: 42,
                node_id: 1,
                pool_guid: [0xAB; 16],
                success: true,
                device_guids: vec![[0x01; 16]],
                error: None,
            },
        );
        responses.insert(
            2,
            ClusterPoolCreateResponse {
                request_id: 42,
                node_id: 2,
                pool_guid: [0xAB; 16],
                success: true,
                device_guids: vec![[0x02; 16]],
                error: None,
            },
        );
        responses.insert(
            3,
            ClusterPoolCreateResponse {
                request_id: 42,
                node_id: 3,
                pool_guid: [0xAB; 16],
                success: true,
                device_guids: vec![[0x03; 16]],
                error: None,
            },
        );

        let outcome = ClusterPoolOrchestrator::aggregate_create_responses(
            [0xAB; 16],
            "clustertest",
            &[1, 2, 3],
            &responses,
        );

        assert_eq!(outcome.total_nodes, 3);
        assert_eq!(outcome.succeeded, 3);
        assert_eq!(outcome.pool_name, "clustertest");
        assert!(ClusterPoolOrchestrator::check_create_quorum(outcome).is_ok());
    }

    #[test]
    fn aggregate_create_partial_failure() {
        let mut responses = BTreeMap::new();
        responses.insert(
            1,
            ClusterPoolCreateResponse {
                request_id: 1,
                node_id: 1,
                pool_guid: [0xEE; 16],
                success: true,
                device_guids: vec![[0xAA; 16]],
                error: None,
            },
        );
        responses.insert(
            2,
            ClusterPoolCreateResponse {
                request_id: 1,
                node_id: 2,
                pool_guid: [0xEE; 16],
                success: false,
                device_guids: vec![],
                error: Some("device too small".into()),
            },
        );
        // Node 3 missing (no response)

        let outcome = ClusterPoolOrchestrator::aggregate_create_responses(
            [0xEE; 16],
            "partial",
            &[1, 2, 3],
            &responses,
        );

        assert_eq!(outcome.total_nodes, 3);
        assert_eq!(outcome.succeeded, 1);
        assert!(outcome.node_results[&2].error.as_deref() == Some("device too small"));
        assert!(!outcome.node_results[&3].success);
        assert!(outcome.node_results[&3].error.as_deref() == Some("no response received"));
        assert!(ClusterPoolOrchestrator::check_create_quorum(outcome).is_err());
    }

    #[test]
    fn check_create_quorum_full_success() {
        let outcome = CreateOutcome {
            pool_guid: [0x00; 16],
            pool_name: "full".into(),
            total_nodes: 3,
            succeeded: 3,
            node_results: BTreeMap::new(),
        };
        assert!(ClusterPoolOrchestrator::check_create_quorum(outcome).is_ok());
    }

    #[test]
    fn check_create_quorum_one_failure() {
        let outcome = CreateOutcome {
            pool_guid: [0x00; 16],
            pool_name: "fail".into(),
            total_nodes: 3,
            succeeded: 2,
            node_results: BTreeMap::from([(
                3,
                NodeCreateResult {
                    success: false,
                    device_guids: vec![],
                    error: Some("timeout".into()),
                },
            )]),
        };
        let err = ClusterPoolOrchestrator::check_create_quorum(outcome).unwrap_err();
        assert!(format!("{err}").contains("2/3"));
    }

    // -- aggregate_import_responses tests --

    #[test]
    fn aggregate_import_all_success() {
        let mut responses = BTreeMap::new();
        for node_id in 1..=3u64 {
            responses.insert(
                node_id,
                ClusterPoolImportResponse {
                    request_id: 1,
                    node_id,
                    pool_guid: [0xBB; 16],
                    success: true,
                    committed_root_epoch: Some(5),
                    intent_log_replayed: Some(10),
                    error: None,
                },
            );
        }

        let outcome =
            ClusterPoolOrchestrator::aggregate_import_responses([0xBB; 16], &[1, 2, 3], &responses);

        assert_eq!(outcome.total_nodes, 3);
        assert_eq!(outcome.succeeded, 3);
        assert!(ClusterPoolOrchestrator::check_import_quorum(&outcome).is_ok());
    }

    #[test]
    fn aggregate_import_partial_failure() {
        let mut responses = BTreeMap::new();
        responses.insert(
            1,
            ClusterPoolImportResponse {
                request_id: 1,
                node_id: 1,
                pool_guid: [0xCC; 16],
                success: true,
                committed_root_epoch: Some(3),
                intent_log_replayed: Some(5),
                error: None,
            },
        );
        // Nodes 2 and 3 missing

        let outcome =
            ClusterPoolOrchestrator::aggregate_import_responses([0xCC; 16], &[1, 2, 3], &responses);

        assert_eq!(outcome.total_nodes, 3);
        assert_eq!(outcome.succeeded, 1);
        assert!(!outcome.node_results[&2].success);
        assert!(ClusterPoolOrchestrator::check_import_quorum(&outcome).is_err());
    }

    #[test]
    fn check_import_quorum_full_success() {
        let outcome = ImportOutcome {
            pool_guid: [0x00; 16],
            total_nodes: 2,
            succeeded: 2,
            node_results: BTreeMap::new(),
        };
        assert!(ClusterPoolOrchestrator::check_import_quorum(&outcome).is_ok());
    }

    #[test]
    fn check_import_quorum_failure() {
        let outcome = ImportOutcome {
            pool_guid: [0x00; 16],
            total_nodes: 2,
            succeeded: 1,
            node_results: BTreeMap::new(),
        };
        assert!(ClusterPoolOrchestrator::check_import_quorum(&outcome).is_err());
    }

    // -- OrchestratorError display tests --

    #[test]
    fn orchestrator_error_display() {
        let err = OrchestratorError::NoDevicesForNode { node_id: 7 };
        assert!(format!("{err}").contains("node 7"));

        let err = OrchestratorError::NodeCreateFailed {
            node_id: 3,
            reason: "disk full".into(),
        };
        assert!(format!("{err}").contains("node 3"));
        assert!(format!("{err}").contains("disk full"));

        let err = OrchestratorError::QuorumNotReached {
            outcome: None,
            succeeded: 2,
            total: 5,
        };
        assert!(format!("{err}").contains("2/5"));
    }
}
