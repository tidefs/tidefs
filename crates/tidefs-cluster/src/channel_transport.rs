//! In-memory channel transport for testing the cluster pool orchestrator.
//!
//! [`ChannelPoolTransport`] implements [`crate::pool_orchestrator::PoolTransport`]
//! using tokio MPSC channels.  It is intended for unit/integration tests of
//! the orchestrator without requiring a real network or transport backend.
//!
//! # Example
//!
//! ```ignore
//! use tidefs_cluster::channel_transport::ChannelPoolTransport;
//! use tidefs_cluster::pool_orchestrator::{ClusterPoolOrchestrator, PoolTransport};
//!
//! let config = /* ClusterPoolConfig */;
//! let transport = ChannelPoolTransport::new();
//! let requests = ClusterPoolOrchestrator::build_create_requests(&config, 1);
//! for (node_id, req) in &requests {
//!     transport.send(*node_id, ClusterPoolMessage::CreateRequest(req.clone())).unwrap();
//! }
//! ```

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::pool_orchestrator::PoolTransport;
use crate::pool_protocol::ClusterPoolMessage;

type InboundQueue = BTreeMap<u64, Vec<(u64, ClusterPoolMessage)>>;
type OutboundQueue = Vec<(u64, ClusterPoolMessage)>;
type SharedInboundQueue = Arc<Mutex<InboundQueue>>;
type SharedOutboundQueue = Arc<Mutex<OutboundQueue>>;

/// Error type for channel transport operations.
#[derive(Clone, Debug)]
pub enum ChannelTransportError {
    /// The target node has no receiver registered.
    NoReceiver(u64),
    /// The channel is closed (receiver dropped).
    ChannelClosed(u64),
    /// No messages available.
    NoMessages,
}

impl std::fmt::Display for ChannelTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoReceiver(node_id) => write!(f, "no receiver registered for node {node_id}"),
            Self::ChannelClosed(node_id) => write!(f, "channel closed for node {node_id}"),
            Self::NoMessages => write!(f, "no messages available"),
        }
    }
}

impl std::error::Error for ChannelTransportError {}

/// A channel-based pool transport for testing.
///
/// Each "node" is represented by a pair of MPSC channels (one for
/// sending to the node, one for receiving from the node).  Messages
/// sent via [`send`](ChannelPoolTransport::send) are delivered to the
/// target node's inbound queue.
///
/// For testing the orchestrator end-to-end, register a receiver for
/// each node, send create/import requests, and simulate node responses
/// by pushing response messages into the transport's outbound queue.
#[derive(Clone, Default)]
pub struct ChannelPoolTransport {
    /// Per-node inbound queues: node_id -> Vec of messages sent TO that node.
    inbound: SharedInboundQueue,
    /// Global outbound queue: messages that nodes "sent back" to the orchestrator.
    outbound: SharedOutboundQueue,
}

impl ChannelPoolTransport {
    /// Create an empty channel transport.
    pub fn new() -> Self {
        Self {
            inbound: Arc::new(Mutex::new(BTreeMap::new())),
            outbound: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Deliver a response from a simulated node back to the orchestrator.
    ///
    /// The `sender_node_id` identifies which simulated node sent this
    /// response.  The message is placed on the transport's outbound queue
    /// where [`recv`](PoolTransport::recv) will pick it up.
    pub fn inject_response(&self, sender_node_id: u64, message: ClusterPoolMessage) {
        self.outbound
            .lock()
            .unwrap()
            .push((sender_node_id, message));
    }

    /// Drain all messages sent to a particular node and return them.
    ///
    /// This lets a test inspect what the orchestrator sent to each node.
    pub fn drain_node(&self, node_id: u64) -> Vec<ClusterPoolMessage> {
        let mut inbound = self.inbound.lock().unwrap();
        inbound
            .remove(&node_id)
            .unwrap_or_default()
            .into_iter()
            .map(|(_, msg)| msg)
            .collect()
    }

    /// Return the number of pending outbound messages (responses not yet
    /// consumed by the orchestrator).
    pub fn pending_response_count(&self) -> usize {
        self.outbound.lock().unwrap().len()
    }

    /// Clear all inbound and outbound queues.
    pub fn clear(&self) {
        self.inbound.lock().unwrap().clear();
        self.outbound.lock().unwrap().clear();
    }
}

impl PoolTransport for ChannelPoolTransport {
    type Error = ChannelTransportError;

    fn send(&self, target_node_id: u64, message: ClusterPoolMessage) -> Result<(), Self::Error> {
        let mut inbound = self.inbound.lock().unwrap();
        inbound
            .entry(target_node_id)
            .or_default()
            .push((target_node_id, message));
        Ok(())
    }

    fn recv(&self) -> Result<Option<(u64, ClusterPoolMessage)>, Self::Error> {
        let mut outbound = self.outbound.lock().unwrap();
        if outbound.is_empty() {
            return Ok(None);
        }
        Ok(Some(outbound.remove(0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool_config::{
        ClusterPlacementPolicy, ClusterPoolConfig, ClusterRedundancy, FailureDomain, NodeDevice,
    };
    use crate::pool_orchestrator::ClusterPoolOrchestrator;
    use crate::pool_protocol::{ClusterPoolCreateRequest, ClusterPoolCreateResponse};
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
            "channeltest".into(),
            devices,
            ClusterPlacementPolicy::Stripe,
        )
    }

    // -- ChannelPoolTransport unit tests --

    #[test]
    fn transport_send_and_drain() {
        let transport = ChannelPoolTransport::new();
        let msg = ClusterPoolMessage::CreateRequest(ClusterPoolCreateRequest {
            request_id: 1,
            pool_guid: [0x11; 16],
            pool_name: "test".into(),
            target_node_id: 5,
            node_devices: vec![],
            redundancy: ClusterRedundancy::None,
            placement: ClusterPlacementPolicy::Stripe,
            allow_file_devices: false,
        });

        transport.send(5, msg.clone()).unwrap();

        let drained = transport.drain_node(5);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0], msg);
    }

    #[test]
    fn transport_send_multiple_nodes() {
        let transport = ChannelPoolTransport::new();
        let msg1 = ClusterPoolMessage::CreateRequest(ClusterPoolCreateRequest {
            request_id: 1,
            pool_guid: [0xAA; 16],
            pool_name: "a".into(),
            target_node_id: 1,
            node_devices: vec![],
            redundancy: ClusterRedundancy::None,
            placement: ClusterPlacementPolicy::Stripe,
            allow_file_devices: false,
        });
        let msg2 = ClusterPoolMessage::CreateRequest(ClusterPoolCreateRequest {
            request_id: 1,
            pool_guid: [0xAA; 16],
            pool_name: "a".into(),
            target_node_id: 2,
            node_devices: vec![],
            redundancy: ClusterRedundancy::None,
            placement: ClusterPlacementPolicy::Stripe,
            allow_file_devices: false,
        });

        transport.send(1, msg1.clone()).unwrap();
        transport.send(2, msg2.clone()).unwrap();

        assert_eq!(transport.drain_node(1).len(), 1);
        assert_eq!(transport.drain_node(2).len(), 1);
    }

    #[test]
    fn transport_recv_returns_none_when_empty() {
        let transport = ChannelPoolTransport::new();
        let result = transport.recv().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn transport_inject_and_recv() {
        let transport = ChannelPoolTransport::new();
        let resp = ClusterPoolMessage::CreateResponse(ClusterPoolCreateResponse {
            request_id: 42,
            node_id: 3,
            pool_guid: [0xBB; 16],
            success: true,
            device_guids: vec![[0x01; 16]],
            error: None,
        });

        transport.inject_response(3, resp.clone());

        let received = transport.recv().unwrap().unwrap();
        assert_eq!(received.0, 3);
        assert_eq!(received.1, resp);

        // Second recv returns None.
        assert!(transport.recv().unwrap().is_none());
    }

    #[test]
    fn transport_pending_response_count() {
        let transport = ChannelPoolTransport::new();
        assert_eq!(transport.pending_response_count(), 0);

        transport.inject_response(
            1,
            ClusterPoolMessage::CreateResponse(ClusterPoolCreateResponse {
                request_id: 1,
                node_id: 1,
                pool_guid: [0x00; 16],
                success: true,
                device_guids: vec![],
                error: None,
            }),
        );
        assert_eq!(transport.pending_response_count(), 1);

        transport.inject_response(
            2,
            ClusterPoolMessage::CreateResponse(ClusterPoolCreateResponse {
                request_id: 1,
                node_id: 2,
                pool_guid: [0x00; 16],
                success: true,
                device_guids: vec![],
                error: None,
            }),
        );
        assert_eq!(transport.pending_response_count(), 2);
    }

    #[test]
    fn transport_clear() {
        let transport = ChannelPoolTransport::new();
        transport.inject_response(
            1,
            ClusterPoolMessage::CreateResponse(ClusterPoolCreateResponse {
                request_id: 1,
                node_id: 1,
                pool_guid: [0x00; 16],
                success: true,
                device_guids: vec![],
                error: None,
            }),
        );
        transport
            .send(
                5,
                ClusterPoolMessage::CreateResponse(ClusterPoolCreateResponse {
                    request_id: 1,
                    node_id: 5,
                    pool_guid: [0x00; 16],
                    success: true,
                    device_guids: vec![],
                    error: None,
                }),
            )
            .unwrap();

        transport.clear();
        assert_eq!(transport.pending_response_count(), 0);
        assert!(transport.drain_node(5).is_empty());
    }

    // -- End-to-end orchestrator test with channel transport --

    #[test]
    fn orchestrator_create_flow_three_nodes() {
        let config = make_three_node_config();
        let transport = ChannelPoolTransport::new();

        // 1. Build per-node create requests.
        let requests = ClusterPoolOrchestrator::build_create_requests(&config, 100);

        // 2. Send requests to each node via the channel transport.
        for (&node_id, req) in &requests {
            transport
                .send(node_id, ClusterPoolMessage::CreateRequest(req.clone()))
                .unwrap();
        }

        // 3. Verify each node received exactly one create request.
        for node_id in [1u64, 2, 3] {
            let msgs = transport.drain_node(node_id);
            assert_eq!(msgs.len(), 1, "node {node_id} should have 1 message");
            match &msgs[0] {
                ClusterPoolMessage::CreateRequest(req) => {
                    assert_eq!(req.request_id, 100);
                    assert_eq!(req.pool_guid, [0xAB; 16]);
                    assert_eq!(req.pool_name, "channeltest");
                    assert_eq!(req.target_node_id, node_id);
                }
                other => panic!("expected CreateRequest, got {other:?}"),
            }
        }

        // 4. Simulate all three nodes responding with success.
        for node_id in [1u64, 2, 3] {
            transport.inject_response(
                node_id,
                ClusterPoolMessage::CreateResponse(ClusterPoolCreateResponse {
                    request_id: 100,
                    node_id,
                    pool_guid: [0xAB; 16],
                    success: true,
                    device_guids: vec![[node_id as u8; 16]],
                    error: None,
                }),
            );
        }

        // 5. Collect responses.
        let mut responses = BTreeMap::new();
        while let Ok(Some((node_id, msg))) = transport.recv() {
            match msg {
                ClusterPoolMessage::CreateResponse(resp) => {
                    responses.insert(node_id, resp);
                }
                other => panic!("expected CreateResponse, got {other:?}"),
            }
        }

        assert_eq!(responses.len(), 3);

        // 6. Aggregate and verify quorum.
        let outcome = ClusterPoolOrchestrator::aggregate_create_responses(
            config.pool_guid,
            &config.pool_name,
            &[1, 2, 3],
            &responses,
        );
        assert_eq!(outcome.total_nodes, 3);
        assert_eq!(outcome.succeeded, 3);
        assert!(ClusterPoolOrchestrator::check_create_quorum(outcome).is_ok());
    }

    #[test]
    fn orchestrator_create_flow_partial_failure() {
        let config = make_three_node_config();
        let transport = ChannelPoolTransport::new();

        let requests = ClusterPoolOrchestrator::build_create_requests(&config, 200);
        for (&node_id, req) in &requests {
            transport
                .send(node_id, ClusterPoolMessage::CreateRequest(req.clone()))
                .unwrap();
        }

        // Node 1 succeeds.
        transport.inject_response(
            1,
            ClusterPoolMessage::CreateResponse(ClusterPoolCreateResponse {
                request_id: 200,
                node_id: 1,
                pool_guid: [0xAB; 16],
                success: true,
                device_guids: vec![[0x01; 16]],
                error: None,
            }),
        );

        // Node 2 fails.
        transport.inject_response(
            2,
            ClusterPoolMessage::CreateResponse(ClusterPoolCreateResponse {
                request_id: 200,
                node_id: 2,
                pool_guid: [0xAB; 16],
                success: false,
                device_guids: vec![],
                error: Some("device too small".into()),
            }),
        );

        // Node 3 times out (no response).

        let mut responses = BTreeMap::new();
        while let Ok(Some((node_id, msg))) = transport.recv() {
            if let ClusterPoolMessage::CreateResponse(resp) = msg {
                responses.insert(node_id, resp);
            }
        }

        assert_eq!(responses.len(), 2);

        let outcome = ClusterPoolOrchestrator::aggregate_create_responses(
            config.pool_guid,
            &config.pool_name,
            &[1, 2, 3],
            &responses,
        );
        assert_eq!(outcome.succeeded, 1);
        assert!(ClusterPoolOrchestrator::check_create_quorum(outcome).is_err());
    }
}
