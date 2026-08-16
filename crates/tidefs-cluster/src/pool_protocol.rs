// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Cluster pool wire protocol: create, import, and lifecycle message types
//! for multi-node pool operations.
//!
//! Each message is serialized with `bincode` prefixed by a 1-byte
//! discriminant.  Node-to-node authenticity and integrity are provided by
//! the transport/session security boundary; this protocol does not add
//! per-message BLAKE3 or MAC layers.

use serde::{Deserialize, Serialize};

use crate::pool_config::{
    ClusterPlacementPolicy, ClusterPoolConfig, ClusterRedundancy, FailureDomain, NodeDevice,
};
use crate::pool_lease_token::PoolLeaseToken;

// ---------------------------------------------------------------------------
// ProtocolError
// ---------------------------------------------------------------------------

/// Encode/decode errors for the cluster pool protocol.
#[derive(Clone, Debug, thiserror::Error)]
pub enum PoolProtocolError {
    #[error("bincode serialize error: {0}")]
    Serialize(String),
    #[error("bincode deserialize error: {0}")]
    Deserialize(String),
    #[error("unknown message discriminant: {0:#x}")]
    UnknownDiscriminant(u8),
    #[error("payload too short: {0} bytes")]
    PayloadTooShort(usize),
}

// ---------------------------------------------------------------------------
// Message discriminants
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PoolDiscriminant {
    CreateRequest = 0x10,
    CreateResponse = 0x11,
    ImportRequest = 0x12,
    ImportResponse = 0x13,
    LeaseRequest = 0x14,
    LeaseResponse = 0x15,
    OwnerObservationRequest = 0x1a,
    OwnerObservationResponse = 0x1b,
}

impl PoolDiscriminant {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x10 => Some(Self::CreateRequest),
            0x11 => Some(Self::CreateResponse),
            0x12 => Some(Self::ImportRequest),
            0x13 => Some(Self::ImportResponse),
            0x14 => Some(Self::LeaseRequest),
            0x15 => Some(Self::LeaseResponse),
            0x1a => Some(Self::OwnerObservationRequest),
            0x1b => Some(Self::OwnerObservationResponse),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// ClusterPoolCreateRequest
// ---------------------------------------------------------------------------

/// A request from the initiating node to all member nodes to create a
/// clustered pool on their local devices.
///
/// The initiating node sends one `ClusterPoolCreateRequest` per member
/// node, listing only the devices owned by that node.  Each node writes
/// its labels and responds with a [`ClusterPoolCreateResponse`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPoolCreateRequest {
    /// Opaque request id for matching responses.
    pub request_id: u64,
    /// Pool UUID shared across all nodes and devices.
    pub pool_guid: [u8; 16],
    /// Human-readable pool name.
    pub pool_name: String,
    /// The target node that should create its local devices.
    pub target_node_id: u64,
    /// Devices on the target node to initialize for this pool.
    pub node_devices: Vec<NodeDeviceSpec>,
    /// Canonical pool-wide redundancy policy for the pool.
    pub redundancy: ClusterRedundancy,
    /// Compatibility placement view derived from `redundancy`.
    ///
    /// Receivers must reject requests where this value does not match
    /// `ClusterPlacementPolicy::from_redundancy(redundancy)`.
    pub placement: ClusterPlacementPolicy,
    /// Permit regular files as explicit development media on the target node.
    ///
    /// Block devices are always allowed. Regular files are accepted only when
    /// this is true; directory/object-store roots are never valid pool media.
    #[serde(default)]
    pub allow_file_devices: bool,
}

/// Specification for a single device to be initialized on a node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDeviceSpec {
    /// Absolute path to the block device on the target node.
    pub device_path: String,
    /// 0-based local device index.
    pub local_device_index: u32,
    /// Global device index across all nodes.
    pub global_device_index: u32,
    /// Expected device capacity in bytes.
    pub capacity_bytes: u64,
    /// Failure domain for this device.
    pub failure_domain: FailureDomain,
}

impl From<&NodeDevice> for NodeDeviceSpec {
    fn from(nd: &NodeDevice) -> Self {
        Self {
            device_path: nd.device_path.to_string_lossy().to_string(),
            local_device_index: nd.local_device_index,
            global_device_index: nd.global_device_index,
            capacity_bytes: nd.capacity_bytes,
            failure_domain: nd.failure_domain,
        }
    }
}

// ---------------------------------------------------------------------------
// ClusterPoolCreateResponse
// ---------------------------------------------------------------------------

/// Response from a node after attempting to create its local devices
/// for a clustered pool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPoolCreateResponse {
    /// Matches the request_id from the corresponding
    /// [`ClusterPoolCreateRequest`].
    pub request_id: u64,
    /// The node that sent this response.
    pub node_id: u64,
    /// Pool UUID for correlation.
    pub pool_guid: [u8; 16],
    /// Whether creation succeeded on this node.
    pub success: bool,
    /// Per-device GUIDs assigned during label creation (only on success).
    pub device_guids: Vec<[u8; 16]>,
    /// Error message if creation failed.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// ClusterPoolImportRequest
// ---------------------------------------------------------------------------

/// Request to import (activate) a clustered pool, sent to all member nodes.
///
/// Each node imports its local devices for the pool, recovering committed
/// roots, replaying intent logs, and transitioning to ACTIVE state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPoolImportRequest {
    /// Opaque request id for matching responses.
    pub request_id: u64,
    /// Pool UUID to import.
    pub pool_guid: [u8; 16],
    /// The target node performing the import.
    pub target_node_id: u64,
    /// Device paths on the target node.
    pub device_paths: Vec<String>,
    /// Open read-only rather than read-write.
    pub read_only: bool,
}

// ---------------------------------------------------------------------------
// ClusterPoolImportResponse
// ---------------------------------------------------------------------------

/// Response from a node after importing its local devices for a clustered
/// pool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPoolImportResponse {
    /// Matches the request_id from the corresponding
    /// [`ClusterPoolImportRequest`].
    pub request_id: u64,
    /// The node that sent this response.
    pub node_id: u64,
    /// Pool UUID for correlation.
    pub pool_guid: [u8; 16],
    /// Whether import succeeded on this node.
    pub success: bool,
    /// Committed root epoch recovered during import (only on success).
    pub committed_root_epoch: Option<u64>,
    /// Number of intent log records replayed (only on success).
    pub intent_log_replayed: Option<u64>,
    /// Error message if import failed.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ClusterPoolLeaseRequest
// ---------------------------------------------------------------------------

/// Requested transition for one Pool owner lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterPoolLeaseAction {
    /// Acquire the Pool's single-writer lease for the authenticated requester.
    Acquire,
    /// Extend the exact current lease without changing its write fence.
    Renew { token: PoolLeaseToken },
    /// Relinquish the exact current lease after carrier drain.
    Release { token: PoolLeaseToken },
}

/// Request a Pool owner lease transition from the cluster authority.
///
/// The transport-authenticated requester identity must equal
/// `requesting_node_id`. On acquire or renew success, the response contains a
/// [`PoolLeaseToken`] authorizing clustered Pool import and mount.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPoolLeaseRequest {
    /// Opaque request id for matching responses.
    pub request_id: u64,
    /// Pool UUID to acquire a lease for.
    pub pool_guid: [u8; 16],
    /// The node requesting the lease.
    pub requesting_node_id: u64,
    /// Exact ownership transition requested by the mounted owner.
    pub action: ClusterPoolLeaseAction,
}

// ---------------------------------------------------------------------------
// ClusterPoolLeaseResponse
// ---------------------------------------------------------------------------

/// Response to a [`ClusterPoolLeaseRequest`] from the cluster authority.
///
/// On success, `lease_token` contains the serialized [`PoolLeaseToken`]
/// (bincode-encoded). The token carries the write fence and expiration
/// needed for cluster-authorized pool import.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPoolLeaseResponse {
    /// Matches the request_id from the corresponding [`ClusterPoolLeaseRequest`].
    pub request_id: u64,
    /// The authority storage-node that handled the request.
    pub node_id: u64,
    /// Pool UUID for correlation.
    pub pool_guid: [u8; 16],
    /// Whether the lease was granted.
    pub success: bool,
    /// Bincode-serialized [`PoolLeaseToken`] on success.
    pub lease_token_bytes: Option<Vec<u8>>,
    /// Opaque expiration counter from the authority's monotonic clock.
    pub lease_expiration_ms: Option<u64>,
    /// Authority-measured lease time remaining when this response was built.
    /// A client subtracts its request round trip before converting this to a
    /// process-local monotonic mutation deadline.
    pub lease_remaining_ms: Option<u64>,
    /// Error message if the lease was denied.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// ClusterPoolOwnerObservationRequest / Response
// ---------------------------------------------------------------------------

/// Request a non-capability observation of one Pool's current owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPoolOwnerObservationRequest {
    /// Opaque request ID for response correlation.
    pub request_id: u64,
    /// Pool whose current owner is requested.
    pub pool_guid: [u8; 16],
    /// Must equal the transport-authenticated requester.
    pub requesting_node_id: u64,
}

/// Current committed Pool owner as observed by the lease authority.
///
/// No import-capable [`PoolLeaseToken`] material is present in this message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPoolOwnerObservationResponse {
    /// Matches the corresponding request ID.
    pub request_id: u64,
    /// Lease-authority node producing the observation.
    pub node_id: u64,
    /// Pool GUID for response correlation.
    pub pool_guid: [u8; 16],
    /// Whether a complete current observation follows.
    pub success: bool,
    /// Current committed owner node on success.
    pub owner_node_id: Option<u64>,
    /// Current committed membership epoch on success.
    pub membership_epoch: Option<u64>,
    /// Current writer-fence generation on success.
    pub write_fence_generation: Option<u64>,
    /// Authority-measured remaining lease lifetime on success.
    pub lease_remaining_ms: Option<u64>,
    /// Refusal reason on failure.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------

/// All cluster pool protocol messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClusterPoolMessage {
    CreateRequest(ClusterPoolCreateRequest),
    CreateResponse(ClusterPoolCreateResponse),
    ImportRequest(ClusterPoolImportRequest),
    ImportResponse(ClusterPoolImportResponse),
    LeaseRequest(ClusterPoolLeaseRequest),
    LeaseResponse(ClusterPoolLeaseResponse),
    OwnerObservationRequest(ClusterPoolOwnerObservationRequest),
    OwnerObservationResponse(ClusterPoolOwnerObservationResponse),
}

impl ClusterPoolMessage {
    /// Encode this message to wire format bytes.
    ///
    /// Format: `[1-byte discriminant][bincode payload]`
    pub fn encode(&self) -> Result<Vec<u8>, PoolProtocolError> {
        let payload = self.serialize_payload()?;
        let mut bytes = Vec::with_capacity(1 + payload.len());
        bytes.push(self.discriminant());
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// Decode a cluster pool message from wire format bytes.
    pub fn decode(data: &[u8]) -> Result<Self, PoolProtocolError> {
        if data.is_empty() {
            return Err(PoolProtocolError::PayloadTooShort(0));
        }

        let discriminant = data[0];
        let payload = &data[1..];

        Self::deserialize_payload(discriminant, payload)
    }

    fn discriminant(&self) -> u8 {
        match self {
            Self::CreateRequest(_) => PoolDiscriminant::CreateRequest as u8,
            Self::CreateResponse(_) => PoolDiscriminant::CreateResponse as u8,
            Self::ImportRequest(_) => PoolDiscriminant::ImportRequest as u8,
            Self::ImportResponse(_) => PoolDiscriminant::ImportResponse as u8,
            Self::LeaseRequest(_) => PoolDiscriminant::LeaseRequest as u8,
            Self::LeaseResponse(_) => PoolDiscriminant::LeaseResponse as u8,
            Self::OwnerObservationRequest(_) => PoolDiscriminant::OwnerObservationRequest as u8,
            Self::OwnerObservationResponse(_) => PoolDiscriminant::OwnerObservationResponse as u8,
        }
    }

    fn serialize_payload(&self) -> Result<Vec<u8>, PoolProtocolError> {
        let payload =
            match self {
                Self::CreateRequest(m) => bincode::serialize(m)
                    .map_err(|e| PoolProtocolError::Serialize(e.to_string()))?,
                Self::CreateResponse(m) => bincode::serialize(m)
                    .map_err(|e| PoolProtocolError::Serialize(e.to_string()))?,
                Self::ImportRequest(m) => bincode::serialize(m)
                    .map_err(|e| PoolProtocolError::Serialize(e.to_string()))?,
                Self::ImportResponse(m) => bincode::serialize(m)
                    .map_err(|e| PoolProtocolError::Serialize(e.to_string()))?,
                Self::LeaseRequest(m) => bincode::serialize(m)
                    .map_err(|e| PoolProtocolError::Serialize(e.to_string()))?,
                Self::LeaseResponse(m) => bincode::serialize(m)
                    .map_err(|e| PoolProtocolError::Serialize(e.to_string()))?,
                Self::OwnerObservationRequest(m) => bincode::serialize(m)
                    .map_err(|e| PoolProtocolError::Serialize(e.to_string()))?,
                Self::OwnerObservationResponse(m) => bincode::serialize(m)
                    .map_err(|e| PoolProtocolError::Serialize(e.to_string()))?,
            };
        Ok(payload)
    }

    fn deserialize_payload(discriminant: u8, payload: &[u8]) -> Result<Self, PoolProtocolError> {
        let disc = PoolDiscriminant::from_u8(discriminant)
            .ok_or(PoolProtocolError::UnknownDiscriminant(discriminant))?;

        match disc {
            PoolDiscriminant::CreateRequest => {
                let msg: ClusterPoolCreateRequest = bincode::deserialize(payload)
                    .map_err(|e| PoolProtocolError::Deserialize(e.to_string()))?;
                Ok(Self::CreateRequest(msg))
            }
            PoolDiscriminant::CreateResponse => {
                let msg: ClusterPoolCreateResponse = bincode::deserialize(payload)
                    .map_err(|e| PoolProtocolError::Deserialize(e.to_string()))?;
                Ok(Self::CreateResponse(msg))
            }
            PoolDiscriminant::ImportRequest => {
                let msg: ClusterPoolImportRequest = bincode::deserialize(payload)
                    .map_err(|e| PoolProtocolError::Deserialize(e.to_string()))?;
                Ok(Self::ImportRequest(msg))
            }
            PoolDiscriminant::ImportResponse => {
                let msg: ClusterPoolImportResponse = bincode::deserialize(payload)
                    .map_err(|e| PoolProtocolError::Deserialize(e.to_string()))?;
                Ok(Self::ImportResponse(msg))
            }
            PoolDiscriminant::LeaseRequest => {
                let msg: ClusterPoolLeaseRequest = bincode::deserialize(payload)
                    .map_err(|e| PoolProtocolError::Deserialize(e.to_string()))?;
                Ok(Self::LeaseRequest(msg))
            }
            PoolDiscriminant::LeaseResponse => {
                let msg: ClusterPoolLeaseResponse = bincode::deserialize(payload)
                    .map_err(|e| PoolProtocolError::Deserialize(e.to_string()))?;
                Ok(Self::LeaseResponse(msg))
            }
            PoolDiscriminant::OwnerObservationRequest => {
                let msg: ClusterPoolOwnerObservationRequest = bincode::deserialize(payload)
                    .map_err(|e| PoolProtocolError::Deserialize(e.to_string()))?;
                Ok(Self::OwnerObservationRequest(msg))
            }
            PoolDiscriminant::OwnerObservationResponse => {
                let msg: ClusterPoolOwnerObservationResponse = bincode::deserialize(payload)
                    .map_err(|e| PoolProtocolError::Deserialize(e.to_string()))?;
                Ok(Self::OwnerObservationResponse(msg))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Builders — construct protocol messages from ClusterPoolConfig
// ---------------------------------------------------------------------------

impl ClusterPoolMessage {
    /// Build per-node create requests from a cluster pool configuration.
    ///
    /// Returns one [`ClusterPoolCreateRequest`] per unique node in the
    /// config, each containing only the devices owned by that node.
    pub fn build_create_requests(
        config: &ClusterPoolConfig,
        request_id: u64,
    ) -> Vec<ClusterPoolCreateRequest> {
        let mut requests = Vec::new();
        let seen_nodes: std::collections::BTreeSet<u64> = config.node_ids.iter().copied().collect();

        for &node_id in &seen_nodes {
            let node_devices: Vec<NodeDeviceSpec> = config
                .devices_for_node(node_id)
                .into_iter()
                .map(NodeDeviceSpec::from)
                .collect();

            if node_devices.is_empty() {
                continue;
            }

            requests.push(ClusterPoolCreateRequest {
                request_id,
                pool_guid: config.pool_guid,
                pool_name: config.pool_name.clone(),
                target_node_id: node_id,
                node_devices,
                redundancy: config.redundancy,
                placement: ClusterPlacementPolicy::from_redundancy(config.redundancy),
                allow_file_devices: config.allow_file_devices,
            });
        }

        requests
    }

    /// Build per-node import requests from a cluster pool configuration.
    pub fn build_import_requests(
        config: &ClusterPoolConfig,
        request_id: u64,
        read_only: bool,
    ) -> Vec<ClusterPoolImportRequest> {
        let seen_nodes: std::collections::BTreeSet<u64> = config.node_ids.iter().copied().collect();

        seen_nodes
            .into_iter()
            .map(|node_id| {
                let device_paths: Vec<String> = config
                    .devices_for_node(node_id)
                    .into_iter()
                    .map(|nd| nd.device_path.to_string_lossy().to_string())
                    .collect();

                ClusterPoolImportRequest {
                    request_id,
                    pool_guid: config.pool_guid,
                    target_node_id: node_id,
                    device_paths,
                    read_only,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool_config::{
        ClusterPlacementPolicy, ClusterPoolConfig, ClusterRedundancy, FailureDomain, NodeDevice,
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
            "testpool".into(),
            devices,
            ClusterPlacementPolicy::Stripe,
        )
    }

    // -- encode/decode round-trip tests --

    #[test]
    fn roundtrip_create_request() {
        let msg = ClusterPoolMessage::CreateRequest(ClusterPoolCreateRequest {
            request_id: 42,
            pool_guid: [0x11; 16],
            pool_name: "mypool".into(),
            target_node_id: 7,
            node_devices: vec![NodeDeviceSpec {
                device_path: "/dev/sda".into(),
                local_device_index: 0,
                global_device_index: 0,
                capacity_bytes: 1024 * 1024 * 1024,
                failure_domain: FailureDomain::for_node(7),
            }],
            redundancy: ClusterRedundancy::None,
            placement: ClusterPlacementPolicy::Stripe,
            allow_file_devices: false,
        });

        let encoded = msg.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_create_response_success() {
        let msg = ClusterPoolMessage::CreateResponse(ClusterPoolCreateResponse {
            request_id: 42,
            node_id: 7,
            pool_guid: [0x11; 16],
            success: true,
            device_guids: vec![[0xAA; 16], [0xBB; 16]],
            error: None,
        });

        let encoded = msg.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_create_response_failure() {
        let msg = ClusterPoolMessage::CreateResponse(ClusterPoolCreateResponse {
            request_id: 99,
            node_id: 3,
            pool_guid: [0x22; 16],
            success: false,
            device_guids: vec![],
            error: Some("device /dev/sdb already labeled".into()),
        });

        let encoded = msg.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_import_request() {
        let msg = ClusterPoolMessage::ImportRequest(ClusterPoolImportRequest {
            request_id: 1,
            pool_guid: [0x33; 16],
            target_node_id: 5,
            device_paths: vec!["/dev/sda".into(), "/dev/sdb".into()],
            read_only: false,
        });

        let encoded = msg.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_import_request_readonly() {
        let msg = ClusterPoolMessage::ImportRequest(ClusterPoolImportRequest {
            request_id: 2,
            pool_guid: [0x44; 16],
            target_node_id: 1,
            device_paths: vec!["/dev/vda".into()],
            read_only: true,
        });

        let encoded = msg.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_import_response() {
        let msg = ClusterPoolMessage::ImportResponse(ClusterPoolImportResponse {
            request_id: 1,
            node_id: 5,
            pool_guid: [0x33; 16],
            success: true,
            committed_root_epoch: Some(7),
            intent_log_replayed: Some(42),
            error: None,
        });

        let encoded = msg.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_import_response_failure() {
        let msg = ClusterPoolMessage::ImportResponse(ClusterPoolImportResponse {
            request_id: 1,
            node_id: 5,
            pool_guid: [0x33; 16],
            success: false,
            committed_root_epoch: None,
            intent_log_replayed: None,
            error: Some("no valid labels found".into()),
        });

        let encoded = msg.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    // -- error path tests --

    #[test]
    fn decode_rejects_empty() {
        assert!(ClusterPoolMessage::decode(&[]).is_err());
    }

    #[test]
    fn decode_rejects_unknown_discriminant() {
        let bytes = vec![0xFF, 0x00, 0x00];
        assert!(ClusterPoolMessage::decode(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_garbage_payload() {
        let mut bytes = vec![0x10]; // CreateRequest discriminant
        bytes.extend_from_slice(&[0xFF; 100]); // garbage
        assert!(ClusterPoolMessage::decode(&bytes).is_err());
    }

    #[test]
    fn deterministic_encoding() {
        let msg1 = ClusterPoolMessage::CreateRequest(ClusterPoolCreateRequest {
            request_id: 1,
            pool_guid: [0x55; 16],
            pool_name: "det".into(),
            target_node_id: 1,
            node_devices: vec![],
            redundancy: ClusterRedundancy::None,
            placement: ClusterPlacementPolicy::Stripe,
            allow_file_devices: false,
        });
        let msg2 = msg1.clone();

        let encoded1 = msg1.encode().unwrap();
        let encoded2 = msg2.encode().unwrap();
        assert_eq!(encoded1, encoded2);
    }

    // -- builder tests --

    #[test]
    fn roundtrip_lease_request() {
        let msg = ClusterPoolMessage::LeaseRequest(ClusterPoolLeaseRequest {
            request_id: 1,
            pool_guid: [0xAA; 16],
            requesting_node_id: 42,
            action: ClusterPoolLeaseAction::Acquire,
        });
        let encoded = msg.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_lease_response_success() {
        let token_bytes = vec![1u8, 2, 3, 4];
        let msg = ClusterPoolMessage::LeaseResponse(ClusterPoolLeaseResponse {
            request_id: 1,
            node_id: 7,
            pool_guid: [0xAA; 16],
            success: true,
            lease_token_bytes: Some(token_bytes.clone()),
            lease_expiration_ms: Some(60_000),
            lease_remaining_ms: Some(30_000),
            error: None,
        });
        let encoded = msg.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
        if let ClusterPoolMessage::LeaseResponse(resp) = &decoded {
            assert_eq!(resp.lease_token_bytes.as_ref().unwrap(), &token_bytes);
        }
    }

    #[test]
    fn roundtrip_lease_response_failure() {
        let msg = ClusterPoolMessage::LeaseResponse(ClusterPoolLeaseResponse {
            request_id: 2,
            node_id: 3,
            pool_guid: [0xBB; 16],
            success: false,
            lease_token_bytes: None,
            lease_expiration_ms: None,
            lease_remaining_ms: None,
            error: Some("pool not found".into()),
        });
        let encoded = msg.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_owner_observation_request_and_response_without_lease_capability() {
        let request =
            ClusterPoolMessage::OwnerObservationRequest(ClusterPoolOwnerObservationRequest {
                request_id: 44,
                pool_guid: [0x44; 16],
                requesting_node_id: 9,
            });
        let encoded = request.encode().unwrap();
        assert_eq!(encoded[0], 0x1a);
        assert_eq!(ClusterPoolMessage::decode(&encoded).unwrap(), request);

        let response =
            ClusterPoolMessage::OwnerObservationResponse(ClusterPoolOwnerObservationResponse {
                request_id: 44,
                node_id: 1,
                pool_guid: [0x44; 16],
                success: true,
                owner_node_id: Some(7),
                membership_epoch: Some(12),
                write_fence_generation: Some(81),
                lease_remaining_ms: Some(29_000),
                error: None,
            });
        let encoded = response.encode().unwrap();
        assert_eq!(encoded[0], 0x1b);
        assert_eq!(ClusterPoolMessage::decode(&encoded).unwrap(), response);
    }

    #[test]
    fn build_create_requests_three_nodes() {
        let config = make_three_node_config();
        let requests = ClusterPoolMessage::build_create_requests(&config, 100);

        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].target_node_id, 1);
        assert_eq!(requests[1].target_node_id, 2);
        assert_eq!(requests[2].target_node_id, 3);
        assert!(requests.iter().all(|r| r.request_id == 100));
        assert!(requests.iter().all(|r| r.pool_guid == [0xAB; 16]));
        assert!(requests.iter().all(|r| r.pool_name == "testpool"));
        assert!(requests
            .iter()
            .all(|r| r.redundancy == ClusterRedundancy::None));
        assert!(requests
            .iter()
            .all(|r| r.placement == ClusterPlacementPolicy::Stripe));

        // Each node should have exactly 1 device.
        for req in &requests {
            assert_eq!(req.node_devices.len(), 1);
        }
    }

    #[test]
    fn build_create_requests_uses_redundancy_as_authority() {
        let mut config = make_three_node_config();
        config.redundancy = ClusterRedundancy::ErasureCoded {
            data_shards: 2,
            parity_shards: 1,
        };
        config.placement = ClusterPlacementPolicy::Stripe;

        let requests = ClusterPoolMessage::build_create_requests(&config, 102);

        assert_eq!(requests.len(), 3);
        for req in &requests {
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
        let requests = ClusterPoolMessage::build_create_requests(&config, 101);

        assert!(requests.iter().all(|req| req.allow_file_devices));
    }

    #[test]
    fn build_import_requests_three_nodes() {
        let config = make_three_node_config();
        let requests = ClusterPoolMessage::build_import_requests(&config, 200, false);

        assert_eq!(requests.len(), 3);
        assert!(requests.iter().all(|r| r.request_id == 200));
        assert!(requests.iter().all(|r| !r.read_only));
        assert!(requests.iter().all(|r| r.device_paths.len() == 1));
    }

    #[test]
    fn node_device_spec_from_node_device() {
        let nd = make_test_device(42, 0, 5);
        let spec = NodeDeviceSpec::from(&nd);
        assert_eq!(spec.device_path, "/dev/node42-disk0");
        assert_eq!(spec.local_device_index, 0);
        assert_eq!(spec.global_device_index, 5);
        assert_eq!(spec.capacity_bytes, 1024 * 1024 * 1024);
        assert_eq!(spec.failure_domain.node, 42);
    }
}
