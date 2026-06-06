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
    CatalogDeltaRequest = 0x16,
    CatalogDeltaResponse = 0x17,
    CatalogQueryRequest = 0x18,
    CatalogQueryResponse = 0x19,
    CreateRequest = 0x10,
    CreateResponse = 0x11,
    ImportRequest = 0x12,
    ImportResponse = 0x13,
    LeaseRequest = 0x14,
    LeaseResponse = 0x15,
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
            0x16 => Some(Self::CatalogDeltaRequest),
            0x17 => Some(Self::CatalogDeltaResponse),
            0x18 => Some(Self::CatalogQueryRequest),
            0x19 => Some(Self::CatalogQueryResponse),
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

/// Request a pool lease token from the cluster authority (storage-node).
///
/// The requesting node sends this to a storage-node that holds the cluster
/// lease runtime. On success, the response contains a [`PoolLeaseToken`]
/// that authorizes clustered pool import and mount.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPoolLeaseRequest {
    /// Opaque request id for matching responses.
    pub request_id: u64,
    /// Pool UUID to acquire a lease for.
    pub pool_guid: [u8; 16],
    /// The node requesting the lease.
    pub requesting_node_id: u64,
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
    /// The storage-node that granted (or denied) the lease.
    pub node_id: u64,
    /// Pool UUID for correlation.
    pub pool_guid: [u8; 16],
    /// Whether the lease was granted.
    pub success: bool,
    /// Bincode-serialized [`PoolLeaseToken`] on success.
    pub lease_token_bytes: Option<Vec<u8>>,
    /// Lease expiration timestamp in milliseconds since epoch (on success).
    pub lease_expiration_ms: Option<u64>,
    /// Error message if the lease was denied.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// CatalogQueryType
// ---------------------------------------------------------------------------

/// Query types for catalog read operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CatalogQueryType {
    /// List all datasets in the pool catalog.
    ListAll = 0,
    /// Look up a single dataset by path.
    Lookup = 1,
}

impl CatalogQueryType {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::ListAll),
            1 => Some(Self::Lookup),
            _ => None,
        }
    }
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// ClusterPoolCatalogQueryRequest
// ---------------------------------------------------------------------------

/// Request to read from the cluster catalog authority.
///
/// No lease is required for read operations; any node can query the
/// catalog state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPoolCatalogQueryRequest {
    /// Opaque request id for matching responses.
    pub request_id: u64,
    /// Pool UUID to query.
    pub pool_guid: [u8; 16],
    /// The node making the query.
    pub requesting_node_id: u64,
    /// Type of query to perform (see [`CatalogQueryType`]).
    pub query_type_u8: u8,
    /// Path argument for Lookup queries (ignored for ListAll).
    pub path: String,
}

// ---------------------------------------------------------------------------
// CatalogEntryRow — serializable catalog entry for query responses
// ---------------------------------------------------------------------------

/// A single dataset catalog entry for wire transmission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntryRow {
    /// Full hierarchical path (e.g. "tank/fs1").
    pub path: String,
    /// Stable dataset identifier (16 bytes).
    pub dataset_id_bytes: Vec<u8>,
    /// Dataset type discriminant (see DatasetType::to_u8).
    pub dataset_type_u8: u8,
    /// Creation txg.
    pub creation_txg: u64,
    /// Lifecycle state discriminant.
    pub lifecycle_state_u8: u8,
    /// Per-dataset flags bitmask.
    pub flags_u16: u16,
}

// ---------------------------------------------------------------------------
// ClusterPoolCatalogQueryResponse
// ---------------------------------------------------------------------------

/// Response to a [`ClusterPoolCatalogQueryRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPoolCatalogQueryResponse {
    pub request_id: u64,
    pub node_id: u64,
    pub pool_guid: [u8; 16],
    pub success: bool,
    /// Catalog entries returned by the query (empty on failure).
    pub entries: Vec<CatalogEntryRow>,
    /// Catalog version at the time of the query.
    pub catalog_version: u64,
    /// Error message if the query failed.
    pub error: Option<String>,
}

// ClusterPoolMessage — union type for dispatch
// ---------------------------------------------------------------------------
// ClusterPoolCatalogDeltaRequest
// ---------------------------------------------------------------------------

/// Request to apply a dataset catalog mutation to the cluster authority.
///
/// Sent by a client node that holds the pool lease. The storage-node applies
/// the delta against its `ClusterLeaseRuntime::pool_catalog` and responds
/// with the new catalog version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPoolCatalogDeltaRequest {
    /// Opaque request id for matching responses.
    pub request_id: u64,
    /// Pool UUID to mutate.
    pub pool_guid: [u8; 16],
    /// The node requesting the mutation.
    pub requesting_node_id: u64,
    /// Bincode-serialized `crate::dataset_catalog::CatalogDelta`.
    pub delta_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// ClusterPoolCatalogDeltaResponse
// ---------------------------------------------------------------------------

/// Response to a `ClusterPoolCatalogDeltaRequest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPoolCatalogDeltaResponse {
    pub request_id: u64,
    pub node_id: u64,
    pub pool_guid: [u8; 16],
    pub success: bool,
    /// New catalog version after applying the delta (on success).
    pub catalog_version: Option<u64>,
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
    CatalogDeltaRequest(ClusterPoolCatalogDeltaRequest),
    CatalogDeltaResponse(ClusterPoolCatalogDeltaResponse),
    CatalogQueryRequest(ClusterPoolCatalogQueryRequest),
    CatalogQueryResponse(ClusterPoolCatalogQueryResponse),
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
            Self::CatalogDeltaRequest(_) => PoolDiscriminant::CatalogDeltaRequest as u8,
            Self::CatalogDeltaResponse(_) => PoolDiscriminant::CatalogDeltaResponse as u8,
            Self::CatalogQueryRequest(_) => PoolDiscriminant::CatalogQueryRequest as u8,
            Self::CatalogQueryResponse(_) => PoolDiscriminant::CatalogQueryResponse as u8,
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
                Self::CatalogDeltaRequest(m) => bincode::serialize(m)
                    .map_err(|e| PoolProtocolError::Serialize(e.to_string()))?,
                Self::CatalogDeltaResponse(m) => bincode::serialize(m)
                    .map_err(|e| PoolProtocolError::Serialize(e.to_string()))?,
                Self::CatalogQueryRequest(m) => bincode::serialize(m)
                    .map_err(|e| PoolProtocolError::Serialize(e.to_string()))?,
                Self::CatalogQueryResponse(m) => bincode::serialize(m)
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
            PoolDiscriminant::CatalogDeltaRequest => {
                let msg: ClusterPoolCatalogDeltaRequest = bincode::deserialize(payload)
                    .map_err(|e| PoolProtocolError::Deserialize(e.to_string()))?;
                Ok(Self::CatalogDeltaRequest(msg))
            }
            PoolDiscriminant::CatalogDeltaResponse => {
                let msg: ClusterPoolCatalogDeltaResponse = bincode::deserialize(payload)
                    .map_err(|e| PoolProtocolError::Deserialize(e.to_string()))?;
                Ok(Self::CatalogDeltaResponse(msg))
            }
            PoolDiscriminant::CatalogQueryRequest => {
                let msg: ClusterPoolCatalogQueryRequest = bincode::deserialize(payload)
                    .map_err(|e| PoolProtocolError::Deserialize(e.to_string()))?;
                Ok(Self::CatalogQueryRequest(msg))
            }
            PoolDiscriminant::CatalogQueryResponse => {
                let msg: ClusterPoolCatalogQueryResponse = bincode::deserialize(payload)
                    .map_err(|e| PoolProtocolError::Deserialize(e.to_string()))?;
                Ok(Self::CatalogQueryResponse(msg))
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
            error: Some("pool not found".into()),
        });
        let encoded = msg.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
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
