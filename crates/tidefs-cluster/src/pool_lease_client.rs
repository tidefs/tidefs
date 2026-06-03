//! Cluster pool lease client: synchronous request-response for acquiring
//! a pool lease token from a cluster authority (storage-node).
//!
//! The [`ClusterLeaseClient`] connects to a storage-node via TCP, sends a
//! [`ClusterPoolLeaseRequest`] framed with the CP01 magic prefix, and
//! receives a [`ClusterPoolLeaseResponse`] containing a serialized
//! [`PoolLeaseToken`] on success.
//!
//! ## Protocol
//!
//! 1. Client opens a TCP connection to the storage-node's transport endpoint.
//! 2. Client sends: `b"CP01" + ClusterPoolLeaseRequest::encode()`.
//! 3. Client reads: `b"CP01" + ClusterPoolLeaseResponse::decode()`.
//! 4. On success, deserializes the PoolLeaseToken from `lease_token_bytes`.
//!
//! The client does not participate in the membership or lease state machine;
//! it requests an already-held lease from the storage-node's
//! [`ClusterLeaseRuntime`].

use crate::pool_lease_token::PoolLeaseToken;
use crate::pool_protocol::{
    CatalogQueryType,
    ClusterPoolCatalogDeltaRequest,
    ClusterPoolCatalogDeltaResponse,
    ClusterPoolCatalogQueryRequest,
    ClusterPoolCatalogQueryResponse,
    ClusterPoolLeaseRequest, ClusterPoolMessage,
    PoolProtocolError,
};

/// Magic prefix for cluster pool protocol messages (CP01 = Cluster Pool v1).
const CLUSTER_POOL_MESSAGE_MAGIC: &[u8; 4] = b"CP01";

/// Error type for cluster lease client operations.
#[derive(Debug)]
pub enum LeaseClientError {
    /// I/O error on the TCP connection.
    Io(std::io::Error),
    /// Protocol-level encode/decode error.
    Protocol(PoolProtocolError),
    /// The storage-node refused the lease request.
    LeaseRefused {
        /// Storage-node error message.
        error: String,
    },
    /// The lease response contained no token bytes on success.
    MissingToken,
    /// Bincode deserialization of the PoolLeaseToken failed.
    TokenDeserialize(String),
    /// The decoded PoolLeaseToken failed validation (zero fields, expired, etc.).
    TokenInvalid(String),
}

impl std::fmt::Display for LeaseClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::LeaseRefused { error } => write!(f, "lease refused: {error}"),
            Self::MissingToken => write!(f, "lease response missing token bytes"),
            Self::TokenDeserialize(e) => write!(f, "token deserialization: {e}"),
            Self::TokenInvalid(e) => write!(f, "token invalid: {e}"),
        }
    }
}

impl std::error::Error for LeaseClientError {}

impl From<std::io::Error> for LeaseClientError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<PoolProtocolError> for LeaseClientError {
    fn from(e: PoolProtocolError) -> Self {
        Self::Protocol(e)
    }
}

/// Synchronous client for requesting a pool lease token from a cluster
/// storage-node.
///
/// Opens a TCP connection, sends a single lease request, reads the response,
/// and returns the validated [`PoolLeaseToken`].
pub struct ClusterLeaseClient;

impl ClusterLeaseClient {
    /// Request a pool lease token from the given storage-node address.
    ///
    /// `node_addr` is a `host:port` string for the storage-node's transport
    /// endpoint. `requesting_node_id` identifies this client to the cluster.
    /// `pool_guid` is the pool to acquire the lease for.
    ///
    /// On success, returns a validated [`PoolLeaseToken`] that can be passed
    /// to [`PoolImporter::import_pool_clustered`].
    pub fn request_lease(
        node_addr: &str,
        requesting_node_id: u64,
        pool_guid: [u8; 16],
    ) -> Result<PoolLeaseToken, LeaseClientError> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        let mut stream = TcpStream::connect(node_addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        // Build the lease request.
        let request = ClusterPoolMessage::LeaseRequest(ClusterPoolLeaseRequest {
            request_id: 1,
            pool_guid,
            requesting_node_id,
        });
        let encoded = request.encode()?;

        // Frame with CP01 magic.
        let mut wire = Vec::with_capacity(4 + encoded.len());
        wire.extend_from_slice(CLUSTER_POOL_MESSAGE_MAGIC);
        wire.extend_from_slice(&encoded);
        stream.write_all(&wire)?;

        // Read response: first 4 bytes for CP01 magic.
        let mut magic_buf = [0u8; 4];
        stream.read_exact(&mut magic_buf)?;
        if &magic_buf != CLUSTER_POOL_MESSAGE_MAGIC {
            return Err(LeaseClientError::Protocol(
                PoolProtocolError::UnknownDiscriminant(0),
            ));
        }

        // Read the rest of the response (up to 64 KiB).
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload)?;
        if payload.is_empty() {
            return Err(LeaseClientError::Protocol(
                PoolProtocolError::PayloadTooShort(0),
            ));
        }

        let response = ClusterPoolMessage::decode(&payload)?;

        match response {
            ClusterPoolMessage::LeaseResponse(resp) => {
                if !resp.success {
                    return Err(LeaseClientError::LeaseRefused {
                        error: resp.error.unwrap_or_else(|| "unknown reason".to_string()),
                    });
                }
                let token_bytes = resp
                    .lease_token_bytes
                    .ok_or(LeaseClientError::MissingToken)?;
                let token: PoolLeaseToken = bincode::deserialize(&token_bytes)
                    .map_err(|e| LeaseClientError::TokenDeserialize(e.to_string()))?;
                if !token.is_valid() {
                    return Err(LeaseClientError::TokenInvalid(
                        "lease token has zero fields (uninitialized)".to_string(),
                    ));
                }
                if !token.authorizes_pool(&pool_guid) {
                    return Err(LeaseClientError::TokenInvalid(
                        "lease token pool GUID mismatch".to_string(),
                    ));
                }
                Ok(token)
            }
            _other => Err(LeaseClientError::Protocol(
                PoolProtocolError::UnknownDiscriminant(0),
            )),
        }
    }

    /// Submit a dataset catalog delta to the cluster authority.
    ///
    /// Connects to the storage-node, sends a `CatalogDeltaRequest` containing
    /// the serialized `CatalogDelta`, and returns the new catalog version.
    pub fn submit_catalog_delta(
        node_addr: &str,
        requesting_node_id: u64,
        pool_guid: [u8; 16],
        delta_bytes: Vec<u8>,
    ) -> Result<ClusterPoolCatalogDeltaResponse, LeaseClientError> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        let mut stream = TcpStream::connect(node_addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        let request = ClusterPoolMessage::CatalogDeltaRequest(ClusterPoolCatalogDeltaRequest {
            request_id: 1,
            pool_guid,
            requesting_node_id,
            delta_bytes,
        });
        let encoded = request.encode()?;

        let mut wire = Vec::with_capacity(4 + encoded.len());
        wire.extend_from_slice(CLUSTER_POOL_MESSAGE_MAGIC);
        wire.extend_from_slice(&encoded);
        stream.write_all(&wire)?;

        let mut magic_buf = [0u8; 4];
        stream.read_exact(&mut magic_buf)?;
        if &magic_buf != CLUSTER_POOL_MESSAGE_MAGIC {
            return Err(LeaseClientError::Protocol(
                PoolProtocolError::UnknownDiscriminant(0),
            ));
        }

        let mut payload = Vec::new();
        stream.read_to_end(&mut payload)?;
        if payload.is_empty() {
            return Err(LeaseClientError::Protocol(
                PoolProtocolError::PayloadTooShort(0),
            ));
        }

        let response = ClusterPoolMessage::decode(&payload)?;
        match response {
            ClusterPoolMessage::CatalogDeltaResponse(resp) => Ok(resp),
            _other => Err(LeaseClientError::Protocol(
                PoolProtocolError::UnknownDiscriminant(0),
            )),
        }
    }

    /// Query the cluster catalog authority for dataset entries.
    ///
    /// Connects to the storage-node, sends a `CatalogQueryRequest`, and
    /// returns the response containing catalog entries and version.
    pub fn query_catalog(
        node_addr: &str,
        requesting_node_id: u64,
        pool_guid: [u8; 16],
        query_type: CatalogQueryType,
        path: &str,
    ) -> Result<ClusterPoolCatalogQueryResponse, LeaseClientError> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        let mut stream = TcpStream::connect(node_addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        let request = ClusterPoolMessage::CatalogQueryRequest(ClusterPoolCatalogQueryRequest {
            request_id: 1,
            pool_guid,
            requesting_node_id,
            query_type_u8: query_type.to_u8(),
            path: path.to_string(),
        });
        let encoded = request.encode()?;

        let mut wire = Vec::with_capacity(4 + encoded.len());
        wire.extend_from_slice(CLUSTER_POOL_MESSAGE_MAGIC);
        wire.extend_from_slice(&encoded);
        stream.write_all(&wire)?;

        let mut magic_buf = [0u8; 4];
        stream.read_exact(&mut magic_buf)?;
        if &magic_buf != CLUSTER_POOL_MESSAGE_MAGIC {
            return Err(LeaseClientError::Protocol(
                PoolProtocolError::UnknownDiscriminant(0),
            ));
        }

        let mut payload = Vec::new();
        stream.read_to_end(&mut payload)?;
        if payload.is_empty() {
            return Err(LeaseClientError::Protocol(
                PoolProtocolError::PayloadTooShort(0),
            ));
        }

        let response = ClusterPoolMessage::decode(&payload)?;
        match response {
            ClusterPoolMessage::CatalogQueryResponse(resp) => Ok(resp),
            _other => Err(LeaseClientError::Protocol(
                PoolProtocolError::UnknownDiscriminant(0),
            )),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::pool_lease_token::PoolLeaseToken;
    use crate::pool_protocol::{ClusterPoolLeaseRequest, ClusterPoolLeaseResponse, ClusterPoolMessage};
    use crate::write_fence::WriteFence;
    use tidefs_membership_epoch::EpochId;

    #[test]
    fn lease_request_encoding_roundtrip() {
        let req = ClusterPoolMessage::LeaseRequest(ClusterPoolLeaseRequest {
            request_id: 42,
            pool_guid: [0xAB; 16],
            requesting_node_id: 7,
        });
        let encoded = req.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn lease_response_success_roundtrip() {
        let token = PoolLeaseToken::new(
            7,
            [0xAB; 16],
            EpochId(3),
            100,
            1,
            WriteFence::new(EpochId(3), 5),
            120_000,
        );
        let token_bytes = bincode::serialize(&token).unwrap();

        let resp = ClusterPoolMessage::LeaseResponse(ClusterPoolLeaseResponse {
            request_id: 42,
            node_id: 7,
            pool_guid: [0xAB; 16],
            success: true,
            lease_token_bytes: Some(token_bytes.clone()),
            lease_expiration_ms: Some(120_000),
            error: None,
        });
        let encoded = resp.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, resp);

        // Verify token roundtrip through the response.
        if let ClusterPoolMessage::LeaseResponse(r) = &decoded {
            let restored: PoolLeaseToken =
                bincode::deserialize(r.lease_token_bytes.as_ref().unwrap()).unwrap();
            assert_eq!(restored, token);
        } else {
            panic!("expected LeaseResponse");
        }
    }

    #[test]
    fn lease_response_failure_roundtrip() {
        let resp = ClusterPoolMessage::LeaseResponse(ClusterPoolLeaseResponse {
            request_id: 99,
            node_id: 1,
            pool_guid: [0xCC; 16],
            success: false,
            lease_token_bytes: None,
            lease_expiration_ms: None,
            error: Some("no active lease".into()),
        });
        let encoded = resp.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, resp);
    }
}
