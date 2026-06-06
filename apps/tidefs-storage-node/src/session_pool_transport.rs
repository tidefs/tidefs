//! Live transport-backed `PoolTransport` implementation using
//! established transport sessions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tidefs_transport::{SessionId, Transport, TransportError};

use tidefs_cluster::pool_orchestrator::{OrchestratorError, PoolTransport};
use tidefs_cluster::pool_protocol::ClusterPoolMessage;

const CLUSTER_POOL_MAGIC: &[u8; 4] = b"CP01";

pub struct SessionPoolTransport {
    transport: Arc<Mutex<Transport>>,
    node_sessions: Arc<Mutex<HashMap<u64, SessionId>>>,
}

impl SessionPoolTransport {
    pub fn new(transport: Arc<Mutex<Transport>>) -> Self {
        Self {
            transport,
            node_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register_node(&self, node_id: u64, session_id: SessionId) {
        self.node_sessions
            .lock()
            .unwrap()
            .insert(node_id, session_id);
    }

    fn frame_message(&self, msg: &ClusterPoolMessage) -> Result<Vec<u8>, OrchestratorError> {
        let payload = msg
            .encode()
            .map_err(|e| OrchestratorError::Transport(format!("encode: {e}")))?;
        let mut wire = Vec::with_capacity(4 + payload.len());
        wire.extend_from_slice(CLUSTER_POOL_MAGIC);
        wire.extend_from_slice(&payload);
        Ok(wire)
    }
}

impl PoolTransport for SessionPoolTransport {
    type Error = OrchestratorError;

    fn send(&self, target_node_id: u64, message: ClusterPoolMessage) -> Result<(), Self::Error> {
        let session_id = {
            let map = self.node_sessions.lock().unwrap();
            map.get(&target_node_id)
                .copied()
                .ok_or(OrchestratorError::UnknownNode {
                    node_id: target_node_id,
                })?
        };

        let wire = self.frame_message(&message)?;

        let mut t = self.transport.lock().unwrap();
        t.send_message(session_id, &wire)
            .map_err(|e| OrchestratorError::Transport(format!("send: {e}")))?;

        Ok(())
    }

    fn recv(&self) -> Result<Option<(u64, ClusterPoolMessage)>, Self::Error> {
        let mut t = self.transport.lock().unwrap();

        let sessions: Vec<(u64, SessionId)> = {
            let map = self.node_sessions.lock().unwrap();
            map.iter().map(|(k, v)| (*k, *v)).collect()
        };

        for (node_id, session_id) in &sessions {
            match t.recv_message(*session_id) {
                Ok(raw) => {
                    if raw.len() >= 4 && raw[..4] == *CLUSTER_POOL_MAGIC {
                        match ClusterPoolMessage::decode(&raw[4..]) {
                            Ok(msg) => {
                                return Ok(Some((*node_id, msg)));
                            }
                            Err(e) => {
                                eprintln!(
                                    "[session-pool-transport] decode error from node {node_id}: {e:?}"
                                );
                            }
                        }
                    }
                }
                Err(TransportError::WouldBlock(_)) => {
                    continue;
                }
                Err(e) => {
                    eprintln!("[session-pool-transport] recv error on node {node_id}: {e:?}");
                }
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_cluster::pool_config::ClusterPlacementPolicy;
    use tidefs_cluster::pool_protocol::{
        ClusterPoolCreateRequest, ClusterPoolCreateResponse, ClusterPoolImportResponse,
    };

    #[test]
    fn frame_and_decode_roundtrip() {
        let t = SessionPoolTransport::new(Arc::new(Mutex::new(Transport::new(0))));
        let msg = ClusterPoolMessage::CreateRequest(ClusterPoolCreateRequest {
            request_id: 42,
            pool_guid: [0x11; 16],
            pool_name: "test".into(),
            target_node_id: 1,
            node_devices: vec![],
            placement: ClusterPlacementPolicy::Stripe,
            allow_file_devices: false,
        });

        let wire = t.frame_message(&msg).unwrap();
        assert_eq!(&wire[..4], CLUSTER_POOL_MAGIC);
        let decoded = ClusterPoolMessage::decode(&wire[4..]).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn frame_create_response() {
        let t = SessionPoolTransport::new(Arc::new(Mutex::new(Transport::new(0))));
        let resp = ClusterPoolMessage::CreateResponse(ClusterPoolCreateResponse {
            request_id: 1,
            node_id: 7,
            pool_guid: [0xAA; 16],
            success: true,
            device_guids: vec![[0x01; 16], [0x02; 16]],
            error: None,
        });

        let wire = t.frame_message(&resp).unwrap();
        let decoded = ClusterPoolMessage::decode(&wire[4..]).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn frame_import_response() {
        let t = SessionPoolTransport::new(Arc::new(Mutex::new(Transport::new(0))));
        let resp = ClusterPoolMessage::ImportResponse(ClusterPoolImportResponse {
            request_id: 1,
            node_id: 5,
            pool_guid: [0xBB; 16],
            success: true,
            committed_root_epoch: Some(3),
            intent_log_replayed: Some(10),
            error: None,
        });

        let wire = t.frame_message(&resp).unwrap();
        let decoded = ClusterPoolMessage::decode(&wire[4..]).unwrap();
        assert_eq!(decoded, resp);
    }
}
