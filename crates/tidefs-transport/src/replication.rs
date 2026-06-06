//! Replication message wire protocol and transport-level send/receive helpers.
//!
//! Defines the structured messages used for distributed object replication
//! over Transport sessions. Messages are serialized with bincode and sent as
//! opaque frames via the Transport send_message/recv_message primitives.

use crate::error::TransportError;
use crate::transport::Transport;
use crate::types::SessionId;
use tidefs_replication_model::PlacementReceiptRef;

/// One object transferred by a peer sync response.
///
/// Compatibility stores may omit `placement_receipt_ref`. Pool-backed sync
/// entries carry the exact placement receipt that authorized the object key and
/// payload bytes being transferred.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct SyncEntry {
    /// Object key bytes used for exact-key sync into the receiver.
    pub object_key: [u8; 32],
    /// Payload bytes for the object.
    pub payload: Vec<u8>,
    /// Optional durable placement receipt authority for this payload.
    pub placement_receipt_ref: Option<PlacementReceiptRef>,
}

impl SyncEntry {
    /// Build a sync entry for compatibility stores without receipt authority.
    #[must_use]
    pub fn receiptless(object_key: [u8; 32], payload: Vec<u8>) -> Self {
        Self {
            object_key,
            payload,
            placement_receipt_ref: None,
        }
    }

    /// Build a sync entry with durable placement receipt authority.
    #[must_use]
    pub fn with_receipt(
        object_key: [u8; 32],
        payload: Vec<u8>,
        placement_receipt_ref: PlacementReceiptRef,
    ) -> Self {
        Self {
            object_key,
            payload,
            placement_receipt_ref: Some(placement_receipt_ref),
        }
    }
}

/// Wire message types for distributed object replication.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub enum ReplicationMessage {
    /// Store an object: key name + payload.
    Put { name: String, payload: Vec<u8> },
    /// Acknowledgement with the stored ObjectKey hash and success flag.
    Ack { key_hash: String, success: bool },
    /// Request an object by name.
    Get { name: String },
    /// Response with optional payload and found flag.
    GetResponse { found: bool, payload: Vec<u8> },
    /// Request to sync all keys from peer.
    SyncRequest,
    /// Sync response: exact object payloads, with receipt authority when known.
    SyncResponse { entries: Vec<SyncEntry> },
    /// Delete an object by name with generation counter for race prevention.
    Delete {
        name: String,
        /// Monotonic generation counter to prevent delete-write races.
        generation: u64,
    },
    /// Acknowledgement of a delete operation with generation counter.
    DeleteAck {
        /// Whether the object was found and deleted.
        deleted: bool,
        /// The generation counter of the object on this replica.
        generation: u64,
    },

    // ── Plan-based replication protocol (P8-03 distributed runtime) ──
    /// Disseminate a serialized write plan to a replica (Control lane, e1).
    WritePlan { plan_bytes: Vec<u8> },
    /// Acknowledge or refuse a write plan (Control lane, e1).
    WritePlanAck {
        accepted: bool,
        member_id: u64,
        reason: String,
    },
    /// Transfer a data chunk to a replica with digest (Data lane, e2).
    TransferChunk {
        digest: Vec<u8>,
        chunk_data: Vec<u8>,
    },
    /// Acknowledge receipt of a transferred chunk (Data lane, e2).
    TransferChunkAck { success: bool, member_id: u64 },
    /// Request a read per a serialized read plan (Control lane, e1).
    ReadPlan { plan_bytes: Vec<u8> },
    /// Response to a read plan request (Control lane, e1).
    ReadPlanResponse {
        found: bool,
        payload: Vec<u8>,
        source_member_id: u64,
    },
    /// Request witness verification of a digest (Shadow lane, e3).
    WitnessVerify { digest: Vec<u8>, payload_len: u64 },
    /// Witness verification response (Shadow lane, e3).
    WitnessVerifyResponse {
        digest_matches: bool,
        member_id: u64,
    },

    // ── Multi-node scrub and repair fanout ──
    /// Request a peer to run a full scrub of its local object store segments
    /// and report findings for cross-replica comparison.
    ScrubRequest,
    /// Scrub report from a peer node, with serialized findings.
    ScrubResponse {
        /// JSON-serialized scrub report.
        report_json: String,
        /// Number of findings (non-clean outcomes).
        findings_count: u64,
    },
    /// Repair an object on a replica under durable placement receipt
    /// authority. The receiver must validate the receipt before writing.
    RepairObject {
        key: Vec<u8>,
        placement_receipt_ref: PlacementReceiptRef,
        authoritative_payload: Vec<u8>,
    },
    /// Acknowledge a repair operation.
    RepairObjectAck {
        key: Vec<u8>,
        success: bool,
        /// Fresh durable placement receipt recorded by a pool-backed repair.
        repaired_placement_receipt_ref: Option<PlacementReceiptRef>,
    },
}

/// Send a structured replication message over a transport session.
pub fn send_replication_msg(
    transport: &mut Transport,
    session_id: SessionId,
    msg: &ReplicationMessage,
) -> Result<(), TransportError> {
    let payload = bincode::serialize(msg)
        .map_err(|e| TransportError::Generic(format!("replication serialize: {e}")))?;
    transport.send_message(session_id, &payload)
}

/// Receive a structured replication message over a transport session.
pub fn recv_replication_msg(
    transport: &mut Transport,
    session_id: SessionId,
) -> Result<ReplicationMessage, TransportError> {
    let payload = transport.recv_message(session_id)?;
    bincode::deserialize(&payload)
        .map_err(|e| TransportError::Generic(format!("replication deserialize: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::EpochId;
    use tidefs_replication_model::ReceiptRedundancyPolicy;

    // ── Helper: round-trip a message through bincode ──

    fn bincode_roundtrip(msg: &ReplicationMessage) -> ReplicationMessage {
        let payload = bincode::serialize(msg).expect("serialize");
        bincode::deserialize::<ReplicationMessage>(&payload).expect("deserialize")
    }

    fn receipt_ref(name: &str, payload: &[u8], generation: u64) -> PlacementReceiptRef {
        let object_key = tidefs_local_object_store::ObjectKey::from_name(name).as_bytes32();
        PlacementReceiptRef::new(
            42,
            object_key,
            EpochId::new(7),
            generation,
            ReceiptRedundancyPolicy::Replicated { copies: 2 },
            payload.len() as u64,
            blake3::hash(payload).into(),
            2,
        )
    }

    // ── ScrubRequest round-trip ──

    #[test]
    fn scrub_request_bincode_roundtrip() {
        let msg = ReplicationMessage::ScrubRequest;
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    // ── ScrubResponse round-trip ──

    #[test]
    fn scrub_response_bincode_roundtrip() {
        let msg = ReplicationMessage::ScrubResponse {
            report_json: r#"{"segments_scanned":12,"findings_count":0}"#.into(),
            findings_count: 0,
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    #[test]
    fn scrub_response_with_findings_bincode_roundtrip() {
        let msg = ReplicationMessage::ScrubResponse {
            report_json: r#"{"segments_scanned":5,"records_verified":42,"bytes_scanned":8192,"chain_breaks_detected":1,"completed":true,"findings_count":3}"#.into(),
            findings_count: 3,
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    #[test]
    fn scrub_response_empty_json_bincode_roundtrip() {
        let msg = ReplicationMessage::ScrubResponse {
            report_json: String::new(),
            findings_count: 0,
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    // ── RepairObject round-trip ──

    #[test]
    fn repair_object_bincode_roundtrip() {
        let payload = b"repaired-data".to_vec();
        let key = tidefs_local_object_store::ObjectKey::from_name("corrupted-key-01")
            .as_bytes32()
            .to_vec();
        let msg = ReplicationMessage::RepairObject {
            key,
            placement_receipt_ref: receipt_ref("corrupted-key-01", &payload, 11),
            authoritative_payload: payload,
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    #[test]
    fn repair_object_empty_payload_bincode_roundtrip() {
        let key = tidefs_local_object_store::ObjectKey::from_name("")
            .as_bytes32()
            .to_vec();
        let msg = ReplicationMessage::RepairObject {
            key,
            placement_receipt_ref: receipt_ref("", &[], 12),
            authoritative_payload: vec![],
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    #[test]
    fn repair_object_large_payload_bincode_roundtrip() {
        let payload = vec![0xABu8; 65536];
        let key = tidefs_local_object_store::ObjectKey::from_name("large-key")
            .as_bytes32()
            .to_vec();
        let msg = ReplicationMessage::RepairObject {
            key,
            placement_receipt_ref: receipt_ref("large-key", &payload, 13),
            authoritative_payload: payload,
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    // ── RepairObjectAck round-trip ──

    #[test]
    fn repair_object_ack_success_bincode_roundtrip() {
        let msg = ReplicationMessage::RepairObjectAck {
            key: tidefs_local_object_store::ObjectKey::from_name("fixed-key")
                .as_bytes32()
                .to_vec(),
            success: true,
            repaired_placement_receipt_ref: Some(receipt_ref("fixed-key", b"fixed", 15)),
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    #[test]
    fn repair_object_ack_failure_bincode_roundtrip() {
        let msg = ReplicationMessage::RepairObjectAck {
            key: tidefs_local_object_store::ObjectKey::from_name("still-bad")
                .as_bytes32()
                .to_vec(),
            success: false,
            repaired_placement_receipt_ref: None,
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    // ── Variant discrimination: all 4 new variants are distinct ──

    #[test]
    fn scrub_variants_are_distinct() {
        let scrub_req = ReplicationMessage::ScrubRequest;
        let scrub_resp = ReplicationMessage::ScrubResponse {
            report_json: "{}".into(),
            findings_count: 0,
        };
        assert_ne!(scrub_req, scrub_resp);
        assert!(!matches!(scrub_resp, ReplicationMessage::ScrubRequest));
        assert!(!matches!(
            scrub_req,
            ReplicationMessage::ScrubResponse { .. }
        ));
    }

    #[test]
    fn repair_variants_are_distinct() {
        let payload = Vec::new();
        let key = tidefs_local_object_store::ObjectKey::from_name("k")
            .as_bytes32()
            .to_vec();
        let repair_obj = ReplicationMessage::RepairObject {
            key: key.clone(),
            placement_receipt_ref: receipt_ref("k", &payload, 14),
            authoritative_payload: payload,
        };
        let repair_ack = ReplicationMessage::RepairObjectAck {
            key,
            success: true,
            repaired_placement_receipt_ref: Some(receipt_ref("k", &[], 15)),
        };
        assert_ne!(repair_obj, repair_ack);
    }

    // ── Existing variant backward-compatibility ──

    #[test]
    fn existing_put_variant_still_roundtrips() {
        let msg = ReplicationMessage::Put {
            name: "existing-key".into(),
            payload: b"existing-data".to_vec(),
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    #[test]
    fn existing_get_variant_still_roundtrips() {
        let msg = ReplicationMessage::Get {
            name: "read-key".into(),
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    #[test]
    fn existing_ack_variant_still_roundtrips() {
        let msg = ReplicationMessage::Ack {
            key_hash: "hash-abc123".into(),
            success: true,
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    #[test]
    fn existing_sync_request_still_roundtrips() {
        let msg = ReplicationMessage::SyncRequest;
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    #[test]
    fn sync_response_preserves_object_key_bytes() {
        let key = [0xA5; 32];
        let msg = ReplicationMessage::SyncResponse {
            entries: vec![SyncEntry::receiptless(key, b"payload".to_vec())],
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    #[test]
    fn sync_response_preserves_placement_receipt_refs() {
        let payload = b"receipt-bound-payload".to_vec();
        let key = tidefs_local_object_store::ObjectKey::from_name("receipt-sync").as_bytes32();
        let receipt = receipt_ref("receipt-sync", &payload, 22);
        let msg = ReplicationMessage::SyncResponse {
            entries: vec![SyncEntry::with_receipt(key, payload, receipt)],
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    #[test]
    fn existing_delete_variant_still_roundtrips() {
        let msg = ReplicationMessage::Delete {
            name: "del-key".into(),
            generation: 4,
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    #[test]
    fn existing_delete_ack_variant_still_roundtrips() {
        let msg = ReplicationMessage::DeleteAck {
            deleted: true,
            generation: 4,
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    #[test]
    fn existing_write_plan_variant_still_roundtrips() {
        let msg = ReplicationMessage::WritePlan {
            plan_bytes: b"plan-data".to_vec(),
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    #[test]
    fn existing_transfer_chunk_variant_still_roundtrips() {
        let msg = ReplicationMessage::TransferChunk {
            digest: vec![0xAA; 32],
            chunk_data: vec![0x42; 1024],
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }

    #[test]
    fn existing_witness_verify_variant_still_roundtrips() {
        let msg = ReplicationMessage::WitnessVerify {
            digest: vec![0xBB; 32],
            payload_len: 2048,
        };
        let rt = bincode_roundtrip(&msg);
        assert_eq!(rt, msg);
    }
}
