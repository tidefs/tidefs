//! Placement transfer control protocol messages for
//! deterministic state transfers between nodes.
//!
//! These messages coordinate the lifecycle of a placement-driven data
//! transfer between a source node and a destination node. Node-to-node
//! authenticity and integrity are provided by the transport/session
//! security boundary.
//!
//! ## Message flow
//!
//! ```text
//! Coordinator --TransferInitiate--> Source
//! Source --(data chunks)--> Destination
//! Destination --TransferChunkAck--> Coordinator
//! Source --TransferComplete--> Coordinator
//! Coordinator --TransferAbort--> Source/Destination (on failure)
//! ```
//!
//! ## Wire format
//!
//! ```text
//! [1-byte discriminant][bincode::serialize payload]
//! ```

use serde::{Deserialize, Serialize};

// ── Discriminants ───────────────────────────────────────────────────

/// One-byte discriminant for transfer control message types.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferControlDiscriminant {
    /// Initiate a placement transfer from source to destination.
    Initiate = 0x41,
    /// Acknowledge receipt of one or more transfer chunks.
    ChunkAck = 0x42,
    /// Signal transfer completed successfully.
    Complete = 0x43,
    /// Abort a transfer — release resources, roll back.
    Abort = 0x44,
    /// Data payload chunk sent from source to destination.
    Chunk = 0x45,
}

impl TransferControlDiscriminant {
    /// Decode a discriminant from a `u8` byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x41 => Some(Self::Initiate),
            0x42 => Some(Self::ChunkAck),
            0x43 => Some(Self::Complete),
            0x44 => Some(Self::Abort),
            0x45 => Some(Self::Chunk),
            _ => None,
        }
    }
}

// ── Error ───────────────────────────────────────────────────────────

/// Errors from transfer control message encode/decode.
#[derive(Clone, Debug, thiserror::Error)]
pub enum TransferControlError {
    #[error("bincode serialize error: {0}")]
    Serialize(String),
    #[error("bincode deserialize error: {0}")]
    Deserialize(String),
    #[error("unknown message discriminant: {0:#x}")]
    UnknownDiscriminant(u8),
}

// ── Message types ───────────────────────────────────────────────────

/// Initiate a placement transfer from a source node to a destination node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferInitiate {
    /// Unique transfer session identifier.
    pub transfer_id: u64,
    /// The epoch this transfer is bound to.
    pub epoch: u64,
    /// The source node that currently holds the data.
    pub source_node: u64,
    /// The destination node that will receive the data.
    pub destination_node: u64,
    /// Data ranges to transfer.
    pub ranges: Vec<TransferRange>,
    /// Maximum chunk size in bytes for data streaming.
    pub max_chunk_bytes: u64,
}

/// A data range within an object to transfer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferRange {
    /// Object identifier for the data.
    pub object_id: u64,
    /// Byte offset within the object.
    pub start_offset: u64,
    /// Number of bytes to transfer.
    pub length_bytes: u64,
}

/// Acknowledge receipt of transfer chunks at the destination node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferChunkAck {
    /// The transfer session this ack belongs to.
    pub transfer_id: u64,
    /// The epoch this transfer is bound to.
    pub epoch: u64,
    /// How many chunks have been received so far.
    pub chunks_received: u64,
    /// How many bytes have been received so far.
    pub bytes_received: u64,
    /// The highest byte position fully received contiguously.
    pub highest_contiguous_offset: u64,
}

/// A chunk of data payload streamed from source to destination during a
/// transfer.
///
/// Carries raw payload bytes with a sequence number for ordering and a
/// transfer-local chunk index. Node-to-node integrity is provided by the
/// transport/session security boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferChunk {
    /// The transfer session this chunk belongs to.
    pub transfer_id: u64,
    /// The epoch this transfer is bound to.
    pub epoch: u64,
    /// Sequence number for ordering within this transfer.
    pub sequence: u64,
    /// Byte offset within the overall transfer stream.
    pub offset: u64,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
    /// Whether this is the last chunk for this transfer.
    pub is_last: bool,
}

/// Signal that a transfer has completed successfully.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferComplete {
    /// The transfer session that completed.
    pub transfer_id: u64,
    /// The epoch this transfer was bound to.
    pub epoch: u64,
    /// Total chunks transferred.
    pub total_chunks: u64,
    /// Total bytes transferred.
    pub total_bytes: u64,
    /// Whether the destination verified all received data.
    pub verified: bool,
}

/// Abort an in-progress transfer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferAbort {
    /// The transfer session to abort.
    pub transfer_id: u64,
    /// The epoch this transfer was bound to.
    pub epoch: u64,
    /// Human-readable reason for the abort.
    pub reason: String,
}

// ── Wire encode / decode ────────────────────────────────────────────

/// Generic encode: discriminant byte + bincode payload.
fn encode_wire<T: Serialize>(
    disc: TransferControlDiscriminant,
    msg: &T,
) -> Result<Vec<u8>, TransferControlError> {
    let mut buf = vec![disc as u8];
    let payload =
        bincode::serialize(msg).map_err(|e| TransferControlError::Serialize(e.to_string()))?;
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Generic decode: bincode deserialize payload bytes.
fn decode_payload<T: serde::de::DeserializeOwned>(
    payload: &[u8],
) -> Result<T, TransferControlError> {
    bincode::deserialize(payload).map_err(|e| TransferControlError::Deserialize(e.to_string()))
}

impl TransferInitiate {
    pub fn encode_wire(&self) -> Result<Vec<u8>, TransferControlError> {
        encode_wire(TransferControlDiscriminant::Initiate, self)
    }
}

impl TransferChunkAck {
    pub fn encode_wire(&self) -> Result<Vec<u8>, TransferControlError> {
        encode_wire(TransferControlDiscriminant::ChunkAck, self)
    }
}

impl TransferChunk {
    pub fn encode_wire(&self) -> Result<Vec<u8>, TransferControlError> {
        encode_wire(TransferControlDiscriminant::Chunk, self)
    }
}

impl TransferComplete {
    pub fn encode_wire(&self) -> Result<Vec<u8>, TransferControlError> {
        encode_wire(TransferControlDiscriminant::Complete, self)
    }
}

impl TransferAbort {
    pub fn encode_wire(&self) -> Result<Vec<u8>, TransferControlError> {
        encode_wire(TransferControlDiscriminant::Abort, self)
    }
}

/// Unified message enum that carries any transfer control variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferControlMessage {
    Initiate(TransferInitiate),
    ChunkAck(TransferChunkAck),
    Chunk(TransferChunk),
    Complete(TransferComplete),
    Abort(TransferAbort),
}

/// Decode a transfer control message from a wire frame.
///
/// The first byte is the discriminant; the rest is the bincode payload.
pub fn decode_transfer_control_message(
    wire: &[u8],
) -> Result<TransferControlMessage, TransferControlError> {
    if wire.is_empty() {
        return Err(TransferControlError::Deserialize("empty wire frame".into()));
    }
    let disc = TransferControlDiscriminant::from_u8(wire[0])
        .ok_or(TransferControlError::UnknownDiscriminant(wire[0]))?;
    let payload = &wire[1..];
    match disc {
        TransferControlDiscriminant::Initiate => {
            Ok(TransferControlMessage::Initiate(decode_payload(payload)?))
        }
        TransferControlDiscriminant::ChunkAck => {
            Ok(TransferControlMessage::ChunkAck(decode_payload(payload)?))
        }
        TransferControlDiscriminant::Chunk => {
            Ok(TransferControlMessage::Chunk(decode_payload(payload)?))
        }
        TransferControlDiscriminant::Complete => {
            Ok(TransferControlMessage::Complete(decode_payload(payload)?))
        }
        TransferControlDiscriminant::Abort => {
            Ok(TransferControlMessage::Abort(decode_payload(payload)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eid(v: u64) -> u64 {
        v
    }

    #[test]
    fn initiate_roundtrip() {
        let msg = TransferInitiate {
            transfer_id: 42,
            epoch: eid(7),
            source_node: 100,
            destination_node: 200,
            ranges: vec![
                TransferRange {
                    object_id: 1,
                    start_offset: 0,
                    length_bytes: 4096,
                },
                TransferRange {
                    object_id: 2,
                    start_offset: 8192,
                    length_bytes: 16384,
                },
            ],
            max_chunk_bytes: 65536,
        };
        let wire = msg.encode_wire().unwrap();
        let decoded = decode_transfer_control_message(&wire).unwrap();
        assert_eq!(decoded, TransferControlMessage::Initiate(msg));
    }

    #[test]
    fn chunk_ack_roundtrip() {
        let msg = TransferChunkAck {
            transfer_id: 42,
            epoch: eid(7),
            chunks_received: 10,
            bytes_received: 655360,
            highest_contiguous_offset: 655360,
        };
        let wire = msg.encode_wire().unwrap();
        let decoded = decode_transfer_control_message(&wire).unwrap();
        assert_eq!(decoded, TransferControlMessage::ChunkAck(msg));
    }

    #[test]
    fn chunk_roundtrip() {
        let msg = TransferChunk {
            transfer_id: 42,
            epoch: eid(7),
            sequence: 3,
            offset: 12288,
            payload: b"transfer data payload".to_vec(),
            is_last: false,
        };
        let wire = msg.encode_wire().unwrap();
        let decoded = decode_transfer_control_message(&wire).unwrap();
        assert_eq!(decoded, TransferControlMessage::Chunk(msg));
    }

    #[test]
    fn chunk_last_flag() {
        let msg = TransferChunk {
            transfer_id: 1,
            epoch: eid(1),
            sequence: 10,
            offset: 65536,
            payload: b"final".to_vec(),
            is_last: true,
        };
        let wire = msg.encode_wire().unwrap();
        let decoded = decode_transfer_control_message(&wire).unwrap();
        match decoded {
            TransferControlMessage::Chunk(c) => assert!(c.is_last),
            _ => panic!("expected Chunk variant"),
        }
    }

    #[test]
    fn chunk_empty_payload() {
        let msg = TransferChunk {
            transfer_id: 99,
            epoch: eid(3),
            sequence: 0,
            offset: 0,
            payload: vec![],
            is_last: true,
        };
        let wire = msg.encode_wire().unwrap();
        let decoded = decode_transfer_control_message(&wire).unwrap();
        assert_eq!(decoded, TransferControlMessage::Chunk(msg));
    }

    #[test]
    fn complete_roundtrip() {
        let msg = TransferComplete {
            transfer_id: 42,
            epoch: eid(7),
            total_chunks: 100,
            total_bytes: 6_553_600,
            verified: true,
        };
        let wire = msg.encode_wire().unwrap();
        let decoded = decode_transfer_control_message(&wire).unwrap();
        assert_eq!(decoded, TransferControlMessage::Complete(msg));
    }

    #[test]
    fn abort_roundtrip() {
        let msg = TransferAbort {
            transfer_id: 42,
            epoch: eid(7),
            reason: "source drained during transfer".into(),
        };
        let wire = msg.encode_wire().unwrap();
        let decoded = decode_transfer_control_message(&wire).unwrap();
        assert_eq!(decoded, TransferControlMessage::Abort(msg));
    }

    #[test]
    fn unknown_discriminant_yields_error() {
        let result = decode_transfer_control_message(&[0xFF, 0, 0, 0]);
        assert!(matches!(
            result.unwrap_err(),
            TransferControlError::UnknownDiscriminant(0xFF)
        ));
    }

    #[test]
    fn empty_wire_fails() {
        assert!(decode_transfer_control_message(&[]).is_err());
    }

    #[test]
    fn from_u8_valid_and_invalid() {
        assert_eq!(
            TransferControlDiscriminant::from_u8(0x41),
            Some(TransferControlDiscriminant::Initiate)
        );
        assert_eq!(
            TransferControlDiscriminant::from_u8(0x42),
            Some(TransferControlDiscriminant::ChunkAck)
        );
        assert_eq!(
            TransferControlDiscriminant::from_u8(0x43),
            Some(TransferControlDiscriminant::Complete)
        );
        assert_eq!(
            TransferControlDiscriminant::from_u8(0x44),
            Some(TransferControlDiscriminant::Abort)
        );
        assert_eq!(
            TransferControlDiscriminant::from_u8(0x45),
            Some(TransferControlDiscriminant::Chunk)
        );
        assert_eq!(TransferControlDiscriminant::from_u8(0x00), None);
        assert_eq!(TransferControlDiscriminant::from_u8(0xFF), None);
    }

    #[test]
    fn all_variants_decode_unified() {
        let msgs: [TransferControlMessage; 5] = [
            TransferControlMessage::Initiate(TransferInitiate {
                transfer_id: 1,
                epoch: eid(10),
                source_node: 7,
                destination_node: 8,
                ranges: vec![TransferRange {
                    object_id: 1,
                    start_offset: 0,
                    length_bytes: 512,
                }],
                max_chunk_bytes: 4096,
            }),
            TransferControlMessage::ChunkAck(TransferChunkAck {
                transfer_id: 1,
                epoch: eid(10),
                chunks_received: 5,
                bytes_received: 2560,
                highest_contiguous_offset: 2560,
            }),
            TransferControlMessage::Chunk(TransferChunk {
                transfer_id: 1,
                epoch: eid(10),
                sequence: 0,
                offset: 0,
                payload: b"hello".to_vec(),
                is_last: true,
            }),
            TransferControlMessage::Complete(TransferComplete {
                transfer_id: 1,
                epoch: eid(10),
                total_chunks: 10,
                total_bytes: 5120,
                verified: true,
            }),
            TransferControlMessage::Abort(TransferAbort {
                transfer_id: 1,
                epoch: eid(10),
                reason: "test".into(),
            }),
        ];
        for msg in &msgs {
            let wire = match msg {
                TransferControlMessage::Initiate(m) => m.encode_wire().unwrap(),
                TransferControlMessage::ChunkAck(m) => m.encode_wire().unwrap(),
                TransferControlMessage::Chunk(m) => m.encode_wire().unwrap(),
                TransferControlMessage::Complete(m) => m.encode_wire().unwrap(),
                TransferControlMessage::Abort(m) => m.encode_wire().unwrap(),
            };
            assert_eq!(&decode_transfer_control_message(&wire).unwrap(), msg);
        }
    }
}
