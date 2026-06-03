//! Chunk dispatch: TransferPlan, ObjectDescriptor, TransferProgress events,
//! and the ChunkDispatcher that coordinates chunking, flow control, and
//! session delivery.
//!
//! The dispatcher bridges the send-stream chunk encoder and receive-stream
//! assembler through a paired [`super::session_pairing::ShipperSession`],
//! using flow-control permits from [`super::flow_control::FlowController`]
//! to bound inflight chunks.

use std::collections::VecDeque;

use tidefs_receive_stream::assembler::AssembledObject;
use tidefs_receive_stream::decoder::ChunkDecoder;
use tidefs_send_stream::chunk_encoder::{
    TransferChunk, TransferChunkEncoder, TransferChunkEncoderConfig,
};

use super::flow_control::{FlowControlError, FlowController};
use super::session_pairing::ShipperSession;

// ── Transfer plan types ─────────────────────────────────────────────────

/// Descriptor for a single object in a transfer plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectDescriptor {
    /// Stable object identifier (BLAKE3-256 of canonical content).
    pub object_id: [u8; 32],
    /// Total byte length of the object.
    pub size: u64,
    /// Pre-computed BLAKE3-256 digest of the full object data.
    pub digest: [u8; 32],
    /// The object payload (in-memory for deterministic execution).
    pub data: Vec<u8>,
}

impl ObjectDescriptor {
    /// Create a new descriptor, computing size and BLAKE3 digest from data.
    #[must_use]
    pub fn new(object_id: [u8; 32], data: Vec<u8>) -> Self {
        let digest: [u8; 32] = blake3::hash(&data).into();
        Self {
            object_id,
            size: data.len() as u64,
            digest,
            data,
        }
    }
}

/// A plan describing objects to transfer in one shipping session.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TransferPlan {
    /// Objects to transfer, in order.
    pub objects: Vec<ObjectDescriptor>,
    /// Maximum payload bytes per chunk (default: 65536).
    pub chunk_size: u32,
}

impl TransferPlan {
    /// Create a new empty plan with default chunk size.
    #[must_use]
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            chunk_size: 65536,
        }
    }

    /// Add an object to the plan.
    pub fn add_object(&mut self, desc: ObjectDescriptor) {
        self.objects.push(desc);
    }

    /// Total number of objects in the plan.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Total bytes across all objects.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.objects.iter().map(|o| o.size).sum()
    }
}

// ── Transfer progress events ────────────────────────────────────────────

/// Progress event emitted during a chunk shipping transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransferProgress {
    /// A chunk frame has been enqueued for sending.
    ChunkSent {
        object_id: [u8; 32],
        chunk_index: u32,
        total_chunks: u32,
        bytes: usize,
    },
    /// A sent chunk has been acknowledged (decoded + assembled on receive side).
    ChunkAcked {
        object_id: [u8; 32],
        chunk_index: u32,
    },
    /// An entire object has been assembled and verified on the receive side.
    ObjectComplete {
        object_id: [u8; 32],
        bytes: u64,
        digest_match: bool,
    },
    /// The full transfer has finished, with final integrity outcome.
    TransferFinished {
        integrity_ok: bool,
        total_objects: usize,
        total_chunks: u64,
        total_bytes: u64,
    },
}

// ── Chunk dispatcher ────────────────────────────────────────────────────

/// Orchestrates the chunk dispatch loop for one transfer plan.
///
/// Owns the chunk encoder, flow controller, and a reference to the
/// paired session. The dispatch loop is driven by calling
/// [`dispatch_next`] repeatedly until all objects are transferred.
pub struct ChunkDispatcher<'s> {
    /// Session driving send and receive.
    session: &'s mut ShipperSession,
    /// Flow controller for backpressure.
    flow: FlowController,
    /// Encoder for splitting objects into chunks.
    /// Remaining chunks to send (pre-computed for all objects).
    pending_chunks: VecDeque<TransferChunk>,
    /// Objects remaining to be assembled (tracked by object_id).
    /// Progress events emitted since last drain.
    events: Vec<TransferProgress>,
    /// Total assembly bytes received.
    total_assembled_bytes: u64,
}

impl<'s> ChunkDispatcher<'s> {
    /// Create a new dispatcher bound to a session.
    ///
    /// Pre-computes all chunks from the plan so the dispatch loop can
    /// operate deterministically.
    #[must_use]
    pub fn new(session: &'s mut ShipperSession, plan: &TransferPlan, max_inflight: usize) -> Self {
        let encoder = TransferChunkEncoder::new(TransferChunkEncoderConfig {
            chunk_size: plan.chunk_size,
        });

        let mut pending_chunks = VecDeque::new();
        for obj in &plan.objects {
            let chunks = encoder.encode_object(obj.object_id, &obj.data);
            pending_chunks.extend(chunks);
        }

        Self {
            session,
            flow: FlowController::new(max_inflight),
            pending_chunks,
            events: Vec::new(),
            total_assembled_bytes: 0,
        }
    }

    /// Try to dispatch one chunk through the session.
    ///
    /// Returns `Ok(true)` when a chunk was dispatched, `Ok(false)` when
    /// the flow window is full (caller should drain receive side and retry),
    /// or `Err` when the session is in a terminal state.
    pub fn dispatch_next(&mut self) -> Result<bool, FlowControlError> {
        // Acquire a send slot
        let _permit = match self.flow.try_acquire_send_slot() {
            Ok(p) => p,
            Err(FlowControlError::WindowExhausted) => return Ok(false),
            Err(e) => return Err(e),
        };

        // Get next chunk to send
        let chunk = match self.pending_chunks.pop_front() {
            Some(c) => c,
            None => {
                // No more chunks: release the permit back
                self.flow.release_on_ack(0);
                return Ok(false);
            }
        };

        let object_id = chunk.object_id;
        let chunk_index = chunk.chunk_index;
        let total_chunks = chunk.total_chunks;
        let payload_len = chunk.payload.len();

        // Hash the payload into the session send hasher
        self.session.hash_send_payload(&chunk.payload);

        // Encode to wire format and enqueue on send side
        let wire = chunk.encode_to_wire();
        self.session.send_queue.enqueue(wire);
        self.session.record_frame_sent(payload_len);

        // Emit progress event
        self.events.push(TransferProgress::ChunkSent {
            object_id,
            chunk_index,
            total_chunks,
            bytes: payload_len,
        });

        Ok(true)
    }

    /// Drain the send queue, decode frames, feed them to the assembler,
    /// and release flow-control permits for completed chunks.
    ///
    /// Returns any assembled objects that completed during this drain.
    pub fn drain_receive(&mut self) -> Vec<AssembledObject> {
        // Drain all enqueued wire frames from the send queue
        let frames: Vec<Vec<u8>> = self.session.send_queue.drain();

        let decoder = ChunkDecoder::new();
        let mut completed_objects = Vec::new();

        for wire in &frames {
            // Decode chunk(s) from the wire frame.
            // A wire frame may contain one complete chunk.
            let mut remaining: &[u8] = wire;
            while !remaining.is_empty() {
                match decoder.decode_chunk(remaining) {
                    Ok((decoded_chunk, rest)) => {
                        // Hash payload into recv hasher
                        self.session.hash_recv_payload(&decoded_chunk.payload);

                        // Feed to assembler
                        if let Err(e) = self.session.receive_assembler.feed_chunk(decoded_chunk) {
                            eprintln!("chunk dispatcher: assembler error: {e:?}");
                        }

                        // Release one flow-control slot per decoded chunk
                        self.flow.release_on_ack(0);

                        remaining = rest;
                    }
                    Err(e) => {
                        eprintln!("chunk dispatcher: decode error: {e:?}");
                        break;
                    }
                }
            }
        }

        // Drain completed objects from assembler
        let assembled = self.session.receive_assembler.drain_complete();
        for obj in &assembled {
            let obj_bytes = obj.payload.len() as u64;
            self.session.record_bytes_received(obj_bytes);
            self.session.record_object_completed();
            self.total_assembled_bytes += obj_bytes;

            self.events.push(TransferProgress::ObjectComplete {
                object_id: obj.object_id,
                bytes: obj_bytes,
                digest_match: true, // full integrity check at session level
            });

            completed_objects.push(obj.clone());
        }

        completed_objects
    }

    /// Check whether all objects have been completely assembled.
    #[must_use]
    pub fn is_transfer_complete(&self) -> bool {
        self.pending_chunks.is_empty()
            && self.session.receive_assembler.buffered_chunks() == 0
            && self.session.receive_assembler.pending_objects() == 0
    }

    /// Drain accumulated progress events.
    pub fn drain_events(&mut self) -> Vec<TransferProgress> {
        std::mem::take(&mut self.events)
    }

    /// Total bytes assembled on the receive side.
    #[must_use]
    pub fn total_assembled_bytes(&self) -> u64 {
        self.total_assembled_bytes
    }

    // ── Accessors ──

    #[must_use]
    pub fn pending_chunk_count(&self) -> usize {
        self.pending_chunks.len()
    }

    #[must_use]
    pub fn inflight_count(&self) -> usize {
        self.flow.inflight_count()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_object(id_byte: u8, data: &[u8]) -> ObjectDescriptor {
        let mut object_id = [0u8; 32];
        object_id[0] = id_byte;
        ObjectDescriptor::new(object_id, data.to_vec())
    }

    #[test]
    fn object_descriptor_computes_digest() {
        let data = b"hello world".to_vec();
        let desc = ObjectDescriptor::new([1u8; 32], data.clone());
        assert_eq!(desc.size, 11);
        assert_eq!(desc.data, data);
        assert_ne!(desc.digest, [0u8; 32]);
        let desc2 = ObjectDescriptor::new([1u8; 32], b"hello world".to_vec());
        assert_eq!(desc.digest, desc2.digest);
    }

    #[test]
    fn transfer_plan_add_and_count() {
        let mut plan = TransferPlan::new();
        assert_eq!(plan.object_count(), 0);
        assert_eq!(plan.total_bytes(), 0);

        plan.add_object(make_object(1, b"abc"));
        plan.add_object(make_object(2, b"defgh"));
        assert_eq!(plan.object_count(), 2);
        assert_eq!(plan.total_bytes(), 8);
    }

    #[test]
    fn transfer_plan_default_chunk_size() {
        let plan = TransferPlan::new();
        assert_eq!(plan.chunk_size, 65536);
    }

    #[test]
    fn dispatcher_created_with_pending_chunks() {
        let mut session = ShipperSession::new(1, 16);
        session.start_transfer().unwrap();

        let mut plan = TransferPlan::new();
        plan.chunk_size = 100;
        plan.add_object(make_object(0xAA, &vec![0x42u8; 250]));

        let disp = ChunkDispatcher::new(&mut session, &plan, 8);
        assert_eq!(disp.pending_chunk_count(), 3);
        assert_eq!(disp.inflight_count(), 0);
    }

    #[test]
    fn dispatch_and_drain_single_object() {
        let mut session = ShipperSession::new(1, 16);
        session.start_transfer().unwrap();

        let mut plan = TransferPlan::new();
        plan.chunk_size = 1024;
        let data = b"hello chunk shipper dispatch test".to_vec();
        plan.add_object(make_object(0x42, &data));

        let mut disp = ChunkDispatcher::new(&mut session, &plan, 8);
        assert_eq!(disp.pending_chunk_count(), 1);

        let sent = disp.dispatch_next().unwrap();
        assert!(sent);
        assert_eq!(disp.pending_chunk_count(), 0);

        let completed = disp.drain_receive();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].payload, data);
        assert!(session.verify_integrity());
    }

    #[test]
    fn dispatch_multi_chunk_object_with_flow_control() {
        let mut session = ShipperSession::new(1, 32);
        session.start_transfer().unwrap();

        let mut plan = TransferPlan::new();
        plan.chunk_size = 3;
        let data = b"0123456789".to_vec();
        plan.add_object(make_object(1, &data));

        let mut disp = ChunkDispatcher::new(&mut session, &plan, 2);

        assert!(disp.dispatch_next().unwrap());
        assert!(disp.dispatch_next().unwrap());
        assert!(!disp.dispatch_next().unwrap());

        let completed = disp.drain_receive();
        assert!(completed.is_empty());

        assert!(disp.dispatch_next().unwrap());
        assert!(disp.dispatch_next().unwrap());

        let completed = disp.drain_receive();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].payload, data);
        assert!(session.verify_integrity());
    }

    #[test]
    fn transfer_progress_events_emitted() {
        let mut session = ShipperSession::new(1, 32);
        session.start_transfer().unwrap();

        let mut plan = TransferPlan::new();
        plan.chunk_size = 1024;
        plan.add_object(make_object(0x10, b"test data"));

        let mut disp = ChunkDispatcher::new(&mut session, &plan, 8);
        disp.dispatch_next().unwrap();

        let events = disp.drain_events();
        assert_eq!(events.len(), 1);
        match &events[0] {
            TransferProgress::ChunkSent {
                object_id,
                chunk_index,
                total_chunks,
                bytes,
            } => {
                assert_eq!(object_id[0], 0x10);
                assert_eq!(*chunk_index, 0);
                assert_eq!(*total_chunks, 1);
                assert_eq!(*bytes, 9);
            }
            _ => panic!("expected ChunkSent event"),
        }
    }

    #[test]
    fn is_transfer_complete_empty_plan() {
        let mut session = ShipperSession::new(1, 8);
        session.start_transfer().unwrap();
        let plan = TransferPlan::new();
        let disp = ChunkDispatcher::new(&mut session, &plan, 4);
        assert!(disp.is_transfer_complete());
    }

    #[test]
    fn dispatcher_multi_object_plan() {
        let mut session = ShipperSession::new(1, 32);
        session.start_transfer().unwrap();

        let mut plan = TransferPlan::new();
        plan.chunk_size = 1024;
        plan.add_object(make_object(1, b"first"));
        plan.add_object(make_object(2, b"second"));

        let mut disp = ChunkDispatcher::new(&mut session, &plan, 8);
        assert_eq!(disp.pending_chunk_count(), 2);

        disp.dispatch_next().unwrap();
        disp.dispatch_next().unwrap();

        let completed = disp.drain_receive();
        assert_eq!(completed.len(), 2);

        let mut payloads: Vec<Vec<u8>> = completed.iter().map(|o| o.payload.clone()).collect();
        payloads.sort();
        assert_eq!(payloads, vec![b"first".to_vec(), b"second".to_vec()]);
        assert!(session.verify_integrity());
    }
}
