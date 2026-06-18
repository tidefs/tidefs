// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Top-level chunk-shipper orchestrator.
//!
//! The [`ChunkShipper`] drives the full transfer lifecycle: session pairing,
//! dispatch loop, drain, and integrity finalization.
//!
//! # Lifecycle
//!
//! ```text
//! Paired -> Transferring -> Draining -> Closed
//!              |                |
//!              v                v
//!          dispatch loop    drain receive
//!          (flow-controlled)  (assembly + verify)
//! ```

use tidefs_receive_stream::assembler::AssembledObject;

use super::dispatch::{ChunkDispatcher, TransferPlan, TransferProgress};
use super::flow_control::FlowControlError;
use super::session_pairing::{SessionState, ShipperSession};

/// Errors that may occur during a chunk-shipping transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShipError {
    SessionSetupFailed(String),
    SendStreamError(String),
    ReceiveStreamError(String),
    IntegrityMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    FlowControlStalled,
    SessionClosed,
}

impl std::fmt::Display for ShipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionSetupFailed(msg) => write!(f, "session setup failed: {msg}"),
            Self::SendStreamError(msg) => write!(f, "send-stream error: {msg}"),
            Self::ReceiveStreamError(msg) => write!(f, "receive-stream error: {msg}"),
            Self::IntegrityMismatch { expected, actual } => write!(
                f,
                "integrity mismatch: expected {:02x?}..., actual {:02x?}...",
                &expected[..4],
                &actual[..4],
            ),
            Self::FlowControlStalled => write!(f, "flow control stalled"),
            Self::SessionClosed => write!(f, "session closed"),
        }
    }
}

impl std::error::Error for ShipError {}

/// The result of a completed chunk-shipping transfer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TransferOutcome {
    pub objects_transferred: usize,
    pub bytes_transferred: u64,
    pub chunks_sent: u64,
    pub object_digests: Vec<([u8; 32], [u8; 32])>,
    pub integrity_ok: bool,
    pub progress_events: Vec<TransferProgress>,
}

/// Top-level orchestrator for chunk shipping transfers.
pub struct ChunkShipper {
    plan: TransferPlan,
    max_inflight: usize,
}

impl ChunkShipper {
    #[must_use]
    pub fn new(plan: TransferPlan, max_inflight: usize) -> Self {
        Self { plan, max_inflight }
    }

    /// Execute the full transfer through the given session.
    ///
    /// The session must be in the `Paired` state.
    pub fn ship_transfer(
        &mut self,
        session: &mut ShipperSession,
    ) -> Result<TransferOutcome, ShipError> {
        // 1. Start transfer
        if session.state != SessionState::Paired {
            return Err(ShipError::SessionSetupFailed(format!(
                "session must be Paired, got {:?}",
                session.state,
            )));
        }
        session
            .start_transfer()
            .map_err(|e| ShipError::SessionSetupFailed(format!("start_transfer failed: {e}")))?;

        // 2. Dispatch loop — scoped so dispatcher's borrow of session is released.
        let (total_chunks_sent, assembled_objects, dispatcher_events) = {
            let mut dispatcher = ChunkDispatcher::new(session, &self.plan, self.max_inflight);

            let mut total_chunks_sent: u64 = 0;
            let mut all_objects: Vec<AssembledObject> = Vec::new();
            let mut stalled_iters: u32 = 0;
            const MAX_STALLED: u32 = 1000;

            loop {
                match dispatcher.dispatch_next() {
                    Ok(true) => {
                        total_chunks_sent += 1;
                        stalled_iters = 0;
                        let completed = dispatcher.drain_receive();
                        all_objects.extend(completed);
                    }
                    Ok(false) => {
                        let completed = dispatcher.drain_receive();
                        all_objects.extend(completed);
                        if dispatcher.is_transfer_complete() {
                            break;
                        }
                        stalled_iters += 1;
                        if stalled_iters > MAX_STALLED {
                            return Err(ShipError::FlowControlStalled);
                        }
                    }
                    Err(FlowControlError::SessionClosed) => {
                        return Err(ShipError::SessionClosed);
                    }
                    Err(FlowControlError::WindowExhausted) => {
                        let completed = dispatcher.drain_receive();
                        all_objects.extend(completed);
                        stalled_iters += 1;
                        if stalled_iters > MAX_STALLED {
                            return Err(ShipError::FlowControlStalled);
                        }
                    }
                }
            }

            // Final drain
            let final_objects = dispatcher.drain_receive();
            all_objects.extend(final_objects);
            let events = dispatcher.drain_events();

            (total_chunks_sent, all_objects, events)
        };

        // 3. State transitions
        session
            .start_drain()
            .map_err(|e| ShipError::SessionSetupFailed(format!("start_drain failed: {e}")))?;

        let integrity_ok = session.verify_integrity();

        // 4. Build outcome from accumulated objects
        let mut object_digests = Vec::new();
        let mut total_bytes: u64 = 0;
        for obj in &assembled_objects {
            let computed: [u8; 32] = blake3::hash(&obj.payload).into();
            object_digests.push((obj.object_id, computed));
            total_bytes += obj.payload.len() as u64;
        }

        let mut progress_events = dispatcher_events;
        progress_events.push(TransferProgress::TransferFinished {
            integrity_ok,
            total_objects: object_digests.len(),
            total_chunks: total_chunks_sent,
            total_bytes,
        });

        session
            .close()
            .map_err(|e| ShipError::SessionSetupFailed(format!("close failed: {e}")))?;

        if integrity_ok {
            Ok(TransferOutcome {
                objects_transferred: object_digests.len(),
                bytes_transferred: total_bytes,
                chunks_sent: total_chunks_sent,
                object_digests,
                integrity_ok,
                progress_events,
            })
        } else {
            Err(ShipError::IntegrityMismatch {
                expected: session.send_digest(),
                actual: session.recv_digest(),
            })
        }
    }

    #[must_use]
    pub fn plan(&self) -> &TransferPlan {
        &self.plan
    }
    #[must_use]
    pub fn max_inflight(&self) -> usize {
        self.max_inflight
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::dispatch::ObjectDescriptor;
    use super::*;

    fn make_obj(id: u8, data: &[u8]) -> ObjectDescriptor {
        let mut oid = [0u8; 32];
        oid[0] = id;
        ObjectDescriptor::new(oid, data.to_vec())
    }

    #[test]
    fn ship_single_object_small() {
        let mut s = ShipperSession::new(1, 16);
        let mut p = TransferPlan::new();
        p.chunk_size = 1024;
        p.add_object(make_obj(0x10, b"hello world"));
        let mut sh = ChunkShipper::new(p, 8);
        let o = sh.ship_transfer(&mut s).unwrap();
        assert!(o.integrity_ok);
        assert_eq!(o.objects_transferred, 1);
        assert_eq!(o.bytes_transferred, 11);
        assert_eq!(o.chunks_sent, 1);
        assert!(s.is_closed());
    }

    #[test]
    fn ship_multi_chunk_object() {
        let mut s = ShipperSession::new(1, 32);
        let mut p = TransferPlan::new();
        p.chunk_size = 4;
        p.add_object(make_obj(0x20, b"0123456789"));
        let mut sh = ChunkShipper::new(p, 8);
        let o = sh.ship_transfer(&mut s).unwrap();
        assert!(o.integrity_ok);
        assert_eq!(o.objects_transferred, 1);
        assert_eq!(o.bytes_transferred, 10);
        assert_eq!(o.chunks_sent, 3);
    }

    #[test]
    fn ship_multi_object_plan() {
        let mut s = ShipperSession::new(1, 32);
        let mut p = TransferPlan::new();
        p.chunk_size = 1024;
        p.add_object(make_obj(1, b"first"));
        p.add_object(make_obj(2, b"second"));
        p.add_object(make_obj(3, b"third"));
        let mut sh = ChunkShipper::new(p, 8);
        let o = sh.ship_transfer(&mut s).unwrap();
        assert!(o.integrity_ok);
        assert_eq!(o.objects_transferred, 3);
        assert_eq!(o.chunks_sent, 3);
    }

    #[test]
    fn ship_with_tight_flow_control() {
        let mut s = ShipperSession::new(1, 32);
        let mut p = TransferPlan::new();
        p.chunk_size = 2;
        p.add_object(make_obj(0x30, &[0xABu8; 20]));
        let mut sh = ChunkShipper::new(p, 3);
        let o = sh.ship_transfer(&mut s).unwrap();
        assert!(o.integrity_ok);
        assert_eq!(o.chunks_sent, 10);
        assert_eq!(o.bytes_transferred, 20);
    }

    #[test]
    fn ship_empty_object() {
        let mut s = ShipperSession::new(1, 16);
        let mut p = TransferPlan::new();
        p.add_object(make_obj(0x40, b""));
        let mut sh = ChunkShipper::new(p, 8);
        let o = sh.ship_transfer(&mut s).unwrap();
        assert!(o.integrity_ok);
        assert_eq!(o.objects_transferred, 1);
        assert_eq!(o.chunks_sent, 1);
        assert_eq!(o.bytes_transferred, 0);
    }

    #[test]
    fn ship_errors_on_wrong_initial_state() {
        let mut s = ShipperSession::new(1, 8);
        s.start_transfer().unwrap();
        s.start_drain().unwrap();
        let mut p = TransferPlan::new();
        p.add_object(make_obj(1, b"data"));
        let mut sh = ChunkShipper::new(p, 8);
        assert!(matches!(
            sh.ship_transfer(&mut s),
            Err(ShipError::SessionSetupFailed(_))
        ));
    }

    #[test]
    fn ship_produces_progress_events() {
        let mut s = ShipperSession::new(1, 32);
        let mut p = TransferPlan::new();
        p.chunk_size = 1024;
        p.add_object(make_obj(0x50, b"progress test"));
        let mut sh = ChunkShipper::new(p, 8);
        let o = sh.ship_transfer(&mut s).unwrap();
        assert!(!o.progress_events.is_empty());
        assert!(o
            .progress_events
            .iter()
            .any(|e| matches!(e, TransferProgress::ChunkSent { .. })));
        assert!(o
            .progress_events
            .iter()
            .any(|e| matches!(e, TransferProgress::ObjectComplete { .. })));
        assert!(o
            .progress_events
            .iter()
            .any(|e| matches!(e, TransferProgress::TransferFinished { .. })));
    }

    #[test]
    fn ship_error_display() {
        let e = ShipError::FlowControlStalled;
        assert_eq!(e.to_string(), "flow control stalled");
    }

    #[test]
    fn ship_large_transfer_64k() {
        let mut s = ShipperSession::new(1, 128);
        let mut p = TransferPlan::new();
        p.chunk_size = 1024;
        let data = vec![0xCCu8; 65536];
        p.add_object(make_obj(0x60, &data));
        let mut sh = ChunkShipper::new(p, 16);
        let o = sh.ship_transfer(&mut s).unwrap();
        assert!(o.integrity_ok);
        assert_eq!(o.chunks_sent, 64);
        assert_eq!(o.bytes_transferred, 65536);
        let expected: [u8; 32] = blake3::hash(&data).into();
        assert_eq!(o.object_digests[0].1, expected);
    }
}
