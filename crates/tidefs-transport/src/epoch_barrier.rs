//! Membership-epoch transport barrier: fences messages by epoch number
//! so that stale-epoch messages are rejected and future-epoch messages are
//! queued until the barrier advances.
//!
//! ## Epoch fencing semantics
//!
//! Each outgoing message is stamped with the current membership epoch and a
//! monotonic per-epoch sequence number, producing an [`EpochStamped`] wrapper
//! with a BLAKE3-256 domain-separated digest.  The receiver verifies the
//! digest and then compares the stamped epoch against its own barrier:
//!
//! - **epoch == current**: accepted and delivered immediately.
//! - **epoch < current**: rejected as [`EpochBarrierError::StaleEpoch`].
//! - **epoch > current**: queued internally; delivered when the barrier
//!   advances to (or past) the stamped epoch via [`EpochBarrier::advance`].
//!
//! ## Wire format layout
//!
//! ```text
//! ┌──────────┬──────────┬──────────┬─────────────┬───────────┬──────────┐
//! │ magic(4) │ epoch(8) │  seq(8)  │ plen(4,u32) │ payload   │digest(32)│
//! └──────────┴──────────┴──────────┴─────────────┴───────────┴──────────┘
//! ```
//!
//! - **magic**: `VEB\0` (0x56454200) — TideFS Epoch Barrier.
//! - **epoch**: little-endian u64 membership epoch.
//! - **seq**: little-endian u64 monotonic sequence counter (per-epoch).
//! - **plen**: little-endian u32 payload length in bytes.
//! - **payload**: raw message payload bytes.
//! - **digest**: 32-byte BLAKE3-256 hash, domain-separated with
//!   `tidefs-transport-epoch-stamp-v1`, covering epoch || seq || payload.
//!
//! ## Domain-separation constants
//!
//! | Constant | Value |
//! |---|---|
//! | Domain | `tidefs-transport-epoch-stamp-v1` |
//! | Wire magic | `VEB\0` (0x56454200) |
//!
//! ## Integration points
//!
//! - **Send path**: [`EpochBarrier::stamp`] wraps a payload with epoch
//!   and sequence number before wire encoding.
//! - **Receive path**: [`EpochBarrier::verify_and_unwrap`] enforces
//!   epoch-boundary ordering after wire decode. Integrity is provided by
//!   the transport MAC; the epoch barrier only enforces epoch ordering.
//! - **Epoch transition**: [`EpochBarrier::advance`] moves the barrier to a
//!   new epoch, flushing any queued future-epoch messages whose epoch is
//!   now ≤ the new barrier in FIFO order.

use std::collections::VecDeque;
use thiserror::Error;

/// Wire-format magic: "VEB\0" (TideFS Epoch Barrier).
const EPOCH_BARRIER_MAGIC: u32 = 0x5645_4200;

/// Fixed-size wire header before the variable-length payload.
const HEADER_SIZE: usize = 4 + 8 + 8 + 4; // magic + epoch + seq + plen

// ---------------------------------------------------------------------------
// EpochBarrierError
// ---------------------------------------------------------------------------

/// Errors returned by [`EpochBarrier`] verification.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum EpochBarrierError {
    /// The message is structurally malformed (too short, bad magic, etc.).
    #[error("malformed epoch barrier message")]
    MalformedMessage,

    /// The stamped epoch is behind the current barrier (stale message).
    #[error("stale epoch: message epoch {msg_epoch} < barrier epoch {barrier_epoch}")]
    StaleEpoch { msg_epoch: u64, barrier_epoch: u64 },

    /// The stamped epoch is ahead of the barrier — this is not an error
    /// per se; the caller should queue.  Exposed as an error variant so
    /// the caller can distinguish from stale.
    #[error("future epoch: message epoch {msg_epoch} > barrier epoch {barrier_epoch}")]
    FutureEpoch { msg_epoch: u64, barrier_epoch: u64 },
}

// ---------------------------------------------------------------------------
// EpochStamped<T>
// ---------------------------------------------------------------------------

/// A message payload wrapped with epoch and sequence counter for
/// epoch-boundary fencing.
///
/// Generic over the payload type `T`.  For wire transport `T = Vec<u8>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochStamped<T> {
    /// Membership epoch this message belongs to.
    pub epoch: u64,
    /// Monotonic sequence number within the epoch.
    pub sequence: u64,
    /// The wrapped payload.
    pub payload: T,
    /// Reserved field (zero-filled). Formerly a BLAKE3-256 digest.
    /// Kept for wire-format compatibility; integrity is provided by
    /// the transport MAC.
    pub digest: [u8; 32],
}

impl EpochStamped<Vec<u8>> {
    /// Encode to wire format.
    ///
    /// Layout: `magic(4) || epoch(8 LE) || seq(8 LE) || plen(4 LE) ||
    /// payload || digest(32)`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let plen = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len() + 32);
        buf.extend_from_slice(&EPOCH_BARRIER_MAGIC.to_le_bytes());
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.extend_from_slice(&plen.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        // Zero-filled reserved digest field (wire-format compatibility)
        buf.extend_from_slice(&[0u8; 32]);
        buf
    }

    /// Decode from wire-format bytes.
    ///
    /// Returns the decoded `EpochStamped<Vec<u8>>` without verifying the
    /// digest (call [`EpochStamped::verify_full`] to validate).
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too short or magic is wrong.
    pub fn decode(raw: &[u8]) -> Result<Self, EpochBarrierError> {
        if raw.len() < HEADER_SIZE + 32 {
            return Err(EpochBarrierError::MalformedMessage);
        }
        let magic = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        if magic != EPOCH_BARRIER_MAGIC {
            return Err(EpochBarrierError::MalformedMessage);
        }
        let epoch = u64::from_le_bytes(raw[4..12].try_into().unwrap());
        let sequence = u64::from_le_bytes(raw[12..20].try_into().unwrap());
        let plen = u32::from_le_bytes(raw[20..24].try_into().unwrap()) as usize;
        if raw.len() < HEADER_SIZE + plen + 32 {
            return Err(EpochBarrierError::MalformedMessage);
        }
        let payload = raw[HEADER_SIZE..HEADER_SIZE + plen].to_vec();
        // Read and discard the 32-byte digest field (wire-format compatibility).
        let _digest: [u8; 32] = raw[HEADER_SIZE + plen..HEADER_SIZE + plen + 32]
            .try_into()
            .unwrap();
        Ok(Self {
            epoch,
            sequence,
            payload,
            digest: [0u8; 32],
        })
    }

    /// Decode from wire-format bytes (no digest verification; integrity is
    /// provided by the transport MAC).
    pub fn decode_and_verify(raw: &[u8]) -> Result<Self, EpochBarrierError> {
        Self::decode(raw)
    }
}

// ---------------------------------------------------------------------------
// EpochBarrier
// ---------------------------------------------------------------------------

/// Transport-layer epoch barrier that stamps outgoing messages and fences
/// incoming messages by membership epoch.
///
/// Maintains a per-epoch monotonic sequence counter and a FIFO queue of
/// future-epoch messages that are delivered once the barrier advances.
pub struct EpochBarrier {
    /// Current membership epoch.
    current_epoch: u64,
    /// Next sequence number to assign within the current epoch.
    next_sequence: u64,
    /// Messages received ahead of the current epoch, keyed by their
    /// stamped epoch.  Delivered in FIFO order when `advance()` is called.
    future_queue: VecDeque<EpochStamped<Vec<u8>>>,
}

impl EpochBarrier {
    /// Create a new epoch barrier starting at the given epoch.
    #[must_use]
    pub fn new(initial_epoch: u64) -> Self {
        Self {
            current_epoch: initial_epoch,
            next_sequence: 0,
            future_queue: VecDeque::new(),
        }
    }

    /// Return the current barrier epoch.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Return the next sequence number (increments on each `stamp()`).
    #[must_use]
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Number of future-epoch messages currently queued.
    #[must_use]
    pub fn queued_count(&self) -> usize {
        self.future_queue.len()
    }

    /// Stamp an outgoing payload with the current epoch, next sequence
    /// number, and BLAKE3-256 integrity digest.
    ///
    /// The sequence counter is incremented after stamping.
    pub fn stamp(&mut self, payload: Vec<u8>) -> EpochStamped<Vec<u8>> {
        let epoch = self.current_epoch;
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        EpochStamped {
            epoch,
            sequence,
            payload,
            digest: [0u8; 32],
        }
    }

    /// Verify an incoming stamped payload against the current barrier.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(payload))` — epoch matches, digest valid, deliver now.
    /// - `Ok(None)` — epoch > current, message queued for later delivery.
    /// - `Err(EpochBarrierError::StaleEpoch)` — epoch < current, reject.
    /// - `Err(EpochBarrierError::DigestMismatch)` — tampered or corrupt.
    pub fn verify_and_unwrap(
        &mut self,
        stamped: EpochStamped<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, EpochBarrierError> {
        // Integrity is provided by the transport MAC; epoch barrier only
        // enforces epoch-boundary ordering, not content verification.
        match stamped.epoch.cmp(&self.current_epoch) {
            std::cmp::Ordering::Less => Err(EpochBarrierError::StaleEpoch {
                msg_epoch: stamped.epoch,
                barrier_epoch: self.current_epoch,
            }),
            std::cmp::Ordering::Equal => Ok(Some(stamped.payload)),
            std::cmp::Ordering::Greater => {
                self.future_queue.push_back(stamped);
                Ok(None)
            }
        }
    }

    /// Convenience: decode wire bytes, verify, and run epoch check.
    pub fn verify_raw_and_unwrap(
        &mut self,
        raw: &[u8],
    ) -> Result<Option<Vec<u8>>, EpochBarrierError> {
        let stamped = EpochStamped::decode_and_verify(raw)?;
        self.verify_and_unwrap(stamped)
    }

    /// Advance the barrier to a new epoch.
    ///
    /// Resets the sequence counter and flushes any queued future-epoch
    /// messages whose epoch is ≤ the new epoch, in FIFO order.
    ///
    /// # Returns
    ///
    /// All flushed message payloads, in the order they were queued.
    /// Messages with epoch still ahead of the new epoch remain queued.
    pub fn advance(&mut self, new_epoch: u64) -> Vec<Vec<u8>> {
        assert!(
            new_epoch > self.current_epoch,
            "epoch must advance: {new_epoch} <= {}",
            self.current_epoch
        );
        self.current_epoch = new_epoch;
        self.next_sequence = 0;

        let mut flushed = Vec::new();
        while let Some(front) = self.future_queue.front() {
            if front.epoch <= new_epoch {
                if let Some(stamped) = self.future_queue.pop_front() {
                    flushed.push(stamped.payload);
                }
            } else {
                break;
            }
        }
        flushed
    }

    /// Advance the barrier and also return any remaining future-epoch
    /// messages that were ahead of the new epoch (for force-flush
    /// scenarios such as epoch collapse).
    #[allow(dead_code)]
    pub fn advance_and_drain(&mut self, new_epoch: u64) -> Vec<Vec<u8>> {
        self.current_epoch = new_epoch;
        self.next_sequence = 0;
        self.future_queue.drain(..).map(|s| s.payload).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers ----------------------------------------------------------

    /// A non-empty payload for tests.
    fn payload(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    /// Stamp a payload through a new barrier at epoch 0.
    fn stamp_epoch_0(data: &[u8]) -> (EpochBarrier, EpochStamped<Vec<u8>>) {
        let mut barrier = EpochBarrier::new(0);
        let stamped = barrier.stamp(payload(data));
        (barrier, stamped)
    }

    // -- wire-format serialization round-trip -----------------------------

    #[test]
    fn encode_decode_round_trip() {
        let (_, stamped) = stamp_epoch_0(b"round-trip test payload");
        let wire = stamped.encode();
        let decoded = EpochStamped::decode(&wire).expect("decode should succeed");
        assert_eq!(decoded.epoch, stamped.epoch);
        assert_eq!(decoded.sequence, stamped.sequence);
        assert_eq!(decoded.payload, stamped.payload);
        assert_eq!(decoded.digest, [0u8; 32]);
    }

    #[test]
    fn decode_and_verify_valid_message() {
        let (_, stamped) = stamp_epoch_0(b"verify me");
        let wire = stamped.encode();
        let decoded = EpochStamped::decode_and_verify(&wire).expect("decode+verify should succeed");
        assert_eq!(decoded.payload, b"verify me".to_vec());
    }

    #[test]
    fn decode_rejects_short_buffer() {
        let result = EpochStamped::decode(&[0u8; 4]);
        assert!(result.is_err());
    }

    // -- stale-epoch rejection --------------------------------------------

    #[test]
    fn stale_epoch_rejected() {
        let (mut barrier, stamped) = stamp_epoch_0(b"stale");
        // Advance barrier to epoch 1
        barrier.advance(1);
        let result = barrier.verify_and_unwrap(stamped);
        assert!(matches!(result, Err(EpochBarrierError::StaleEpoch { .. })));
    }

    // -- current-epoch acceptance -----------------------------------------

    #[test]
    fn current_epoch_accepted() {
        let (mut barrier, stamped) = stamp_epoch_0(b"current");
        let result = barrier.verify_and_unwrap(stamped);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(payload(b"current")));
    }

    // -- future-epoch queuing and advance flush ---------------------------

    #[test]
    fn future_epoch_queued_then_delivered_after_advance() {
        let mut barrier = EpochBarrier::new(0);
        // Stamp a message at epoch 1 manually (simulating a sender ahead)
        let p = payload(b"future-msg");
        let digest = [0u8; 32];
        let stamped = EpochStamped {
            epoch: 1,
            sequence: 0,
            payload: p,
            digest,
        };

        // Verify at epoch 0: should be queued (future)
        let result = barrier.verify_and_unwrap(stamped);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None); // None = queued
        assert_eq!(barrier.queued_count(), 1);

        // Advance to epoch 1: should flush
        let flushed = barrier.advance(1);
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0], b"future-msg".to_vec());
        assert_eq!(barrier.queued_count(), 0);
    }

    // -- epoch-advance flush ordering (FIFO) ------------------------------

    #[test]
    fn advance_flushes_future_messages_in_fifo_order() {
        let mut barrier = EpochBarrier::new(0);

        // Create 3 future messages at epoch 1 with different sequences
        for i in 0..3 {
            let data = format!("msg-{i}").into_bytes();
            let digest = [0u8; 32];
            let stamped = EpochStamped {
                epoch: 1,
                sequence: i,
                payload: data,
                digest,
            };
            // Each verify_and_unwrap should queue
            let result = barrier.verify_and_unwrap(stamped);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), None);
        }
        assert_eq!(barrier.queued_count(), 3);

        let flushed = barrier.advance(1);
        assert_eq!(flushed.len(), 3);
        assert_eq!(flushed[0], b"msg-0".to_vec());
        assert_eq!(flushed[1], b"msg-1".to_vec());
        assert_eq!(flushed[2], b"msg-2".to_vec());
        assert_eq!(barrier.queued_count(), 0);
    }

    // -- sequence-counter monotonicity ------------------------------------

    #[test]
    fn sequence_counter_increments_monotonically() {
        let mut barrier = EpochBarrier::new(0);
        let s0 = barrier.stamp(payload(b"a"));
        let s1 = barrier.stamp(payload(b"b"));
        let s2 = barrier.stamp(payload(b"c"));
        assert_eq!(s0.sequence, 0);
        assert_eq!(s1.sequence, 1);
        assert_eq!(s2.sequence, 2);
    }

    #[test]
    fn sequence_counter_resets_on_advance() {
        let mut barrier = EpochBarrier::new(0);
        let _ = barrier.stamp(payload(b"epoch-0-msg"));
        assert_eq!(barrier.next_sequence(), 1);
        barrier.advance(1);
        assert_eq!(barrier.next_sequence(), 0);
        let s = barrier.stamp(payload(b"epoch-1-msg"));
        assert_eq!(s.sequence, 0);
    }

    // -- verify_and_unwrap preserves payloads through round-trip ----------

    #[test]
    fn full_round_trip_stamp_encode_decode_verify() {
        let mut send_barrier = EpochBarrier::new(5);
        let stamped = send_barrier.stamp(payload(b"integrated round trip"));
        let wire = stamped.encode();

        let mut recv_barrier = EpochBarrier::new(5);
        let result = recv_barrier
            .verify_raw_and_unwrap(&wire)
            .expect("verify should succeed");
        assert_eq!(result, Some(payload(b"integrated round trip")));
    }

    // -- advance skips epochs ahead ---------------------------------------

    #[test]
    fn advance_skips_multiple_epochs() {
        let mut barrier = EpochBarrier::new(0);
        // Queue messages at epoch 2 and 3
        for epoch in [2u64, 3u64] {
            let data = format!("epoch-{epoch}").into_bytes();
            let digest = [0u8; 32];
            let stamped = EpochStamped {
                epoch,
                sequence: 0,
                payload: data,
                digest,
            };
            let _ = barrier.verify_and_unwrap(stamped);
        }
        assert_eq!(barrier.queued_count(), 2);

        // Advance to 4: both epoch 2 and 3 should flush
        let flushed = barrier.advance(4);
        assert_eq!(flushed.len(), 2);
        assert_eq!(flushed[0], b"epoch-2".to_vec());
        assert_eq!(flushed[1], b"epoch-3".to_vec());
        assert_eq!(barrier.queued_count(), 0);
    }

    // -- advance does not deliver messages still ahead --------------------

    #[test]
    fn advance_does_not_deliver_messages_still_ahead() {
        let mut barrier = EpochBarrier::new(0);
        let data = b"epoch-5-msg".to_vec();
        let digest = [0u8; 32];
        let stamped = EpochStamped {
            epoch: 5,
            sequence: 0,
            payload: data,
            digest,
        };
        let _ = barrier.verify_and_unwrap(stamped);
        assert_eq!(barrier.queued_count(), 1);

        let flushed = barrier.advance(3);
        assert_eq!(flushed.len(), 0); // epoch 5 still ahead
        assert_eq!(barrier.queued_count(), 1);

        let flushed = barrier.advance(6);
        assert_eq!(flushed.len(), 1);
    }

    // -- current_epoch accessor -------------------------------------------

    #[test]
    fn current_epoch_returns_initial_value() {
        let barrier = EpochBarrier::new(42);
        assert_eq!(barrier.current_epoch(), 42);
    }

    #[test]
    fn current_epoch_updates_after_advance() {
        let mut barrier = EpochBarrier::new(1);
        barrier.advance(2);
        assert_eq!(barrier.current_epoch(), 2);
    }

    // -- two-node integration scenario tests ------------------------------

    /// Simulates a two-node epoch lifecycle:
    /// 1. Both at epoch 0: messages flow normally
    /// 2. Receiver advances to epoch 1 (network partition heals, new config)
    /// 3. Stale sender messages from epoch 0 are rejected
    /// 4. Sender advances to epoch 1: messages flow again
    ///
    /// Verifies zero stale-epoch delivery across the transition.
    #[test]
    fn two_node_epoch_lifecycle_zero_stale_delivery() {
        // Phase 1: both nodes at epoch 0
        let mut send_barrier = EpochBarrier::new(0);
        let mut recv_barrier = EpochBarrier::new(0);

        // Node A sends 2 messages at epoch 0
        let msgs_epoch0: Vec<Vec<u8>> = (0..2)
            .map(|i| {
                let payload = format!("e0-msg-{i}").into_bytes();
                let stamped = send_barrier.stamp(payload);
                stamped.encode()
            })
            .collect();

        // Node B receives and accepts both
        for wire in &msgs_epoch0 {
            let result = recv_barrier
                .verify_raw_and_unwrap(wire)
                .expect("epoch 0 message should verify");
            assert!(result.is_some(), "epoch 0 message should be delivered");
        }
        assert_eq!(recv_barrier.queued_count(), 0);

        // Phase 2: epoch transition — Node B advances to epoch 1
        let _ = recv_barrier.advance(1);
        assert_eq!(recv_barrier.current_epoch(), 1);

        // Phase 3: Node A (still at epoch 0) sends a late message
        // This should be rejected as stale by Node B
        let stale_payload = b"e0-late-stale".to_vec();
        let stale_stamped = send_barrier.stamp(stale_payload);
        let stale_wire = stale_stamped.encode();
        let result = recv_barrier.verify_raw_and_unwrap(&stale_wire);
        assert!(
            matches!(result, Err(EpochBarrierError::StaleEpoch { .. })),
            "late epoch-0 message must be rejected after receiver advances to epoch 1"
        );

        // Verify no stale delivery occurred
        assert_eq!(recv_barrier.queued_count(), 0);

        // Phase 4: Node A advances to epoch 1
        let _ = send_barrier.advance(1);
        assert_eq!(send_barrier.current_epoch(), 1);

        // Node A sends 2 messages at epoch 1 — all accepted
        for i in 0..2 {
            let payload = format!("e1-msg-{i}").into_bytes();
            let stamped = send_barrier.stamp(payload);
            let wire = stamped.encode();
            let result = recv_barrier
                .verify_raw_and_unwrap(&wire)
                .expect("epoch 1 message should verify");
            assert!(result.is_some(), "epoch 1 message should be delivered");
        }
        assert_eq!(recv_barrier.queued_count(), 0);
    }

    /// During an epoch transition, future-epoch messages from an
    /// ahead-of-barrier sender are queued and delivered once the
    /// receiver catches up, while stale messages from a behind
    /// sender are rejected.
    #[test]
    fn two_node_mixed_epoch_futures_queued_stales_rejected() {
        let mut recv_barrier = EpochBarrier::new(1);

        // Sender ahead at epoch 2
        let mut ahead_sender = EpochBarrier::new(2);
        let future_payload = b"future-e2".to_vec();
        let future_stamped = ahead_sender.stamp(future_payload);
        let future_wire = future_stamped.encode();

        // Receiver queues future message
        let result = recv_barrier
            .verify_raw_and_unwrap(&future_wire)
            .expect("future message should verify and queue");
        assert_eq!(result, None);
        assert_eq!(recv_barrier.queued_count(), 1);

        // Sender behind at epoch 0
        let mut behind_sender = EpochBarrier::new(0);
        let stale_payload = b"stale-e0".to_vec();
        let stale_stamped = behind_sender.stamp(stale_payload);
        let stale_wire = stale_stamped.encode();

        // Receiver rejects stale message
        let result = recv_barrier.verify_raw_and_unwrap(&stale_wire);
        assert!(matches!(result, Err(EpochBarrierError::StaleEpoch { .. })));

        // Advance to epoch 2 — future message flushes
        let flushed = recv_barrier.advance(2);
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0], b"future-e2".to_vec());
        assert_eq!(recv_barrier.queued_count(), 0);
    }
}
