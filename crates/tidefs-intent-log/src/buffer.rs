// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Lock-free in-memory intent-log append buffer.
//!
//! [`IntentLogBuffer`] provides a concurrent append interface for recording
//! mutating filesystem operations. It uses an atomic sequence counter for
//! ordering and a mutex-protected vector for storage. The
//! [`CommitGroupCoordinator`] drains frames during two-phase commit preparation.
//!
//! # Concurrency
//!
//! - `append()`: lock-free sequence acquisition (atomic increment), mutex
//!   for storage push. Multiple writers can append concurrently.
//! - `drain_since(seq)`: acquires the storage mutex, splits off frames with
//!   `record_seq >= seq`, and returns them.
//! - `current_seq()`: lock-free atomic read.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::{IntentLogFrame, IntentLogRecord};

/// A lock-free MPSC append buffer for intent-log records.
///
/// Writers call [`append`](Self::append) from FUSE dispatch threads. The
/// [`CommitGroupCoordinator`] calls [`drain_since`](Self::drain_since) to collect
/// all records since the last drain point and anchor them into the two-phase
/// commit pipeline.
///
/// # Example
///
/// ```ignore
/// let buf = IntentLogBuffer::new();
/// let frame = buf.append(IntentLogRecord::Write { ino: 42, offset: 0, data_hash: [0; 32] }, 1);
/// assert_eq!(buf.current_seq(), 1);
/// let frames = buf.drain_since(0);
/// assert_eq!(frames.len(), 1);
/// ```
#[derive(Debug)]
pub struct IntentLogBuffer {
    /// Monotonically increasing sequence number (next value to assign).
    next_seq: AtomicU64,
    /// Stored frames in append order.
    frames: Mutex<Vec<IntentLogFrame>>,
    /// Associated write payloads keyed by record_seq.
    /// Large writes store data here so the TxgCoordinator can persist
    /// it alongside frames during two-phase commit.
    data_map: Mutex<HashMap<u64, Vec<u8>>>,
}

impl IntentLogBuffer {
    /// Create an empty buffer with sequence number starting at 0.
    pub fn new() -> Self {
        Self {
            next_seq: AtomicU64::new(0),
            frames: Mutex::new(Vec::new()),
            data_map: Mutex::new(HashMap::new()),
        }
    }

    /// Append a record and return its authenticated frame.
    ///
    /// The record is assigned the next available sequence number, wrapped
    /// in an [`IntentLogFrame`] with the given `txg_id`, and stored.
    /// Returns the frame (which includes the computed BLAKE3 checksum).
    pub fn append(&self, record: IntentLogRecord, txg_id: u64) -> IntentLogFrame {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let frame = IntentLogFrame::new(record, txg_id, seq);
        let mut frames = self.frames.lock().unwrap();
        frames.push(frame.clone());
        frame
    }

    /// Append a record with an associated data payload and return its
    /// authenticated frame.
    ///
    /// The record is assigned the next sequence number and stored like
    /// [`append`](Self::append). Additionally, `data` is stored in the
    /// buffer keyed by the assigned `record_seq`. The caller (typically
    /// the TxgCoordinator) drains both frames and data together via
    /// [`drain_with_data_since`](Self::drain_with_data_since).
    ///
    /// This is used for large buffered writes where the data is too large
    /// to embed inline in a [`BufferedWrite`](crate::IntentLogRecord::BufferedWrite)
    /// record. The data is stored alongside the frame so crash replay can
    /// recover the written bytes.
    pub fn append_with_data(
        &self,
        record: IntentLogRecord,
        txg_id: u64,
        data: Vec<u8>,
    ) -> IntentLogFrame {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let frame = IntentLogFrame::new(record, txg_id, seq);
        let mut frames = self.frames.lock().unwrap();
        frames.push(frame.clone());
        self.data_map.lock().unwrap().insert(seq, data);
        frame
    }

    /// Take the data payload associated with `record_seq`, removing it
    /// from the buffer.
    ///
    /// Returns `None` if no data was stored for this sequence number.
    pub fn take_data(&self, record_seq: u64) -> Option<Vec<u8>> {
        self.data_map.lock().unwrap().remove(&record_seq)
    }

    /// Drain all frames and their associated data payloads with
    /// `record_seq >= since_seq`.
    ///
    /// Returns a tuple of `(frames, data_map)` where `data_map` maps
    /// `record_seq` to the stored data payload. Both frames and data are
    /// removed from the buffer.
    pub fn drain_with_data_since(
        &self,
        since_seq: u64,
    ) -> (Vec<IntentLogFrame>, HashMap<u64, Vec<u8>>) {
        let mut frames = self.frames.lock().unwrap();
        let mut data_map = self.data_map.lock().unwrap();
        if frames.is_empty() {
            return (Vec::new(), HashMap::new());
        }
        let split_idx = frames.partition_point(|f| f.record_seq < since_seq);
        if split_idx >= frames.len() {
            return (Vec::new(), HashMap::new());
        }
        let drained_frames: Vec<IntentLogFrame> = frames.drain(split_idx..).collect();
        let mut drained_data = HashMap::new();
        for frame in &drained_frames {
            if let Some(data) = data_map.remove(&frame.record_seq) {
                drained_data.insert(frame.record_seq, data);
            }
        }
        (drained_frames, drained_data)
    }

    /// Return the number of stored data payloads (lock-protected).
    pub fn data_count(&self) -> usize {
        self.data_map.lock().unwrap().len()
    }

    /// Drain all frames with `record_seq >= since_seq`.
    ///
    /// The returned frames are removed from the buffer. The caller (typically
    /// the [`CommitGroupCoordinator`]) is responsible for anchoring them into the
    /// commit pipeline.
    ///
    /// `since_seq` is inclusive: frames with `record_seq >= since_seq` are
    /// drained. Frames with `record_seq < since_seq` are retained. Pass 0 to
    /// drain all frames.
    pub fn drain_since(&self, since_seq: u64) -> Vec<IntentLogFrame> {
        let mut frames = self.frames.lock().unwrap();
        if frames.is_empty() {
            return Vec::new();
        }
        // Find first frame with record_seq >= since_seq
        let split_idx = frames.partition_point(|f| f.record_seq < since_seq);
        if split_idx >= frames.len() {
            return Vec::new();
        }
        frames.drain(split_idx..).collect()
    }

    /// Return the current (next-to-be-assigned) sequence number.
    ///
    /// This is a lock-free read. After `n` successful appends, `current_seq()`
    /// returns `n`.
    pub fn current_seq(&self) -> u64 {
        self.next_seq.load(Ordering::SeqCst)
    }

    /// Return the number of buffered frames (lock-protected).
    pub fn len(&self) -> usize {
        self.frames.lock().unwrap().len()
    }

    /// Return true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for IntentLogBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IntentLogRecord;

    #[test]
    fn new_buffer_starts_empty() {
        let buf = IntentLogBuffer::new();
        assert_eq!(buf.current_seq(), 0);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn drain_empty_returns_empty() {
        let buf = IntentLogBuffer::new();
        assert!(buf.drain_since(0).is_empty());
    }

    #[test]
    fn drain_preserves_frames_before_since() {
        let buf = IntentLogBuffer::new();
        for i in 0..5 {
            buf.append(
                IntentLogRecord::Truncate {
                    ino: i,
                    new_size: 100,
                },
                1,
            );
        }
        // drain from seq 2 (seqs 0,1 kept; 2,3,4 drained)
        let drained = buf.drain_since(2);
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].record_seq, 2);
        assert_eq!(drained[2].record_seq, 4);

        // buffer should still contain seqs 0,1 (2 frames)
        assert_eq!(buf.len(), 2);
        // draining from seq 0 returns both remaining
        let remaining = buf.drain_since(0);
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].record_seq, 0);
        assert_eq!(remaining[1].record_seq, 1);
        assert!(buf.is_empty());
    }

    #[test]
    fn drain_since_high_seq_returns_empty() {
        let buf = IntentLogBuffer::new();
        buf.append(
            IntentLogRecord::Truncate {
                ino: 1,
                new_size: 0,
            },
            1,
        );
        let drained = buf.drain_since(100);
        assert!(drained.is_empty());
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn append_returns_correct_seq() {
        let buf = IntentLogBuffer::new();
        let f0 = buf.append(
            IntentLogRecord::Truncate {
                ino: 1,
                new_size: 0,
            },
            1,
        );
        assert_eq!(f0.record_seq, 0);
        let f1 = buf.append(
            IntentLogRecord::Truncate {
                ino: 2,
                new_size: 10,
            },
            1,
        );
        assert_eq!(f1.record_seq, 1);
    }

    // ── append_with_data / drain_with_data_since tests ─────────────

    #[test]
    fn append_with_data_stores_payload() {
        let buf = IntentLogBuffer::new();
        let rec = IntentLogRecord::Write {
            ino: 1,
            offset: 0,
            length: 4,
            data_hash: [0xAB; 32],
        };
        let payload = b"data".to_vec();
        let frame = buf.append_with_data(rec, 1, payload.clone());
        assert_eq!(frame.record_seq, 0);

        let stored = buf.take_data(0).expect("data should be stored");
        assert_eq!(stored, payload);
        assert_eq!(buf.data_count(), 0); // taken
    }

    #[test]
    fn take_data_unknown_seq_returns_none() {
        let buf = IntentLogBuffer::new();
        assert!(buf.take_data(999).is_none());
    }

    #[test]
    fn drain_with_data_returns_both_frames_and_data() {
        let buf = IntentLogBuffer::new();
        let r1 = IntentLogRecord::Write {
            ino: 1,
            offset: 0,
            length: 3,
            data_hash: [0x11; 32],
        };
        let r2 = IntentLogRecord::BufferedWrite {
            ino: 2,
            offset: 0,
            length: 5,
            data: b"hello".to_vec(),
        };
        buf.append_with_data(r1, 1, b"foo".to_vec());
        buf.append_with_data(r2, 1, b"hello".to_vec());

        let (frames, data_map) = buf.drain_with_data_since(0);
        assert_eq!(frames.len(), 2);
        assert_eq!(data_map.len(), 2);
        assert_eq!(data_map.get(&0).unwrap(), b"foo");
        assert_eq!(data_map.get(&1).unwrap(), b"hello");
        assert!(buf.is_empty());
        assert_eq!(buf.data_count(), 0);
    }

    #[test]
    fn drain_with_data_respects_since_seq() {
        let buf = IntentLogBuffer::new();
        for i in 0..4 {
            let rec = IntentLogRecord::Write {
                ino: i,
                offset: 0,
                length: 1,
                data_hash: [0; 32],
            };
            buf.append_with_data(rec, 1, vec![i as u8]);
        }

        // Drain from seq 2 (keep 0,1; drain 2,3)
        let (frames, data_map) = buf.drain_with_data_since(2);
        assert_eq!(frames.len(), 2);
        assert_eq!(data_map.len(), 2);
        assert_eq!(frames[0].record_seq, 2);
        assert_eq!(frames[1].record_seq, 3);

        // Remaining: seqs 0,1
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.data_count(), 2);

        let (remaining, remaining_data) = buf.drain_with_data_since(0);
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining_data.len(), 2);
        assert!(buf.is_empty());
        assert_eq!(buf.data_count(), 0);
    }

    #[test]
    fn drain_with_data_empty_returns_empty() {
        let buf = IntentLogBuffer::new();
        let (frames, data_map) = buf.drain_with_data_since(0);
        assert!(frames.is_empty());
        assert!(data_map.is_empty());
    }

    #[test]
    fn data_count_tracks_stored_payloads() {
        let buf = IntentLogBuffer::new();
        assert_eq!(buf.data_count(), 0);
        buf.append_with_data(
            IntentLogRecord::Write {
                ino: 1,
                offset: 0,
                length: 2,
                data_hash: [0; 32],
            },
            1,
            b"ab".to_vec(),
        );
        assert_eq!(buf.data_count(), 1);
    }
}
