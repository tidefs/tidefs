// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::types::HlcTimestamp;

pub use tidefs_types_transport_session::LaneClass;

// ---------------------------------------------------------------------------
// LaneDemux: 5-lane multiplexer
// ---------------------------------------------------------------------------

/// Multiplexes 5 lane classes over a single TCP connection.
/// Each lane has independent read/write queues and backpressure.
/// Control lane messages are always sent before Background lane messages.
pub struct LaneDemux {
    /// Per-lane write queues (messages waiting to be sent)
    write_queues: [VecDeque<Vec<u8>>; LaneClass::COUNT],

    /// Per-lane write sequence numbers
    write_sequences: [u64; LaneClass::COUNT],

    /// Per-lane backpressure state
    backpressure: [LaneBackpressure; LaneClass::COUNT],

    /// Per-lane read buffers (for reassembling received messages)
    read_buffers: [Vec<u8>; LaneClass::COUNT],

    /// Total bytes in write queues (for global backpressure)
    total_queued_bytes: AtomicUsize,
}

impl LaneDemux {
    #[must_use]
    /// Create a new empty lane demux with default per-lane queues.
    pub fn new() -> Self {
        const QUEUE: VecDeque<Vec<u8>> = VecDeque::new();
        const SEQ: u64 = 0;
        const BP: LaneBackpressure = LaneBackpressure::new();
        const BUF: Vec<u8> = Vec::new();

        Self {
            write_queues: [QUEUE; LaneClass::COUNT],
            write_sequences: [SEQ; LaneClass::COUNT],
            backpressure: [BP; LaneClass::COUNT],
            read_buffers: [BUF; LaneClass::COUNT],
            total_queued_bytes: AtomicUsize::new(0),
        }
    }

    /// Write a message to a lane.
    /// Returns `Paused` if the lane's write queue exceeds the high-water mark.
    #[must_use]
    pub fn write(&mut self, lane: LaneClass, message: Vec<u8>) -> WriteResult {
        let idx = lane.as_usize();
        let msg_len = message.len();

        // Check if lane is paused
        if self.backpressure[idx].paused {
            return WriteResult::Paused {
                lane,
                queued_bytes: self.write_queues[idx].iter().map(|m| m.len()).sum(),
            };
        }

        self.write_queues[idx].push_back(message);
        self.total_queued_bytes
            .fetch_add(msg_len, Ordering::Relaxed);

        // Check high-water mark after enqueue
        let queued = self.write_queues[idx]
            .iter()
            .map(|m| m.len())
            .sum::<usize>();
        if queued > self.backpressure[idx].high_watermark {
            self.backpressure[idx].paused = true;
            self.backpressure[idx].paused_since = Some(HlcTimestamp::default());
            return WriteResult::Paused {
                lane,
                queued_bytes: queued,
            };
        }

        WriteResult::Queued
    }

    /// Read the next message to send on the wire.
    /// Selects the highest-priority non-empty, non-paused lane.
    #[must_use]
    pub fn next_to_send(&mut self) -> Option<(LaneClass, Vec<u8>)> {
        for lane in LaneClass::all() {
            let idx = lane.as_usize();
            // Skip paused lanes
            if self.backpressure[idx].paused {
                continue;
            }
            if let Some(msg) = self.write_queues[idx].pop_front() {
                let msg_len = msg.len();
                self.total_queued_bytes
                    .fetch_sub(msg_len, Ordering::Relaxed);
                self.write_sequences[idx] += 1;
                return Some((lane, msg));
            }
        }
        None
    }

    /// Received bytes from the wire — classify by lane and buffer.
    pub fn receive(&mut self, lane: LaneClass, data: &[u8]) {
        let idx = lane.as_usize();
        self.read_buffers[idx].extend_from_slice(data);
    }

    /// Drain the read buffer for a lane and return all available complete messages.
    /// Returns empty vec if no complete message is available.
    #[must_use]
    pub fn drain_read(&mut self, lane: LaneClass) -> Vec<u8> {
        let idx = lane.as_usize();
        std::mem::take(&mut self.read_buffers[idx])
    }

    /// Lane is drained below low-water — resume sending.
    pub fn resume(&mut self, lane: LaneClass) {
        let idx = lane.as_usize();
        self.backpressure[idx].paused = false;
        self.backpressure[idx].paused_since = None;
    }

    /// Check if all lanes are paused — signal global backpressure to sender.
    #[must_use]
    pub fn all_paused(&self) -> bool {
        self.backpressure.iter().all(|bp| bp.paused)
    }

    /// Total bytes across all write queues.
    #[must_use]
    pub fn total_queued_bytes(&self) -> usize {
        self.total_queued_bytes.load(Ordering::Relaxed)
    }

    /// Check if any messages are queued for sending.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.write_queues.iter().any(|q| !q.is_empty())
    }

    /// Get the per-lane write sequence number.
    #[must_use]
    pub fn write_sequence(&self, lane: LaneClass) -> u64 {
        self.write_sequences[lane.as_usize()]
    }

    /// Get backpressure state for a lane.
    #[must_use]
    pub fn is_paused(&self, lane: LaneClass) -> bool {
        self.backpressure[lane.as_usize()].paused
    }
}

impl Default for LaneDemux {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Lane backpressure
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
/// Per-lane backpressure state with high/low water marks.
pub struct LaneBackpressure {
    /// High-water mark: pause sending on this lane
    pub high_watermark: usize,
    /// Low-water mark: resume sending on this lane
    pub low_watermark: usize,
    /// Is this lane currently paused?
    pub paused: bool,
    /// Paused since (for diagnostics)
    pub paused_since: Option<HlcTimestamp>,
}

impl LaneBackpressure {
    /// Default watermarks: 16MB high, 4MB low.
    pub const fn new() -> Self {
        Self {
            high_watermark: 16 * 1024 * 1024,
            low_watermark: 4 * 1024 * 1024,
            paused: false,
            paused_since: None,
        }
    }

    /// Custom watermarks for specific lane needs.
    #[must_use]
    pub const fn with_watermarks(high_watermark: usize, low_watermark: usize) -> Self {
        Self {
            high_watermark,
            low_watermark,
            paused: false,
            paused_since: None,
        }
    }
}

impl Default for LaneBackpressure {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// WriteResult
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
/// Result of writing a message to a lane through the demux.
pub enum WriteResult {
    /// Message queued successfully.
    Queued,
    /// Lane is paused due to backpressure.
    Paused {
        lane: LaneClass,
        queued_bytes: usize,
    },
}
