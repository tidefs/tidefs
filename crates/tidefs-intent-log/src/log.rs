//! High-level intent log with bounded ring buffer, backpressure, commit,
//! and replay.
//!
//! [`IntentLog`] wraps the low-level [`IntentLogBuffer`] and adds:
//! - Configurable maximum record count for bounded memory use
//! - Backpressure: `append()` blocks when the ring buffer is full
//! - `commit()`: drain all pending frames, serialize to a log-segment byte
//!   vector, and return the log sequence number (LSN)
//! - `replay()`: deserialize frames from a log-segment byte vector, returning
//!   only records with sequence numbers greater than a given LSN
//! - [`IntentLogStats`]: counters for records appended, bytes logged, commits,
//!   replays, and backpressure events
//!
//! The on-disk log segment format is a concatenation of encoded
//! [`IntentLogFrame`]s, each prefixed by a 4-byte little-endian length.
//! This is the format written by `commit()` and consumed by `replay()`.

use std::sync::{Condvar, Mutex};

use crate::buffer::IntentLogBuffer;
use crate::{IntentLogFrame, IntentLogRecord};

// ── IntentLogStats ────────────────────────────────────────────────────

/// Cumulative statistics for intent-log operations.
///
/// All counters are monotonic. Use `snapshot()` to read a point-in-time
/// copy; use `merge()` to accumulate stats from multiple sources (e.g.,
/// after replay).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IntentLogStats {
    /// Total number of records appended.
    pub records_appended: u64,
    /// Total bytes of log-segment data produced by `commit()`.
    pub bytes_logged: u64,
    /// Number of successful `commit()` calls.
    pub commits: u64,
    /// Number of successful `replay()` calls.
    pub replays: u64,
    /// Number of times `append()` blocked because the ring buffer was full.
    pub log_full_backpressure_events: u64,
}

// ── IntentLog ─────────────────────────────────────────────────────────

/// A bounded in-memory intent log for sync-write fast-path recording.
///
/// `IntentLog` is the primary API for FUSE dispatch threads to record
/// mutating operations before they commit. It provides:
///
/// - **Bounded ring buffer**: cannot grow beyond `max_records` entries.
///   When full, `append()` blocks until a `commit()` drains frames.
/// - **Commit**: serializes all pending frames into a log-segment byte
///   vector for the CommitGroupCoordinator to write to stable storage.
/// - **Replay**: deserializes a previously committed log segment and
///   returns frames newer than a given LSN for crash recovery.
///
/// # Thread Safety
///
/// `IntentLog` is `Send + Sync`. Multiple writer threads may call
/// `append()` concurrently. `commit()` and `replay()` are typically
/// called from a single coordinator thread.
///
/// # Example
///
/// ```ignore
/// let log = IntentLog::new(1024);
/// log.append(IntentLogRecord::Write { ino: 1, offset: 0, data_hash: [0; 32] }, 1);
/// let (segment, lsn) = log.commit(1);
/// // ... write segment to disk ...
/// let frames = log.replay(&segment, lsn);
/// ```
pub struct IntentLog {
    /// Underlying append buffer.
    buffer: IntentLogBuffer,
    /// Maximum number of records allowed in the buffer at once.
    max_records: usize,
    /// Condition variable for backpressure: appenders wait here when full;
    /// `commit()` notifies all.
    backpressure: Condvar,
    /// Mutex guarding backpressure wait + stats update.
    /// This is separate from the buffer's internal mutex to avoid deadlock.
    state: Mutex<IntentLogState>,
    /// Statistics counters.
    stats: Mutex<IntentLogStats>,
}

/// Internal state tracking (separate from buffer storage).
struct IntentLogState {
    /// Number of appenders currently blocked on backpressure.
    blocked_writers: u64,
}

impl IntentLog {
    /// Create a new intent log with room for at most `max_records` records.
    ///
    /// # Panics
    ///
    /// Panics if `max_records` is 0.
    pub fn new(max_records: usize) -> Self {
        assert!(max_records > 0, "IntentLog max_records must be > 0");
        Self {
            buffer: IntentLogBuffer::new(),
            max_records,
            backpressure: Condvar::new(),
            state: Mutex::new(IntentLogState { blocked_writers: 0 }),
            stats: Mutex::new(IntentLogStats::default()),
        }
    }

    /// Append a record to the intent log.
    ///
    /// Returns the authenticated [`IntentLogFrame`] for the record.
    ///
    /// If the buffer has reached `max_records`, this call **blocks** the
    /// current thread until a subsequent `commit()` drains frames and frees
    /// space. The [`IntentLogStats::log_full_backpressure_events`] counter
    /// is incremented each time a writer blocks.
    pub fn append(&self, record: IntentLogRecord, txg_id: u64) -> IntentLogFrame {
        loop {
            // Check capacity before appending
            {
                let len = self.buffer.len();
                if len < self.max_records {
                    // Space available: append and return
                    let frame = self.buffer.append(record.clone(), txg_id);
                    self.stats.lock().unwrap().records_appended += 1;
                    return frame;
                }
            }

            // Buffer is full: record backpressure and wait
            {
                let mut state = self.state.lock().unwrap();
                self.stats.lock().unwrap().log_full_backpressure_events += 1;
                state.blocked_writers += 1;
                // Wait for commit() to drain and notify
                let _guard = self.backpressure.wait(state).unwrap();
                // When woken, loop back to retry the append
            }
        }
    }

    /// Try to append a record without blocking.
    ///
    /// Returns `Ok(frame)` on success, or `Err(record)` if the buffer is full.
    /// The returned record is the original (cloned) record for retry.
    pub fn try_append(
        &self,
        record: IntentLogRecord,
        txg_id: u64,
    ) -> Result<IntentLogFrame, IntentLogRecord> {
        if self.buffer.len() >= self.max_records {
            return Err(record);
        }
        let frame = self.buffer.append(record, txg_id);
        self.stats.lock().unwrap().records_appended += 1;
        Ok(frame)
    }

    /// Commit all pending records to a log segment.
    ///
    /// Drains all frames from the buffer, serializes them into a log-segment
    /// byte vector, and returns the segment plus the LSN (log sequence number).
    ///
    /// The LSN is the highest `record_seq` in the segment + 1, i.e., the next
    /// sequence number that would be assigned after this commit. An empty
    /// commit returns the current next_seq as LSN.
    ///
    /// After draining, notifies all threads blocked in `append()`.
    pub fn commit(&self, _txg_id: u64) -> (Vec<u8>, u64) {
        let frames = self.buffer.drain_since(0);

        if frames.is_empty() {
            let lsn = self.buffer.current_seq();
            self.stats.lock().unwrap().commits += 1;
            self.backpressure.notify_all();
            return (Vec::new(), lsn);
        }

        // Compute LSN as the highest seq + 1
        let max_seq = frames.iter().map(|f| f.record_seq).max().unwrap_or(0);
        let lsn = max_seq + 1;

        // Serialize: length-prefixed frames
        let mut segment = Vec::new();
        for frame in &frames {
            let encoded = frame.encode();
            segment.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            segment.extend_from_slice(&encoded);
        }

        let bytes_logged = segment.len() as u64;

        // Update stats (outside the buffer lock)
        {
            let mut stats = self.stats.lock().unwrap();
            stats.commits += 1;
            stats.bytes_logged += bytes_logged;
        }

        // Notify blocked appenders
        self.backpressure.notify_all();

        (segment, lsn)
    }

    /// Replay a previously committed log segment.
    ///
    /// Deserializes frames from `segment_bytes` and returns only those with
    /// `record_seq >= lsn`. Frames with `record_seq < lsn` are skipped (they
    /// were already durably committed in a prior transaction group).
    ///
    /// The returned frames have been verified (BLAKE3 checksum validated).
    ///
    /// # Errors
    ///
    /// Returns [`crate::IntentLogError`] if the segment is corrupt or
    /// truncated.
    pub fn replay(
        &self,
        segment_bytes: &[u8],
        lsn: u64,
    ) -> Result<Vec<IntentLogFrame>, crate::IntentLogError> {
        let mut frames = Vec::new();
        let mut pos = 0;

        while pos + 4 <= segment_bytes.len() {
            let frame_len =
                u32::from_le_bytes(segment_bytes[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + frame_len > segment_bytes.len() {
                return Err(crate::IntentLogError::BufferTooShort);
            }
            let frame = IntentLogFrame::decode(&segment_bytes[pos..pos + frame_len])?;
            pos += frame_len;

            if frame.record_seq >= lsn {
                frames.push(frame);
            }
        }

        self.stats.lock().unwrap().replays += 1;
        Ok(frames)
    }

    /// Return a snapshot of the current statistics.
    pub fn stats(&self) -> IntentLogStats {
        *self.stats.lock().unwrap()
    }

    /// Return the number of records currently buffered.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Return true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Return the current (next-to-be-assigned) sequence number.
    pub fn current_seq(&self) -> u64 {
        self.buffer.current_seq()
    }

    /// Return the configured maximum record count.
    pub fn max_records(&self) -> usize {
        self.max_records
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IntentLogRecord;

    // ── append / commit / replay round-trip ────────────────────────

    #[test]
    fn commit_replay_roundtrip_single_record() {
        let log = IntentLog::new(16);
        let rec = IntentLogRecord::Create {
            parent: 1,
            name: b"hello.txt".to_vec(),
            mode: 0o644,
            ino: 42,
        };
        log.append(rec.clone(), 1);

        let (segment, lsn) = log.commit(1);
        assert!(!segment.is_empty());
        assert_eq!(lsn, 1); // seq 0 produced, so LSN = 1

        // Replay the segment
        let frames = log.replay(&segment, 0).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].record, rec);
        assert_eq!(frames[0].txg_id, 1);
        assert!(frames[0].verify().is_ok());
    }

    #[test]
    fn commit_replay_multiple_record_types() {
        let log = IntentLog::new(64);
        let records: Vec<IntentLogRecord> = vec![
            IntentLogRecord::Write {
                ino: 1,
                offset: 0,
                length: 0,
                data_hash: [0xAA; 32],
            },
            IntentLogRecord::Truncate {
                ino: 1,
                new_size: 4096,
            },
            IntentLogRecord::Mkdir {
                parent: 1,
                name: b"subdir".to_vec(),
                mode: 0o755,
                ino: 10,
            },
            IntentLogRecord::Symlink {
                parent: 1,
                name: b"link".to_vec(),
                target: b"/etc/hosts".to_vec(),
                ino: 11,
            },
            IntentLogRecord::Rename {
                src_parent: 1,
                src_name: b"old".to_vec(),
                dst_parent: 2,
                dst_name: b"new".to_vec(),
                overwrite_target_ino: None,
                ino: 5,
                rename_flags: 0,
            },
        ];

        for rec in &records {
            log.append(rec.clone(), 7);
        }

        let (segment, lsn) = log.commit(7);
        assert_eq!(lsn, records.len() as u64);

        let frames = log.replay(&segment, 0).unwrap();
        assert_eq!(frames.len(), records.len());
        for (i, rec) in records.iter().enumerate() {
            assert_eq!(frames[i].record, *rec);
            assert_eq!(frames[i].txg_id, 7);
            assert_eq!(frames[i].record_seq, i as u64);
        }
    }

    // ── LSN filtering in replay ────────────────────────────────────

    #[test]
    fn replay_respects_lsn() {
        let log = IntentLog::new(16);
        for i in 0..5 {
            log.append(
                IntentLogRecord::Truncate {
                    ino: i,
                    new_size: 100,
                },
                1,
            );
        }

        let (segment, _lsn) = log.commit(1);

        // Replay with lsn=3: only frames with seq >= 3 (seqs 3,4)
        let frames = log.replay(&segment, 3).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].record_seq, 3);
        assert_eq!(frames[1].record_seq, 4);
    }

    #[test]
    fn replay_with_lsn_past_all_frames_returns_empty() {
        let log = IntentLog::new(16);
        log.append(
            IntentLogRecord::Truncate {
                ino: 1,
                new_size: 0,
            },
            1,
        );
        let (segment, _lsn) = log.commit(1);

        let frames = log.replay(&segment, 999).unwrap();
        assert!(frames.is_empty());
    }

    // ── Empty commit / replay ──────────────────────────────────────

    #[test]
    fn empty_commit_returns_empty_segment() {
        let log = IntentLog::new(16);
        let (segment, lsn) = log.commit(1);
        assert!(segment.is_empty());
        assert_eq!(lsn, 0); // no records, current_seq is 0
    }

    #[test]
    fn replay_empty_segment_returns_empty() {
        let log = IntentLog::new(16);
        let frames = log.replay(&[], 0).unwrap();
        assert!(frames.is_empty());
    }

    // ── Backpressure ───────────────────────────────────────────────

    #[test]
    fn append_blocks_when_full() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let log = Arc::new(IntentLog::new(3));

        // Fill the buffer
        for i in 0..3 {
            log.append(
                IntentLogRecord::Truncate {
                    ino: i,
                    new_size: 100,
                },
                1,
            );
        }
        assert_eq!(log.len(), 3);

        // Start a writer that will block
        let log2 = Arc::clone(&log);
        let handle = thread::spawn(move || {
            log2.append(
                IntentLogRecord::Truncate {
                    ino: 99,
                    new_size: 0,
                },
                1,
            )
        });

        // Give the writer time to block
        thread::sleep(Duration::from_millis(50));

        // Verify backpressure counter incremented
        let stats = log.stats();
        assert!(
            stats.log_full_backpressure_events >= 1,
            "expected backpressure events, got {stats:?}"
        );

        // Drain to unblock
        log.commit(1);

        // Writer should now complete
        let frame = handle.join().unwrap();
        assert_eq!(frame.record_seq, 3);
    }

    #[test]
    fn try_append_rejects_when_full() {
        let log = IntentLog::new(2);
        log.append(
            IntentLogRecord::Truncate {
                ino: 1,
                new_size: 0,
            },
            1,
        );
        log.append(
            IntentLogRecord::Truncate {
                ino: 2,
                new_size: 0,
            },
            1,
        );

        let rec = IntentLogRecord::Truncate {
            ino: 3,
            new_size: 0,
        };
        let result = log.try_append(rec.clone(), 1);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), rec);
    }

    // ── Ring buffer wraparound ─────────────────────────────────────

    #[test]
    fn ring_buffer_wraparound() {
        let log = IntentLog::new(4);

        // Append 4 records (fill buffer)
        for i in 0..4 {
            log.append(
                IntentLogRecord::Truncate {
                    ino: i,
                    new_size: 100,
                },
                1,
            );
        }
        assert_eq!(log.len(), 4);

        // Commit and drain (frees all 4 slots)
        let (seg1, lsn1) = log.commit(1);
        assert_eq!(log.len(), 0);
        assert_eq!(lsn1, 4);

        // Append 4 more (reuses freed capacity — wraparound)
        for i in 4..8 {
            log.append(
                IntentLogRecord::Truncate {
                    ino: i,
                    new_size: 200,
                },
                2,
            );
        }
        assert_eq!(log.len(), 4);

        let (seg2, lsn2) = log.commit(2);
        assert_eq!(lsn2, 8);

        // Verify both segments replay correctly
        let frames1 = log.replay(&seg1, 0).unwrap();
        assert_eq!(frames1.len(), 4);
        assert_eq!(frames1[0].record_seq, 0);
        assert_eq!(frames1[3].record_seq, 3);

        let frames2 = log.replay(&seg2, 4).unwrap();
        assert_eq!(frames2.len(), 4);
        assert_eq!(frames2[0].record_seq, 4);
        assert_eq!(frames2[3].record_seq, 7);
    }

    // ── LSN monotonicity ───────────────────────────────────────────

    #[test]
    fn lsn_is_monotonic() {
        let log = IntentLog::new(16);
        let mut prev_lsn = 0u64;

        for round in 0..5 {
            for i in 0..3 {
                log.append(
                    IntentLogRecord::Truncate {
                        ino: round * 10 + i,
                        new_size: 100,
                    },
                    round,
                );
            }
            let (_segment, lsn) = log.commit(round);
            assert!(
                lsn >= prev_lsn,
                "LSN not monotonic: {lsn} < {prev_lsn} at round {round}"
            );
            prev_lsn = lsn;
        }
        assert!(prev_lsn > 0);
    }

    // ── Stats ──────────────────────────────────────────────────────

    #[test]
    fn stats_track_all_counters() {
        let log = IntentLog::new(16);

        // Append 5 records
        for i in 0..5 {
            log.append(
                IntentLogRecord::Truncate {
                    ino: i,
                    new_size: 100,
                },
                1,
            );
        }

        // Commit
        let (segment, _lsn) = log.commit(1);

        // Replay
        log.replay(&segment, 0).unwrap();

        let stats = log.stats();
        assert_eq!(stats.records_appended, 5);
        assert!(stats.bytes_logged > 0);
        assert_eq!(stats.commits, 1);
        assert_eq!(stats.replays, 1);
    }

    // ── Concurrent append stress with backpressure ─────────────────

    #[test]
    fn concurrent_append_with_backpressure() {
        use std::sync::Arc;
        use std::sync::Barrier;
        use std::thread;

        let log = Arc::new(IntentLog::new(32));
        let n_threads = 4;
        let n_records = 200;
        let barrier = Arc::new(Barrier::new(n_threads + 1)); // +1 for drainer

        let mut handles = Vec::new();
        for t in 0..n_threads {
            let log = Arc::clone(&log);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait(); // synchronize start
                for i in 0..n_records {
                    let rec = IntentLogRecord::Truncate {
                        ino: (t * 10000 + i) as u64,
                        new_size: i as u64,
                    };
                    log.append(rec, 1);
                }
            }));
        }

        // Drainer thread
        let log_drain = Arc::clone(&log);
        let barrier_drain = Arc::clone(&barrier);
        let drainer = thread::spawn(move || {
            barrier_drain.wait();
            for _ in 0..((n_threads * n_records) / 16) {
                thread::sleep(std::time::Duration::from_micros(100));
                log_drain.commit(1);
            }
            // Final drain
            log_drain.commit(1);
        });

        for h in handles {
            h.join().unwrap();
        }
        drainer.join().unwrap();

        let total = n_threads * n_records;
        assert_eq!(log.stats().records_appended as usize, total);

        // Drain remaining and verify all frames are valid
        let (segment, _) = log.commit(1);
        if !segment.is_empty() {
            let frames = log.replay(&segment, 0).unwrap();
            for frame in &frames {
                assert!(frame.verify().is_ok());
            }
        }
    }

    // ── Corrupt segment detection ──────────────────────────────────

    #[test]
    fn replay_rejects_truncated_segment() {
        let log = IntentLog::new(16);
        log.append(
            IntentLogRecord::Write {
                ino: 1,
                offset: 0,
                length: 0,
                data_hash: [0xAB; 32],
            },
            1,
        );
        let (mut segment, _lsn) = log.commit(1);

        // Truncate in the middle of a frame
        segment.truncate(segment.len() - 1);
        assert!(log.replay(&segment, 0).is_err());
    }

    #[test]
    fn replay_rejects_corrupt_frame_in_segment() {
        let log = IntentLog::new(16);
        log.append(
            IntentLogRecord::Truncate {
                ino: 1,
                new_size: 100,
            },
            1,
        );
        let (mut segment, _lsn) = log.commit(1);

        // Corrupt a byte in the frame payload
        if segment.len() > 10 {
            segment[10] ^= 0xFF;
        }
        assert!(log.replay(&segment, 0).is_err());
    }

    // ── Partial commit ─────────────────────────────────────────────

    #[test]
    fn partial_commit_drains_exact_written_records() {
        let log = IntentLog::new(16);

        // Append 3 records
        for i in 0..3 {
            log.append(
                IntentLogRecord::Truncate {
                    ino: i,
                    new_size: 100,
                },
                1,
            );
        }
        let (seg1, lsn1) = log.commit(1);
        assert_eq!(lsn1, 3);
        assert_eq!(log.len(), 0);

        // Append 2 more
        for i in 3..5 {
            log.append(
                IntentLogRecord::Truncate {
                    ino: i,
                    new_size: 200,
                },
                2,
            );
        }
        let (seg2, lsn2) = log.commit(2);
        assert_eq!(lsn2, 5);

        // Replay seg1: frames 0,1,2
        let r1 = log.replay(&seg1, 0).unwrap();
        assert_eq!(r1.len(), 3);
        assert_eq!(r1[0].record_seq, 0);
        assert_eq!(r1[2].record_seq, 2);

        // Replay seg2: frames 3,4
        let r2 = log.replay(&seg2, 3).unwrap();
        assert_eq!(r2.len(), 2);
        assert_eq!(r2[0].record_seq, 3);
        assert_eq!(r2[1].record_seq, 4);
    }

    #[test]
    fn max_records_zero_panics() {
        let result = std::panic::catch_unwind(|| {
            IntentLog::new(0);
        });
        assert!(result.is_err());
    }
}
