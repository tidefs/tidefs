// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

//! Intent-log replay idempotency crash matrix.
//!
//! Tests replay behavior under crash-injection: create segments, truncate
//! them at various points to simulate torn log tails, and verify that
//! fresh-engine re-replay over already-mutated durable state remains
//! idempotent.
//!
//! This module is gated behind the `intent-log-replay` feature.

use std::collections::BTreeMap;

use tidefs_intent_log::{
    IntentLogFrame, IntentLogRecord, IntentLogWriter, IntentReplayEngine, IntentReplayHandler,
};

// ── Test helpers ──────────────────────────────────────────────────────

/// A handler that collects record hashes for state-comparison.
#[derive(Debug, Default)]
struct CollectingHandler {
    records: Vec<IntentLogRecord>,
}

impl IntentReplayHandler for CollectingHandler {
    type Error = String;

    fn handle_record(&mut self, record: &IntentLogRecord) -> Result<(), String> {
        self.records.push(record.clone());
        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct DurableWriteState {
    writes: BTreeMap<(u64, u64, u64), [u8; 32]>,
}

#[allow(dead_code)]
#[derive(Debug, Default)]
struct DurableWriteHandler {
    state: DurableWriteState,
    dispatches: u64,
}

impl IntentReplayHandler for DurableWriteHandler {
    type Error = String;

    fn handle_record(&mut self, record: &IntentLogRecord) -> Result<(), String> {
        self.dispatches += 1;
        if let IntentLogRecord::Write {
            ino,
            offset,
            length,
            data_hash,
        } = record
        {
            self.state
                .writes
                .insert((*ino, *offset, *length), *data_hash);
        }
        Ok(())
    }
}

fn make_write_frame(seq: u64, ino: u64) -> IntentLogFrame {
    let rec = IntentLogRecord::Write {
        ino,
        offset: seq * 4096,
        length: 4096,
        data_hash: [0xAA; 32],
    };
    IntentLogFrame::new(rec, 1, seq)
}

fn make_segment(frames: &[IntentLogFrame]) -> Vec<u8> {
    let mut writer = IntentLogWriter::new(64 * 1024 * 1024);
    for f in frames {
        writer.append_frame(f).unwrap();
    }
    writer.finish().unwrap().unwrap()
}

/// Replay a segment and return the checkpoint digest.
fn replay_and_checkpoint(segment: &[u8], applied_txg: u64) -> [u8; 32] {
    let mut engine = IntentReplayEngine::new(applied_txg);
    let mut handler = CollectingHandler::default();
    engine.replay_segment(segment, &mut handler).unwrap();
    engine.compute_checkpoint().digest
}

// ── Crash matrix: segment-level crash-injection ───────────────────────

/// Crash matrix entry describing one crash-injection scenario.
#[derive(Clone, Debug)]
pub struct IntentLogCrashCase {
    /// Human-readable case identifier.
    pub id: String,
    /// Number of records in the segment.
    pub record_count: usize,
    /// Segment truncation applied before crash replay.
    pub truncation: Option<IntentLogTruncation>,
    /// Whether the clean-run and truncated-replay checkpoints should match.
    pub expect_clean_checkpoint_match: bool,
}

/// Where a crash-injection case truncates the encoded segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentLogTruncation {
    /// Truncate at an absolute byte offset.
    At(usize),
    /// Truncate this many bytes from the tail of the encoded segment.
    TailBytes(usize),
}

impl IntentLogCrashCase {
    fn truncate_segment(&self, segment: &mut Vec<u8>) {
        let Some(truncation) = self.truncation else {
            return;
        };

        let offset = match truncation {
            IntentLogTruncation::At(offset) => offset,
            IntentLogTruncation::TailBytes(bytes) => segment.len().saturating_sub(bytes),
        };
        if offset < segment.len() {
            segment.truncate(offset);
        }
    }

    /// Run this crash case and return whether the expected checkpoint relation held.
    pub fn run(&self) -> Result<bool, String> {
        let frames: Vec<_> = (0..self.record_count)
            .map(|i| make_write_frame(i as u64, 100 + i as u64))
            .collect();
        let mut segment = make_segment(&frames);

        // Clean replay checkpoint
        let clean_checkpoint = replay_and_checkpoint(&segment, 0);

        // Apply crash truncation
        self.truncate_segment(&mut segment);

        // Crash-replay checkpoint
        let crash_checkpoint = replay_and_checkpoint(&segment, 0);

        if self.expect_clean_checkpoint_match {
            Ok(clean_checkpoint == crash_checkpoint)
        } else {
            Ok(clean_checkpoint != crash_checkpoint)
        }
    }
}

/// Run the full intent-log replay crash matrix.
pub fn run_intent_log_crash_matrix() -> Vec<IntentLogCrashCase> {
    vec![
        // ── Crash at start of segment ────────────────────────────
        IntentLogCrashCase {
            id: "crash-at-start-header-only".into(),
            record_count: 5,
            truncation: Some(IntentLogTruncation::At(64)), // only header, no records
            expect_clean_checkpoint_match: false, // no records survived, so checkpoint differs
        },
        IntentLogCrashCase {
            id: "crash-after-one-record".into(),
            record_count: 5,
            truncation: Some(IntentLogTruncation::At(200)), // header + partial first record
            expect_clean_checkpoint_match: false,
        },
        // ── Crash mid-segment ────────────────────────────────────
        IntentLogCrashCase {
            id: "crash-mid-segment".into(),
            record_count: 8,
            truncation: Some(IntentLogTruncation::At(512)), // some records survive
            expect_clean_checkpoint_match: false,
        },
        // ── Crash near end (most records survive) ────────────────
        IntentLogCrashCase {
            id: "crash-near-end".into(),
            record_count: 10,
            truncation: Some(IntentLogTruncation::TailBytes(420)),
            expect_clean_checkpoint_match: false,
        },
        // ── Double-replay idempotency (no crash) ─────────────────
        IntentLogCrashCase {
            id: "double-replay-idempotent".into(),
            record_count: 5,
            truncation: None, // no truncation — test pure double-replay
            expect_clean_checkpoint_match: true,
        },
    ]
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_intent_log::replay::{SegmentReplayOutcome, SkippedReason};

    #[test]
    fn intent_log_crash_matrix_all_cases_run() {
        let cases = run_intent_log_crash_matrix();
        assert!(!cases.is_empty());

        for case in &cases {
            let result = case.run().unwrap_or_else(|e| panic!("{e}"));
            assert!(
                result,
                "case {}: expected clean_checkpoint_match={}",
                case.id, case.expect_clean_checkpoint_match
            );
        }
    }

    #[test]
    fn clean_replay_produces_consistent_checkpoint() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 200 + i)).collect();
        let segment = make_segment(&frames);

        let cp1 = replay_and_checkpoint(&segment, 0);
        let cp2 = replay_and_checkpoint(&segment, 0);
        assert_eq!(
            cp1, cp2,
            "identical replays must produce identical checkpoints"
        );
    }

    #[test]
    fn truncated_tail_replay_differs_from_full_segment() {
        let frames: Vec<_> = (0..8).map(|i| make_write_frame(i, 300 + i)).collect();
        let full_segment = make_segment(&frames);

        // Simulate crash: truncate segment to leave only 5 records
        let mut truncated = full_segment.clone();
        // Cut at roughly 60% of the segment
        let cut = full_segment.len() * 3 / 5;
        truncated.truncate(cut);

        // First mount: replay truncated segment
        let mut engine = IntentReplayEngine::new(0);
        let mut handler = CollectingHandler::default();
        engine.replay_segment(&truncated, &mut handler).unwrap();
        let after_crash = engine.compute_checkpoint();

        // Second mount (clean): replay full segment
        let clean = replay_and_checkpoint(&full_segment, 0);

        // The checkpoints differ because different record counts were recovered
        assert_ne!(
            after_crash.digest, clean,
            "crash recovery with fewer records differs from clean full replay"
        );
    }

    #[test]
    fn fresh_engine_replay_after_checkpoint_crash_keeps_durable_state() {
        let frames: Vec<_> = (1..6).map(|i| make_write_frame(i, 700 + i)).collect();
        let segment = make_segment(&frames);

        let mut handler = DurableWriteHandler::default();
        let mut first_engine = IntentReplayEngine::new(0);
        first_engine.replay_segment(&segment, &mut handler).unwrap();
        let state_after_first_replay = handler.state.clone();
        let first_dispatches = handler.dispatches;
        let first_checkpoint = first_engine.compute_checkpoint();

        let mut fresh_engine = IntentReplayEngine::new(0);
        fresh_engine.replay_segment(&segment, &mut handler).unwrap();

        assert_eq!(handler.state, state_after_first_replay);
        assert_eq!(handler.dispatches, first_dispatches * 2);
        assert_eq!(
            fresh_engine.compute_checkpoint().digest,
            first_checkpoint.digest
        );
    }

    #[test]
    fn applied_lsns_dedup_prevents_same_engine_duplicate_dispatch() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 400 + i)).collect();
        let segment = make_segment(&frames);

        // First replay
        let mut engine = IntentReplayEngine::new(0);
        let mut handler = CollectingHandler::default();
        engine.replay_segment(&segment, &mut handler).unwrap();
        let first_applied = engine.state.applied_lsns.clone();
        let first_checkpoint = engine.compute_checkpoint();

        // Second replay with same engine (applied_lsns still populated)
        let mut handler2 = CollectingHandler::default();
        engine.replay_segment(&segment, &mut handler2).unwrap();
        let second_checkpoint = engine.compute_checkpoint();

        // applied_lsns unchanged, checkpoints match
        assert_eq!(engine.state.applied_lsns, first_applied);
        assert_eq!(first_checkpoint.digest, second_checkpoint.digest);
        // Handler received no new records
        assert!(handler2.records.is_empty());
    }

    #[test]
    fn checkpoint_gating_after_replay() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 500 + i)).collect();
        let segment = make_segment(&frames);

        let mut engine = IntentReplayEngine::new(0);
        let mut handler = CollectingHandler::default();
        engine.replay_segment(&segment, &mut handler).unwrap();

        // LSNs 1-4 applied, LSN 0 covered by applied_txg=0
        assert!(engine.is_checkpointable_up_to(4));
        engine.advance_watermark(4);
        assert_eq!(engine.state.applied_txg, 4);

        // Replay again: everything should be skipped
        let mut handler2 = CollectingHandler::default();
        let outcome = engine.replay_segment(&segment, &mut handler2).unwrap();
        assert!(matches!(
            outcome,
            SegmentReplayOutcome::Skipped {
                reason: SkippedReason::AllApplied
            }
        ));
        assert!(handler2.records.is_empty());
    }

    #[test]
    fn partial_final_record_truncation_handled() {
        // Create a segment and truncate in the middle of the last record
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 600 + i)).collect();
        let mut segment = make_segment(&frames);

        // Truncate at a point that cuts the last record partially
        // The segment footer is at the end; cutting well before it leaves
        // the last record(s) truncated
        let cut = segment.len() - 16;
        segment.truncate(cut);

        let mut engine = IntentReplayEngine::new(0);
        let mut handler = CollectingHandler::default();
        let result = engine.replay_segment(&segment, &mut handler);
        // Should not panic; may skip corrupted last record
        assert!(result.is_ok());
        // At least some records were replayed
        assert!(engine.state.entries_replayed > 0);
    }

    #[test]
    fn watermark_cannot_advance_with_gaps() {
        let mut engine = IntentReplayEngine::new(0);
        engine.state.mark_lsn_applied(0);
        engine.state.mark_lsn_applied(1);
        // gap at 2
        engine.state.mark_lsn_applied(3);

        assert!(!engine.is_checkpointable_up_to(3));
        assert!(engine.is_checkpointable_up_to(1));
    }
}
