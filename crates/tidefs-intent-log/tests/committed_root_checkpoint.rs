// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests: committed-root LSN-based checkpoint bounding.
//!
//! The committed-root LSN determines which records need replay after a crash.
//! Records with `record_seq < committed_lsn` were already durably committed
//! and must be skipped during recovery.

use tidefs_intent_log::{IntentLog, IntentLogRecord};

fn make_truncate(ino: u64, new_size: u64) -> IntentLogRecord {
    IntentLogRecord::Truncate { ino, new_size }
}

// ── LSN bounds the replay window ──────────────────────────────────────

#[test]
fn lsn_correctly_bounds_replay_window() {
    let log = IntentLog::new(32);

    // Append 10 records, all seqs 0..9
    for i in 0..10 {
        log.append(make_truncate(i, i * 100), 1);
    }
    let (segment, lsn) = log.commit(1);
    assert_eq!(lsn, 10);

    drop(log);
    let recovery = IntentLog::new(32);

    // Replay with lsn=0: all records returned
    let all = recovery.replay(&segment, 0).unwrap();
    assert_eq!(all.len(), 10);

    // Replay with lsn=5: only seqs 5..9
    let partial = recovery.replay(&segment, 5).unwrap();
    assert_eq!(partial.len(), 5);
    assert_eq!(partial[0].record_seq, 5);
    assert_eq!(partial[4].record_seq, 9);

    // Replay with lsn=10: empty (all already committed)
    let none = recovery.replay(&segment, 10).unwrap();
    assert!(none.is_empty());

    // Replay with lsn past all: empty
    let past = recovery.replay(&segment, 999).unwrap();
    assert!(past.is_empty());
}

// ── Multiple commits, progressive LSN ─────────────────────────────────

#[test]
fn multiple_commits_progressive_lsn() {
    let log = IntentLog::new(32);
    let mut segments = Vec::new();

    // Round 1: seqs 0..2
    for i in 0..3 {
        log.append(make_truncate(i, 100), 1);
    }
    let (seg1, lsn1) = log.commit(1);
    assert_eq!(lsn1, 3);
    segments.push((seg1, lsn1));

    // Round 2: seqs 3..5
    for i in 3..6 {
        log.append(make_truncate(i, 200), 2);
    }
    let (seg2, lsn2) = log.commit(2);
    assert_eq!(lsn2, 6);
    segments.push((seg2, lsn2));

    // Round 3: seqs 6..8
    for i in 6..9 {
        log.append(make_truncate(i, 300), 3);
    }
    let (seg3, lsn3) = log.commit(3);
    assert_eq!(lsn3, 9);
    segments.push((seg3, lsn3));

    drop(log);
    let recovery = IntentLog::new(32);

    // Replay each segment with appropriate LSN
    let mut cumulative_base = 0u64;
    for (i, (seg, _lsn)) in segments.iter().enumerate() {
        let replayed = recovery.replay(seg, cumulative_base).unwrap();
        assert_eq!(replayed.len(), 3, "round {i}: expected 3 records");
        for f in &replayed {
            assert!(
                f.record_seq >= cumulative_base,
                "seq {} below base {}",
                f.record_seq,
                cumulative_base
            );
            assert!(f.verify().is_ok());
        }
        cumulative_base += 3;
    }

    // Cumulative base should be 9
    assert_eq!(cumulative_base, 9);
}

// ── Simulated crash between commits ───────────────────────────────────

#[test]
fn crash_between_commits_only_replays_lost_records() {
    let log = IntentLog::new(32);

    // Commit A: seqs 0..3
    for i in 0..4 {
        log.append(make_truncate(i, 100), 1);
    }
    let (seg_a, lsn_a) = log.commit(1);
    assert_eq!(lsn_a, 4); // committed through LSN 4

    // Commit B: seqs 4..7
    for i in 4..8 {
        log.append(make_truncate(i, 200), 2);
    }
    let (seg_b, lsn_b) = log.commit(2);
    assert_eq!(lsn_b, 8); // committed through LSN 8

    // Simulate crash: we have seg_a and seg_b durably stored.
    // The committed root is at LSN 8.
    // Replay seg_a with lsn=0: should get seqs 0..3
    // Replay seg_b with lsn=4: should get seqs 4..7
    drop(log);
    let recovery = IntentLog::new(32);

    let r_a = recovery.replay(&seg_a, 0).unwrap();
    assert_eq!(r_a.len(), 4);
    assert_eq!(r_a[3].record_seq, 3);

    let r_b = recovery.replay(&seg_b, 4).unwrap();
    assert_eq!(r_b.len(), 4);
    assert_eq!(r_b[0].record_seq, 4);
    assert_eq!(r_b[3].record_seq, 7);
}

// ── Committed root past all segments filters everything ───────────────

#[test]
fn committed_root_past_all_segments_filters_everything() {
    let log = IntentLog::new(32);
    for i in 0..5 {
        log.append(make_truncate(i, 100), 1);
    }
    let (segment, lsn) = log.commit(1);
    assert_eq!(lsn, 5);

    drop(log);
    let recovery = IntentLog::new(32);

    // If committed root is at LSN 100, no records need replay
    let replayed = recovery.replay(&segment, 100).unwrap();
    assert!(replayed.is_empty());
}

// ── Empty segment with non-zero LSN ───────────────────────────────────

#[test]
fn empty_commit_lsn_matches_current_seq() {
    let log = IntentLog::new(32);

    // Append and commit 3 records
    for i in 0..3 {
        log.append(make_truncate(i, 100), 1);
    }
    let (_segment, lsn) = log.commit(1);
    assert_eq!(lsn, 3);

    // Empty commit: no new records, LSN = current_seq (3)
    let (empty, empty_lsn) = log.commit(1);
    assert!(empty.is_empty());
    assert_eq!(empty_lsn, 3);

    // Replaying empty segment is a no-op
    drop(log);
    let recovery = IntentLog::new(32);
    let replayed = recovery.replay(&empty, 0).unwrap();
    assert!(replayed.is_empty());
}

// ── LSN monotonicity across many rounds ───────────────────────────────

#[test]
fn lsn_monotonic_across_many_rounds() {
    let log = IntentLog::new(16);
    let mut prev_lsn = 0u64;

    for round in 0..20 {
        for i in 0..3 {
            log.append(make_truncate(round * 10 + i, 100), round);
        }
        let (_seg, lsn) = log.commit(round);
        assert!(
            lsn >= prev_lsn,
            "LSN {lsn} < prev {prev_lsn} at round {round}"
        );
        prev_lsn = lsn;
    }
    assert!(prev_lsn >= 60);
}
