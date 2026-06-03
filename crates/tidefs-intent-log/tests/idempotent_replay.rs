//! Integration tests: idempotent replay.
//!
//! Replaying an already-recovered log segment must be a no-op.
//! The committed-root LSN mechanism ensures that records with
//! `record_seq < committed_lsn` are skipped, preventing duplicate
//! application of already-applied mutations.

use tidefs_intent_log::{IntentLog, IntentLogRecord};

fn make_truncate(ino: u64, new_size: u64) -> IntentLogRecord {
    IntentLogRecord::Truncate { ino, new_size }
}

// ── Replay the same segment twice: second replay is empty ─────────────

#[test]
fn replay_same_segment_twice_second_is_empty() {
    let log = IntentLog::new(32);
    for i in 0..5 {
        log.append(make_truncate(i, 100), 1);
    }
    let (segment, lsn) = log.commit(1);
    assert_eq!(lsn, 5);

    drop(log);
    let recovery = IntentLog::new(32);

    // First replay gets all 5 records
    let r1 = recovery.replay(&segment, 0).unwrap();
    assert_eq!(r1.len(), 5);

    // Second replay with lsn=5 (the committed LSN): should get nothing
    let r2 = recovery.replay(&segment, 5).unwrap();
    assert!(
        r2.is_empty(),
        "second replay should be empty (already applied)"
    );
}

// ── Replay with progressive LSN ───────────────────────────────────────

#[test]
fn progressive_lsn_makes_replay_idempotent() {
    let log = IntentLog::new(32);
    for i in 0..10 {
        log.append(make_truncate(i, 100), 1);
    }
    let (segment, lsn) = log.commit(1);
    assert_eq!(lsn, 10);

    drop(log);
    let recovery = IntentLog::new(32);

    // Simulate progressive recovery: apply records in chunks
    let chunk1 = recovery.replay(&segment, 0).unwrap();
    assert_eq!(chunk1.len(), 10);

    // "Commit" chunk1 → committed LSN is now 10
    // Replay again with LSN=10 → empty
    let chunk2 = recovery.replay(&segment, 10).unwrap();
    assert!(chunk2.is_empty());

    // Even repeated calls with same LSN return empty
    let chunk3 = recovery.replay(&segment, 10).unwrap();
    assert!(chunk3.is_empty());
}

// ── Partial application then replay is idempotent ─────────────────────

#[test]
fn partial_application_then_replay_skips_applied() {
    let log = IntentLog::new(32);
    for i in 0..8 {
        log.append(make_truncate(i, 100), 1);
    }
    let (segment, lsn) = log.commit(1);
    assert_eq!(lsn, 8);

    drop(log);
    let recovery = IntentLog::new(32);

    // Apply first 4 records (LSN advances to 4)
    let applied = recovery.replay(&segment, 0).unwrap();
    assert_eq!(applied.len(), 8);

    // Simulate: we confirmed first 4 are durable → committed LSN = 4
    // Replay with lsn=4 should only return seqs 4..7
    let remaining = recovery.replay(&segment, 4).unwrap();
    assert_eq!(remaining.len(), 4);
    assert_eq!(remaining[0].record_seq, 4);
    assert_eq!(remaining[3].record_seq, 7);

    // Replay with lsn=8 (all applied) → empty
    let none = recovery.replay(&segment, 8).unwrap();
    assert!(none.is_empty());
}

// ── Multiple segments, idempotent across segments ─────────────────────

#[test]
fn multiple_segments_idempotent_replay() {
    let log = IntentLog::new(32);
    let mut all_segments = Vec::new();

    // Segment 1: seqs 0..3
    for i in 0..4 {
        log.append(make_truncate(i, 100), 1);
    }
    all_segments.push(log.commit(1));

    // Segment 2: seqs 4..7
    for i in 4..8 {
        log.append(make_truncate(i, 200), 2);
    }
    all_segments.push(log.commit(2));

    // Segment 3: seqs 8..11
    for i in 8..12 {
        log.append(make_truncate(i, 300), 3);
    }
    all_segments.push(log.commit(3));

    drop(log);

    // First recovery: apply all segments
    {
        let recovery = IntentLog::new(32);
        let mut base = 0u64;
        for (seg, _lsn) in &all_segments {
            let replayed = recovery.replay(seg, base).unwrap();
            assert_eq!(replayed.len(), 4);
            base = replayed.last().unwrap().record_seq + 1;
        }
        assert_eq!(base, 12);
    }

    // Second recovery: committed root at 12, replay should be empty
    {
        let recovery2 = IntentLog::new(32);
        for (seg, _lsn) in &all_segments {
            let replayed = recovery2.replay(seg, 12).unwrap();
            assert!(
                replayed.is_empty(),
                "segment already applied should replay empty"
            );
        }
    }

    // Third recovery: committed root at 6, only later parts apply
    {
        let recovery3 = IntentLog::new(32);
        // seg1 (seqs 0..3): all < 6 → empty
        let r1 = recovery3.replay(&all_segments[0].0, 6).unwrap();
        assert!(r1.is_empty());

        // seg2 (seqs 4..7): seqs 6,7 >= 6 → 2 records
        let r2 = recovery3.replay(&all_segments[1].0, 6).unwrap();
        assert_eq!(r2.len(), 2);
        assert_eq!(r2[0].record_seq, 6);
        assert_eq!(r2[1].record_seq, 7);

        // seg3 (seqs 8..11): all >= 6 → 4 records
        let r3 = recovery3.replay(&all_segments[2].0, 6).unwrap();
        assert_eq!(r3.len(), 4);
        assert_eq!(r3[0].record_seq, 8);
    }
}

// ── Empty replay preserves stats correctly ────────────────────────────

#[test]
fn empty_replay_records_stats() {
    let log = IntentLog::new(32);
    log.append(make_truncate(1, 100), 1);
    let (segment, lsn) = log.commit(1);
    assert_eq!(lsn, 1);

    drop(log);
    let recovery = IntentLog::new(32);

    // Replay with lsn=1 (past all records) → empty but still counts as replay
    let replayed = recovery.replay(&segment, 1).unwrap();
    assert!(replayed.is_empty());

    let stats = recovery.stats();
    assert_eq!(stats.replays, 1);
}

// ── Corrupt segment is never silently accepted ────────────────────────

#[test]
fn corrupt_segment_replay_always_errors() {
    let log = IntentLog::new(32);
    log.append(make_truncate(1, 100), 1);
    let (mut segment, _lsn) = log.commit(1);

    // Corrupt a byte
    if segment.len() > 8 {
        segment[8] ^= 0xFF;
    }

    drop(log);

    // Multiple attempts to replay corrupt segment all fail
    for _ in 0..3 {
        let recovery = IntentLog::new(32);
        let result = recovery.replay(&segment, 0);
        assert!(result.is_err(), "corrupt segment must always error");
    }
}

// ── Replay idempotent after successful previous replay ────────────────

#[test]
fn replay_idempotent_after_successful_previous_replay() {
    let log = IntentLog::new(32);
    for i in 0..5 {
        log.append(make_truncate(i, 100), 1);
    }
    let (segment, lsn) = log.commit(1);
    assert_eq!(lsn, 5);

    drop(log);

    // Replay with the committed LSN (5): should return nothing
    let recovery = IntentLog::new(32);
    let replayed = recovery.replay(&segment, 5).unwrap();
    assert!(replayed.is_empty());

    // Replay again with same LSN: still empty
    let replayed2 = recovery.replay(&segment, 5).unwrap();
    assert!(replayed2.is_empty());

    // Replay with lower LSN (0) returns all records — but this is a
    // different recovery scenario where we chose to re-apply from scratch
    let replayed3 = recovery.replay(&segment, 0).unwrap();
    assert_eq!(replayed3.len(), 5);
}
