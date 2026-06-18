// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests: transaction ordering and interleaved group recovery.
//!
//! Validates that sequential transactions are replayed in commit order
//! and that interleaved transaction groups select the correct recovery
//! point based on committed LSN.

use tidefs_intent_log::{IntentLog, IntentLogRecord, XattrNamespace};

fn make_create(ino: u64, name: &str) -> IntentLogRecord {
    IntentLogRecord::Create {
        parent: 1,
        name: name.as_bytes().to_vec(),
        mode: 0o644,
        ino,
    }
}

fn make_truncate(ino: u64, new_size: u64) -> IntentLogRecord {
    IntentLogRecord::Truncate { ino, new_size }
}

// ── Sequential transactions preserve order ────────────────────────────

#[test]
fn sequential_transactions_replay_in_commit_order() {
    let log = IntentLog::new(32);
    let mut all_segments: Vec<(Vec<u8>, u64)> = Vec::new();

    // Three sequential transaction groups
    let txg_specs = [
        (1u64, vec![make_create(10, "a"), make_create(11, "b")]),
        (2u64, vec![make_truncate(10, 4096), make_truncate(11, 8192)]),
        (3u64, vec![make_create(12, "c"), make_truncate(12, 1024)]),
    ];

    for (txg_id, recs) in &txg_specs {
        for rec in recs {
            log.append(rec.clone(), *txg_id);
        }
        let (seg, lsn) = log.commit(*txg_id);
        all_segments.push((seg, lsn));
    }

    drop(log);
    let recovery = IntentLog::new(32);

    // Replay all segments in order with progressive LSN
    let mut cumulative_lsn = 0u64;
    let mut total_replayed = 0usize;

    for (i, (seg, _lsn)) in all_segments.iter().enumerate() {
        let replayed = recovery.replay(seg, cumulative_lsn).unwrap();
        assert_eq!(replayed.len(), 2, "round {i}: expected 2 records");
        for f in &replayed {
            assert_eq!(f.txg_id, txg_specs[i].0);
            assert!(f.record_seq >= cumulative_lsn);
            assert!(f.verify().is_ok());
        }
        cumulative_lsn = replayed.last().unwrap().record_seq + 1;
        total_replayed += replayed.len();
    }

    assert_eq!(total_replayed, 6);
}

// ── Interleaved transaction groups ────────────────────────────────────

#[test]
fn interleaved_transaction_groups_recover_correctly() {
    // Simulate two transaction groups whose records were interleaved
    // in the buffer but committed in separate segments.
    let log = IntentLog::new(64);

    // Interleave: txg1 records mixed with txg2 records
    let txg1_recs: Vec<IntentLogRecord> = (0..3)
        .map(|i| make_create(100 + i as u64, &format!("txg1_f{i}")))
        .collect();
    let txg2_recs: Vec<IntentLogRecord> = (0..3)
        .map(|i| make_create(200 + i as u64, &format!("txg2_f{i}")))
        .collect();

    // Append interleaved: txg1, txg2, txg1, txg2, txg1, txg2
    for i in 0..3 {
        log.append(txg1_recs[i].clone(), 1);
        log.append(txg2_recs[i].clone(), 2);
    }

    let (segment_a, lsn_a) = log.commit(1);
    assert_eq!(lsn_a, 6); // all 6 records in one segment

    // All records are in one segment because commit drains everything.
    // The txg_id field distinguishes which group they belong to.
    drop(log);
    let recovery = IntentLog::new(32);
    let replayed = recovery.replay(&segment_a, 0).unwrap();
    assert_eq!(replayed.len(), 6);

    // Verify interleaved order is preserved
    for i in 0..3 {
        assert_eq!(replayed[i * 2].txg_id, 1);
        assert_eq!(replayed[i * 2 + 1].txg_id, 2);
    }

    // Now simulate recovery with committed LSN that skips first half
    let partial = recovery.replay(&segment_a, 3).unwrap();
    assert_eq!(partial.len(), 3);
    assert!(partial[0].record_seq >= 3);
}

// ── Multiple txgs in one segment ──────────────────────────────────────

#[test]
fn multiple_txgs_in_one_segment_replay_correctly() {
    let log = IntentLog::new(64);

    // Records from different txgs in the same segment
    for i in 0..4 {
        let txg_id = (i % 2) + 1; // alternates 1,2,1,2
        log.append(make_truncate(i, i * 100), txg_id);
    }
    let (segment, lsn) = log.commit(1);
    assert_eq!(lsn, 4);

    drop(log);
    let recovery = IntentLog::new(32);
    let replayed = recovery.replay(&segment, 0).unwrap();
    assert_eq!(replayed.len(), 4);

    // Verify txg_id alternates
    assert_eq!(replayed[0].txg_id, 1);
    assert_eq!(replayed[1].txg_id, 2);
    assert_eq!(replayed[2].txg_id, 1);
    assert_eq!(replayed[3].txg_id, 2);

    // Verify record contents
    for (i, record) in replayed.iter().enumerate().take(4) {
        assert_eq!(record.record_seq, i as u64);
        assert!(record.verify().is_ok());
    }
}

// ── All 15 record types survive sequential commits ────────────────────

#[test]
fn all_record_types_survive_sequential_commits() {
    let log = IntentLog::new(128);

    let all_types: Vec<IntentLogRecord> = vec![
        IntentLogRecord::Write {
            ino: 1,
            offset: 0,
            length: 4096,
            data_hash: [0x11; 32],
        },
        IntentLogRecord::Truncate {
            ino: 1,
            new_size: 8192,
        },
        IntentLogRecord::Setattr {
            ino: 1,
            attr_mask: 0xFFFF,
            attrs: [0x22; 64],
        },
        IntentLogRecord::Create {
            parent: 1,
            name: b"f1".to_vec(),
            mode: 0o644,
            ino: 2,
        },
        IntentLogRecord::Unlink {
            parent: 1,
            name: b"f1".to_vec(),
            ino: 2,
        },
        IntentLogRecord::Rename {
            src_parent: 1,
            src_name: b"old".to_vec(),
            dst_parent: 1,
            dst_name: b"new".to_vec(),
            overwrite_target_ino: None,
            ino: 3,
            rename_flags: 0,
        },
        IntentLogRecord::Symlink {
            parent: 1,
            name: b"sl".to_vec(),
            target: b"/t".to_vec(),
            ino: 4,
        },
        IntentLogRecord::HardLink {
            ino: 3,
            new_parent: 1,
            new_name: b"hl".to_vec(),
        },
        IntentLogRecord::Mkdir {
            parent: 1,
            name: b"d".to_vec(),
            mode: 0o755,
            ino: 5,
        },
        IntentLogRecord::Rmdir {
            parent: 1,
            name: b"d".to_vec(),
            ino: 5,
        },
        IntentLogRecord::Mknod {
            parent: 1,
            name: b"fifo".to_vec(),
            mode: 0o644,
            rdev: 0,
            ino: 6,
        },
        IntentLogRecord::XattrSet {
            ino: 1,
            namespace: XattrNamespace::User,
            key_hash: [0xAA; 32],
            value_hash: [0xBB; 32],
        },
        IntentLogRecord::XattrRemove {
            ino: 1,
            namespace: XattrNamespace::User,
            key_hash: [0xAA; 32],
        },
        IntentLogRecord::Tmpfile {
            parent: 1,
            mode: 0o644,
            ino: 7,
        },
        IntentLogRecord::Fallocate {
            ino: 1,
            offset: 0,
            length: 65536,
            mode: 0,
        },
        IntentLogRecord::BufferedWrite {
            ino: 1,
            offset: 0,
            length: 4,
            data: b"data".to_vec(),
        },
        IntentLogRecord::WriteIntentAck {
            ino: 1,
            offset: 0,
            length: 4096,
        },
    ];

    for rec in &all_types {
        log.append(rec.clone(), 1);
    }
    let (segment, lsn) = log.commit(1);
    assert_eq!(lsn, all_types.len() as u64);

    drop(log);
    let recovery = IntentLog::new(128);
    let replayed = recovery.replay(&segment, 0).unwrap();
    assert_eq!(replayed.len(), all_types.len());

    for (i, (expected, frame)) in all_types.iter().zip(replayed.iter()).enumerate() {
        assert_eq!(frame.record, *expected, "type mismatch at index {i}");
        assert_eq!(frame.record_seq, i as u64);
        assert!(frame.verify().is_ok());
    }
}

// ── Commit drains all, then new append starts from fresh ──────────────

#[test]
fn commit_drains_all_new_append_starts_from_current_seq() {
    let log = IntentLog::new(32);

    // First batch
    for i in 0..5 {
        log.append(make_truncate(i, 100), 1);
    }
    let (seg1, lsn1) = log.commit(1);
    assert_eq!(lsn1, 5);
    assert_eq!(log.current_seq(), 5);

    // Second batch
    for i in 0..3 {
        log.append(make_truncate(i + 100, 200), 2);
    }
    let (seg2, lsn2) = log.commit(2);
    assert_eq!(lsn2, 8);
    assert_eq!(log.current_seq(), 8);

    drop(log);
    let recovery = IntentLog::new(32);

    // Replay seg1: seqs 0..4 at LSN 0
    let r1 = recovery.replay(&seg1, 0).unwrap();
    assert_eq!(r1.len(), 5);
    assert_eq!(r1[0].record_seq, 0);
    assert_eq!(r1[4].record_seq, 4);

    // Replay seg2: seqs 5..7 at LSN 5
    let r2 = recovery.replay(&seg2, 5).unwrap();
    assert_eq!(r2.len(), 3);
    assert_eq!(r2[0].record_seq, 5);
    assert_eq!(r2[2].record_seq, 7);

    // Verify all checksums
    for f in r1.iter().chain(r2.iter()) {
        assert!(f.verify().is_ok());
    }
}
