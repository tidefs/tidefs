//! Integration tests: crash recovery with simulated process death.
//!
//! These tests verify that committed intent-log records survive a simulated
//! crash (dropping the IntentLog and creating a fresh one) and are correctly
//! replayed from the serialized segment bytes.

use tidefs_intent_log::reader::SegmentReadResult;
use tidefs_intent_log::{
    IntentLog, IntentLogFrame, IntentLogReader, IntentLogRecord, IntentLogWriter,
};

// ── Helpers ───────────────────────────────────────────────────────────

fn make_create(ino: u64, name: &str) -> IntentLogRecord {
    IntentLogRecord::Create {
        parent: 1,
        name: name.as_bytes().to_vec(),
        mode: 0o644,
        ino,
    }
}

fn make_write(ino: u64, offset: u64, length: u64) -> IntentLogRecord {
    IntentLogRecord::Write {
        ino,
        offset,
        length,
        data_hash: [0xAB; 32],
    }
}

fn make_truncate(ino: u64, new_size: u64) -> IntentLogRecord {
    IntentLogRecord::Truncate { ino, new_size }
}

// ── Single-commit crash -> replay round-trip ──────────────────────────

#[test]
fn commit_replay_all_records_survive_crash() {
    let log = IntentLog::new(64);
    let records: Vec<IntentLogRecord> = (0..5)
        .map(|i| make_create(i + 100, &format!("file_{i}")))
        .collect();

    for rec in &records {
        log.append(rec.clone(), 1);
    }
    let (segment, lsn) = log.commit(1);
    assert!(!segment.is_empty());
    assert_eq!(lsn, records.len() as u64);

    // Simulate crash: drop log, create fresh one
    drop(log);
    let recovery_log = IntentLog::new(64);

    let replayed = recovery_log
        .replay(&segment, 0)
        .expect("replay must succeed");
    assert_eq!(replayed.len(), records.len());

    for (i, (expected, frame)) in records.iter().zip(replayed.iter()).enumerate() {
        assert_eq!(frame.record, *expected, "mismatch at index {i}");
        assert_eq!(frame.txg_id, 1);
        assert_eq!(frame.record_seq, i as u64);
        assert!(frame.verify().is_ok());
    }

    let stats = recovery_log.stats();
    assert_eq!(stats.replays, 1);
}

#[test]
fn multiple_record_types_survive_crash() {
    let log = IntentLog::new(64);
    let records: Vec<IntentLogRecord> = vec![
        make_create(10, "hello.txt"),
        make_write(10, 0, 4096),
        IntentLogRecord::Mkdir {
            parent: 1,
            name: b"subdir".to_vec(),
            mode: 0o755,
            ino: 20,
        },
        IntentLogRecord::Symlink {
            parent: 1,
            name: b"link".to_vec(),
            target: b"/usr/bin/tool".to_vec(),
            ino: 30,
        },
        IntentLogRecord::Rename {
            src_parent: 1,
            src_name: b"hello.txt".to_vec(),
            dst_parent: 20,
            dst_name: b"moved.txt".to_vec(),
            overwrite_target_ino: None,
            ino: 10,
            rename_flags: 0,
        },
        IntentLogRecord::Unlink {
            parent: 20,
            name: b"moved.txt".to_vec(),
            ino: 10,
        },
    ];

    for rec in &records {
        log.append(rec.clone(), 7);
    }
    let (segment, lsn) = log.commit(7);
    assert_eq!(lsn, records.len() as u64);

    drop(log);
    let recovery_log = IntentLog::new(64);
    let replayed = recovery_log
        .replay(&segment, 0)
        .expect("replay must succeed");

    assert_eq!(replayed.len(), records.len());
    for (i, (expected, frame)) in records.iter().zip(replayed.iter()).enumerate() {
        assert_eq!(frame.record, *expected, "type mismatch at index {i}");
        assert_eq!(frame.txg_id, 7);
        assert!(frame.verify().is_ok());
    }
}

// ── Writer -> Reader crash path ───────────────────────────────────────

#[test]
fn writer_reader_complete_segment_survives() {
    let mut writer = IntentLogWriter::new(1024 * 1024);

    let records: Vec<IntentLogRecord> = (0..4)
        .map(|i| make_write(i + 100, i * 4096, 1024))
        .collect();

    for (i, rec) in records.iter().enumerate() {
        let frame = IntentLogFrame::new(rec.clone(), 1, i as u64);
        let sealed = writer.append_frame(&frame).unwrap();
        assert!(sealed.is_none(), "should not rotate with 4 records");
    }

    let sealed_bytes = writer.finish().unwrap().expect("should have records");

    let result = IntentLogReader::read_segment(&sealed_bytes);
    match result {
        SegmentReadResult::Complete {
            records: seg_records,
            header,
            ..
        } => {
            assert_eq!(header.record_count, records.len() as u32);
            assert_eq!(seg_records.len(), records.len());
            for (i, (expected, seg_rec)) in records.iter().zip(seg_records.iter()).enumerate() {
                assert_eq!(seg_rec.record, *expected, "mismatch at index {i}");
                assert_eq!(seg_rec.lsn, i as u64);
            }
        }
        other => panic!("expected Complete, got {other:?}"),
    }
}

#[test]
fn truncated_segment_detected_on_crash() {
    let mut writer = IntentLogWriter::new(1024 * 1024);

    for i in 0..3 {
        let rec = make_truncate(i + 1, i * 100);
        let frame = IntentLogFrame::new(rec, 1, i);
        writer.append_frame(&frame).unwrap();
    }

    let mut sealed = writer.finish().unwrap().unwrap();

    // Simulate crash: truncate before footer
    let truncate_at = sealed.len() - 10;
    sealed.truncate(truncate_at);

    let result = IntentLogReader::read_segment(&sealed);
    match result {
        SegmentReadResult::Truncated { valid_records, .. } => {
            assert!(!valid_records.is_empty(), "should recover some records");
            assert!(valid_records.len() <= 3);
        }
        SegmentReadResult::Corrupt => {
            // Acceptable if truncation landed poorly
        }
        SegmentReadResult::Complete { .. } => {
            panic!("truncated segment should not be Complete");
        }
    }
}

#[test]
fn corrupt_segment_header_detected() {
    let corrupted = vec![0xFF; 128];
    let result = IntentLogReader::read_segment(&corrupted);
    assert!(
        matches!(result, SegmentReadResult::Corrupt),
        "corrupt header should produce Corrupt, got {result:?}"
    );
}

// ── Backpressure + crash recovery ─────────────────────────────────────

#[test]
fn backpressure_then_commit_then_crash_replay() {
    let log = IntentLog::new(5);

    for i in 0..5 {
        log.append(make_truncate(i, i * 100), 1);
    }
    assert_eq!(log.len(), 5);

    let (segment, lsn) = log.commit(1);
    assert_eq!(lsn, 5);
    assert_eq!(log.len(), 0);

    // Append more after commit (wraparound)
    for i in 5..8 {
        log.append(make_truncate(i, i * 100), 2);
    }
    let (segment2, lsn2) = log.commit(2);
    assert_eq!(lsn2, 8);

    drop(log);
    let recovery = IntentLog::new(16);

    let r1 = recovery.replay(&segment, 0).unwrap();
    assert_eq!(r1.len(), 5);
    assert_eq!(r1[0].record_seq, 0);
    assert_eq!(r1[4].record_seq, 4);

    let r2 = recovery.replay(&segment2, 5).unwrap();
    assert_eq!(r2.len(), 3);
    assert_eq!(r2[0].record_seq, 5);
    assert_eq!(r2[2].record_seq, 7);

    for f in r1.iter().chain(r2.iter()) {
        assert!(f.verify().is_ok());
    }
}

// ── Append-with-data crash recovery ───────────────────────────────────

#[test]
fn append_with_data_survives_crash() {
    let buffer = tidefs_intent_log::IntentLogBuffer::new();

    let rec1 = IntentLogRecord::BufferedWrite {
        ino: 1,
        offset: 0,
        length: 5,
        data: b"hello".to_vec(),
    };
    let rec2 = IntentLogRecord::BufferedWrite {
        ino: 2,
        offset: 0,
        length: 5,
        data: b"world".to_vec(),
    };

    buffer.append_with_data(rec1.clone(), 1, b"hello".to_vec());
    buffer.append_with_data(rec2.clone(), 1, b"world".to_vec());

    let (frames, data_map) = buffer.drain_with_data_since(0);
    assert_eq!(frames.len(), 2);
    assert_eq!(data_map.len(), 2);
    assert_eq!(data_map.get(&0).unwrap(), b"hello");
    assert_eq!(data_map.get(&1).unwrap(), b"world");

    assert_eq!(frames[0].record, rec1);
    assert_eq!(frames[1].record, rec2);
    assert!(frames[0].verify().is_ok());
    assert!(frames[1].verify().is_ok());
}
