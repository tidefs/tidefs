// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use tidefs_intent_log::replay::{
    IntentReplayEngine, IntentReplayHandler, SegmentReplayOutcome, SkippedReason,
};
use tidefs_intent_log::{IntentLogFrame, IntentLogRecord, IntentLogWriter};

#[derive(Debug, Default)]
struct RecordingHandler {
    records: Vec<IntentLogRecord>,
}
impl IntentReplayHandler for RecordingHandler {
    type Error = String;
    fn handle_record(&mut self, record: &IntentLogRecord) -> Result<(), String> {
        self.records.push(record.clone());
        Ok(())
    }
}

#[derive(Debug, Default)]
struct SemanticHandler {
    dispatched: Vec<IntentLogRecord>,
    created: Vec<String>,
    unlinked: Vec<String>,
    dirs_made: Vec<String>,
    dirs_removed: Vec<String>,
    renamed: Vec<(String, String)>,
    truncated: Vec<(u64, u64)>,
}
impl IntentReplayHandler for SemanticHandler {
    type Error = String;
    fn handle_record(&mut self, record: &IntentLogRecord) -> Result<(), String> {
        self.dispatched.push(record.clone());
        match record {
            IntentLogRecord::Create { name, ino, .. } => {
                self.created
                    .push(format!("ino={ino}:{}", String::from_utf8_lossy(name)));
            }
            IntentLogRecord::Unlink { name, ino, .. } => {
                self.unlinked
                    .push(format!("ino={ino}:{}", String::from_utf8_lossy(name)));
            }
            IntentLogRecord::Mkdir { name, ino, .. } => {
                self.dirs_made
                    .push(format!("ino={ino}:{}", String::from_utf8_lossy(name)));
            }
            IntentLogRecord::Rmdir { name, ino, .. } => {
                self.dirs_removed
                    .push(format!("ino={ino}:{}", String::from_utf8_lossy(name)));
            }
            IntentLogRecord::Rename {
                src_name, dst_name, ..
            } => {
                self.renamed.push((
                    String::from_utf8_lossy(src_name).to_string(),
                    String::from_utf8_lossy(dst_name).to_string(),
                ));
            }
            IntentLogRecord::Truncate { ino, new_size } => {
                self.truncated.push((*ino, *new_size));
            }
            _ => {}
        }
        Ok(())
    }
}

fn mk_create(seq: u64, parent: u64, name: &[u8], mode: u32, ino: u64) -> IntentLogFrame {
    IntentLogFrame::new(
        IntentLogRecord::Create {
            parent,
            name: name.to_vec(),
            mode,
            ino,
        },
        1,
        seq,
    )
}
fn mk_unlink(seq: u64, parent: u64, name: &[u8], ino: u64) -> IntentLogFrame {
    IntentLogFrame::new(
        IntentLogRecord::Unlink {
            parent,
            name: name.to_vec(),
            ino,
        },
        1,
        seq,
    )
}
fn mk_mkdir(seq: u64, parent: u64, name: &[u8], mode: u32, ino: u64) -> IntentLogFrame {
    IntentLogFrame::new(
        IntentLogRecord::Mkdir {
            parent,
            name: name.to_vec(),
            mode,
            ino,
        },
        1,
        seq,
    )
}
fn mk_rename(seq: u64, sp: u64, sn: &[u8], dp: u64, dn: &[u8], ino: u64) -> IntentLogFrame {
    IntentLogFrame::new(
        IntentLogRecord::Rename {
            src_parent: sp,
            src_name: sn.to_vec(),
            dst_parent: dp,
            dst_name: dn.to_vec(),
            overwrite_target_ino: None,
            ino,
            rename_flags: 0,
        },
        1,
        seq,
    )
}
fn mk_trunc(seq: u64, ino: u64, new_size: u64) -> IntentLogFrame {
    IntentLogFrame::new(IntentLogRecord::Truncate { ino, new_size }, 1, seq)
}
fn mk_symlink(seq: u64, parent: u64, name: &[u8], target: &[u8], ino: u64) -> IntentLogFrame {
    IntentLogFrame::new(
        IntentLogRecord::Symlink {
            parent,
            name: name.to_vec(),
            target: target.to_vec(),
            ino,
        },
        1,
        seq,
    )
}
fn mk_rmdir(seq: u64, parent: u64, name: &[u8], ino: u64) -> IntentLogFrame {
    IntentLogFrame::new(
        IntentLogRecord::Rmdir {
            parent,
            name: name.to_vec(),
            ino,
        },
        1,
        seq,
    )
}
fn segment(frames: &[IntentLogFrame]) -> Vec<u8> {
    let mut w = IntentLogWriter::new(64 * 1024);
    for f in frames {
        w.append_frame(f).expect("append");
    }
    w.finish().expect("finish").expect("data")
}

#[test]
fn crash_after_create_replay_dispatches_creation() {
    let seg = segment(&[mk_create(1, 1, b"f.txt", 0o644, 100)]);
    let mut e = IntentReplayEngine::new(0);
    let mut h = RecordingHandler::default();
    let o = e.replay_segment(&seg, &mut h).expect("ok");
    assert!(matches!(o, SegmentReplayOutcome::Replayed { .. }));
    assert_eq!(h.records.len(), 1);
    match &h.records[0] {
        IntentLogRecord::Create {
            parent,
            name,
            mode,
            ino,
        } => {
            assert_eq!(*parent, 1);
            assert_eq!(name, b"f.txt");
            assert_eq!(*mode, 0o644);
            assert_eq!(*ino, 100);
        }
        _ => panic!("expected Create"),
    }
}

#[test]
fn replay_multi_operation_transaction_all_dispatched() {
    let seg = segment(&[
        mk_mkdir(1, 1, b"d", 0o755, 200),
        mk_create(2, 200, b"n.txt", 0o644, 300),
        mk_trunc(3, 300, 4096),
    ]);
    let mut e = IntentReplayEngine::new(0);
    let mut h = SemanticHandler::default();
    let o = e.replay_segment(&seg, &mut h).expect("ok");
    assert!(matches!(o, SegmentReplayOutcome::Replayed { .. }));
    assert_eq!(e.state.entries_replayed, 3);
    assert_eq!(h.dispatched.len(), 3);
    assert_eq!(h.dirs_made.len(), 1);
    assert_eq!(h.created.len(), 1);
    assert_eq!(h.truncated.len(), 1);
}

#[test]
fn empty_intent_log_is_noop() {
    let mut e = IntentReplayEngine::new(0);
    let mut h = RecordingHandler::default();
    let o = e.replay_segment(&[0u8; 64], &mut h).expect("ok");
    assert!(matches!(o, SegmentReplayOutcome::Skipped { .. }));
    assert_eq!(e.state.entries_replayed, 0);
    assert!(h.records.is_empty());
}

#[test]
fn truncated_segment_replays_valid_records() {
    let frames: Vec<_> = vec![
        mk_create(1, 1, b"f1", 0o644, 400),
        mk_create(2, 1, b"f2", 0o644, 401),
        mk_create(3, 1, b"f3", 0o644, 402),
    ];
    let mut s = segment(&frames);
    s.truncate(s.len().saturating_sub(200));
    let mut e = IntentReplayEngine::new(0);
    let mut h = RecordingHandler::default();
    let o = e.replay_segment(&s, &mut h).expect("ok");
    assert!(matches!(o, SegmentReplayOutcome::Replayed { .. }));
    assert!(
        e.state.entries_replayed > 0,
        "should replay at least one record"
    );
    assert!(h.records.len() <= 3, "cannot exceed original record count");
}

#[test]
fn replay_is_idempotent_on_repeat() {
    let seg = segment(&[
        mk_create(1, 1, b"f.txt", 0o644, 500),
        mk_mkdir(2, 1, b"d", 0o755, 501),
    ]);
    let mut e1 = IntentReplayEngine::new(0);
    let mut h1 = SemanticHandler::default();
    e1.replay_segment(&seg, &mut h1).expect("first");
    assert_eq!(e1.state.entries_replayed, 2);
    let mut e2 = IntentReplayEngine::new(2);
    let mut h2 = SemanticHandler::default();
    let o2 = e2.replay_segment(&seg, &mut h2).expect("second");
    assert!(matches!(
        o2,
        SegmentReplayOutcome::Skipped {
            reason: SkippedReason::AllApplied
        }
    ));
    assert_eq!(e2.state.entries_skipped, 2);
    assert!(h2.dispatched.is_empty());
}

#[test]
fn crash_after_unlink_replay_dispatches_unlink() {
    let seg = segment(&[mk_unlink(1, 1, b"stale.txt", 600)]);
    let mut e = IntentReplayEngine::new(0);
    let mut h = SemanticHandler::default();
    e.replay_segment(&seg, &mut h).expect("ok");
    assert_eq!(h.unlinked.len(), 1);
    assert!(h.unlinked[0].contains("stale.txt"));
}

#[test]
fn crash_after_rename_replay_dispatches_rename() {
    let seg = segment(&[mk_rename(1, 1, b"old.txt", 1, b"new.txt", 700)]);
    let mut e = IntentReplayEngine::new(0);
    let mut h = SemanticHandler::default();
    e.replay_segment(&seg, &mut h).expect("ok");
    assert_eq!(h.renamed.len(), 1);
    assert_eq!(h.renamed[0], ("old.txt".to_string(), "new.txt".to_string()));
}

#[test]
fn checkpoint_determinism() {
    let mut e1 = IntentReplayEngine::new(42);
    e1.state.entries_replayed = 100;
    e1.state.entries_skipped = 20;
    e1.state.highest_lsn_seen = 150;
    let cp1 = e1.compute_checkpoint();
    let cp2 = e1.compute_checkpoint();
    assert_eq!(cp1.digest, cp2.digest);
    let mut e2 = IntentReplayEngine::new(42);
    e2.state.entries_replayed = 101;
    assert_ne!(cp1.digest, e2.compute_checkpoint().digest);
}

#[test]
fn replay_mixed_record_types() {
    let seg = segment(&[
        mk_create(1, 1, b"a.txt", 0o644, 800),
        mk_mkdir(2, 1, b"sub", 0o755, 801),
        mk_create(3, 801, b"b.txt", 0o644, 802),
        mk_trunc(4, 800, 1024),
    ]);
    let mut e = IntentReplayEngine::new(0);
    let mut h = SemanticHandler::default();
    e.replay_segment(&seg, &mut h).expect("ok");
    assert_eq!(e.state.entries_replayed, 4);
    assert_eq!(h.created.len(), 2);
    assert_eq!(h.dirs_made.len(), 1);
    assert_eq!(h.truncated.len(), 1);
}

#[test]
fn replay_multiple_segments() {
    let s1 = segment(&[
        mk_create(1, 1, b"s1a", 0o644, 900),
        mk_create(2, 1, b"s1b", 0o644, 901),
    ]);
    let s2 = segment(&[
        mk_create(3, 1, b"s2a", 0o644, 902),
        mk_unlink(4, 1, b"s1b", 901),
    ]);
    let mut e = IntentReplayEngine::new(0);
    let mut h = SemanticHandler::default();
    e.replay_segment(&s1, &mut h).expect("s1");
    e.replay_segment(&s2, &mut h).expect("s2");
    assert_eq!(h.created.len(), 3);
    assert_eq!(h.unlinked.len(), 1);
    assert_eq!(e.state.entries_replayed, 4);
    assert_eq!(e.state.highest_lsn_seen, 4);
}

#[test]
fn corrupt_segment_skipped() {
    let mut e = IntentReplayEngine::new(0);
    let mut h = RecordingHandler::default();
    let o = e.replay_segment(&[0xFFu8; 256], &mut h).expect("ok");
    assert!(matches!(
        o,
        SegmentReplayOutcome::Skipped {
            reason: SkippedReason::Corrupt
        }
    ));
    assert_eq!(e.state.entries_replayed, 0);
    assert!(h.records.is_empty());
}

#[test]
fn symlink_replay() {
    let seg = segment(&[mk_symlink(1, 1, b"lnk", b"/etc/hosts", 1000)]);
    let mut e = IntentReplayEngine::new(0);
    let mut h = RecordingHandler::default();
    e.replay_segment(&seg, &mut h).expect("ok");
    assert_eq!(h.records.len(), 1);
    assert!(matches!(h.records[0], IntentLogRecord::Symlink { .. }));
}

#[test]
fn rmdir_replay() {
    let seg = segment(&[mk_rmdir(1, 1, b"d", 1100)]);
    let mut e = IntentReplayEngine::new(0);
    let mut h = SemanticHandler::default();
    e.replay_segment(&seg, &mut h).expect("ok");
    assert_eq!(h.dirs_removed.len(), 1);
    assert!(h.dirs_removed[0].contains("d"));
}

#[test]
fn checkpoint_32_bytes() {
    let e = IntentReplayEngine::new(0);
    assert_eq!(e.compute_checkpoint().digest.len(), 32);
}

#[test]
fn verify_checkpoint() {
    let mut e = IntentReplayEngine::new(7);
    e.state.entries_replayed = 5;
    e.state.highest_lsn_seen = 10;
    let cp = e.compute_checkpoint();
    assert!(e.verify_checkpoint(&cp));
    e.state.entries_replayed += 1;
    assert!(!e.verify_checkpoint(&cp));
}

#[test]
fn non_replayable_records_skipped() {
    let flush = IntentLogFrame::new(
        IntentLogRecord::Flush {
            ino: 1,
            fh: 42,
            lock_owner: 0,
        },
        1,
        1,
    );
    let fsync = IntentLogFrame::new(
        IntentLogRecord::Fsync {
            ino: 1,
            fh: 42,
            mode: 0,
        },
        1,
        2,
    );
    let seg = segment(&[flush, fsync, mk_create(3, 1, b"real.txt", 0o644, 1200)]);
    let mut e = IntentReplayEngine::new(0);
    let mut h = SemanticHandler::default();
    e.replay_segment(&seg, &mut h).expect("ok");
    assert_eq!(e.state.entries_replayed, 1);
    assert_eq!(e.state.entries_skipped, 2);
}

#[test]
fn state_tracks_correctly() {
    let seg = segment(&[
        mk_create(1, 1, b"f1", 0o644, 1300),
        mk_create(2, 1, b"f2", 0o644, 1301),
        mk_create(3, 1, b"f3", 0o644, 1302),
    ]);
    let mut e = IntentReplayEngine::new(1);
    let mut h = RecordingHandler::default();
    e.replay_segment(&seg, &mut h).expect("ok");
    assert_eq!(e.state.entries_replayed, 2);
    assert_eq!(e.state.entries_skipped, 1);
    assert_eq!(e.state.highest_lsn_seen, 3);
    assert_eq!(e.state.total_processed(), 3);
}
