//! CommitGroup smoke: deterministic dirty tracking, accumulation, sync-gate, and
//! journal payload checks over `tidefs-commit_group`.
//!
//! Gated on `feature = "fuse"`.

use std::io::ErrorKind;

use crate::smoke::SmokeHarness;
use crate::trace::{deserialize_trace, serialize_trace, TraceEvent};
use tidefs_commit_group::{
    CommitGroupAccumulator, CommitGroupCommit, CommitGroupError, CommitGroupId, CommitGroupState,
    CommitGroupSync, DirtyMetaFlags, DirtyRange, DirtyTracker, InodeTableCommit, NamespaceCommit,
    NoopInodeTable, NoopNamespace, RecoveryResult, SyncGate,
};

/// Run the full commit_group smoke sequence and return the harness.
#[must_use]
pub fn run_commit_group_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("commit_group/smoke");
    smoke_commit_group_id_and_state(&mut h);
    smoke_dirty_tracker(&mut h);
    smoke_accumulator(&mut h);
    smoke_sync_gate(&mut h);
    smoke_recovery_and_journal_types(&mut h);
    smoke_error_variants(&mut h);
    h.scenario_end("commit_group/smoke");

    let trace_before_round_trip = h.trace.clone();
    let serialized = serialize_trace(&trace_before_round_trip)
        .expect("commit_group smoke trace should serialize");
    let decoded =
        deserialize_trace(&serialized).expect("commit_group smoke trace should deserialize");
    h.assert_eq_ev(
        "commit_group smoke trace round-trips",
        decoded,
        trace_before_round_trip,
    );

    h
}

fn smoke_commit_group_id_and_state(h: &mut SmokeHarness) {
    record_commit_group_op(h, "commit_group.id.first", CommitGroupId::FIRST, b"first");

    h.assert_ev(
        "CommitGroupId::NIL is invalid",
        !CommitGroupId::NIL.is_valid(),
    );
    h.assert_ev(
        "CommitGroupId::FIRST is valid",
        CommitGroupId::FIRST.is_valid(),
    );
    h.assert_eq_ev(
        "CommitGroupId::FIRST.next is commit_group 2",
        CommitGroupId::FIRST.next(),
        CommitGroupId(2),
    );
    h.assert_eq_ev(
        "CommitGroupId display is stable",
        CommitGroupId(7).to_string(),
        "commit_group-7".to_string(),
    );

    let states = [
        CommitGroupState::Open,
        CommitGroupState::Committing,
        CommitGroupState::Committed,
        CommitGroupState::Synced,
    ];
    h.assert_eq_ev(
        "commit_group state catalog has four states",
        states.len(),
        4usize,
    );
    h.assert_eq_ev(
        "commit_group committed state is matchable",
        states[2],
        CommitGroupState::Committed,
    );
}

fn smoke_dirty_tracker(h: &mut SmokeHarness) {
    let mut tracker = DirtyTracker::new();

    record_commit_group_op(h, "commit_group.dirty.new", CommitGroupId::FIRST, b"empty");
    h.assert_ev("new dirty tracker is empty", tracker.is_empty());

    record_commit_group_op(
        h,
        "commit_group.dirty.mark_range",
        CommitGroupId::FIRST,
        b"ino=11 offset=0 len=4096",
    );
    tracker.mark_dirty(11, 0, 4096);
    tracker.mark_dirty(11, 4096, 2048);
    tracker.mark_dirty(12, 128, 256);
    tracker.mark_dirty(13, 64, 0);
    tracker.mark_meta_dirty(11, DirtyMetaFlags::SIZE | DirtyMetaFlags::MTIME);

    h.assert_eq_ev(
        "zero-length dirty mark is ignored",
        tracker.has_dirty_data(13),
        false,
    );
    h.assert_eq_ev(
        "dirty tracker reports sorted dirty inodes",
        tracker.dirty_inodes(),
        vec![11, 12],
    );
    h.assert_eq_ev(
        "dirty tracker counts two dirty inodes",
        tracker.dirty_inode_count(),
        2usize,
    );
    h.assert_ev("inode 11 has dirty data", tracker.has_dirty_data(11));
    h.assert_ev("inode 11 has dirty metadata", tracker.has_dirty_meta(11));
    h.assert_ev(
        "inode 11 dirty metadata contains size and mtime",
        tracker
            .dirty_meta(11)
            .contains(DirtyMetaFlags::SIZE | DirtyMetaFlags::MTIME),
    );

    let ranges = tracker.dirty_ranges(11);
    h.assert_eq_ev(
        "adjacent dirty ranges coalesce",
        ranges,
        vec![DirtyRange::new(11, 0, 6144)],
    );
    h.assert_eq_ev(
        "dirty range exposes exclusive byte range",
        DirtyRange::new(11, 0, 6144).as_range(),
        0..6144,
    );

    record_commit_group_op(
        h,
        "commit_group.dirty.clear",
        CommitGroupId::FIRST,
        b"ino=11",
    );
    tracker.clear_dirty(11);
    h.assert_ev(
        "clear_dirty removes inode 11 data",
        !tracker.has_dirty_data(11),
    );
    h.assert_ev(
        "clear_dirty removes inode 11 metadata",
        !tracker.has_dirty_meta(11),
    );
    h.assert_eq_ev(
        "inode 12 remains dirty after clearing inode 11",
        tracker.dirty_inodes(),
        vec![12],
    );

    record_commit_group_op(
        h,
        "commit_group.dirty.remove_inode",
        CommitGroupId::FIRST,
        b"ino=12",
    );
    tracker.remove_inode(12);
    h.assert_ev("remove_inode clears final dirty state", tracker.is_empty());
}

fn smoke_accumulator(h: &mut SmokeHarness) {
    let mut accumulator = CommitGroupAccumulator::new(CommitGroupId::FIRST);

    record_commit_group_op(
        h,
        "commit_group.accumulator.new",
        accumulator.commit_group_id(),
        b"open",
    );
    h.assert_eq_ev(
        "accumulator owns first commit_group",
        accumulator.commit_group_id(),
        CommitGroupId::FIRST,
    );
    h.assert_eq_ev(
        "new accumulator starts open",
        accumulator.state(),
        CommitGroupState::Open,
    );
    h.assert_ev("new accumulator is empty", accumulator.is_empty());

    record_commit_group_op(
        h,
        "commit_group.accumulator.queue_write",
        CommitGroupId::FIRST,
        b"ino=40 offset=0",
    );
    accumulator.queue_write(40, 0, b"alpha".to_vec());
    h.assert_eq_ev(
        "queued write count is one",
        accumulator.write_count(),
        1usize,
    );
    h.assert_eq_ev(
        "queued write data is retained",
        accumulator.writes()[0].data.clone(),
        b"alpha".to_vec(),
    );

    record_commit_group_op(
        h,
        "commit_group.accumulator.queue_setattr",
        CommitGroupId::FIRST,
        b"ino=40",
    );
    accumulator.queue_setattr(40, DirtyMetaFlags::SIZE, Some(5), None, None);
    accumulator.queue_setattr(40, DirtyMetaFlags::MTIME, None, Some(100), None);
    h.assert_eq_ev(
        "setattrs coalesce by inode",
        accumulator.setattr_count(),
        1usize,
    );
    h.assert_ev(
        "coalesced setattr keeps size and mtime flags",
        accumulator.setattrs()[0]
            .attr_mask
            .contains(DirtyMetaFlags::SIZE | DirtyMetaFlags::MTIME),
    );
    h.assert_eq_ev(
        "coalesced setattr keeps size",
        accumulator.setattrs()[0].new_size,
        Some(5),
    );
    h.assert_eq_ev(
        "coalesced setattr keeps mtime",
        accumulator.setattrs()[0].new_mtime,
        Some(100),
    );

    record_commit_group_op(
        h,
        "commit_group.accumulator.queue_link_unlink",
        CommitGroupId::FIRST,
        b"dir=2",
    );
    accumulator
        .queue_link(2, b"name".to_vec(), 40)
        .expect("queue_link should succeed");
    accumulator
        .queue_unlink(2, b"old-name".to_vec(), &[])
        .expect("queue_unlink should succeed");
    h.assert_eq_ev("link count is one", accumulator.link_count(), 1usize);
    h.assert_eq_ev("unlink count is one", accumulator.unlink_count(), 1usize);

    record_commit_group_op(
        h,
        "commit_group.accumulator.mark_committing",
        CommitGroupId::FIRST,
        b"commit",
    );
    accumulator.mark_committing();
    h.assert_eq_ev(
        "mark_committing updates state",
        accumulator.state(),
        CommitGroupState::Committing,
    );

    let retry = accumulator.clone_for_retry();
    let mut merged = CommitGroupAccumulator::new(CommitGroupId(2));
    merged.merge(&retry);
    h.assert_eq_ev("merge copies queued writes", merged.write_count(), 1usize);
    h.assert_eq_ev(
        "merge copies queued setattrs",
        merged.setattr_count(),
        1usize,
    );
    h.assert_eq_ev("merge copies queued links", merged.link_count(), 1usize);
    h.assert_eq_ev("merge copies queued unlinks", merged.unlink_count(), 1usize);

    let (writes, setattrs, links, unlinks) = merged.drain();
    h.assert_eq_ev("drain returns queued writes", writes.len(), 1usize);
    h.assert_eq_ev("drain returns queued setattrs", setattrs.len(), 1usize);
    h.assert_eq_ev("drain returns queued links", links.len(), 1usize);
    h.assert_eq_ev("drain returns queued unlinks", unlinks.len(), 1usize);
}

fn smoke_sync_gate(h: &mut SmokeHarness) {
    let gate = SyncGate::new();
    let sync = CommitGroupSync::new(gate.clone());

    record_commit_group_op(
        h,
        "commit_group.sync.clean_fsync",
        CommitGroupId::NIL,
        b"ino=99",
    );
    h.assert_eq_ev(
        "clean inode fsync returns immediately",
        sync.fsync(99),
        Ok(()),
    );
    h.assert_eq_ev(
        "new sync gate has nil durable commit_group",
        gate.durable_commit_group(),
        CommitGroupId::NIL,
    );

    record_commit_group_op(
        h,
        "commit_group.sync.register_notify",
        CommitGroupId(3),
        b"ino=40",
    );
    gate.register_dirty(40, CommitGroupId(3));
    gate.notify_committed(CommitGroupId(3));
    h.assert_eq_ev(
        "notify_committed advances durable commit_group",
        gate.durable_commit_group(),
        CommitGroupId(3),
    );
    h.assert_eq_ev(
        "fsync observes already-signaled barrier",
        sync.fsync(40),
        Ok(()),
    );
    h.assert_eq_ev(
        "CommitGroupSync exposes the same gate",
        sync.gate().durable_commit_group(),
        CommitGroupId(3),
    );

    gate.notify_committed(CommitGroupId(2));
    h.assert_eq_ev(
        "durable commit_group does not regress",
        gate.durable_commit_group(),
        CommitGroupId(3),
    );
    gate.notify_synced();
}

fn smoke_recovery_and_journal_types(h: &mut SmokeHarness) {
    record_commit_group_op(
        h,
        "commit_group.recovery.result",
        CommitGroupId(5),
        b"manual-result",
    );
    let recovery = RecoveryResult {
        highest_committed_commit_group: CommitGroupId(5),
        next_commit_group_id: CommitGroupId(6),
        committed_keys: Vec::new(),
        torn_commit_groups: vec![CommitGroupId(4)],
        replayed_commit_groups: vec![CommitGroupId(3)],
    };
    h.assert_eq_ev(
        "recovery tracks highest committed commit_group",
        recovery.highest_committed_commit_group,
        CommitGroupId(5),
    );
    h.assert_eq_ev(
        "recovery tracks next commit_group id",
        recovery.next_commit_group_id,
        CommitGroupId(6),
    );
    h.assert_eq_ev(
        "recovery tracks torn commit_groups",
        recovery.torn_commit_groups,
        vec![CommitGroupId(4)],
    );
    h.assert_eq_ev(
        "recovery tracks replayed commit_groups",
        recovery.replayed_commit_groups,
        vec![CommitGroupId(3)],
    );

    record_commit_group_op(
        h,
        "commit_group.journal.parse",
        CommitGroupId(7),
        b"empty-journal",
    );
    let mut payload = Vec::new();
    payload.extend_from_slice(&7u64.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    let parsed = CommitGroupCommit::parse_journal_payload(&payload)
        .expect("empty commit_group journal payload should parse");
    h.assert_eq_ev(
        "journal parser returns commit_group id",
        parsed.0,
        CommitGroupId(7),
    );
    h.assert_ev("journal parser returns no keys", parsed.1.is_empty());
    h.assert_ev("journal parser returns no inodes", parsed.2.is_empty());
    h.assert_ev(
        "truncated journal payload is rejected",
        CommitGroupCommit::parse_journal_payload(&[0u8; 4]).is_none(),
    );

    let mut inode_table = NoopInodeTable;
    let mut namespace = NoopNamespace;
    h.assert_eq_ev(
        "noop inode table accepts setattr",
        inode_table.apply_setattr(40, Some(5), Some(100), Some(101)),
        Ok(()),
    );
    h.assert_eq_ev(
        "noop namespace accepts link",
        namespace.apply_link(2, b"name", 40),
        Ok(()),
    );
    h.assert_eq_ev(
        "noop namespace accepts unlink",
        namespace.apply_unlink(2, b"old-name"),
        Ok(()),
    );
}

fn smoke_error_variants(h: &mut SmokeHarness) {
    record_commit_group_op(
        h,
        "commit_group.error.variants",
        CommitGroupId::NIL,
        b"errors",
    );
    let errors = [
        CommitGroupError::StorePutFailed {
            ino: 1,
            offset: 0,
            reason: "put".to_string(),
        },
        CommitGroupError::StoreDeleteFailed {
            key: "object".to_string(),
            reason: "delete".to_string(),
        },
        CommitGroupError::ExtentMapFailed {
            ino: 2,
            reason: "extent".to_string(),
        },
        CommitGroupError::UnlinkWithDirtyWrites { ino: 3 },
        CommitGroupError::EmptyCommitGroup,
        CommitGroupError::RecoveryFailed {
            commit_group_id: CommitGroupId(4),
            reason: "recovery".to_string(),
        },
        CommitGroupError::Io(ErrorKind::Other),
    ];

    h.assert_eq_ev(
        "commit_group error catalog covers seven variants",
        errors.len(),
        7usize,
    );
    h.assert_ev(
        "empty commit_group error display is stable",
        CommitGroupError::EmptyCommitGroup
            .to_string()
            .contains("empty"),
    );
    h.assert_ev(
        "store put error is matchable",
        matches!(
            &errors[0],
            CommitGroupError::StorePutFailed {
                ino: 1,
                offset: 0,
                ..
            }
        ),
    );
}

fn record_commit_group_op(
    h: &mut SmokeHarness,
    op_name: &str,
    commit_group_id: CommitGroupId,
    payload: &[u8],
) {
    h.record(TraceEvent::FsLifecycleOp {
        inode_id: commit_group_id.0,
        op_name: op_name.to_string(),
        payload: payload.to_vec(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_group_smoke_passes() {
        let h = run_commit_group_smoke();
        for event in &h.trace {
            if let TraceEvent::Assert {
                passed,
                ref condition,
            } = event
            {
                assert!(passed, "assertion failed: {condition}");
            }
        }
    }
}
