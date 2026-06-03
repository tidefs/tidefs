//! Scheduler smoke: deterministic writeback scheduling checks over
//! `tidefs-posix-filesystem-adapter-daemon (scheduler module)`.
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::{deserialize_trace, serialize_trace, TraceEvent};
use tidefs_posix_filesystem_adapter_daemon::scheduler::{
    DirtyExtentScheduler, DirtyExtentSchedulerError, WritebackDirtyPageRecord,
    WritebackDirtyScanBatch, WritebackDispatchError, WritebackDispatchState,
    WritebackLifecycleEventDraft, WritebackLifecycleEventKind, WritebackLifecycleStatus,
    WritebackLifecycleTrace, WritebackQueue, WritebackQueueError, WritebackWorkItem,
};
use tidefs_types_posix_filesystem_adapter_core::PosixFilesystemAdapterWriteStagingOutcome;

/// Run the full scheduler smoke sequence and return the harness.
#[must_use]
pub fn run_scheduler_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("scheduler/smoke");
    smoke_dirty_extent_scheduler(&mut h);
    smoke_writeback_queue(&mut h);
    smoke_dirty_scan_batch(&mut h);
    smoke_dispatch_state_and_lifecycle(&mut h);
    h.scenario_end("scheduler/smoke");

    let trace_before_round_trip = h.trace.clone();
    let serialized =
        serialize_trace(&trace_before_round_trip).expect("scheduler smoke trace should serialize");
    let decoded = deserialize_trace(&serialized).expect("scheduler smoke trace should deserialize");
    h.assert_eq_ev(
        "scheduler smoke trace round-trips",
        decoded,
        trace_before_round_trip,
    );

    h
}

fn smoke_dirty_extent_scheduler(h: &mut SmokeHarness) {
    let mut scheduler = DirtyExtentScheduler::<2>::new();
    record_scheduler_op(h, "scheduler.dirty_extent.new", 0, b"cap=2");

    h.assert_ev("dirty extent scheduler starts empty", scheduler.is_empty());
    h.assert_eq_ev(
        "dirty extent scheduler len starts at zero",
        scheduler.len(),
        0,
    );

    let first_id = scheduler
        .submit_dirty_extent(staging_outcome(70, 42, 0, 4096))
        .expect("first dirty extent should enqueue");
    let second_id = scheduler
        .submit_dirty_extent(staging_outcome(71, 42, 4096, 4096))
        .expect("second dirty extent should enqueue");
    record_scheduler_op(h, "scheduler.dirty_extent.submit", 42, b"two-extents");

    h.assert_eq_ev("dirty extent ids start at one", first_id, 1);
    h.assert_eq_ev("dirty extent ids increment", second_id, 2);
    h.assert_ev("dirty extent scheduler reports full", scheduler.is_full());
    h.assert_eq_ev("dirty extent scheduler keeps two items", scheduler.len(), 2);
    h.assert_eq_ev(
        "dirty extent slice preserves first work id",
        scheduler.as_slice()[0].work_item_id,
        1,
    );
    h.assert_eq_ev(
        "dirty extent slice preserves second offset",
        scheduler.as_slice()[1].offset,
        4096,
    );
    h.assert_eq_ev(
        "dirty extent scheduler refuses overflow",
        scheduler.submit_dirty_extent(staging_outcome(72, 42, 8192, 4096)),
        Err(DirtyExtentSchedulerError::Full),
    );
}

fn smoke_writeback_queue(h: &mut SmokeHarness) {
    let mut queue = WritebackQueue::<4>::new();
    record_scheduler_op(h, "scheduler.writeback_queue.new", 0, b"cap=4");

    h.assert_ev("writeback queue starts empty", queue.is_empty());
    h.assert_eq_ev("writeback queue capacity is exposed", queue.capacity(), 4);
    h.assert_eq_ev(
        "writeback queue remaining capacity starts full",
        queue.remaining_capacity(),
        4,
    );

    queue
        .push(item(30, 3, 4096, 10))
        .expect("push commit_group 3");
    queue
        .push(item(10, 1, 4096, 20))
        .expect("push commit_group 1");
    queue
        .push(item(20, 2, 8192, 5))
        .expect("push commit_group 2");
    record_scheduler_op(
        h,
        "scheduler.writeback_queue.push",
        0,
        b"commit_group=3,1,2",
    );

    h.assert_eq_ev("writeback queue len tracks pushes", queue.len(), 3);
    h.assert_eq_ev(
        "writeback queue remaining capacity decrements",
        queue.remaining_capacity(),
        1,
    );
    h.assert_eq_ev(
        "writeback queue peeks lowest commit_group first",
        queue.peek().expect("peek queued work").commit_group_id,
        1,
    );
    h.assert_eq_ev(
        "writeback queue pops lowest commit_group first",
        queue.pop().expect("pop first queued item").commit_group_id,
        1,
    );

    queue
        .push(item(11, 1, 2048, 30))
        .expect("push commit_group 1");
    queue
        .push(item(12, 1, 8192, 30))
        .expect("push commit_group 1");
    h.assert_ev("writeback queue is full after refill", queue.is_full());
    h.assert_eq_ev(
        "writeback queue refuses over-capacity push",
        queue.push(item(99, 9, 1024, 1)),
        Err(WritebackQueueError::Full),
    );

    let drained = queue.drain_commit_group(1);
    record_scheduler_op(
        h,
        "scheduler.writeback_queue.drain_commit_group",
        1,
        b"commit_group=1",
    );
    h.assert_eq_ev(
        "drain_commit_group returns matching item count",
        drained.len(),
        2,
    );
    h.assert_ev(
        "drain_commit_group removes matching commit_group from queue",
        !queue.contains_commit_group(1),
    );
    h.assert_eq_ev(
        "drain_commit_group preserves priority order within commit_group",
        drained.as_slice()[0].dirty_byte_count,
        8192,
    );
}

fn smoke_dirty_scan_batch(h: &mut SmokeHarness) {
    let mut batch = WritebackDirtyScanBatch::<4>::new();
    record_scheduler_op(h, "scheduler.dirty_scan.new", 0, b"cap=4");

    h.assert_ev("dirty scan batch starts empty", batch.is_empty());
    h.assert_eq_ev("dirty scan batch exposes capacity", batch.capacity(), 4);

    batch
        .push(dirty(7, 0, 4096, 12, 4096, 15))
        .expect("push first dirty page");
    batch
        .push(dirty(7, 4096, 8192, 12, 4096, 25))
        .expect("push adjacent dirty page");
    batch
        .push(dirty(8, 0, 4096, 13, 2048, 5))
        .expect("push non-adjacent dirty page");
    record_scheduler_op(h, "scheduler.dirty_scan.push", 7, b"group-adjacent");

    h.assert_eq_ev("dirty scan batch len tracks records", batch.len(), 3);
    h.assert_eq_ev(
        "dirty scan slice preserves first object id",
        batch.as_slice()[0].object_id,
        7,
    );

    let groups = batch.group_adjacent();
    h.assert_eq_ev("dirty scan groups adjacent ranges", groups.len(), 2);
    h.assert_eq_ev(
        "grouped range extends across adjacent records",
        groups.as_slice()[0].offset_end,
        8192,
    );
    h.assert_eq_ev(
        "grouped range sums dirty bytes",
        groups.as_slice()[0].dirty_byte_count,
        8192,
    );
    h.assert_eq_ev(
        "grouped range keeps oldest dirty age",
        groups.as_slice()[0].oldest_dirty_age_ms,
        25,
    );

    let mut state = WritebackDispatchState::<4, 2>::new();
    let summary = batch
        .enqueue_grouped(&mut state)
        .expect("grouped scan should enqueue");
    h.assert_eq_ev(
        "dirty scan enqueue scans three records",
        summary.scanned_records,
        3,
    );
    h.assert_eq_ev(
        "dirty scan enqueue groups two items",
        summary.grouped_items,
        2,
    );
    h.assert_eq_ev("dirty scan enqueue queues two items", state.queued_len(), 2);
}

fn smoke_dispatch_state_and_lifecycle(h: &mut SmokeHarness) {
    let mut state = WritebackDispatchState::<4, 2>::new();
    let mut lifecycle = WritebackLifecycleTrace::<8>::new();
    let mut batch = WritebackDirtyScanBatch::<4>::new();

    batch
        .push(dirty(100, 0, 4096, 21, 4096, 20))
        .expect("push first commit_group dirty record");
    batch
        .push(dirty(100, 4096, 8192, 21, 4096, 40))
        .expect("push second commit_group dirty record");

    let summary = batch
        .enqueue_grouped(&mut state)
        .expect("enqueue grouped dirty scan");
    record_scheduler_op(
        h,
        "scheduler.dispatch.enqueue_grouped",
        100,
        b"commit_group=21",
    );
    let scan_event = lifecycle
        .record_scan_enqueue(summary, state.queued_len())
        .expect("record scan enqueue");
    h.assert_eq_ev(
        "lifecycle scan event records accepted status",
        scan_event.status,
        WritebackLifecycleStatus::Accepted,
    );
    h.assert_eq_ev("dispatch state tracks queued group", state.queued_len(), 1);

    let ticket = state.dispatch_next().expect("dispatch queued item");
    let started = lifecycle
        .record_dispatch_started(ticket, state.queued_len(), state.in_flight_len())
        .expect("record dispatch start");
    h.assert_eq_ev("dispatch ticket id starts at one", ticket.ticket_id, 1);
    h.assert_eq_ev(
        "dispatch moves queue item in-flight",
        state.in_flight_len(),
        1,
    );
    h.assert_eq_ev(
        "lifecycle dispatch event records ticket",
        started.ticket_id,
        ticket.ticket_id,
    );

    state.retry(ticket.ticket_id).expect("retry first ticket");
    lifecycle
        .record_dispatch_retried(
            ticket.ticket_id,
            ticket.item,
            state.queued_len(),
            state.in_flight_len(),
        )
        .expect("record dispatch retry");
    h.assert_eq_ev("retry clears in-flight slot", state.in_flight_len(), 0);
    h.assert_eq_ev("retry requeues work", state.queued_len(), 1);

    let retried = state.dispatch_next().expect("redispatch retried work");
    lifecycle
        .record_dispatch_started(retried, state.queued_len(), state.in_flight_len())
        .expect("record redispatch");
    let completed = state
        .complete(retried.ticket_id)
        .expect("complete retried ticket");
    lifecycle
        .record_dispatch_completed(
            retried.ticket_id,
            completed,
            state.queued_len(),
            state.in_flight_len(),
        )
        .expect("record dispatch completion");
    record_scheduler_op(h, "scheduler.dispatch.complete", 100, b"retry-complete");

    h.assert_eq_ev("complete clears in-flight state", state.in_flight_len(), 0);
    h.assert_eq_ev("complete leaves queue empty", state.queued_len(), 0);
    h.assert_ev(
        "commit_group is idle after completion",
        state.is_commit_group_idle(21),
    );
    h.assert_eq_ev(
        "unknown ticket completion returns error",
        state.complete(99),
        Err(WritebackDispatchError::UnknownTicket),
    );

    let manual = lifecycle
        .record(
            WritebackLifecycleEventDraft::new(
                WritebackLifecycleEventKind::CommitGroupFlushCompleted,
                WritebackLifecycleStatus::Completed,
            )
            .with_commit_group_object(21, 100)
            .with_counts(0, 1, 8192)
            .with_depths(state.queued_len(), state.in_flight_len()),
        )
        .expect("record manual lifecycle event");
    h.assert_eq_ev(
        "manual lifecycle event increments sequence",
        manual.sequence_id,
        lifecycle.len() as u64,
    );

    let events = lifecycle.as_slice();
    h.assert_eq_ev("lifecycle trace records six events", events.len(), 6);
    h.assert_eq_ev(
        "lifecycle first event is scan enqueue",
        events[0].kind,
        WritebackLifecycleEventKind::DirtyScanEnqueued,
    );
    h.assert_eq_ev(
        "lifecycle retry event records retried status",
        events[2].status,
        WritebackLifecycleStatus::Retried,
    );
    h.assert_eq_ev(
        "lifecycle final event records completion",
        events[5].status,
        WritebackLifecycleStatus::Completed,
    );
}

fn staging_outcome(
    unique: u64,
    inode: u64,
    offset: u64,
    length: u32,
) -> PosixFilesystemAdapterWriteStagingOutcome {
    PosixFilesystemAdapterWriteStagingOutcome {
        unique,
        inode,
        offset,
        length,
        buffer_handle: unique + 1000,
        content_hash64: unique ^ inode,
        write_flags: 0,
        _reserved: [0_u32; 1],
    }
}

fn item(
    object_id: u64,
    commit_group_id: u64,
    dirty_byte_count: u64,
    oldest_dirty_age_ms: u64,
) -> WritebackWorkItem {
    WritebackWorkItem::new(
        object_id,
        0,
        dirty_byte_count,
        commit_group_id,
        dirty_byte_count,
        oldest_dirty_age_ms,
    )
}

fn dirty(
    object_id: u64,
    offset_start: u64,
    offset_end: u64,
    commit_group_id: u64,
    dirty_byte_count: u64,
    dirty_age_ms: u64,
) -> WritebackDirtyPageRecord {
    WritebackDirtyPageRecord::new(
        object_id,
        offset_start,
        offset_end,
        commit_group_id,
        dirty_byte_count,
        dirty_age_ms,
    )
}

fn record_scheduler_op(h: &mut SmokeHarness, op_name: &str, object_id: u64, payload: &[u8]) {
    h.record(TraceEvent::FsLifecycleOp {
        inode_id: object_id,
        op_name: op_name.to_string(),
        payload: payload.to_vec(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_smoke_passes() {
        let h = run_scheduler_smoke();
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
