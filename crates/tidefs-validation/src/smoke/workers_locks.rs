// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Workers-locks smoke: deterministic lock-wait dispatch and POSIX advisory
//! byte-range lock checks over `tidefs-posix-filesystem-adapter-workers-locks`.
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::{deserialize_trace, serialize_trace, TraceEvent};
use tidefs_posix_filesystem_adapter_workers_locks::{
    dispatch_lock_wait, is_blocking_lock, is_lock_wait_request, lock_wait_shard_key, LockList,
    LockRange, LockTracker, LockType, SEAM_FAMILY_DOC,
};
use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterRequestClass, PosixFilesystemAdapterRequestContextMirrorRecord,
    PosixFilesystemAdapterShardKeyPolicy,
};

/// Run the full workers-locks smoke sequence and return the harness.
#[must_use]
pub fn run_workers_locks_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("workers-locks/smoke");
    smoke_dispatch_helpers(&mut h);
    smoke_lock_tracker_conflict_and_release(&mut h);
    smoke_lock_list_split_and_merge(&mut h);
    h.scenario_end("workers-locks/smoke");

    let trace_before_round_trip = h.trace.clone();
    let serialized = serialize_trace(&trace_before_round_trip)
        .expect("workers-locks smoke trace should serialize");
    let decoded =
        deserialize_trace(&serialized).expect("workers-locks smoke trace should deserialize");
    h.assert_eq_ev(
        "workers-locks smoke trace round-trips",
        decoded,
        trace_before_round_trip,
    );

    h
}

fn smoke_dispatch_helpers(h: &mut SmokeHarness) {
    record_lock_op(h, 44, "workers_locks.dispatch", b"context");
    let ctx = lock_ctx(900, 44);
    h.assert_ev("lock wait class is detected", is_lock_wait_request(&ctx));
    h.assert_eq_ev(
        "lock wait shard key uses nodeid",
        lock_wait_shard_key(44),
        44,
    );

    let dispatched = dispatch_lock_wait(ctx);
    h.assert_eq_ev("dispatch preserves unique", dispatched.unique, ctx.unique);
    h.assert_eq_ev("dispatch preserves nodeid", dispatched.nodeid, ctx.nodeid);
    h.assert_eq_ev(
        "dispatch preserves request class",
        dispatched.request_class,
        PosixFilesystemAdapterRequestClass::LockWait.as_u32(),
    );
    h.assert_eq_ev(
        "dispatch preserves shard policy",
        dispatched.shard_key_policy,
        PosixFilesystemAdapterShardKeyPolicy::LockScope.as_u32(),
    );

    let file_read_ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
        request_class: PosixFilesystemAdapterRequestClass::FileRead.as_u32(),
        ..Default::default()
    };
    h.assert_ev(
        "non-lock class is rejected by lock detector",
        !is_lock_wait_request(&file_read_ctx),
    );
    h.assert_ev("setlkw opcode is blocking", is_blocking_lock(33));
    h.assert_ev("setlk opcode is not blocking", !is_blocking_lock(32));
    h.assert_eq_ev(
        "read lock fcntl value decodes",
        LockType::from_fcntl(LockType::F_RDLCK),
        Some(LockType::Read),
    );
    h.assert_eq_ev(
        "write lock fcntl value encodes",
        LockType::Write.as_fcntl(),
        LockType::F_WRLCK,
    );
    h.assert_ev(
        "seam family doc names workers-locks",
        SEAM_FAMILY_DOC.contains("tidefs-posix-filesystem-adapter-daemon"),
    );
}

fn smoke_lock_tracker_conflict_and_release(h: &mut SmokeHarness) {
    record_lock_op(h, 7, "workers_locks.acquire", b"write");
    let mut tracker = LockTracker::new();
    let existing = LockRange::write(0, 100, 100);
    tracker.acquire(7, existing).expect("initial write lock");
    h.assert_eq_ev(
        "tracker has one inode after acquire",
        tracker.inode_count(),
        1,
    );
    h.assert_eq_ev(
        "tracker stores initial range",
        tracker.locks_for_inode(7).expect("inode lock list").locks(),
        &[existing],
    );

    record_lock_op(h, 7, "workers_locks.query_conflict", b"read");
    let requested = LockRange::read(50, 10, 200);
    let conflict = tracker
        .query_conflict(7, requested)
        .expect("read should conflict with write");
    h.assert_eq_ev("conflict requested range", conflict.requested, requested);
    h.assert_eq_ev("conflict existing range", conflict.existing, existing);

    let acquire_conflict = tracker
        .acquire(7, requested)
        .expect_err("acquire should return conflict");
    h.assert_eq_ev(
        "acquire conflict matches query conflict",
        acquire_conflict,
        conflict,
    );
    h.assert_eq_ev(
        "failed acquire leaves existing lock intact",
        tracker.locks_for_inode(7).expect("inode lock list").locks(),
        &[existing],
    );

    record_lock_op(h, 7, "workers_locks.compatible_read", b"same-range");
    tracker
        .acquire(8, LockRange::read(0, 50, 300))
        .expect("first read lock");
    tracker
        .acquire(8, LockRange::read(25, 50, 400))
        .expect("compatible read lock");
    h.assert_eq_ev(
        "read locks from different pids are compatible",
        tracker.locks_for_inode(8).expect("read lock list").len(),
        2,
    );

    record_lock_op(h, 7, "workers_locks.release", b"all");
    tracker.release(7, LockRange::unlock(0, 100, 100));
    h.assert_ev(
        "released inode lock list is removed",
        tracker.locks_for_inode(7).is_none(),
    );

    tracker.release_by_pid(300);
    h.assert_eq_ev(
        "release_by_pid preserves other pid",
        tracker
            .locks_for_inode(8)
            .expect("remaining lock list")
            .locks(),
        &[LockRange::read(25, 50, 400)],
    );
    tracker.release_by_pid(400);
    h.assert_ev("release_by_pid clears final lock", tracker.is_empty());
}

fn smoke_lock_list_split_and_merge(h: &mut SmokeHarness) {
    record_lock_op(h, 11, "workers_locks.lock_list", b"split-merge");
    let mut list = LockList::new();
    list.acquire(LockRange::write(0, 100, 500))
        .expect("initial list write lock");
    list.release(LockRange::unlock(40, 20, 500));
    h.assert_eq_ev(
        "unlock splits existing range",
        list.locks(),
        &[LockRange::write(0, 40, 500), LockRange::write(60, 40, 500)],
    );

    list.acquire(LockRange::write(40, 20, 500))
        .expect("reacquire gap");
    h.assert_eq_ev(
        "adjacent same-pid locks merge",
        list.locks(),
        &[LockRange::write(0, 100, 500)],
    );

    list.release_by_pid(500);
    h.assert_ev("release_by_pid empties lock list", list.is_empty());
}

fn lock_ctx(unique: u64, nodeid: u64) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    PosixFilesystemAdapterRequestContextMirrorRecord {
        unique,
        nodeid,
        request_class: PosixFilesystemAdapterRequestClass::LockWait.as_u32(),
        shard_key_policy: PosixFilesystemAdapterShardKeyPolicy::LockScope.as_u32(),
        ..Default::default()
    }
}

fn record_lock_op(h: &mut SmokeHarness, inode_id: u64, op_name: &str, payload: &[u8]) {
    h.record(TraceEvent::FsLifecycleOp {
        inode_id,
        op_name: op_name.to_string(),
        payload: payload.to_vec(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workers_locks_smoke_passes() {
        let h = run_workers_locks_smoke();
        assert!(h.trace.len() >= 10);
    }
}
