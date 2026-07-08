// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Ingress smoke: deterministic API coverage for
//! `tidefs-posix-filesystem-adapter-daemon`.
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::{deserialize_trace, serialize_trace, TraceEvent};
use tidefs_posix_filesystem_adapter_daemon::ingress::{
    admit_request, backpressure_constants, classify_access_request,
    classify_copy_file_range_request, classify_create_request, classify_fallocate_request,
    classify_flush_request, classify_fsync_request, classify_fsyncdir_request,
    classify_getattr_request, classify_link_request, classify_lookup_request,
    classify_lseek_request, classify_mkdir_request, classify_mknod_request, classify_open_request,
    classify_opendir_request, classify_read_request, classify_readdir_request,
    classify_readdirplus_request, classify_readlink_request, classify_release_request,
    classify_releasedir_request, classify_rename2_request, classify_rename_request,
    classify_request_context, classify_rmdir_request, classify_statfs_request,
    classify_symlink_request, classify_unlink_request, classify_write_request, make_ingress_frame,
    update_backpressure_on_drain, update_backpressure_on_ingress, ClassifiedWrite,
    IngressWriteHandle, IngressWriteHandleTable, RawFuseWriteRequest, WriteClassifier,
    FUSE_ACCESS_OPCODE, FUSE_COPY_FILE_RANGE_OPCODE, FUSE_CREATE_OPCODE, FUSE_FALLOCATE_OPCODE,
    FUSE_FLUSH_OPCODE, FUSE_FSYNCDIR_OPCODE, FUSE_FSYNC_OPCODE, FUSE_GETATTR_OPCODE,
    FUSE_LINK_OPCODE, FUSE_LOOKUP_OPCODE, FUSE_LSEEK_OPCODE, FUSE_MKDIR_OPCODE, FUSE_MKNOD_OPCODE,
    FUSE_OPENDIR_OPCODE, FUSE_OPEN_OPCODE, FUSE_READDIRPLUS_OPCODE, FUSE_READDIR_OPCODE,
    FUSE_READLINK_OPCODE, FUSE_READ_OPCODE, FUSE_RELEASEDIR_OPCODE, FUSE_RELEASE_OPCODE,
    FUSE_RENAME2_OPCODE, FUSE_RENAME_OPCODE, FUSE_RMDIR_OPCODE, FUSE_STATFS_OPCODE,
    FUSE_SYMLINK_OPCODE, FUSE_UNLINK_OPCODE, FUSE_WRITE_CACHE, FUSE_WRITE_KILL_PRIV,
    FUSE_WRITE_LOCKOWNER, FUSE_WRITE_OPCODE, SEAM_FAMILY_DOC, WRITE_ERRNO_EBADF,
    WRITE_ERRNO_EINVAL,
};
use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterBackpressureStateRecord, PosixFilesystemAdapterRequestClass,
    PosixFilesystemAdapterRequestContextMirrorRecord, PosixFilesystemAdapterShardKeyPolicy,
};

/// Run the ingress crate smoke sequence and return the harness.
#[must_use]
pub fn run_ingress_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("ingress/smoke");
    smoke_request_classifiers(&mut h);
    smoke_write_classifier(&mut h);
    smoke_backpressure_accounting(&mut h);
    smoke_frame_and_constants(&mut h);
    h.scenario_end("ingress/smoke");

    let trace_before_round_trip = h.trace.clone();
    let serialized =
        serialize_trace(&trace_before_round_trip).expect("ingress smoke trace should serialize");
    let decoded = deserialize_trace(&serialized).expect("ingress smoke trace should deserialize");
    h.assert_eq_ev(
        "ingress smoke trace round-trips",
        decoded,
        trace_before_round_trip,
    );

    h
}

fn smoke_request_classifiers(h: &mut SmokeHarness) {
    record_ingress_op(h, "ingress.classify.context", 10, b"request-context");
    let direct = classify_request_context(
        900,
        10,
        1000,
        1001,
        1234,
        FUSE_LOOKUP_OPCODE,
        PosixFilesystemAdapterRequestClass::MetaRead,
        PosixFilesystemAdapterShardKeyPolicy::ParentDir,
        10,
    );
    assert_context(
        h,
        "direct context",
        direct,
        ExpectedContext {
            opcode: FUSE_LOOKUP_OPCODE,
            request_class: PosixFilesystemAdapterRequestClass::MetaRead,
            shard_key_policy: PosixFilesystemAdapterShardKeyPolicy::ParentDir,
            nodeid: 10,
            shard_key: 10,
        },
    );
    h.assert_eq_ev("direct context preserves unique", direct.unique, 900);
    h.assert_eq_ev("direct context preserves uid", direct.uid, 1000);
    h.assert_eq_ev("direct context preserves gid", direct.gid, 1001);
    h.assert_eq_ev("direct context preserves pid", direct.pid, 1234);

    record_ingress_op(h, "ingress.classify.read-side", 20, b"read-side");
    assert_context(
        h,
        "lookup",
        classify_lookup_request(1, 11, 1000, 1001, 1234),
        expected(
            FUSE_LOOKUP_OPCODE,
            PosixFilesystemAdapterRequestClass::MetaRead,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir,
            11,
            11,
        ),
    );
    assert_context(
        h,
        "getattr",
        classify_getattr_request(1, 20, 1000, 1001, 1234),
        inode_expected(
            FUSE_GETATTR_OPCODE,
            PosixFilesystemAdapterRequestClass::MetaRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
            20,
        ),
    );
    assert_context(
        h,
        "readlink",
        classify_readlink_request(1, 20, 1000, 1001, 1234),
        inode_expected(
            FUSE_READLINK_OPCODE,
            PosixFilesystemAdapterRequestClass::MetaRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
            20,
        ),
    );
    assert_context(
        h,
        "open",
        classify_open_request(1, 20, 1000, 1001, 1234),
        inode_expected(
            FUSE_OPEN_OPCODE,
            PosixFilesystemAdapterRequestClass::MetaRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
            20,
        ),
    );
    assert_context(
        h,
        "read",
        classify_read_request(1, 20, 1000, 1001, 1234),
        inode_expected(
            FUSE_READ_OPCODE,
            PosixFilesystemAdapterRequestClass::FileRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
            20,
        ),
    );
    assert_context(
        h,
        "statfs",
        classify_statfs_request(1, 20, 1000, 1001, 1234),
        inode_expected(
            FUSE_STATFS_OPCODE,
            PosixFilesystemAdapterRequestClass::MetaRead,
            PosixFilesystemAdapterShardKeyPolicy::Session,
            20,
        ),
    );
    assert_context(
        h,
        "release",
        classify_release_request(1, 20, 1000, 1001, 1234),
        inode_expected(
            FUSE_RELEASE_OPCODE,
            PosixFilesystemAdapterRequestClass::MetaRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
            20,
        ),
    );
    assert_context(
        h,
        "access",
        classify_access_request(1, 20, 1000, 1001, 1234),
        inode_expected(
            FUSE_ACCESS_OPCODE,
            PosixFilesystemAdapterRequestClass::MetaRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
            20,
        ),
    );

    record_ingress_op(h, "ingress.classify.file-handle", 21, b"file-handle");
    assert_context(
        h,
        "write",
        classify_write_request(1, 20, 0xfeed, 1000, 1001, 1234),
        expected(
            FUSE_WRITE_OPCODE,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,
            20,
            0xfeed,
        ),
    );
    assert_context(
        h,
        "fallocate",
        classify_fallocate_request(1, 20, 0xfeed, 1000, 1001, 1234),
        inode_expected(
            FUSE_FALLOCATE_OPCODE,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,
            20,
        ),
    );
    assert_context(
        h,
        "flush",
        classify_flush_request(1, 20, 0xfeed, 1000, 1001, 1234),
        expected(
            FUSE_FLUSH_OPCODE,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,
            20,
            0xfeed,
        ),
    );
    assert_context(
        h,
        "fsync",
        classify_fsync_request(1, 20, 0xfeed, 1000, 1001, 1234),
        expected(
            FUSE_FSYNC_OPCODE,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,
            20,
            0xfeed,
        ),
    );
    assert_context(
        h,
        "lseek",
        classify_lseek_request(1, 20, 0xfeed, 1000, 1001, 1234),
        expected(
            FUSE_LSEEK_OPCODE,
            PosixFilesystemAdapterRequestClass::FileRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
            20,
            0xfeed,
        ),
    );
    assert_context(
        h,
        "copy-file-range",
        classify_copy_file_range_request(1, 20, 0xfeed, 1000, 1001, 1234),
        expected(
            FUSE_COPY_FILE_RANGE_OPCODE,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,
            20,
            0xfeed,
        ),
    );

    record_ingress_op(h, "ingress.classify.dir-stream", 22, b"dir-stream");
    assert_context(
        h,
        "opendir",
        classify_opendir_request(1, 30, 1000, 1001, 1234),
        inode_expected(
            FUSE_OPENDIR_OPCODE,
            PosixFilesystemAdapterRequestClass::DirStream,
            PosixFilesystemAdapterShardKeyPolicy::DirHandle,
            30,
        ),
    );
    assert_context(
        h,
        "readdir",
        classify_readdir_request(1, 30, 1000, 1001, 1234),
        inode_expected(
            FUSE_READDIR_OPCODE,
            PosixFilesystemAdapterRequestClass::DirStream,
            PosixFilesystemAdapterShardKeyPolicy::DirHandle,
            30,
        ),
    );
    assert_context(
        h,
        "releasedir",
        classify_releasedir_request(1, 30, 1000, 1001, 1234),
        inode_expected(
            FUSE_RELEASEDIR_OPCODE,
            PosixFilesystemAdapterRequestClass::DirStream,
            PosixFilesystemAdapterShardKeyPolicy::DirHandle,
            30,
        ),
    );
    assert_context(
        h,
        "fsyncdir",
        classify_fsyncdir_request(1, 30, 0xbeef, 1000, 1001, 1234),
        expected(
            FUSE_FSYNCDIR_OPCODE,
            PosixFilesystemAdapterRequestClass::DirStream,
            PosixFilesystemAdapterShardKeyPolicy::DirHandle,
            30,
            0xbeef,
        ),
    );
    assert_context(
        h,
        "readdirplus",
        classify_readdirplus_request(1, 30, 1000, 1001, 1234),
        inode_expected(
            FUSE_READDIRPLUS_OPCODE,
            PosixFilesystemAdapterRequestClass::DirStream,
            PosixFilesystemAdapterShardKeyPolicy::DirHandle,
            30,
        ),
    );

    record_ingress_op(h, "ingress.classify.namespace", 40, b"namespace");
    assert_context(
        h,
        "rename",
        classify_rename_request(1, 40, 41, 1000, 1001, 1234),
        expected(
            FUSE_RENAME_OPCODE,
            PosixFilesystemAdapterRequestClass::NamespaceMut,
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair,
            40,
            40 ^ 41,
        ),
    );
    assert_context(
        h,
        "rename2",
        classify_rename2_request(1, 40, 41, 1000, 1001, 1234),
        expected(
            FUSE_RENAME2_OPCODE,
            PosixFilesystemAdapterRequestClass::NamespaceMut,
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair,
            40,
            40 ^ 41,
        ),
    );
    assert_context(
        h,
        "create",
        classify_create_request(1, 40, 1000, 1001, 1234),
        parent_expected(FUSE_CREATE_OPCODE, 40),
    );
    assert_context(
        h,
        "mknod",
        classify_mknod_request(1, 40, 1000, 1001, 1234),
        parent_expected(FUSE_MKNOD_OPCODE, 40),
    );
    assert_context(
        h,
        "mkdir",
        classify_mkdir_request(1, 40, 1000, 1001, 1234),
        parent_expected(FUSE_MKDIR_OPCODE, 40),
    );
    assert_context(
        h,
        "unlink",
        classify_unlink_request(1, 40, 1000, 1001, 1234),
        parent_expected(FUSE_UNLINK_OPCODE, 40),
    );
    assert_context(
        h,
        "rmdir",
        classify_rmdir_request(1, 40, 1000, 1001, 1234),
        parent_expected(FUSE_RMDIR_OPCODE, 40),
    );
    assert_context(
        h,
        "symlink",
        classify_symlink_request(1, 40, 1000, 1001, 1234),
        parent_expected(FUSE_SYMLINK_OPCODE, 40),
    );
    assert_context(
        h,
        "link",
        classify_link_request(1, 50, 40, 1000, 1001, 1234),
        expected(
            FUSE_LINK_OPCODE,
            PosixFilesystemAdapterRequestClass::NamespaceMut,
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair,
            50,
            50 ^ 40,
        ),
    );
}

fn smoke_write_classifier(h: &mut SmokeHarness) {
    record_ingress_op(h, "ingress.write.classifier", 42, b"dirty-extent");
    let result = WriteClassifier::new().classify(&write_handles(), write_req());
    match result {
        ClassifiedWrite::DirtyExtent(staging) => {
            h.assert_eq_ev("write staging preserves unique", staging.unique, 77);
            h.assert_eq_ev("write staging preserves inode", staging.inode, 42);
            h.assert_eq_ev("write staging preserves file handle", staging.fh, 9);
            h.assert_eq_ev("write staging preserves offset", staging.offset, 4096);
            h.assert_eq_ev("write staging preserves length", staging.length, 4096);
            h.assert_eq_ev(
                "write staging preserves supported flags",
                staging.write_flags,
                FUSE_WRITE_LOCKOWNER | FUSE_WRITE_KILL_PRIV,
            );
            h.assert_eq_ev(
                "write staging computes end offset",
                staging.end_offset(),
                Some(8192),
            );
            h.assert_ev("non-empty write is not empty", !staging.is_empty());
        }
        ClassifiedWrite::Rejected { errno, .. } => {
            h.assert_eq_ev("valid write should not reject", errno, 0);
        }
    }

    let zero = RawFuseWriteRequest {
        size: 0,
        payload_len: 0,
        ..write_req()
    };
    match WriteClassifier::new().classify(&write_handles(), zero) {
        ClassifiedWrite::DirtyExtent(staging) => {
            h.assert_ev("zero-length write classifies as empty", staging.is_empty());
        }
        ClassifiedWrite::Rejected { errno, .. } => {
            h.assert_eq_ev("zero-length write should not reject", errno, 0);
        }
    }

    record_ingress_op(h, "ingress.write.reject", 42, b"errors");
    let unknown = RawFuseWriteRequest {
        fh: 99,
        ..write_req()
    };
    h.assert_eq_ev(
        "unknown handle rejects with EBADF",
        WriteClassifier::new()
            .classify(&write_handles(), unknown)
            .errno(),
        Some(WRITE_ERRNO_EBADF),
    );

    let cache_flag = RawFuseWriteRequest {
        write_flags: FUSE_WRITE_CACHE,
        ..write_req()
    };
    let cache_classification = WriteClassifier::new().classify(&write_handles(), cache_flag);
    h.assert_eq_ev(
        "cache flag should not reject at ingress",
        cache_classification.errno(),
        None,
    );
    if let ClassifiedWrite::DirtyExtent(staging) = cache_classification {
        h.assert_eq_ev(
            "cache flag is preserved for handler gating",
            staging.write_flags,
            FUSE_WRITE_CACHE,
        );
    }

    let unsupported_flag = RawFuseWriteRequest {
        write_flags: 0x08,
        ..write_req()
    };
    h.assert_eq_ev(
        "unsupported write flag rejects with EINVAL",
        WriteClassifier::new()
            .classify(&write_handles(), unsupported_flag)
            .errno(),
        Some(WRITE_ERRNO_EINVAL),
    );

    let mismatched_payload = RawFuseWriteRequest {
        payload_len: 1,
        ..write_req()
    };
    h.assert_eq_ev(
        "payload size mismatch rejects with EINVAL",
        WriteClassifier::new()
            .classify(&write_handles(), mismatched_payload)
            .errno(),
        Some(WRITE_ERRNO_EINVAL),
    );
}

fn smoke_backpressure_accounting(h: &mut SmokeHarness) {
    record_ingress_op(h, "ingress.backpressure.admit", 60, b"admission");
    let default_bp = PosixFilesystemAdapterBackpressureStateRecord::default();
    h.assert_ev(
        "default backpressure admits meta read",
        admit_request(&default_bp, PosixFilesystemAdapterRequestClass::MetaRead),
    );

    let full_bp = PosixFilesystemAdapterBackpressureStateRecord {
        inflight_request_count: backpressure_constants::MAX_INFLIGHT_REQUEST_COUNT,
        inflight_request_bytes: backpressure_constants::MAX_INFLIGHT_REQUEST_BYTES,
        dirty_window_bytes: backpressure_constants::MAX_DIRTY_WINDOW_BYTES,
        lock_wait_count: backpressure_constants::MAX_LOCK_WAIT_COUNT,
        ..Default::default()
    };
    h.assert_ev(
        "control urgent bypasses full backpressure",
        admit_request(&full_bp, PosixFilesystemAdapterRequestClass::ControlUrgent),
    );
    h.assert_ev(
        "full dirty window blocks file writeback",
        !admit_request(&full_bp, PosixFilesystemAdapterRequestClass::FileWriteback),
    );
    h.assert_ev(
        "full lock wait count blocks lock wait",
        !admit_request(&full_bp, PosixFilesystemAdapterRequestClass::LockWait),
    );

    record_ingress_op(h, "ingress.backpressure.counters", 61, b"accounting");
    let mut bp = PosixFilesystemAdapterBackpressureStateRecord::default();
    update_backpressure_on_ingress(
        &mut bp,
        PosixFilesystemAdapterRequestClass::FileWriteback,
        4096,
    );
    h.assert_eq_ev(
        "writeback ingress increments count",
        bp.inflight_request_count,
        1,
    );
    h.assert_eq_ev(
        "writeback ingress increments bytes",
        bp.inflight_request_bytes,
        4096,
    );
    h.assert_eq_ev(
        "writeback ingress increments dirty window",
        bp.dirty_window_bytes,
        4096,
    );

    update_backpressure_on_drain(
        &mut bp,
        PosixFilesystemAdapterRequestClass::FileWriteback,
        4096,
        256,
    );
    h.assert_eq_ev(
        "writeback drain decrements count",
        bp.inflight_request_count,
        0,
    );
    h.assert_eq_ev(
        "writeback drain decrements bytes",
        bp.inflight_request_bytes,
        0,
    );
    h.assert_eq_ev(
        "writeback drain decrements dirty window",
        bp.dirty_window_bytes,
        0,
    );

    update_backpressure_on_ingress(&mut bp, PosixFilesystemAdapterRequestClass::FileRead, 8192);
    h.assert_eq_ev(
        "file read ingress increments bulk reply bytes",
        bp.bulk_read_reply_bytes,
        8192,
    );
    update_backpressure_on_drain(
        &mut bp,
        PosixFilesystemAdapterRequestClass::FileRead,
        8192,
        0,
    );
    h.assert_eq_ev(
        "file read drain decrements bulk reply bytes",
        bp.bulk_read_reply_bytes,
        0,
    );

    update_backpressure_on_ingress(&mut bp, PosixFilesystemAdapterRequestClass::LockWait, 0);
    h.assert_eq_ev("lock wait ingress increments count", bp.lock_wait_count, 1);
    update_backpressure_on_drain(&mut bp, PosixFilesystemAdapterRequestClass::LockWait, 0, 0);
    h.assert_eq_ev("lock wait drain decrements count", bp.lock_wait_count, 0);
}

fn smoke_frame_and_constants(h: &mut SmokeHarness) {
    record_ingress_op(h, "ingress.frame.constants", 70, b"constants");
    let frame = make_ingress_frame(55, 4096);
    h.assert_eq_ev("ingress frame preserves id", frame.frame_id, 55);
    h.assert_eq_ev("ingress frame preserves length", frame.payload_len, 4096);

    h.assert_eq_ev("lookup opcode is stable", FUSE_LOOKUP_OPCODE, 1);
    h.assert_eq_ev("write opcode is stable", FUSE_WRITE_OPCODE, 16);
    h.assert_eq_ev("fallocate opcode is stable", FUSE_FALLOCATE_OPCODE, 43);
    h.assert_eq_ev("lseek opcode is stable", FUSE_LSEEK_OPCODE, 46);
    h.assert_eq_ev(
        "copy_file_range opcode is stable",
        FUSE_COPY_FILE_RANGE_OPCODE,
        47,
    );
    h.assert_eq_ev(
        "file writeback class tag is stable",
        PosixFilesystemAdapterRequestClass::FileWriteback.as_u32(),
        5,
    );
    h.assert_eq_ev(
        "object write shard policy tag is stable",
        PosixFilesystemAdapterShardKeyPolicy::ObjectWrite.as_u32(),
        4,
    );
    h.assert_ev(
        "seam family doc names ingress crate",
        SEAM_FAMILY_DOC.contains("tidefs-posix-filesystem-adapter-daemon"),
    );
}

#[derive(Clone, Copy)]
struct ExpectedContext {
    opcode: u32,
    request_class: PosixFilesystemAdapterRequestClass,
    shard_key_policy: PosixFilesystemAdapterShardKeyPolicy,
    nodeid: u64,
    shard_key: u64,
}

fn expected(
    opcode: u32,
    request_class: PosixFilesystemAdapterRequestClass,
    shard_key_policy: PosixFilesystemAdapterShardKeyPolicy,
    nodeid: u64,
    shard_key: u64,
) -> ExpectedContext {
    ExpectedContext {
        opcode,
        request_class,
        shard_key_policy,
        nodeid,
        shard_key,
    }
}

fn inode_expected(
    opcode: u32,
    request_class: PosixFilesystemAdapterRequestClass,
    shard_key_policy: PosixFilesystemAdapterShardKeyPolicy,
    ino: u64,
) -> ExpectedContext {
    expected(opcode, request_class, shard_key_policy, ino, ino)
}

fn parent_expected(opcode: u32, parent_ino: u64) -> ExpectedContext {
    expected(
        opcode,
        PosixFilesystemAdapterRequestClass::NamespaceMut,
        PosixFilesystemAdapterShardKeyPolicy::ParentDir,
        parent_ino,
        parent_ino,
    )
}

fn assert_context(
    h: &mut SmokeHarness,
    label: &str,
    ctx: PosixFilesystemAdapterRequestContextMirrorRecord,
    expected: ExpectedContext,
) {
    h.assert_eq_ev(&format!("{label} opcode"), ctx.opcode, expected.opcode);
    h.assert_eq_ev(&format!("{label} nodeid"), ctx.nodeid, expected.nodeid);
    h.assert_eq_ev(
        &format!("{label} request class"),
        ctx.request_class,
        expected.request_class.as_u32(),
    );
    h.assert_eq_ev(
        &format!("{label} shard policy"),
        ctx.shard_key_policy,
        expected.shard_key_policy.as_u32(),
    );
    h.assert_eq_ev(
        &format!("{label} shard key"),
        ctx.shard_key,
        expected.shard_key,
    );
}

#[derive(Clone, Copy)]
struct StaticWriteHandles {
    fh: u64,
    handle: IngressWriteHandle,
}

impl IngressWriteHandleTable for StaticWriteHandles {
    fn lookup_write_handle(&self, fh: u64) -> Option<IngressWriteHandle> {
        (fh == self.fh).then_some(self.handle)
    }
}

fn write_handles() -> StaticWriteHandles {
    StaticWriteHandles {
        fh: 9,
        handle: IngressWriteHandle {
            inode: 42,
            writable: true,
        },
    }
}

fn write_req() -> RawFuseWriteRequest {
    RawFuseWriteRequest {
        unique: 77,
        inode: 42,
        fh: 9,
        offset: 4096,
        size: 4096,
        payload_len: 4096,
        write_flags: FUSE_WRITE_LOCKOWNER | FUSE_WRITE_KILL_PRIV,
        lock_owner: 123,
    }
}

fn record_ingress_op(h: &mut SmokeHarness, op_name: &str, inode_id: u64, payload: &[u8]) {
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
    fn ingress_smoke_passes() {
        let h = run_ingress_smoke();
        assert!(h.trace.len() >= 40);
    }
}
