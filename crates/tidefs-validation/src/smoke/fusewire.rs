//! Fusewire smoke: compile-time API coverage for
//! `tidefs-posix-filesystem-adapter-daemon (fusewire module)`.
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::{deserialize_trace, serialize_trace, TraceEvent};
use tidefs_posix_filesystem_adapter_daemon::fusewire::{
    classify_fuse_request, classify_reply_class, derive_shard_key_policy, fallocate_flags,
    fsync_flags, init_flags, lseek_whence, opcode, parse_fuse_access_request,
    parse_fuse_batch_forget_request, parse_fuse_copy_file_range_request, parse_fuse_create_request,
    parse_fuse_destroy_request, parse_fuse_fallocate_request, parse_fuse_flush_request,
    parse_fuse_forget_request, parse_fuse_fsyncdir_request, parse_fuse_getattr_request,
    parse_fuse_getlk_request, parse_fuse_getxattr_request, parse_fuse_init_request,
    parse_fuse_interrupt_request, parse_fuse_link_request, parse_fuse_listxattr_request,
    parse_fuse_lookup_request, parse_fuse_lseek_request, parse_fuse_mkdir_request,
    parse_fuse_mknod_request, parse_fuse_open_request, parse_fuse_opendir_request,
    parse_fuse_read_request, parse_fuse_readdir_request, parse_fuse_readdirplus_request,
    parse_fuse_readlink_request, parse_fuse_release_request, parse_fuse_releasedir_request,
    parse_fuse_removexattr_request, parse_fuse_rename2_request, parse_fuse_rename_request,
    parse_fuse_rmdir_request, parse_fuse_setattr_request, parse_fuse_setlk_request,
    parse_fuse_setlkw_request, parse_fuse_setxattr_request, parse_fuse_statfs_request,
    parse_fuse_statx_request, parse_fuse_symlink_request, parse_fuse_unlink_request,
    parse_fuse_write_request, plan_current_adapter_fuse_init_reply, readdirplus_read_flags,
    write_flags, CreateRequestParseError, FsyncdirRequestParseError, MknodRequestParseError,
    ReadlinkRequestParseError, XattrRequestParseError, FUSE_ACCESS_IN_WIRE_SIZE,
    FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE, FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE,
    FUSE_CREATE_IN_WIRE_SIZE, FUSE_FALLOCATE_IN_WIRE_SIZE, FUSE_FLUSH_IN_WIRE_SIZE,
    FUSE_FORGET_ONE_WIRE_SIZE, FUSE_FSYNCDIR_IN_WIRE_SIZE, FUSE_GETATTR_FH,
    FUSE_GETATTR_IN_WIRE_SIZE, FUSE_GETLK_IN_WIRE_SIZE, FUSE_GETXATTR_IN_WIRE_SIZE,
    FUSE_INIT_DEFAULT_MAX_WRITE, FUSE_INIT_IN_WIRE_SIZE, FUSE_LINK_IN_WIRE_SIZE,
    FUSE_LK_TYPE_RDLCK, FUSE_LK_TYPE_UNLCK, FUSE_LK_TYPE_WRLCK, FUSE_LSEEK_IN_WIRE_SIZE,
    FUSE_MKDIR_IN_WIRE_SIZE, FUSE_MKNOD_IN_WIRE_SIZE, FUSE_NAME_MAX_BYTES,
    FUSE_OPENDIR_IN_WIRE_SIZE, FUSE_OPEN_IN_WIRE_SIZE, FUSE_READDIRPLUS_IN_WIRE_SIZE,
    FUSE_READDIR_IN_WIRE_SIZE, FUSE_READ_IN_WIRE_SIZE, FUSE_RELEASEDIR_IN_WIRE_SIZE,
    FUSE_RELEASE_IN_WIRE_SIZE, FUSE_RENAME2_IN_WIRE_SIZE, FUSE_RENAME_IN_WIRE_SIZE,
    FUSE_SETATTR_IN_WIRE_SIZE, FUSE_SETLKW_IN_WIRE_SIZE, FUSE_SETLK_IN_WIRE_SIZE,
    FUSE_SETXATTR_IN_WIRE_SIZE, FUSE_STATX_IN_WIRE_SIZE, FUSE_SYMLINK_MIN_WIRE_SIZE,
    FUSE_UNLINK_MIN_WIRE_SIZE, FUSE_WRITE_IN_WIRE_SIZE, SEAM_FAMILY_DOC,
    TIDEFS_FUSE_INIT_DEFAULT_WANTED_FLAGS, TIDEFS_FUSE_INIT_REQUIRED_FLAGS,
};
use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterReplyClass, PosixFilesystemAdapterRequestClass,
    PosixFilesystemAdapterShardKeyPolicy,
};

/// Run the fusewire crate smoke sequence and return the harness.
#[must_use]
pub fn run_fusewire_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("fusewire/smoke");
    smoke_classification_api(&mut h);
    smoke_init_api(&mut h);
    smoke_parser_api(&mut h);
    smoke_wire_constants(&mut h);
    smoke_parser_error_paths(&mut h);
    smoke_remaining_parsers(&mut h);
    h.scenario_end("fusewire/smoke");

    let trace_before_round_trip = h.trace.clone();
    let serialized =
        serialize_trace(&trace_before_round_trip).expect("fusewire smoke trace should serialize");
    let decoded = deserialize_trace(&serialized).expect("fusewire smoke trace should deserialize");
    h.assert_eq_ev(
        "fusewire smoke trace round-trips",
        decoded,
        trace_before_round_trip,
    );

    h
}

fn smoke_classification_api(h: &mut SmokeHarness) {
    record_fusewire_op(h, "fusewire.classify", opcode::FUSE_LOOKUP, b"classifier");

    h.assert_eq_ev(
        "init is control urgent",
        classify_fuse_request(opcode::FUSE_INIT),
        PosixFilesystemAdapterRequestClass::ControlUrgent,
    );
    h.assert_eq_ev(
        "lookup is metadata read",
        classify_fuse_request(opcode::FUSE_LOOKUP),
        PosixFilesystemAdapterRequestClass::MetaRead,
    );
    h.assert_eq_ev(
        "rename2 is namespace mutation",
        classify_fuse_request(opcode::FUSE_RENAME2),
        PosixFilesystemAdapterRequestClass::NamespaceMut,
    );
    h.assert_eq_ev(
        "readdirplus is dir stream",
        classify_fuse_request(opcode::FUSE_READDIRPLUS),
        PosixFilesystemAdapterRequestClass::DirStream,
    );
    h.assert_eq_ev(
        "read is file read",
        classify_fuse_request(opcode::FUSE_READ),
        PosixFilesystemAdapterRequestClass::FileRead,
    );
    h.assert_eq_ev(
        "write is file writeback",
        classify_fuse_request(opcode::FUSE_WRITE),
        PosixFilesystemAdapterRequestClass::FileWriteback,
    );
    h.assert_eq_ev(
        "setlkw is lock wait",
        classify_fuse_request(opcode::FUSE_SETLKW),
        PosixFilesystemAdapterRequestClass::LockWait,
    );
    h.assert_eq_ev(
        "bmap is fuse",
        classify_fuse_request(opcode::FUSE_BMAP),
        PosixFilesystemAdapterRequestClass::Maintenance,
    );

    h.assert_eq_ev(
        "statfs is session scoped",
        derive_shard_key_policy(opcode::FUSE_STATFS),
        PosixFilesystemAdapterShardKeyPolicy::Session,
    );
    h.assert_eq_ev(
        "lookup uses parent-dir shard",
        derive_shard_key_policy(opcode::FUSE_LOOKUP),
        PosixFilesystemAdapterShardKeyPolicy::ParentDir,
    );
    h.assert_eq_ev(
        "rename2 uses dual-parent shard",
        derive_shard_key_policy(opcode::FUSE_RENAME2),
        PosixFilesystemAdapterShardKeyPolicy::DualParentPair,
    );
    h.assert_eq_ev(
        "read uses object-read shard",
        derive_shard_key_policy(opcode::FUSE_READ),
        PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
    );
    h.assert_eq_ev(
        "write uses object-write shard",
        derive_shard_key_policy(opcode::FUSE_WRITE),
        PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,
    );
    h.assert_eq_ev(
        "readdir uses dir-handle shard",
        derive_shard_key_policy(opcode::FUSE_READDIR),
        PosixFilesystemAdapterShardKeyPolicy::DirHandle,
    );
    h.assert_eq_ev(
        "getlk uses lock-scope shard",
        derive_shard_key_policy(opcode::FUSE_GETLK),
        PosixFilesystemAdapterShardKeyPolicy::LockScope,
    );

    h.assert_eq_ev(
        "file-read replies are bulk",
        classify_reply_class(PosixFilesystemAdapterRequestClass::FileRead),
        PosixFilesystemAdapterReplyClass::BulkReply,
    );
    h.assert_eq_ev(
        "metadata replies are small",
        classify_reply_class(PosixFilesystemAdapterRequestClass::MetaRead),
        PosixFilesystemAdapterReplyClass::SmallReply,
    );
}

fn smoke_init_api(h: &mut SmokeHarness) {
    record_fusewire_op(h, "fusewire.init", opcode::FUSE_INIT, b"init");

    let payload = fuse_init_payload(
        7,
        31,
        256 * 1024,
        TIDEFS_FUSE_INIT_REQUIRED_FLAGS | TIDEFS_FUSE_INIT_DEFAULT_WANTED_FLAGS,
    );
    let request = parse_fuse_init_request(&payload).expect("init request should parse");
    h.assert_eq_ev("init major parses", request.major, 7);
    h.assert_eq_ev("init minor parses", request.minor, 31);
    h.assert_ev(
        "default init wanted flags include POSIX ACL",
        TIDEFS_FUSE_INIT_DEFAULT_WANTED_FLAGS & init_flags::FUSE_POSIX_ACL != 0,
    );

    let plan = plan_current_adapter_fuse_init_reply(request)
        .expect("current adapter init reply should plan");
    h.assert_eq_ev("init reply clamps minor", plan.minor, 28);
    h.assert_eq_ev(
        "init reply default max-write",
        plan.max_write,
        FUSE_INIT_DEFAULT_MAX_WRITE,
    );
    h.assert_ev(
        "init reply preserves required flags",
        plan.flags & TIDEFS_FUSE_INIT_REQUIRED_FLAGS != 0,
    );
}

fn smoke_parser_api(h: &mut SmokeHarness) {
    record_fusewire_op(h, "fusewire.parsers", opcode::FUSE_READ, b"parsers");

    let lookup = parse_fuse_lookup_request(42, b"child\0").expect("lookup parses");
    h.assert_eq_ev("lookup parent parses", lookup.parent, 42);
    h.assert_eq_ev(
        "lookup name parses",
        lookup.name.to_vec(),
        b"child".to_vec(),
    );

    h.assert_eq_ev(
        "interrupt unique parses",
        parse_fuse_interrupt_request(&u64_payload(100))
            .expect("interrupt parses")
            .unique,
        100,
    );
    h.assert_eq_ev(
        "forget nlookup parses",
        parse_fuse_forget_request(&u64_payload(2))
            .expect("forget parses")
            .nlookup,
        2,
    );
    let batch =
        parse_fuse_batch_forget_request(&batch_forget_payload()).expect("batch forget parses");
    h.assert_eq_ev("batch forget entry count", batch.entries.len(), 2usize);
    h.assert_eq_ev("batch forget first nodeid", batch.entries[0].nodeid, 11);

    let getattr = parse_fuse_getattr_request(&getattr_payload(FUSE_GETATTR_FH, 0xfeed))
        .expect("getattr parses");
    h.assert_eq_ev(
        "getattr flags parse",
        getattr.getattr_flags,
        FUSE_GETATTR_FH,
    );
    h.assert_eq_ev("getattr fh parses", getattr.fh, 0xfeed);

    let statx = parse_fuse_statx_request(&statx_payload()).expect("statx parses");
    h.assert_eq_ev("statx fh parses", statx.fh, 0x1234);
    h.assert_eq_ev("statx mask parses", statx.sx_mask, 0x0fff);

    h.assert_eq_ev(
        "open flags parse",
        parse_fuse_open_request(&open_payload(0x2, 0))
            .expect("open parses")
            .flags,
        0x2,
    );
    h.assert_eq_ev(
        "opendir flags parse",
        parse_fuse_opendir_request(&open_payload(0x10, 0))
            .expect("opendir parses")
            .flags,
        0x10,
    );
    h.assert_eq_ev(
        "release fh parses",
        parse_fuse_release_request(&release_payload())
            .expect("release parses")
            .fh,
        0x44,
    );
    h.assert_eq_ev(
        "releasedir fh parses",
        parse_fuse_releasedir_request(&release_payload())
            .expect("releasedir parses")
            .fh,
        0x44,
    );

    h.assert_ev(
        "statfs accepts empty payload",
        parse_fuse_statfs_request(&[]).is_ok(),
    );
    h.assert_ev(
        "destroy accepts empty payload",
        parse_fuse_destroy_request(&[]).is_ok(),
    );

    let setattr = parse_fuse_setattr_request(&setattr_payload()).expect("setattr parses");
    h.assert_eq_ev("setattr size parses", setattr.size, 4096);
    h.assert_eq_ev("setattr mode parses", setattr.mode, 0o100_644);

    let link_payload = link_payload();
    let link = parse_fuse_link_request(&link_payload).expect("link parses");
    h.assert_eq_ev("link olobject_nodeid parses", link.olobject_nodeid, 77);
    h.assert_eq_ev("link name parses", link.name, "hardlink");

    let rename_bytes = rename_payload(false);
    let rename = parse_fuse_rename_request(&rename_bytes).expect("rename parses");
    h.assert_eq_ev("rename newdir parses", rename.newdir, 88);
    h.assert_eq_ev(
        "rename old name parses",
        rename.old_name.to_vec(),
        b"old".to_vec(),
    );
    let rename2_bytes = rename_payload(true);
    let rename2 = parse_fuse_rename2_request(&rename2_bytes).expect("rename2 parses");
    h.assert_eq_ev("rename2 flags parse", rename2.flags, 1);

    let setxattr_payload = setxattr_payload();
    let setxattr = parse_fuse_setxattr_request(&setxattr_payload).expect("setxattr parses");
    h.assert_eq_ev(
        "setxattr name parses",
        setxattr.name.to_vec(),
        b"user.key".to_vec(),
    );
    h.assert_eq_ev(
        "setxattr value parses",
        setxattr.value.to_vec(),
        b"value".to_vec(),
    );

    h.assert_eq_ev(
        "mkdir name parses",
        parse_fuse_mkdir_request(&mkdir_payload())
            .expect("mkdir parses")
            .name
            .to_vec(),
        b"dir".to_vec(),
    );
    h.assert_eq_ev(
        "unlink parent parses",
        parse_fuse_unlink_request(9, b"gone\0")
            .expect("unlink parses")
            .parent,
        9,
    );
    h.assert_eq_ev(
        "rmdir name parses",
        parse_fuse_rmdir_request(9, b"dir\0")
            .expect("rmdir parses")
            .name
            .to_vec(),
        b"dir".to_vec(),
    );
    h.assert_eq_ev(
        "access mask parses",
        parse_fuse_access_request(&u32_payload(0o4))
            .expect("access parses")
            .mask,
        0o4,
    );

    let read = parse_fuse_read_request(&read_payload()).expect("read parses");
    h.assert_eq_ev("read fh parses", read.fh, 0x80);
    h.assert_eq_ev("read size parses", read.size, 4096);
    h.assert_eq_ev(
        "readdir fh parses",
        parse_fuse_readdir_request(&read_payload())
            .expect("readdir parses")
            .fh,
        0x80,
    );
    h.assert_eq_ev(
        "readdirplus read flags parse",
        parse_fuse_readdirplus_request(&readdirplus_payload())
            .expect("readdirplus parses")
            .read_flags,
        readdirplus_read_flags::FUSE_READ_LOCKOWNER,
    );

    h.assert_eq_ev(
        "flush lock owner parses",
        parse_fuse_flush_request(&flush_payload())
            .expect("flush parses")
            .lock_owner,
        0x55,
    );
    h.assert_eq_ev(
        "symlink target parses",
        parse_fuse_symlink_request(b"link\0target\0")
            .expect("symlink parses")
            .target
            .to_vec(),
        b"target".to_vec(),
    );
    h.assert_eq_ev(
        "fallocate mode parses",
        parse_fuse_fallocate_request(&fallocate_payload())
            .expect("fallocate parses")
            .mode,
        fallocate_flags::FALLOC_FL_KEEP_SIZE,
    );
    h.assert_eq_ev(
        "lseek whence parses",
        parse_fuse_lseek_request(&lseek_payload())
            .expect("lseek parses")
            .whence,
        lseek_whence::SEEK_DATA,
    );

    let copy = parse_fuse_copy_file_range_request(&copy_file_range_payload())
        .expect("copy_file_range parses");
    h.assert_eq_ev("copy_file_range len parses", copy.len, 512);
    h.assert_eq_ev("copy_file_range output fh parses", copy.fh_out, 0x33);

    let write_payload = write_payload();
    let write = parse_fuse_write_request(&write_payload).expect("write parses");
    h.assert_eq_ev(
        "write flags parse",
        write.write_flags,
        write_flags::FUSE_WRITE_LOCKOWNER,
    );
    h.assert_eq_ev("write data parses", write.data.to_vec(), b"data".to_vec());

    let getlk = parse_fuse_getlk_request(&lock_payload()).expect("getlk parses");
    h.assert_eq_ev("getlk lock type parses", getlk.lk.typ, FUSE_LK_TYPE_RDLCK);
    h.assert_eq_ev(
        "setlk sleep false",
        parse_fuse_setlk_request(&lock_payload())
            .expect("setlk parses")
            .sleep,
        false,
    );
    h.assert_eq_ev(
        "setlkw sleep true",
        parse_fuse_setlkw_request(&lock_payload())
            .expect("setlkw parses")
            .sleep,
        true,
    );
}

fn smoke_parser_error_paths(h: &mut SmokeHarness) {
    record_fusewire_op(h, "fusewire.errors", opcode::FUSE_LOOKUP, b"error-paths");

    // BufferTooSmall errors
    let err = parse_fuse_create_request(&[0u8; 4]).unwrap_err();
    h.assert_ev(
        "create too-short is BufferTooSmall",
        matches!(
            err,
            CreateRequestParseError::BufferTooSmall {
                required: FUSE_CREATE_IN_WIRE_SIZE,
                actual: 4
            }
        ),
    );
    let err = parse_fuse_mknod_request(1, &[0u8; 4]).unwrap_err();
    h.assert_ev(
        "mknod too-short is BufferTooSmall",
        matches!(
            err,
            MknodRequestParseError::BufferTooSmall {
                required: FUSE_MKNOD_IN_WIRE_SIZE,
                actual: 4
            }
        ),
    );
    let err = parse_fuse_fsyncdir_request(&[0u8; 4]).unwrap_err();
    h.assert_ev(
        "fsyncdir too-short is PayloadTooShort",
        matches!(
            err,
            FsyncdirRequestParseError::PayloadTooShort {
                required: FUSE_FSYNCDIR_IN_WIRE_SIZE,
                actual: 4
            }
        ),
    );

    // TrailingBytes errors
    let mut trailing = vec![0u8; FUSE_FSYNCDIR_IN_WIRE_SIZE + 4];
    put_u32(&mut trailing, 12, 0);
    h.assert_ev(
        "fsyncdir trailing bytes rejected",
        matches!(
            parse_fuse_fsyncdir_request(&trailing).unwrap_err(),
            FsyncdirRequestParseError::TrailingBytes { .. }
        ),
    );
    let xattr_buf = vec![0u8; FUSE_GETXATTR_IN_WIRE_SIZE + 4];
    let err = parse_fuse_listxattr_request(&xattr_buf).unwrap_err();
    h.assert_ev(
        "listxattr trailing bytes is TrailingBytes",
        matches!(err, XattrRequestParseError::TrailingBytes { .. }),
    );

    // NonEmptyPayload error
    let err = parse_fuse_readlink_request(&[1u8], 42).unwrap_err();
    h.assert_ev(
        "readlink non-empty payload rejected",
        matches!(
            err,
            ReadlinkRequestParseError::NonEmptyPayload { actual: 1 }
        ),
    );

    // InvalidPadding error
    let mut mknod_pad = [0u8; FUSE_MKNOD_IN_WIRE_SIZE + 4];
    mknod_pad[FUSE_MKNOD_IN_WIRE_SIZE..].copy_from_slice(b"dev\0");
    put_u32(&mut mknod_pad, 12, 0xdead);
    let err = parse_fuse_mknod_request(1, &mknod_pad).unwrap_err();
    h.assert_ev(
        "mknod invalid padding",
        matches!(err, MknodRequestParseError::InvalidPadding),
    );

    // MissingNulTerminator errors
    let mut no_nul = vec![0u8; FUSE_CREATE_IN_WIRE_SIZE];
    no_nul.extend_from_slice(b"nonul");
    h.assert_ev(
        "create missing nul terminator",
        matches!(
            parse_fuse_create_request(&no_nul).unwrap_err(),
            CreateRequestParseError::MissingNulTerminator
        ),
    );
    let mut no_nul = vec![0u8; FUSE_MKNOD_IN_WIRE_SIZE];
    no_nul.extend_from_slice(b"nonul");
    h.assert_ev(
        "mknod missing nul terminator",
        matches!(
            parse_fuse_mknod_request(1, &no_nul).unwrap_err(),
            MknodRequestParseError::MissingNulTerminator
        ),
    );

    // Xattr BufferTooSmall
    let err = parse_fuse_getxattr_request(&[0u8; 4]).unwrap_err();
    h.assert_ev(
        "getxattr too-short is BufferTooSmall",
        matches!(
            err,
            XattrRequestParseError::BufferTooSmall {
                required: FUSE_GETXATTR_IN_WIRE_SIZE,
                actual: 4
            }
        ),
    );

    // Xattr MissingNulTerminator / TrailingBytes
    h.assert_ev(
        "removexattr missing nul",
        matches!(
            parse_fuse_removexattr_request(b"nonul").unwrap_err(),
            XattrRequestParseError::MissingNulTerminator
        ),
    );
    let err = parse_fuse_removexattr_request(b"\0extra").unwrap_err();
    h.assert_ev(
        "removexattr empty name rejected",
        matches!(err, XattrRequestParseError::EmptyName),
    );
}

fn smoke_wire_constants(h: &mut SmokeHarness) {
    record_fusewire_op(
        h,
        "fusewire.constants",
        opcode::FUSE_STATX,
        SEAM_FAMILY_DOC.as_bytes(),
    );

    h.assert_ev(
        "seam doc names fusewire crate",
        SEAM_FAMILY_DOC.contains("tidefs-posix-filesystem-adapter-daemon"),
    );
    h.assert_eq_ev("lookup minimum payload", FUSE_UNLINK_MIN_WIRE_SIZE, 2usize);
    h.assert_eq_ev(
        "name max is Linux component max",
        FUSE_NAME_MAX_BYTES,
        255usize,
    );
    h.assert_eq_ev(
        "open and opendir payloads match",
        FUSE_OPEN_IN_WIRE_SIZE,
        FUSE_OPENDIR_IN_WIRE_SIZE,
    );
    h.assert_eq_ev(
        "release and releasedir payloads match",
        FUSE_RELEASE_IN_WIRE_SIZE,
        FUSE_RELEASEDIR_IN_WIRE_SIZE,
    );
    h.assert_eq_ev(
        "readdir and readdirplus payloads match",
        FUSE_READDIR_IN_WIRE_SIZE,
        FUSE_READDIRPLUS_IN_WIRE_SIZE,
    );
    h.assert_eq_ev(
        "setlk and setlkw payloads match",
        FUSE_SETLK_IN_WIRE_SIZE,
        FUSE_SETLKW_IN_WIRE_SIZE,
    );
    h.assert_eq_ev(
        "required symlink payload minimum",
        FUSE_SYMLINK_MIN_WIRE_SIZE,
        2usize,
    );
    h.assert_eq_ev("lock type read", FUSE_LK_TYPE_RDLCK, 0);
    h.assert_eq_ev("lock type write", FUSE_LK_TYPE_WRLCK, 1);
    h.assert_eq_ev("lock type unlock", FUSE_LK_TYPE_UNLCK, 2);
    h.assert_eq_ev("fdatasync flag bit", fsync_flags::FUSE_FSYNC_FDATASYNC, 1);
    h.assert_eq_ev("seek data whence", lseek_whence::SEEK_DATA, 3);
}

fn smoke_remaining_parsers(h: &mut SmokeHarness) {
    record_fusewire_op(h, "fusewire.remaining", opcode::FUSE_CREATE, b"remaining");

    // FUSE_GETXATTR
    let mut gx = vec![0u8; FUSE_GETXATTR_IN_WIRE_SIZE];
    put_u32(&mut gx, 0, 64);
    gx.extend_from_slice(b"user.name\0");
    let getxattr = parse_fuse_getxattr_request(&gx).expect("getxattr parses");
    h.assert_eq_ev("getxattr size parses", getxattr.size, 64);
    h.assert_eq_ev(
        "getxattr name parses",
        getxattr.name.to_vec(),
        b"user.name".to_vec(),
    );

    // FUSE_LISTXATTR
    let mut lx = [0u8; FUSE_GETXATTR_IN_WIRE_SIZE];
    put_u32(&mut lx, 0, 256);
    let listxattr = parse_fuse_listxattr_request(&lx).expect("listxattr parses");
    h.assert_eq_ev("listxattr size parses", listxattr.size, 256);

    // FUSE_REMOVEXATTR
    let removexattr = parse_fuse_removexattr_request(b"user.key\0").expect("removexattr parses");
    h.assert_eq_ev(
        "removexattr name parses",
        removexattr.name.to_vec(),
        b"user.key".to_vec(),
    );

    // FUSE_CREATE
    let mut cr = vec![0u8; FUSE_CREATE_IN_WIRE_SIZE];
    put_u32(&mut cr, 0, 0o2);
    put_u32(&mut cr, 4, 0o644);
    put_u32(&mut cr, 8, 0o022);
    put_u32(&mut cr, 12, 0o1);
    cr.extend_from_slice(b"newfile\0");
    let create = parse_fuse_create_request(&cr).expect("create parses");
    h.assert_eq_ev("create flags parses", create.flags, 0o2);
    h.assert_eq_ev("create mode parses", create.mode, 0o644);
    h.assert_eq_ev("create umask parses", create.umask, 0o022);
    h.assert_eq_ev("create open_flags parses", create.open_flags, 0o1);
    h.assert_eq_ev(
        "create name parses",
        create.name.to_vec(),
        b"newfile".to_vec(),
    );
    let mut empty_create = vec![0u8; FUSE_CREATE_IN_WIRE_SIZE];
    empty_create.extend_from_slice(b"\0");
    let empty_err = parse_fuse_create_request(&empty_create).unwrap_err();
    h.assert_ev(
        "create empty name is EmptyName",
        matches!(empty_err, CreateRequestParseError::EmptyName),
    );

    // FUSE_MKNOD
    let mut mk = [0u8; FUSE_MKNOD_IN_WIRE_SIZE + 4];
    put_u32(&mut mk, 0, 0o644 | 0o010_000);
    put_u32(&mut mk, 4, 0x0103);
    put_u32(&mut mk, 8, 0o022);
    put_u32(&mut mk, 12, 0);
    mk[FUSE_MKNOD_IN_WIRE_SIZE..].copy_from_slice(b"dev\0");
    let mknod = parse_fuse_mknod_request(42, &mk).expect("mknod parses");
    h.assert_eq_ev("mknod parent parses", mknod.parent, 42);
    h.assert_eq_ev("mknod mode parses", mknod.mode, 0o644 | 0o010_000);
    h.assert_eq_ev("mknod rdev parses", mknod.rdev, 0x0103);
    h.assert_eq_ev("mknod name parses", mknod.name.to_vec(), b"dev".to_vec());

    // FUSE_FSYNCDIR
    let mut fsd = [0u8; FUSE_FSYNCDIR_IN_WIRE_SIZE];
    put_u64(&mut fsd, 0, 0x99);
    put_u32(&mut fsd, 8, fsync_flags::FUSE_FSYNC_FDATASYNC);
    let fsyncdir = parse_fuse_fsyncdir_request(&fsd).expect("fsyncdir parses");
    h.assert_eq_ev("fsyncdir fh parses", fsyncdir.fh, 0x99);
    h.assert_eq_ev(
        "fsyncdir flags parse",
        fsyncdir.fsync_flags,
        fsync_flags::FUSE_FSYNC_FDATASYNC,
    );

    // FUSE_READLINK
    let readlink = parse_fuse_readlink_request(&[], 99).expect("readlink parses");
    h.assert_eq_ev("readlink nodeid parses", readlink.nodeid, 99);
}

fn record_fusewire_op(h: &mut SmokeHarness, op_name: &str, opcode: u32, payload: &[u8]) {
    h.record(TraceEvent::FsLifecycleOp {
        inode_id: opcode as u64,
        op_name: op_name.to_string(),
        payload: payload.to_vec(),
    });
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn u32_payload(value: u32) -> [u8; FUSE_ACCESS_IN_WIRE_SIZE] {
    let mut payload = [0_u8; FUSE_ACCESS_IN_WIRE_SIZE];
    put_u32(&mut payload, 0, value);
    payload
}

fn u64_payload(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

fn fuse_init_payload(
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
) -> [u8; FUSE_INIT_IN_WIRE_SIZE] {
    let mut payload = [0_u8; FUSE_INIT_IN_WIRE_SIZE];
    put_u32(&mut payload, 0, major);
    put_u32(&mut payload, 4, minor);
    put_u32(&mut payload, 8, max_readahead);
    put_u32(&mut payload, 12, flags);
    payload
}

fn batch_forget_payload() -> Vec<u8> {
    let mut payload =
        vec![0_u8; FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE + 2 * FUSE_FORGET_ONE_WIRE_SIZE];
    put_u32(&mut payload, 0, 2);
    put_u64(&mut payload, FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE, 11);
    put_u64(&mut payload, FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE + 8, 1);
    put_u64(
        &mut payload,
        FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE + FUSE_FORGET_ONE_WIRE_SIZE,
        12,
    );
    put_u64(
        &mut payload,
        FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE + FUSE_FORGET_ONE_WIRE_SIZE + 8,
        2,
    );
    payload
}

fn getattr_payload(getattr_flags: u32, fh: u64) -> [u8; FUSE_GETATTR_IN_WIRE_SIZE] {
    let mut payload = [0_u8; FUSE_GETATTR_IN_WIRE_SIZE];
    put_u32(&mut payload, 0, getattr_flags);
    put_u64(&mut payload, 8, fh);
    payload
}

fn statx_payload() -> [u8; FUSE_STATX_IN_WIRE_SIZE] {
    let mut payload = [0_u8; FUSE_STATX_IN_WIRE_SIZE];
    put_u32(&mut payload, 0, FUSE_GETATTR_FH);
    put_u64(&mut payload, 8, 0x1234);
    put_u32(&mut payload, 16, 0x10);
    put_u32(&mut payload, 20, 0x0fff);
    payload
}

fn open_payload(flags: u32, padding: u32) -> [u8; FUSE_OPEN_IN_WIRE_SIZE] {
    let mut payload = [0_u8; FUSE_OPEN_IN_WIRE_SIZE];
    put_u32(&mut payload, 0, flags);
    put_u32(&mut payload, 4, padding);
    payload
}

fn release_payload() -> [u8; FUSE_RELEASE_IN_WIRE_SIZE] {
    let mut payload = [0_u8; FUSE_RELEASE_IN_WIRE_SIZE];
    put_u64(&mut payload, 0, 0x44);
    put_u32(&mut payload, 8, 0x2);
    put_u32(&mut payload, 12, 0x1);
    put_u64(&mut payload, 16, 0x55);
    payload
}

fn setattr_payload() -> [u8; FUSE_SETATTR_IN_WIRE_SIZE] {
    let mut payload = [0_u8; FUSE_SETATTR_IN_WIRE_SIZE];
    put_u32(&mut payload, 0, 0xff);
    put_u64(&mut payload, 8, 0x44);
    put_u64(&mut payload, 16, 4096);
    put_u64(&mut payload, 24, 0x55);
    put_u64(&mut payload, 32, 1);
    put_u64(&mut payload, 40, 2);
    put_u64(&mut payload, 48, 3);
    put_u32(&mut payload, 56, 4);
    put_u32(&mut payload, 60, 5);
    put_u32(&mut payload, 64, 6);
    put_u32(&mut payload, 68, 0o100_644);
    put_u32(&mut payload, 76, 1000);
    put_u32(&mut payload, 80, 1001);
    payload
}

fn link_payload() -> Vec<u8> {
    let mut payload = vec![0_u8; FUSE_LINK_IN_WIRE_SIZE];
    put_u64(&mut payload, 0, 77);
    payload.extend_from_slice(b"hardlink\0");
    payload
}

fn rename_payload(rename2: bool) -> Vec<u8> {
    let header = if rename2 {
        FUSE_RENAME2_IN_WIRE_SIZE
    } else {
        FUSE_RENAME_IN_WIRE_SIZE
    };
    let mut payload = vec![0_u8; header];
    put_u64(&mut payload, 0, 88);
    if rename2 {
        put_u32(&mut payload, 8, 1);
    }
    payload.extend_from_slice(b"old\0new\0");
    payload
}

fn setxattr_payload() -> Vec<u8> {
    let mut payload = vec![0_u8; FUSE_SETXATTR_IN_WIRE_SIZE];
    put_u32(&mut payload, 0, 5);
    put_u32(&mut payload, 4, 1);
    put_u32(&mut payload, 8, 0);
    payload.extend_from_slice(b"user.key\0value");
    payload
}

fn mkdir_payload() -> Vec<u8> {
    let mut payload = vec![0_u8; FUSE_MKDIR_IN_WIRE_SIZE];
    put_u32(&mut payload, 0, 0o755);
    put_u32(&mut payload, 4, 0o022);
    payload.extend_from_slice(b"dir\0");
    payload
}

fn read_payload() -> [u8; FUSE_READ_IN_WIRE_SIZE] {
    let mut payload = [0_u8; FUSE_READ_IN_WIRE_SIZE];
    put_u64(&mut payload, 0, 0x80);
    put_u64(&mut payload, 8, 128);
    put_u32(&mut payload, 16, 4096);
    put_u64(&mut payload, 24, 0x55);
    put_u32(&mut payload, 32, 0x2);
    payload
}

fn readdirplus_payload() -> [u8; FUSE_READDIRPLUS_IN_WIRE_SIZE] {
    let mut payload = read_payload();
    put_u32(
        &mut payload,
        20,
        readdirplus_read_flags::FUSE_READ_LOCKOWNER,
    );
    payload
}

fn flush_payload() -> [u8; FUSE_FLUSH_IN_WIRE_SIZE] {
    let mut payload = [0_u8; FUSE_FLUSH_IN_WIRE_SIZE];
    put_u64(&mut payload, 0, 0x44);
    put_u64(&mut payload, 16, 0x55);
    payload
}

fn fallocate_payload() -> [u8; FUSE_FALLOCATE_IN_WIRE_SIZE] {
    let mut payload = [0_u8; FUSE_FALLOCATE_IN_WIRE_SIZE];
    put_u64(&mut payload, 0, 0x44);
    put_u64(&mut payload, 8, 1024);
    put_u64(&mut payload, 16, 2048);
    put_u32(&mut payload, 24, fallocate_flags::FALLOC_FL_KEEP_SIZE);
    payload
}

fn lseek_payload() -> [u8; FUSE_LSEEK_IN_WIRE_SIZE] {
    let mut payload = [0_u8; FUSE_LSEEK_IN_WIRE_SIZE];
    put_u64(&mut payload, 0, 0x44);
    put_u64(&mut payload, 8, 1024);
    put_u32(&mut payload, 16, lseek_whence::SEEK_DATA);
    payload
}

fn copy_file_range_payload() -> [u8; FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE] {
    let mut payload = [0_u8; FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE];
    put_u64(&mut payload, 0, 0x11);
    put_u64(&mut payload, 8, 64);
    put_u64(&mut payload, 16, 0x22);
    put_u64(&mut payload, 24, 0x33);
    put_u64(&mut payload, 32, 128);
    put_u64(&mut payload, 40, 512);
    payload
}

fn write_payload() -> Vec<u8> {
    let mut payload = vec![0_u8; FUSE_WRITE_IN_WIRE_SIZE];
    put_u64(&mut payload, 0, 0x44);
    put_u64(&mut payload, 8, 1024);
    put_u32(&mut payload, 16, 4);
    put_u32(&mut payload, 20, write_flags::FUSE_WRITE_LOCKOWNER);
    put_u64(&mut payload, 24, 0x55);
    put_u32(&mut payload, 32, 0x2);
    payload.extend_from_slice(b"data");
    payload
}

fn lock_payload() -> [u8; FUSE_GETLK_IN_WIRE_SIZE] {
    let mut payload = [0_u8; FUSE_GETLK_IN_WIRE_SIZE];
    put_u64(&mut payload, 0, 0x44);
    put_u64(&mut payload, 8, 0x55);
    put_u64(&mut payload, 16, 10);
    put_u64(&mut payload, 24, 20);
    put_u32(&mut payload, 32, FUSE_LK_TYPE_RDLCK);
    put_u32(&mut payload, 36, 1234);
    put_u32(&mut payload, 40, 0);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::verify_trace_assertions;

    #[test]
    fn fusewire_smoke_exercises_public_api() {
        let h = run_fusewire_smoke();
        assert!(verify_trace_assertions(&h.trace).is_empty());
    }
}
