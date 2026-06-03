//! Reply smoke: deterministic API coverage for
//! `tidefs-posix-filesystem-adapter-daemon (reply module)`.
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::{deserialize_trace, serialize_trace, TraceEvent};
use tidefs_posix_filesystem_adapter_daemon::reply::{
    commit_bulk_reply, commit_lookup_error, commit_lookup_reply, commit_rename_error,
    commit_rename_reply, commit_small_reply, encode_lookup_entry_reply, lookup_entry_wire_len,
    pack_dirent, pack_dirent_plus, rename_reply_wire_len, reply_errno, would_overflow,
    DirentPlusAttr, DirentPlusWire, LookupEntryAttr, LookupEntryEncodeError, LookupEntryReply,
    ReplyBuilder, ReplyDirEntry, ReplyDirEntryPlus, ReplyError, StatfsReply, XattrReplyEncodeError,
    DIRENT_MAX_NAME, FUSE_CREATE_OUT_WIRE_SIZE, FUSE_DIRENT_HEADER_SIZE, FUSE_ENTRY_OUT_WIRE_SIZE,
    FUSE_GETXATTR_OUT_WIRE_SIZE, FUSE_OUT_HEADER_WIRE_SIZE, FUSE_STATFS_OUT_WIRE_SIZE,
    FUSE_WRITE_OUT_WIRE_SIZE, READDIR_MAX_BUFFER, XATTR_REPLY_MAX_PAYLOAD,
};

/// Run the reply crate smoke sequence and return the harness.
#[must_use]
pub fn run_reply_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("reply/smoke");
    smoke_lookup_reply_api(&mut h);
    smoke_reply_builder_api(&mut h);
    smoke_dirent_and_readdir_api(&mut h);
    smoke_commit_records(&mut h);
    h.scenario_end("reply/smoke");

    let trace_before_round_trip = h.trace.clone();
    let serialized =
        serialize_trace(&trace_before_round_trip).expect("reply smoke trace should serialize");
    let decoded = deserialize_trace(&serialized).expect("reply smoke trace should deserialize");
    h.assert_eq_ev(
        "reply smoke trace round-trips",
        decoded,
        trace_before_round_trip,
    );

    h
}

fn smoke_lookup_reply_api(h: &mut SmokeHarness) {
    record_reply_op(h, "reply.lookup.attr", 44, b"lookup-entry-attr");

    let attr = lookup_attr();
    h.assert_eq_ev("lookup attr constructor keeps inode", attr.ino, 44);
    h.assert_eq_ev("lookup attr constructor keeps mode", attr.mode, 0o100_644);
    h.assert_eq_ev(
        "lookup attr zero is default",
        LookupEntryAttr::ZERO,
        LookupEntryAttr::default(),
    );

    let entry = LookupEntryReply::positive(44, 7, 5, 123, 2, 456).with_attr(attr);
    h.assert_eq_ev("positive lookup keeps nodeid", entry.nodeid, 44);
    h.assert_eq_ev("positive lookup keeps generation", entry.generation, 7);
    h.assert_ev("positive lookup is not negative", !entry.negative);

    let mut out = [0_u8; FUSE_ENTRY_OUT_WIRE_SIZE as usize];
    let encoded_len =
        encode_lookup_entry_reply(&entry, &mut out).expect("lookup entry should encode");
    h.assert_eq_ev(
        "lookup entry wire length matches encoded length",
        encoded_len,
        lookup_entry_wire_len(),
    );
    h.assert_eq_ev("encoded lookup nodeid", read_u64_le(&out, 0), 44);
    h.assert_eq_ev("encoded lookup attr size", read_u64_le(&out, 48), 4096);
    h.assert_eq_ev("encoded lookup attr uid", read_u32_le(&out, 108), 1000);

    let mut too_short = [0_u8; 127];
    h.assert_eq_ev(
        "short lookup buffer is rejected",
        encode_lookup_entry_reply(&entry, &mut too_short),
        Err(LookupEntryEncodeError::BufferTooSmall {
            required: lookup_entry_wire_len(),
            actual: 127,
        }),
    );

    let negative = LookupEntryReply::negative(3, 250_000_000);
    h.assert_ev("negative lookup is marked", negative.negative);
    h.assert_eq_ev("negative lookup has zero nodeid", negative.nodeid, 0);
}

fn smoke_reply_builder_api(h: &mut SmokeHarness) {
    record_reply_op(h, "reply.builder.headers", 100, b"fuse-out-header");

    let builder = ReplyBuilder::new(100);
    h.assert_eq_ev("reply builder preserves unique", builder.unique(), 100);

    let none = builder.reply_none();
    h.assert_eq_ev(
        "reply_none length is header only",
        none.len(),
        FUSE_OUT_HEADER_WIRE_SIZE,
    );
    h.assert_eq_ev("reply_none header length", read_u32_le(&none, 0), 16);
    h.assert_eq_ev("reply_none unique", read_u64_le(&none, 8), 100);

    let error = ReplyBuilder::new(101).reply_error(reply_errno::ENOENT);
    h.assert_eq_ev(
        "positive errno becomes negative",
        read_i32_le(&error, 4),
        -2,
    );

    let mapped = ReplyBuilder::new(102).reply_mapped_error(&ReplyError::NoSpace);
    h.assert_eq_ev(
        "mapped reply error uses errno",
        read_i32_le(&mapped, 4),
        -reply_errno::ENOSPC,
    );

    let read = ReplyBuilder::new(103).reply_read(b"data");
    h.assert_eq_ev("read reply total length", read.len(), 20usize);
    h.assert_eq_ev(
        "read reply payload is preserved",
        read[FUSE_OUT_HEADER_WIRE_SIZE..].to_vec(),
        b"data".to_vec(),
    );

    let readlink = ReplyBuilder::new(104).reply_readlink(b"../target");
    h.assert_eq_ev(
        "readlink reply reuses data payload shape",
        readlink[FUSE_OUT_HEADER_WIRE_SIZE..].to_vec(),
        b"../target".to_vec(),
    );

    let write = ReplyBuilder::new(105).reply_write(4096);
    h.assert_eq_ev(
        "write reply includes write-out payload",
        write.len(),
        FUSE_OUT_HEADER_WIRE_SIZE + FUSE_WRITE_OUT_WIRE_SIZE,
    );
    h.assert_eq_ev("write reply size field", read_u32_le(&write, 16), 4096);

    let statfs = StatfsReply {
        blocks: 1000,
        bfree: 900,
        bavail: 800,
        files: 700,
        ffree: 600,
        favail: 500,
        bsize: 4096,
        namemax: 255,
        frsize: 4096,
    };
    let statfs_reply = ReplyBuilder::new(106).reply_statfs(&statfs);
    h.assert_eq_ev(
        "statfs reply includes statfs payload",
        statfs_reply.len(),
        FUSE_OUT_HEADER_WIRE_SIZE + FUSE_STATFS_OUT_WIRE_SIZE,
    );
    h.assert_eq_ev("statfs blocks field", read_u64_le(&statfs_reply, 16), 1000);
    h.assert_eq_ev("statfs namemax field", read_u64_le(&statfs_reply, 72), 255);

    let xattr_size = ReplyBuilder::new(107).reply_getxattr_size(512);
    h.assert_eq_ev(
        "xattr size reply uses fuse_getxattr_out",
        xattr_size.len(),
        FUSE_OUT_HEADER_WIRE_SIZE + FUSE_GETXATTR_OUT_WIRE_SIZE,
    );
    h.assert_eq_ev(
        "xattr size payload field",
        read_u32_le(&xattr_size, 16),
        512,
    );

    let xattr_value = ReplyBuilder::new(108)
        .reply_getxattr_value(b"value")
        .expect("xattr value reply");
    h.assert_eq_ev(
        "xattr value payload is preserved",
        xattr_value[FUSE_OUT_HEADER_WIRE_SIZE..].to_vec(),
        b"value".to_vec(),
    );

    let too_large = vec![0_u8; XATTR_REPLY_MAX_PAYLOAD + 1];
    h.assert_eq_ev(
        "oversized xattr value is rejected",
        ReplyBuilder::new(109).reply_getxattr_value(&too_large),
        Err(XattrReplyEncodeError::PayloadTooLarge {
            max: XATTR_REPLY_MAX_PAYLOAD,
            actual: XATTR_REPLY_MAX_PAYLOAD + 1,
        }),
    );
}

fn smoke_dirent_and_readdir_api(h: &mut SmokeHarness) {
    record_reply_op(h, "reply.dirent.pack", 77, b"dirent-plus");

    let (wire, packed_len) = pack_dirent(77, 12, 8, b"alpha");
    h.assert_eq_ev("dirent ino is packed", wire.ino, 77);
    h.assert_eq_ev("dirent offset is packed", wire.off, 12);
    h.assert_eq_ev("dirent name length is packed", wire.namelen, 5);
    h.assert_eq_ev("dirent padded length is aligned", packed_len % 8, 0);
    h.assert_eq_ev(
        "dirent payload preserves name",
        wire.name[..5].to_vec(),
        b"alpha".to_vec(),
    );

    let long_name = vec![b'x'; DIRENT_MAX_NAME + 16];
    let (truncated, _) = pack_dirent(78, 13, 4, &long_name);
    h.assert_eq_ev(
        "dirent name is capped at kernel max",
        truncated.namelen as usize,
        DIRENT_MAX_NAME,
    );

    let plus_attr = DirentPlusAttr {
        ino: 77,
        size: 4096,
        blocks: 8,
        mode: 0o100_644,
        nlink: 1,
        uid: 1000,
        gid: 1001,
        blksize: 4096,
        ..Default::default()
    };
    let (plus_wire, plus_len) = pack_dirent_plus(77, 4, 14, b"alpha", 987_654_321, plus_attr);
    h.assert_eq_ev("direntplus ino is packed", plus_wire.ino, 77);
    h.assert_eq_ev("direntplus attr size is packed", plus_wire.attr.size, 4096);
    h.assert_ev(
        "direntplus length includes entry and dirent headers",
        plus_len >= lookup_entry_wire_len() + FUSE_DIRENT_HEADER_SIZE,
    );
    h.assert_eq_ev(
        "zeroed direntplus has zero inode",
        DirentPlusWire::zeroed().ino,
        0,
    );

    let attr = lookup_attr();
    let dirent = ReplyDirEntry::new(77, 14, 8, b"alpha");
    let plus = ReplyDirEntryPlus::new(dirent, 4, 2, 0, 3, 0, attr);
    let lookup = plus.lookup_entry();
    h.assert_eq_ev("readdirplus lookup keeps nodeid", lookup.nodeid, 77);
    h.assert_eq_ev("readdirplus lookup keeps generation", lookup.generation, 4);

    let readdir = ReplyBuilder::new(110).reply_readdir(&[dirent], READDIR_MAX_BUFFER);
    h.assert_ev(
        "readdir reply includes at least one entry",
        readdir.len() > FUSE_OUT_HEADER_WIRE_SIZE,
    );
    h.assert_eq_ev("readdir packed inode", read_u64_le(&readdir, 16), 77);

    let readdirplus = ReplyBuilder::new(111).reply_readdirplus(&[plus], READDIR_MAX_BUFFER);
    h.assert_eq_ev(
        "readdirplus packed nodeid",
        read_u64_le(&readdirplus, 16),
        77,
    );
    h.assert_eq_ev(
        "readdirplus first dirent follows entry payload",
        read_u64_le(&readdirplus, 16 + lookup_entry_wire_len()),
        77,
    );

    h.assert_ev(
        "would_overflow detects too-large entry",
        would_overflow(8, 9),
    );
    h.assert_ev("would_overflow allows exact fit", !would_overflow(8, 8));
}

fn smoke_commit_records(h: &mut SmokeHarness) {
    record_reply_op(h, "reply.commit.records", 200, b"commit-records");

    let entry = LookupEntryReply::positive(44, 7, 5, 0, 2, 0).with_attr(lookup_attr());
    let small = commit_small_reply(200, 0, FUSE_ENTRY_OUT_WIRE_SIZE);
    let bulk = commit_bulk_reply(201, 0, READDIR_MAX_BUFFER as u32);
    h.assert_eq_ev("small reply unique", small.unique, 200);
    h.assert_eq_ev("small reply payload length", small.payload_len, 128);
    h.assert_eq_ev("bulk reply unique", bulk.unique, 201);
    h.assert_ev(
        "small and bulk reply classes differ",
        small.reply_class != bulk.reply_class,
    );

    let lookup = commit_lookup_reply(202, &entry);
    h.assert_eq_ev("lookup commit unique", lookup.unique, 202);
    h.assert_eq_ev("lookup commit is successful", lookup.error_or_zero, 0);
    h.assert_eq_ev("lookup commit payload length", lookup.payload_len, 128);

    let lookup_error = commit_lookup_error(203, -reply_errno::ENOENT);
    h.assert_eq_ev("lookup error unique", lookup_error.unique, 203);
    h.assert_eq_ev("lookup error errno", lookup_error.error_or_zero, -2);
    h.assert_eq_ev("lookup error has no payload", lookup_error.payload_len, 0);

    let rename = commit_rename_reply(204);
    h.assert_eq_ev("rename reply has empty wire payload", rename.payload_len, 0);
    h.assert_eq_ev("rename reply wire len const", rename_reply_wire_len(), 0);

    let rename_error = commit_rename_error(205, -reply_errno::EEXIST);
    h.assert_eq_ev("rename error errno", rename_error.error_or_zero, -17);

    let create = ReplyBuilder::new(206).reply_create(&entry, 0xAABB, 0x22);
    h.assert_eq_ev(
        "create reply includes entry and open payload",
        create.len(),
        FUSE_OUT_HEADER_WIRE_SIZE + FUSE_CREATE_OUT_WIRE_SIZE,
    );
    h.assert_eq_ev(
        "create reply file handle field",
        read_u64_le(&create, 144),
        0xAABB,
    );
}

fn lookup_attr() -> LookupEntryAttr {
    LookupEntryAttr::new(
        44, 4096, 8, 10, 20, 30, 111, 222, 333, 0o100_644, 2, 1000, 1001, 0, 4096,
    )
}

fn record_reply_op(h: &mut SmokeHarness, op_name: &str, inode_id: u64, payload: &[u8]) {
    h.record(TraceEvent::FsLifecycleOp {
        inode_id,
        op_name: op_name.to_string(),
        payload: payload.to_vec(),
    });
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_i32_le(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_smoke_passes() {
        let h = run_reply_smoke();
        assert!(h.trace.len() > 8);
    }

    #[test]
    fn reply_smoke_trace_round_trips() {
        let h = run_reply_smoke();
        let data = serialize_trace(&h.trace).expect("reply trace serialize");
        let back = deserialize_trace(&data).expect("reply trace deserialize");
        assert_eq!(h.trace, back);
    }
}
