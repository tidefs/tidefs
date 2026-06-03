//! Inode-attributes smoke: deterministic lifecycle coverage for attribute
//! get/set, link-count tracking, stat translation, and error paths against
//! `MemInodeAttributeStore` (the default `InodeAttributeStore` backend).
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::TraceEvent;
use tidefs_inode_attributes::{
    apply_setattr, AttrError, InodeAttributeStore, MemInodeAttributeStore,
};
use tidefs_types_vfs_core::{
    Generation, InodeAttr, InodeFlags, InodeId, NodeKind, PosixAttrs, SetAttr, FATTR_ATIME,
    FATTR_GID, FATTR_MODE, FATTR_MTIME, FATTR_SIZE, FATTR_UID, S_IFREG,
};

fn file_attrs(ino: u64, mode: u32, uid: u32, gid: u32) -> InodeAttr {
    InodeAttr {
        inode_id: InodeId::new(ino),
        generation: Generation::new(1),
        kind: NodeKind::File,
        posix: PosixAttrs {
            mode: S_IFREG | mode,
            uid,
            gid,
            nlink: 1,
            rdev: 0,
            atime_ns: 1_000_000_000,
            mtime_ns: 2_000_000_000,
            ctime_ns: 3_000_000_000,
            btime_ns: 4_000_000_000,
            size: 0,
            blocks_512: 0,
            blksize: 4096,
        },
        flags: InodeFlags::none(),
        subtree_rev: 0,
        dir_rev: 0,
    }
}

/// Run the full inode-attributes smoke sequence and return the harness.
#[must_use]
pub fn run_inode_attributes_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();
    let store = MemInodeAttributeStore::new();
    h.scenario_begin("inode-attributes/smoke");

    h.assert_ev("new store is empty", store.is_empty());
    h.assert_eq_ev("new store len", store.len(), 0);

    h.record(TraceEvent::InodeGetattr { inode_id: 99 });
    h.assert_eq_ev(
        "getattr missing returns InoNotFound",
        store.getattr(99),
        Err(AttrError::InoNotFound),
    );

    let a1 = file_attrs(1, 0o644, 1000, 100);
    store.insert(1, a1);
    h.record(TraceEvent::InodeGetattr { inode_id: 1 });
    let got = store.getattr(1).expect("inode 1 should exist");
    h.assert_eq_ev("getattr returns correct inode_id", got.inode_id.get(), 1);
    h.assert_eq_ev(
        "getattr returns correct mode",
        got.posix.mode,
        S_IFREG | 0o644,
    );
    h.assert_eq_ev("getattr returns correct uid", got.posix.uid, 1000);
    h.assert_eq_ev("getattr returns correct gid", got.posix.gid, 100);
    h.assert_eq_ev("getattr returns correct nlink", got.posix.nlink, 1);
    h.assert_eq_ev("getattr returns correct kind", got.kind, NodeKind::File);
    h.assert_ev("store not empty after insert", !store.is_empty());
    h.assert_eq_ev("store len after insert", store.len(), 1);

    // setattr: mode
    let mut set = SetAttr::new();
    set.valid = FATTR_MODE;
    set.mode = 0o600;
    h.record(TraceEvent::InodeSetattr {
        inode_id: 1,
        attr_mask: FATTR_MODE as u64,
    });
    let updated = store.setattr(1, &set).expect("setattr mode should succeed");
    h.assert_eq_ev(
        "setattr mode changes mode bits",
        updated.posix.mode & !S_IFREG,
        0o600,
    );
    h.assert_eq_ev(
        "setattr mode preserves type bits",
        updated.posix.mode & S_IFREG,
        S_IFREG,
    );
    h.assert_eq_ev("setattr mode preserves uid", updated.posix.uid, 1000);
    h.assert_ev(
        "setattr mode advances ctime",
        updated.posix.ctime_ns > a1.posix.ctime_ns,
    );

    // setattr: uid + gid
    let mut set_ug = SetAttr::new();
    set_ug.valid = FATTR_UID | FATTR_GID;
    set_ug.uid = 2000;
    set_ug.gid = 200;
    h.record(TraceEvent::InodeSetattr {
        inode_id: 1,
        attr_mask: FATTR_UID as u64 | FATTR_GID as u64,
    });
    let updated_ug = store
        .setattr(1, &set_ug)
        .expect("setattr uid+gid should succeed");
    h.assert_eq_ev("setattr updates uid", updated_ug.posix.uid, 2000);
    h.assert_eq_ev("setattr updates gid", updated_ug.posix.gid, 200);

    // setattr: size
    let mut set_sz = SetAttr::new();
    set_sz.valid = FATTR_SIZE;
    set_sz.size = 8192;
    h.record(TraceEvent::InodeSetattr {
        inode_id: 1,
        attr_mask: FATTR_SIZE as u64,
    });
    let updated_sz = store
        .setattr(1, &set_sz)
        .expect("setattr size should succeed");
    h.assert_eq_ev("setattr size field", updated_sz.posix.size, 8192);
    h.assert_eq_ev(
        "setattr blocks_512 recomputed",
        updated_sz.posix.blocks_512,
        16,
    );

    // setattr: timestamps
    let mut set_ts = SetAttr::new();
    set_ts.valid = FATTR_ATIME | FATTR_MTIME;
    set_ts.atime_ns = 111;
    set_ts.mtime_ns = 222;
    h.record(TraceEvent::InodeSetattr {
        inode_id: 1,
        attr_mask: FATTR_ATIME as u64 | FATTR_MTIME as u64,
    });
    let updated_ts = store
        .setattr(1, &set_ts)
        .expect("setattr timestamps should succeed");
    h.assert_eq_ev("setattr atime_ns", updated_ts.posix.atime_ns, 111);
    h.assert_eq_ev("setattr mtime_ns", updated_ts.posix.mtime_ns, 222);

    // no-op
    let before_noop = store.getattr(1).unwrap();
    let noop = SetAttr::new();
    let after_noop = store
        .setattr(1, &noop)
        .expect("no-op setattr should succeed");
    h.assert_eq_ev(
        "no-op setattr preserves ctime",
        after_noop.posix.ctime_ns,
        before_noop.posix.ctime_ns,
    );
    h.assert_eq_ev(
        "no-op setattr preserves mode",
        after_noop.posix.mode,
        before_noop.posix.mode,
    );

    h.record(TraceEvent::InodeSetattr {
        inode_id: 99,
        attr_mask: FATTR_MODE as u64,
    });
    h.assert_eq_ev(
        "setattr missing returns InoNotFound",
        store.setattr(99, &noop),
        Err(AttrError::InoNotFound),
    );

    // re-insert with fresh nlink after setattr underflow
    store.remove(1);
    store.insert(1, file_attrs(1, 0o600, 2000, 200));

    h.record(TraceEvent::InodeLink { inode_id: 1 });
    h.assert_eq_ev("bump_link increments to 2", store.bump_link(1).unwrap(), 2);
    h.assert_eq_ev(
        "second bump_link increments to 3",
        store.bump_link(1).unwrap(),
        3,
    );

    h.record(TraceEvent::InodeUnlink { inode_id: 1 });
    h.assert_eq_ev("drop_link decrements to 2", store.drop_link(1).unwrap(), 2);
    h.assert_eq_ev(
        "second drop_link decrements to 1",
        store.drop_link(1).unwrap(),
        1,
    );
    h.assert_eq_ev(
        "third drop_link decrements to 0",
        store.drop_link(1).unwrap(),
        0,
    );

    h.record(TraceEvent::InodeUnlink { inode_id: 1 });
    h.assert_eq_ev(
        "drop_link underflow returns LinkUnderflow",
        store.drop_link(1),
        Err(AttrError::LinkUnderflow),
    );

    h.record(TraceEvent::InodeLink { inode_id: 99 });
    h.assert_eq_ev(
        "bump_link missing returns InoNotFound",
        store.bump_link(99),
        Err(AttrError::InoNotFound),
    );
    h.record(TraceEvent::InodeUnlink { inode_id: 99 });
    h.assert_eq_ev(
        "drop_link missing returns InoNotFound",
        store.drop_link(99),
        Err(AttrError::InoNotFound),
    );

    // set size back before to_stat
    let mut set_sz3 = SetAttr::new();
    set_sz3.valid = FATTR_SIZE;
    set_sz3.size = 8192;
    store.setattr(1, &set_sz3).unwrap();

    // to_stat (libc::stat lacks PartialEq)
    let st = store.to_stat(1).expect("to_stat should succeed");
    h.assert_eq_ev("to_stat ino", st.st_ino as u64, 1);
    h.assert_eq_ev("to_stat mode", st.st_mode as u32, S_IFREG | 0o600);
    h.assert_eq_ev("to_stat uid", st.st_uid, 2000u32);
    h.assert_eq_ev("to_stat gid", st.st_gid, 200u32);
    h.assert_eq_ev("to_stat nlink", st.st_nlink as u32, 0);
    h.assert_eq_ev("to_stat size", st.st_size as u64, 8192);

    h.record(TraceEvent::InodeGetattr { inode_id: 99 });
    h.assert_ev(
        "to_stat missing returns InoNotFound",
        matches!(store.to_stat(99), Err(AttrError::InoNotFound)),
    );

    // multi-inode independence
    store.insert(10, file_attrs(10, 0o755, 500, 50));
    store.insert(20, file_attrs(20, 0o700, 600, 60));
    let a10 = store.getattr(10).expect("inode 10 should exist");
    let a20 = store.getattr(20).expect("inode 20 should exist");
    h.assert_eq_ev("multi-inode: inode 10 uid", a10.posix.uid, 500);
    h.assert_eq_ev("multi-inode: inode 20 uid", a20.posix.uid, 600);
    h.assert_eq_ev("store len after two more inserts", store.len(), 3);
    store.bump_link(20).unwrap();
    let a10_after = store.getattr(10).unwrap();
    h.assert_eq_ev(
        "bump on inode 20 does not change inode 10 nlink",
        a10_after.posix.nlink,
        1,
    );

    // remove
    let removed = store.remove(10);
    h.assert_ev("remove existing returns Some", removed.is_some());
    h.assert_eq_ev("store len after remove", store.len(), 2);
    let removed_again = store.remove(10);
    h.assert_ev("remove missing returns None", removed_again.is_none());
    h.record(TraceEvent::InodeGetattr { inode_id: 10 });
    h.assert_eq_ev(
        "getattr after remove returns InoNotFound",
        store.getattr(10),
        Err(AttrError::InoNotFound),
    );

    // apply_setattr
    let mut pure_attrs = file_attrs(99, 0o644, 1000, 100);
    let mut set_sz2 = SetAttr::new();
    set_sz2.valid = FATTR_SIZE;
    set_sz2.size = 42;
    let changed = apply_setattr(&mut pure_attrs, &set_sz2);
    h.assert_ev("apply_setattr reports changed", changed);
    h.assert_eq_ev("apply_setattr size", pure_attrs.posix.size, 42);

    let mut pure_attrs2 = file_attrs(98, 0o644, 1000, 100);
    let original_ctime = pure_attrs2.posix.ctime_ns;
    let changed2 = apply_setattr(&mut pure_attrs2, &SetAttr::new());
    h.assert_ev("apply_setattr empty reports no change", !changed2);
    h.assert_eq_ev(
        "apply_setattr empty preserves ctime",
        pure_attrs2.posix.ctime_ns,
        original_ctime,
    );

    h.scenario_end("inode-attributes/smoke");
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_all_passed(h: &SmokeHarness) {
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

    #[test]
    fn inode_attributes_smoke_passes() {
        let h = run_inode_attributes_smoke();
        assert_all_passed(&h);
        let data =
            crate::trace::serialize_trace(&h.trace).expect("serialize inode-attributes trace");
        let back =
            crate::trace::deserialize_trace(&data).expect("deserialize inode-attributes trace");
        assert_eq!(h.trace, back);
    }
}
