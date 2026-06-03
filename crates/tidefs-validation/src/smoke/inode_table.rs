//! Inode-table smoke: deterministic lifecycle coverage for create, lookup,
//! attribute updates, link count transitions, removal, slot reuse, and error
//! paths against `InodeTable`.
//!
//! Gated on `feature = "fuse"`.

use std::time::Duration;

use crate::smoke::SmokeHarness;
use crate::trace::TraceEvent;
use tidefs_inode_table::{
    Ino, InodeAttributes, InodeKind, InodeTable, InodeTableError, TimeSource,
};

const ATTR_MASK_MODE: u64 = 1 << 0;
const ATTR_MASK_SIZE: u64 = 1 << 1;
const ATTR_MASK_NLINK: u64 = 1 << 2;

#[derive(Debug)]
struct FixedTimeSource {
    now: Duration,
}

impl FixedTimeSource {
    fn new(seconds: u64) -> Self {
        Self {
            now: Duration::from_secs(seconds),
        }
    }
}

impl TimeSource for FixedTimeSource {
    fn now(&self) -> Duration {
        self.now
    }
}

fn attrs(mode: u32, uid: u32, gid: u32, kind: InodeKind) -> InodeAttributes {
    InodeAttributes::new(mode, uid, gid, kind)
}

fn record_create(h: &mut SmokeHarness, ino: Ino, attrs: &InodeAttributes) {
    h.record(TraceEvent::InodeCreate {
        inode_id: ino.0,
        mode: attrs.mode,
        uid: attrs.uid,
        gid: attrs.gid,
    });
}

/// Run the full inode-table smoke sequence and return the harness.
#[must_use]
pub fn run_inode_table_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();
    let table = InodeTable::new(4, Box::new(FixedTimeSource::new(1_717_171_717)));

    h.scenario_begin("inode-table/smoke");
    h.assert_ev("new table is empty", table.is_empty());
    h.assert_eq_ev("new table capacity", table.capacity(), 4);

    let file_ino = table
        .create(
            InodeKind::File,
            attrs(0o100644, 1000, 1000, InodeKind::File),
        )
        .expect("file create should succeed");
    let file_attrs = table.getattr(file_ino).expect("file inode should exist");
    record_create(&mut h, file_ino, &file_attrs);
    h.assert_eq_ev("file inode number", file_ino.0, 1);
    h.assert_eq_ev("file kind", file_attrs.kind, InodeKind::File);
    h.assert_eq_ev("file mode", file_attrs.mode, 0o100644);
    h.assert_eq_ev("file uid", file_attrs.uid, 1000);
    h.assert_eq_ev("file gid", file_attrs.gid, 1000);
    h.assert_eq_ev("file nlink", file_attrs.nlink, 1);
    h.assert_ev("file generation assigned", file_attrs.generation > 0);

    h.record(TraceEvent::InodeGetattr {
        inode_id: file_ino.0,
    });
    let lookup_file = table.lookup(file_ino).expect("lookup should find file");
    h.assert_eq_ev(
        "lookup returns file generation",
        lookup_file.generation,
        file_attrs.generation,
    );

    let dir_ino = table
        .create(
            InodeKind::Directory,
            attrs(0o040755, 0, 0, InodeKind::Directory),
        )
        .expect("directory create should succeed");
    let dir_attrs = table
        .getattr(dir_ino)
        .expect("directory inode should exist");
    record_create(&mut h, dir_ino, &dir_attrs);
    h.assert_eq_ev("directory inode number", dir_ino.0, 2);
    h.assert_ev("directory kind predicate", dir_attrs.kind.is_dir());

    let symlink_ino = table
        .create(
            InodeKind::Symlink,
            attrs(0o120777, 1000, 1000, InodeKind::Symlink),
        )
        .expect("symlink create should succeed");
    let symlink_attrs = table
        .getattr(symlink_ino)
        .expect("symlink inode should exist");
    record_create(&mut h, symlink_ino, &symlink_attrs);
    h.assert_eq_ev("symlink inode number", symlink_ino.0, 3);
    h.assert_ev("symlink kind predicate", symlink_attrs.kind.is_symlink());

    h.record(TraceEvent::InodeSetattr {
        inode_id: file_ino.0,
        attr_mask: ATTR_MASK_MODE | ATTR_MASK_SIZE,
    });
    let mut updated_file = file_attrs.clone();
    updated_file.mode = 0o100600;
    updated_file.size = 4096;
    table
        .setattr(file_ino, updated_file.clone())
        .expect("file setattr should succeed");
    let stored_file = table.getattr(file_ino).expect("updated file should exist");
    h.assert_eq_ev("setattr updates file mode", stored_file.mode, 0o100600);
    h.assert_eq_ev("setattr updates file size", stored_file.size, 4096);
    h.assert_eq_ev(
        "setattr preserves file generation",
        stored_file.generation,
        file_attrs.generation,
    );

    h.record(TraceEvent::InodeLink {
        inode_id: file_ino.0,
    });
    let linked_nlink = table.link(file_ino).expect("file link should succeed");
    h.assert_eq_ev("link increments nlink", linked_nlink, 2);

    h.record(TraceEvent::InodeUnlink {
        inode_id: file_ino.0,
    });
    table.unlink(file_ino).expect("first unlink should succeed");
    let once_unlinked = table
        .getattr(file_ino)
        .expect("file should remain after one unlink");
    h.assert_eq_ev("first unlink decrements nlink", once_unlinked.nlink, 1);

    h.record(TraceEvent::InodeUnlink {
        inode_id: file_ino.0,
    });
    table
        .unlink(file_ino)
        .expect("second unlink should succeed");
    h.assert_ev(
        "second unlink removes file",
        table.lookup(file_ino).is_none(),
    );

    let reused_ino = table
        .create(
            InodeKind::File,
            attrs(0o100640, 2000, 2000, InodeKind::File),
        )
        .expect("create after remove should reuse free slot");
    let reused_attrs = table
        .getattr(reused_ino)
        .expect("reused file inode should exist");
    record_create(&mut h, reused_ino, &reused_attrs);
    h.assert_eq_ev("free-list reuses removed slot", reused_ino.0, file_ino.0);
    h.assert_ev(
        "slot reuse advances generation",
        reused_attrs.generation > file_attrs.generation,
    );
    h.assert_eq_ev("live inode count after reuse", table.len(), 3);

    h.record(TraceEvent::InodeGetattr { inode_id: 99 });
    h.assert_ev(
        "missing lookup returns none",
        table.lookup(Ino(99)).is_none(),
    );

    h.record(TraceEvent::InodeSetattr {
        inode_id: 99,
        attr_mask: ATTR_MASK_MODE,
    });
    h.assert_eq_ev(
        "setattr missing returns InodeNotFound",
        table.setattr(Ino(99), attrs(0o100644, 0, 0, InodeKind::File)),
        Err(InodeTableError::InodeNotFound),
    );

    h.record(TraceEvent::InodeUnlink { inode_id: 99 });
    h.assert_eq_ev(
        "remove missing returns InodeNotFound",
        table.remove(Ino(99)),
        Err(InodeTableError::InodeNotFound),
    );

    h.record(TraceEvent::InodeSetattr {
        inode_id: dir_ino.0,
        attr_mask: ATTR_MASK_NLINK,
    });
    table
        .unlink(dir_ino)
        .expect("directory unlink should succeed");
    let unlinked_dir = table
        .getattr(dir_ino)
        .expect("directory remains until explicit remove");
    h.assert_eq_ev("directory unlink reaches zero nlink", unlinked_dir.nlink, 0);

    h.record(TraceEvent::InodeUnlink {
        inode_id: dir_ino.0,
    });
    table
        .remove(dir_ino)
        .expect("zero-link directory remove should succeed");
    h.assert_ev(
        "directory remove clears inode",
        table.lookup(dir_ino).is_none(),
    );

    h.assert_eq_ev("final live inode count", table.count(), 2);
    h.scenario_end("inode-table/smoke");
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
    fn inode_table_smoke_passes() {
        let h = run_inode_table_smoke();
        assert_all_passed(&h);

        let data = crate::trace::serialize_trace(&h.trace).expect("serialize inode-table trace");
        let back = crate::trace::deserialize_trace(&data).expect("deserialize inode-table trace");
        assert_eq!(h.trace, back);
    }
}
