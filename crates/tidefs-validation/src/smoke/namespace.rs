//! Namespace smoke: deterministic namespace lifecycle operations.
//!
//! Gated on `feature = "fuse"`.

use std::path::Path;

use tidefs_dir_index::DirCookie;

use crate::smoke::SmokeHarness;
use crate::trace::TraceEvent;
use tidefs_namespace::{
    InodeAttributes, Namespace, NamespaceError, KIND_DIR, KIND_FILE, KIND_SYMLINK, ROOT_INODE,
};

const FILE_MODE: u32 = 0o100644;
const DIR_MODE: u32 = 0o40755;
const SYMLINK_MODE: u32 = 0o120777;

/// Run the full namespace smoke sequence and return the harness.
#[must_use]
pub fn run_namespace_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();
    let ns = Namespace::new();

    h.scenario_begin("namespace/smoke");

    h.record(TraceEvent::NamespaceResolve {
        path: b"/".to_vec(),
    });
    h.assert_eq_ev(
        "namespace root resolves",
        ns.resolve(Path::new("/")),
        Ok(ROOT_INODE),
    );

    h.record(TraceEvent::NamespaceCreate {
        parent: ROOT_INODE,
        name: b"alpha".to_vec(),
        mode: FILE_MODE,
    });
    let file = ns
        .create_file(ROOT_INODE, "alpha", InodeAttributes::new_file(0))
        .expect("namespace smoke create file");
    h.record(TraceEvent::InodeCreate {
        inode_id: file,
        mode: FILE_MODE,
        uid: 0,
        gid: 0,
    });
    h.record(TraceEvent::NamespaceResolve {
        path: b"/alpha".to_vec(),
    });
    h.assert_eq_ev(
        "namespace file resolves after create",
        ns.resolve(Path::new("/alpha")),
        Ok(file),
    );
    h.assert_eq_ev(
        "namespace lookup finds created file",
        ns.lookup(ROOT_INODE, "alpha"),
        Ok(Some(file)),
    );
    h.assert_eq_ev(
        "namespace file attrs identify regular file",
        ns.get_attrs(file).map(|attrs| attrs.mode & 0o170000),
        Some(FILE_MODE & 0o170000),
    );

    h.record(TraceEvent::NamespaceCreate {
        parent: ROOT_INODE,
        name: b"dir".to_vec(),
        mode: DIR_MODE,
    });
    let dir = ns
        .create_dir(ROOT_INODE, "dir", InodeAttributes::new_dir(0))
        .expect("namespace smoke create dir");
    h.record(TraceEvent::InodeCreate {
        inode_id: dir,
        mode: DIR_MODE,
        uid: 0,
        gid: 0,
    });
    h.assert_eq_ev(
        "namespace lookup finds created dir",
        ns.lookup(ROOT_INODE, "dir"),
        Ok(Some(dir)),
    );

    h.record(TraceEvent::NamespaceCreate {
        parent: dir,
        name: b"child".to_vec(),
        mode: FILE_MODE,
    });
    let child = ns
        .create_file(dir, "child", InodeAttributes::new_file(0))
        .expect("namespace smoke create child");
    h.record(TraceEvent::InodeCreate {
        inode_id: child,
        mode: FILE_MODE,
        uid: 0,
        gid: 0,
    });
    h.assert_eq_ev(
        "namespace lookup finds child file",
        ns.lookup(dir, "child"),
        Ok(Some(child)),
    );

    h.record(TraceEvent::FsLifecycleOp {
        inode_id: file,
        op_name: "namespace.rename".to_string(),
        payload: b"alpha->beta".to_vec(),
    });
    ns.rename(ROOT_INODE, "alpha", ROOT_INODE, "beta")
        .expect("namespace smoke same-dir rename");
    h.assert_eq_ev(
        "namespace old same-dir name is absent",
        ns.lookup(ROOT_INODE, "alpha"),
        Ok(None),
    );
    h.assert_eq_ev(
        "namespace new same-dir name points at file",
        ns.lookup(ROOT_INODE, "beta"),
        Ok(Some(file)),
    );

    h.record(TraceEvent::FsLifecycleOp {
        inode_id: file,
        op_name: "namespace.rename".to_string(),
        payload: b"beta->dir/moved".to_vec(),
    });
    ns.rename(ROOT_INODE, "beta", dir, "moved")
        .expect("namespace smoke cross-dir rename");
    h.assert_eq_ev(
        "namespace old cross-dir name is absent",
        ns.lookup(ROOT_INODE, "beta"),
        Ok(None),
    );
    h.assert_eq_ev(
        "namespace cross-dir rename destination points at file",
        ns.lookup(dir, "moved"),
        Ok(Some(file)),
    );
    h.record(TraceEvent::NamespaceResolve {
        path: b"/dir/moved".to_vec(),
    });
    h.assert_eq_ev(
        "namespace moved file resolves",
        ns.resolve(Path::new("/dir/moved")),
        Ok(file),
    );

    h.record(TraceEvent::NamespaceCreate {
        parent: ROOT_INODE,
        name: b"link".to_vec(),
        mode: SYMLINK_MODE,
    });
    let symlink = ns
        .create_symlink(ROOT_INODE, "link", b"dir/moved")
        .expect("namespace smoke create symlink");
    h.record(TraceEvent::InodeCreate {
        inode_id: symlink,
        mode: SYMLINK_MODE,
        uid: 0,
        gid: 0,
    });
    h.record(TraceEvent::FsLifecycleOp {
        inode_id: symlink,
        op_name: "namespace.readlink".to_string(),
        payload: b"link".to_vec(),
    });
    h.assert_eq_ev(
        "namespace readlink preserves target bytes",
        ns.readlink_at(ROOT_INODE, "link"),
        Ok(b"dir/moved".to_vec()),
    );
    h.record(TraceEvent::NamespaceResolve {
        path: b"/link".to_vec(),
    });
    h.assert_eq_ev(
        "namespace symlink resolves to target inode",
        ns.resolve(Path::new("/link")),
        Ok(file),
    );
    h.assert_eq_ev(
        "namespace symlink attrs identify symlink",
        ns.get_attrs(symlink).map(|attrs| attrs.mode & 0o170000),
        Some(SYMLINK_MODE & 0o170000),
    );

    h.record(TraceEvent::InodeLink { inode_id: file });
    let alias = ns
        .create_hard_link(dir, "moved", ROOT_INODE, "alias")
        .expect("namespace smoke hard link");
    h.assert_eq_ev("namespace hard link shares inode", alias, file);
    h.assert_eq_ev(
        "namespace hard link increments nlink",
        ns.get_attrs(file).map(|attrs| attrs.nlink),
        Some(2),
    );
    h.record(TraceEvent::NamespaceResolve {
        path: b"/alias".to_vec(),
    });
    h.assert_eq_ev(
        "namespace hard link resolves to source inode",
        ns.resolve(Path::new("/alias")),
        Ok(file),
    );

    h.record(TraceEvent::NamespaceUnlink {
        parent: ROOT_INODE,
        name: b"alias".to_vec(),
    });
    ns.unlink(ROOT_INODE, "alias")
        .expect("namespace smoke unlink hard link");
    h.record(TraceEvent::InodeUnlink { inode_id: file });
    h.assert_eq_ev(
        "namespace alias removed after unlink",
        ns.lookup(ROOT_INODE, "alias"),
        Ok(None),
    );
    h.assert_eq_ev(
        "namespace source name survives alias unlink",
        ns.lookup(dir, "moved"),
        Ok(Some(file)),
    );
    h.assert_eq_ev(
        "namespace hard link unlink decrements nlink",
        ns.get_attrs(file).map(|attrs| attrs.nlink),
        Some(1),
    );

    h.record(TraceEvent::DirIter { cookie: 0 });
    let (root_entries, _) = ns
        .read_dir(ROOT_INODE, DirCookie(0))
        .expect("namespace smoke root readdir");
    let root_names: Vec<Vec<u8>> = root_entries
        .iter()
        .map(|entry| entry.name.clone())
        .collect();
    h.assert_ev(
        "namespace root readdir contains dot",
        root_names.iter().any(|name| name == b"."),
    );
    h.assert_ev(
        "namespace root readdir contains dotdot",
        root_names.iter().any(|name| name == b".."),
    );
    h.assert_ev(
        "namespace root readdir contains dir",
        root_names.iter().any(|name| name == b"dir"),
    );
    h.assert_ev(
        "namespace root readdir contains symlink",
        root_names.iter().any(|name| name == b"link"),
    );

    h.record(TraceEvent::DirIter { cookie: 0 });
    let (dir_entries, _) = ns
        .read_dir(dir, DirCookie(0))
        .expect("namespace smoke child readdir");
    let dir_names: Vec<Vec<u8>> = dir_entries.iter().map(|entry| entry.name.clone()).collect();
    h.assert_ev(
        "namespace child readdir contains dot",
        dir_names.iter().any(|name| name == b"."),
    );
    h.assert_ev(
        "namespace child readdir contains dotdot",
        dir_names.iter().any(|name| name == b".."),
    );
    h.assert_ev(
        "namespace child readdir contains moved",
        dir_names.iter().any(|name| name == b"moved"),
    );
    h.assert_ev(
        "namespace child readdir contains child",
        dir_names.iter().any(|name| name == b"child"),
    );

    h.record(TraceEvent::NamespaceUnlink {
        parent: ROOT_INODE,
        name: b"dir".to_vec(),
    });
    h.assert_eq_ev(
        "namespace rmdir non-empty returns NotEmpty",
        ns.unlink(ROOT_INODE, "dir"),
        Err(NamespaceError::NotEmpty),
    );

    h.record(TraceEvent::NamespaceUnlink {
        parent: ROOT_INODE,
        name: b"link".to_vec(),
    });
    ns.unlink(ROOT_INODE, "link")
        .expect("namespace smoke unlink symlink");
    h.record(TraceEvent::InodeUnlink { inode_id: symlink });
    h.assert_eq_ev(
        "namespace symlink removed after unlink",
        ns.lookup(ROOT_INODE, "link"),
        Ok(None),
    );

    h.record(TraceEvent::NamespaceUnlink {
        parent: dir,
        name: b"moved".to_vec(),
    });
    ns.unlink(dir, "moved")
        .expect("namespace smoke unlink moved file");
    h.record(TraceEvent::InodeUnlink { inode_id: file });
    h.assert_eq_ev(
        "namespace moved file removed after unlink",
        ns.lookup(dir, "moved"),
        Ok(None),
    );

    h.record(TraceEvent::NamespaceUnlink {
        parent: dir,
        name: b"child".to_vec(),
    });
    ns.unlink(dir, "child")
        .expect("namespace smoke unlink child");
    h.record(TraceEvent::InodeUnlink { inode_id: child });
    h.assert_eq_ev(
        "namespace child removed after unlink",
        ns.lookup(dir, "child"),
        Ok(None),
    );

    h.record(TraceEvent::NamespaceUnlink {
        parent: ROOT_INODE,
        name: b"dir".to_vec(),
    });
    ns.unlink(ROOT_INODE, "dir")
        .expect("namespace smoke rmdir empty dir");
    h.record(TraceEvent::InodeUnlink { inode_id: dir });
    h.assert_eq_ev(
        "namespace empty dir removed after rmdir",
        ns.lookup(ROOT_INODE, "dir"),
        Ok(None),
    );
    h.assert_eq_ev(
        "namespace file inode freed after final unlink",
        ns.get_attrs(file).is_none(),
        true,
    );
    h.assert_eq_ev(
        "namespace directory inode freed after rmdir",
        ns.get_attrs(dir).is_none(),
        true,
    );
    h.assert_eq_ev(
        "namespace smoke returns to root-only live set",
        ns.inode_table().live_count(),
        1,
    );

    h.assert_eq_ev(
        "namespace entry kind constants remain stable",
        (KIND_DIR, KIND_FILE, KIND_SYMLINK),
        (0, 1, 2),
    );

    h.scenario_end("namespace/smoke");
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_namespace_passes() {
        let h = run_namespace_smoke();
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
