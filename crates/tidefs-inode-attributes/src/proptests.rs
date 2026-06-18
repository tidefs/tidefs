// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#[cfg(test)]
use super::*;
use proptest::prelude::*;
use tidefs_types_vfs_core::{S_IFBLK, S_IFDIR, S_IFIFO, S_IFLNK, S_IFREG, S_IFSOCK};

fn dummy_attrs(ino: u64) -> InodeAttr {
    InodeAttr {
        inode_id: InodeId::new(ino),
        generation: tidefs_types_vfs_core::Generation::new(1),
        kind: NodeKind::File,
        posix: PosixAttrs {
            mode: S_IFREG | 0o644,
            uid: 1000,
            gid: 1000,
            nlink: 1,
            rdev: 0,
            atime_ns: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            btime_ns: 0,
            size: 0,
            blocks_512: 0,
            blksize: 4096,
        },
        flags: InodeFlags::none(),
        subtree_rev: Default::default(),
        dir_rev: Default::default(),
    }
}

fn arb_file_type() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(S_IFREG),
        Just(S_IFDIR),
        Just(S_IFLNK),
        Just(S_IFBLK),
        Just(0o020_000u32), // S_IFCHR
        Just(S_IFIFO),
        Just(S_IFSOCK),
    ]
}

fn arb_mode() -> impl Strategy<Value = u32> {
    any::<u32>()
}

fn arb_timestamp_ns() -> impl Strategy<Value = i64> {
    any::<i64>()
}

fn stat_timestamp_ns(sec: libc::time_t, nsec: libc::c_long) -> i128 {
    i128::from(sec) * 1_000_000_000_i128 + i128::from(nsec)
}

fn arb_uid() -> impl Strategy<Value = u32> {
    any::<u32>()
}

// ── Mode mask proptest ─────────────────────────────────────────────────

proptest! {
    #[test]
    fn mode_preserves_file_type(
        initial_type in arb_file_type(),
        initial_perms in arb_mode(),
        new_mode in arb_mode(),
    ) {
        let store = MemInodeAttributeStore::new();
        let initial_mode = initial_type | (initial_perms & !S_IFMT);
        let mut attrs = dummy_attrs(1);
        attrs.posix.mode = initial_mode;
        store.insert(1, attrs);

        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = new_mode;

        let result = store.setattr(1, &set).unwrap();
        prop_assert_eq!(
            result.posix.mode & S_IFMT,
            initial_type,
            "file type must be preserved"
        );
        prop_assert_eq!(
            result.posix.mode & !S_IFMT,
            new_mode & !S_IFMT,
            "permission bits must match new mode"
        );
    }

    #[test]
    fn mode_preserves_special_bits(
        initial_type in arb_file_type(),
        special_bits in prop_oneof![
            Just(0o4000u32), // S_ISUID
            Just(0o2000u32), // S_ISGID
            Just(0o1000u32), // S_ISVTX
            Just(0o7000u32), // all three
            Just(0u32),
        ],
    ) {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.mode = initial_type | 0o644;
        store.insert(1, attrs);

        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = special_bits | 0o644;

        let result = store.setattr(1, &set).unwrap();
        prop_assert_eq!(
            result.posix.mode & 0o7000,
            special_bits & 0o7000,
            "special mode bits must be stored as provided"
        );
    }

    #[test]
    fn mode_iterates_known_types(
        initial_type in arb_file_type(),
        new_perms in arb_mode()
    ) {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.mode = initial_type | 0o644;
        store.insert(1, attrs);
        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = new_perms;
        let result = store.setattr(1, &set).unwrap();
        prop_assert_eq!(result.posix.mode & S_IFMT, initial_type);
    }
}

// ── mode boundary tests ────────────────────────────────────────────────

#[test]
fn mode_zero_clears_all_permissions() {
    let store = MemInodeAttributeStore::new();
    let mut attrs = dummy_attrs(1);
    attrs.posix.mode = S_IFREG | 0o777 | 0o7000;
    store.insert(1, attrs);

    let mut set = SetAttr::new();
    set.valid = FATTR_MODE;
    set.mode = 0;

    let result = store.setattr(1, &set).unwrap();
    assert_eq!(result.posix.mode, S_IFREG);
}

#[test]
fn mode_u32_max_strips_to_perm_and_special_bits() {
    let store = MemInodeAttributeStore::new();
    let mut attrs = dummy_attrs(1);
    attrs.posix.mode = S_IFREG | 0o644;
    store.insert(1, attrs);

    let mut set = SetAttr::new();
    set.valid = FATTR_MODE;
    set.mode = u32::MAX;

    let result = store.setattr(1, &set).unwrap();
    assert_eq!(result.posix.mode & S_IFMT, S_IFREG);
    assert_eq!(result.posix.mode & !S_IFMT, u32::MAX & !S_IFMT);
}

// ── Timestamp proptests ────────────────────────────────────────────────

proptest! {
    #[test]
    fn timestamp_atime_setattr_roundtrip(ns in arb_timestamp_ns()) {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME;
        set.atime_ns = ns;
        let result = store.setattr(1, &set).unwrap();
        prop_assert_eq!(result.posix.atime_ns, ns);
    }

    #[test]
    fn timestamp_mtime_setattr_roundtrip(ns in arb_timestamp_ns()) {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let mut set = SetAttr::new();
        set.valid = FATTR_MTIME;
        set.mtime_ns = ns;
        let result = store.setattr(1, &set).unwrap();
        prop_assert_eq!(result.posix.mtime_ns, ns);
    }

    #[test]
    fn timestamp_to_stat_reconstructs_nanoseconds(ns in arb_timestamp_ns()) {
        let mut posix = PosixAttrs::default();
        posix.atime_ns = ns;
        let st = to_stat(1, &posix);
        prop_assert_eq!(
            stat_timestamp_ns(st.st_atime, st.st_atime_nsec),
            i128::from(ns)
        );
    }

    #[test]
    fn timestamp_triple_to_stat_roundtrip(
        atime in arb_timestamp_ns(),
        mtime in arb_timestamp_ns(),
        ctime in arb_timestamp_ns(),
    ) {
        let mut posix = PosixAttrs::default();
        posix.atime_ns = atime;
        posix.mtime_ns = mtime;
        posix.ctime_ns = ctime;
        let st = to_stat(1, &posix);
        prop_assert_eq!(
            stat_timestamp_ns(st.st_atime, st.st_atime_nsec),
            i128::from(atime)
        );
        prop_assert_eq!(
            stat_timestamp_ns(st.st_mtime, st.st_mtime_nsec),
            i128::from(mtime)
        );
        prop_assert_eq!(
            stat_timestamp_ns(st.st_ctime, st.st_ctime_nsec),
            i128::from(ctime)
        );
    }
}

// ── timestamp boundary tests ───────────────────────────────────────────

#[test]
fn timestamp_zero_is_epoch() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_ATIME | FATTR_MTIME;
    set.atime_ns = 0;
    set.mtime_ns = 0;

    let result = store.setattr(1, &set).unwrap();
    assert_eq!(result.posix.atime_ns, 0);
    assert_eq!(result.posix.mtime_ns, 0);

    let st = to_stat(1, &result.posix);
    assert_eq!(st.st_atime, 0);
    assert_eq!(st.st_atime_nsec, 0);
    assert_eq!(st.st_mtime, 0);
    assert_eq!(st.st_mtime_nsec, 0);
}

#[test]
fn timestamp_y2038_boundary_survives() {
    let y2038_ns: i64 = 2_147_483_647_i64 * 1_000_000_000;
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_ATIME;
    set.atime_ns = y2038_ns;

    let result = store.setattr(1, &set).unwrap();
    assert_eq!(result.posix.atime_ns, y2038_ns);

    let st = to_stat(1, &result.posix);
    assert_eq!(
        stat_timestamp_ns(st.st_atime, st.st_atime_nsec),
        i128::from(y2038_ns)
    );
}

#[test]
fn timestamp_y2038_plus_one_second_survives() {
    let post_y2038_ns: i64 = 2_147_483_648_i64 * 1_000_000_000;
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_MTIME;
    set.mtime_ns = post_y2038_ns;

    let result = store.setattr(1, &set).unwrap();
    assert_eq!(result.posix.mtime_ns, post_y2038_ns);
}

#[test]
fn timestamp_near_max_roundtrips() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_ATIME;
    set.atime_ns = i64::MAX;

    let result = store.setattr(1, &set).unwrap();
    assert_eq!(result.posix.atime_ns, i64::MAX);

    let st = to_stat(1, &result.posix);
    assert_eq!(
        stat_timestamp_ns(st.st_atime, st.st_atime_nsec),
        i128::from(i64::MAX)
    );
}

#[test]
fn timestamp_sub_second_nanosecond_precision_preserved() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let values: &[u64] = &[1, 999_999_999, 500_000_000, 123_456_789];
    for &ns in values {
        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME;
        set.atime_ns = ns;

        let result = store.setattr(1, &set).unwrap();
        assert_eq!(result.posix.atime_ns, ns, "ns={ns}");

        let st = to_stat(1, &result.posix);
        assert_eq!(st.st_atime, 0, "seconds should be 0 for ns={ns}");
        assert_eq!(st.st_atime_nsec as u64, ns, "nsec mismatch for ns={ns}");
    }
}

// ── uid/gid proptests ──────────────────────────────────────────────────

proptest! {
    #[test]
    fn uid_setattr_roundtrip(uid in arb_uid()) {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let mut set = SetAttr::new();
        set.valid = FATTR_UID;
        set.uid = uid;
        let result = store.setattr(1, &set).unwrap();
        prop_assert_eq!(result.posix.uid, uid);
    }

    #[test]
    fn gid_setattr_roundtrip(gid in arb_uid()) {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let mut set = SetAttr::new();
        set.valid = FATTR_GID;
        set.gid = gid;
        let result = store.setattr(1, &set).unwrap();
        prop_assert_eq!(result.posix.gid, gid);
    }

    #[test]
    fn uid_gid_simultaneous_setattr(uid in arb_uid(), gid in arb_uid()) {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let mut set = SetAttr::new();
        set.valid = FATTR_UID | FATTR_GID;
        set.uid = uid;
        set.gid = gid;
        let result = store.setattr(1, &set).unwrap();
        prop_assert_eq!(result.posix.uid, uid);
        prop_assert_eq!(result.posix.gid, gid);
    }
}

// ── uid/gid boundary tests ─────────────────────────────────────────────

#[test]
fn uid_zero_is_root() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_UID;
    set.uid = 0;

    let result = store.setattr(1, &set).unwrap();
    assert_eq!(result.posix.uid, 0);
    assert_eq!(
        result.posix.gid, 1000,
        "gid unchanged when not in valid mask"
    );

    let st = to_stat(1, &result.posix);
    assert_eq!(st.st_uid, 0);
}

#[test]
fn uid_65534_is_nobody() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_UID | FATTR_GID;
    set.uid = 65534;
    set.gid = 65534;

    let result = store.setattr(1, &set).unwrap();
    assert_eq!(result.posix.uid, 65534);
    assert_eq!(result.posix.gid, 65534);
}

#[test]
fn uid_65535_is_16bit_max() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_UID;
    set.uid = 65535;

    let result = store.setattr(1, &set).unwrap();
    assert_eq!(result.posix.uid, 65535);
}

#[test]
fn uid_u32_max_preserved() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_UID;
    set.uid = u32::MAX;

    let result = store.setattr(1, &set).unwrap();
    assert_eq!(result.posix.uid, u32::MAX);

    let st = to_stat(1, &result.posix);
    assert_eq!(st.st_uid, u32::MAX);
}
