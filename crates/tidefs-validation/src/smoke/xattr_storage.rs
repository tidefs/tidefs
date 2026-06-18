// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Xattr-storage smoke: deterministic POSIX xattr lifecycle checks over
//! `XattrStore`.
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::TraceEvent;
use tidefs_types_polymorphic_xattr_core::{DatasetXattrPolicy, XattrStorageKind};
use tidefs_xattr_storage::{
    parse_posix_xattr_namespace, PosixXattrNamespace, XattrNameListBufferAction, XattrSetPlanError,
    XattrStore, XattrStoreError, XattrValueBufferAction, POSIX_XATTR_CREATE, POSIX_XATTR_REPLACE,
};

/// Run the full xattr-storage smoke sequence and return the harness.
#[must_use]
pub fn run_xattr_storage_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("xattr-storage/smoke");

    let mut store = XattrStore::new(DatasetXattrPolicy::DEFAULT);
    record_xattr_op(&mut h, "xattr.new", b"");
    h.assert_eq_ev(
        "new xattr store starts inline",
        store.representation(),
        XattrStorageKind::INLINE,
    );
    h.assert_ev("new xattr store is empty", store.is_empty());
    h.assert_eq_ev("new xattr store length is zero", store.len(), 0);
    h.assert_eq_ev("new xattr store version is zero", store.version(), 0);
    h.assert_eq_ev(
        "new xattr store value bytes are zero",
        store.total_value_bytes(),
        0,
    );
    h.assert_ev("new xattr store has no ACL flag", !store.has_acl());
    h.assert_ev(
        "missing xattr lookup returns none",
        store.get(b"user.missing").is_none(),
    );

    record_xattr_op(&mut h, "xattr.acl.set", b"system.posix_acl_access");
    store.set_has_acl(true);
    h.assert_ev("ACL flag can be set", store.has_acl());

    record_xattr_op(&mut h, "xattr.set", b"user.author");
    let previous = store.set(b"user.author", b"s2", 0);
    h.assert_eq_ev("first raw set returns no previous value", previous, None);
    h.assert_ev(
        "raw set makes xattr visible",
        store.contains(b"user.author"),
    );
    h.assert_eq_ev(
        "raw set value round-trips",
        store.get(b"user.author"),
        Some(b"s2".to_vec()),
    );
    h.assert_eq_ev("raw set bumps version", store.version(), 1);
    h.assert_eq_ev("raw set tracks value bytes", store.total_value_bytes(), 2);

    record_xattr_op(&mut h, "xattr.set.create", b"user.created");
    let created = store
        .set_with_posix_flags(b"user.created", b"created-v1", POSIX_XATTR_CREATE)
        .expect("XATTR_CREATE should create absent name");
    h.assert_eq_ev("XATTR_CREATE returns no previous value", created, None);
    h.assert_eq_ev("create adds a second entry", store.len(), 2);

    let create_existing =
        store.set_with_posix_flags(b"user.created", b"created-again", POSIX_XATTR_CREATE);
    h.assert_ev(
        "XATTR_CREATE refuses existing name",
        matches!(create_existing, Err(XattrSetPlanError::EntryExists)),
    );
    h.assert_eq_ev(
        "failed XATTR_CREATE leaves value unchanged",
        store.get(b"user.created"),
        Some(b"created-v1".to_vec()),
    );

    record_xattr_op(&mut h, "xattr.set.replace", b"user.created");
    let replaced = store
        .set_with_posix_flags(b"user.created", b"created-v2", POSIX_XATTR_REPLACE)
        .expect("XATTR_REPLACE should replace existing name");
    h.assert_eq_ev(
        "XATTR_REPLACE returns previous value",
        replaced,
        Some(b"created-v1".to_vec()),
    );
    h.assert_eq_ev(
        "XATTR_REPLACE updates stored value",
        store.get(b"user.created"),
        Some(b"created-v2".to_vec()),
    );

    let replace_missing = store.set_with_posix_flags(b"user.absent", b"value", POSIX_XATTR_REPLACE);
    h.assert_ev(
        "XATTR_REPLACE refuses absent name",
        matches!(replace_missing, Err(XattrSetPlanError::EntryNotFound)),
    );

    record_xattr_op(&mut h, "xattr.list.inline", b"");
    let inline_names = store.list_names();
    h.assert_ev(
        "inline list_names includes raw name",
        inline_names.iter().any(|name| name == b"user.author"),
    );
    h.assert_ev(
        "inline list includes created value",
        store
            .list()
            .iter()
            .any(|(name, value)| name == b"user.created" && value == b"created-v2"),
    );
    h.assert_eq_ev(
        "inline POSIX name buffer is deterministic",
        store
            .list_posix_name_bytes()
            .expect("inline POSIX name list should pack"),
        expected_posix_name_bytes(inline_names),
    );

    record_xattr_op(&mut h, "xattr.get.size", b"user.created");
    let size_probe = store
        .get_posix_xattr_value_for_size(b"user.created", 0)
        .expect("size-only getxattr should succeed");
    h.assert_eq_ev(
        "getxattr size probe reports required length",
        size_probe.plan.required_size,
        b"created-v2".len(),
    );
    h.assert_eq_ev(
        "getxattr size probe copies no bytes",
        size_probe.plan.action,
        XattrValueBufferAction::ReportRequiredSize,
    );
    h.assert_eq_ev(
        "getxattr size probe value is empty",
        size_probe.value.len(),
        0,
    );

    let copied_value = store
        .get_posix_xattr_value_for_size(b"user.created", b"created-v2".len())
        .expect("sized getxattr should copy value");
    h.assert_eq_ev(
        "sized getxattr copies value",
        copied_value.value,
        b"created-v2".to_vec(),
    );
    h.assert_eq_ev(
        "sized getxattr selects copy action",
        copied_value.plan.action,
        XattrValueBufferAction::CopyValue,
    );

    record_xattr_op(&mut h, "xattr.remove", b"user.author");
    store
        .remove(b"user.author")
        .expect("removing existing xattr should succeed");
    h.assert_ev("removed xattr is absent", !store.contains(b"user.author"));
    h.assert_eq_ev(
        "removing missing xattr returns EntryNotFound",
        store.remove(b"user.author"),
        Err(XattrStoreError::EntryNotFound),
    );

    record_xattr_op(&mut h, "xattr.promote", b"user.bulk");
    for index in 0..17 {
        let name = format!("user.bulk{index:02}");
        let value = format!("value-{index:02}");
        store
            .set_with_posix_flags(name.as_bytes(), value.as_bytes(), POSIX_XATTR_CREATE)
            .expect("bulk xattr insert should succeed");
    }
    store.check_and_switch();
    h.assert_eq_ev(
        "bulk inserts promote storage to external B-tree",
        store.representation(),
        XattrStorageKind::EXTERNAL,
    );
    h.assert_ev("ACL flag survives B-tree promotion", store.has_acl());
    h.assert_eq_ev(
        "bulk xattr value survives B-tree promotion",
        store.get(b"user.bulk16"),
        Some(b"value-16".to_vec()),
    );
    h.assert_eq_ev(
        "total_value_bytes matches listed values",
        store.total_value_bytes(),
        listed_value_bytes(&store),
    );

    let packed_names = store
        .list_posix_name_bytes()
        .expect("external POSIX name list should pack");
    let list_size_probe = store
        .list_posix_name_bytes_for_size(0)
        .expect("size-only listxattr should succeed");
    h.assert_eq_ev(
        "listxattr size probe reports packed length",
        list_size_probe.plan.required_size,
        packed_names.len(),
    );
    h.assert_eq_ev(
        "listxattr size probe copies no names",
        list_size_probe.plan.action,
        XattrNameListBufferAction::ReportRequiredSize,
    );
    h.assert_eq_ev(
        "listxattr size probe returns no bytes",
        list_size_probe.bytes.len(),
        0,
    );

    let copied_names = store
        .list_posix_name_bytes_for_size(packed_names.len())
        .expect("sized listxattr should copy names");
    h.assert_eq_ev(
        "sized listxattr copies names",
        copied_names.bytes,
        packed_names,
    );
    h.assert_eq_ev(
        "sized listxattr selects copy action",
        copied_names.plan.action,
        XattrNameListBufferAction::CopyNames,
    );

    record_xattr_op(&mut h, "xattr.namespace", b"user.created");
    h.assert_eq_ev(
        "user namespace parses",
        parse_posix_xattr_namespace(b"user.created"),
        Some(PosixXattrNamespace::User),
    );
    h.assert_eq_ev(
        "system namespace parses",
        parse_posix_xattr_namespace(b"system.posix_acl_access"),
        Some(PosixXattrNamespace::System),
    );
    h.assert_eq_ev(
        "security namespace parses",
        parse_posix_xattr_namespace(b"security.selinux"),
        Some(PosixXattrNamespace::Security),
    );
    h.assert_eq_ev(
        "trusted namespace parses",
        parse_posix_xattr_namespace(b"trusted.overlay"),
        Some(PosixXattrNamespace::Trusted),
    );
    h.assert_eq_ev(
        "prefix-only namespace is unclassified",
        parse_posix_xattr_namespace(b"user."),
        None,
    );

    h.scenario_end("xattr-storage/smoke");
    h
}

fn record_xattr_op(h: &mut SmokeHarness, op_name: &str, name: &[u8]) {
    h.record(TraceEvent::FsLifecycleOp {
        inode_id: 1,
        op_name: op_name.to_string(),
        payload: name.to_vec(),
    });
}

fn expected_posix_name_bytes(mut names: Vec<Vec<u8>>) -> Vec<u8> {
    names.sort_unstable();
    let mut bytes = Vec::new();
    for name in names {
        bytes.extend_from_slice(&name);
        bytes.push(0);
    }
    bytes
}

fn listed_value_bytes(store: &XattrStore) -> u64 {
    store
        .list()
        .iter()
        .map(|(_name, value)| value.len() as u64)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_xattr_storage_passes() {
        let h = run_xattr_storage_smoke();
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
