// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Merge-plan integration for the receive execution path.
//!
//! Bridges the `receive_merge_planner` output (`ReceiveMergePlan`) into the
//! incremental receive path so the receiver can consult per-object decisions
//! instead of failing closed on conflicting non-empty targets
//! (`docs/RECEIVE_STREAM_MERGE_POLICY.md` §1.3).
//!
//! # Integration point
//!
//! [`merge_plan_gate_for_incremental_receive`] is the fail-closed gate
//! relaxation: when a merge plan is present, the receive proceeds even when
//! the base root authority check (`verify_incremental_base_root_authority`)
//! would otherwise reject a conflicting target.
//!
//! [`should_import_object`] is the per-object decision: during the import
//! loop, objects whose merge-plan decision is `KeepLocal` are skipped so
//! the target's existing version is preserved.

use crate::receive_merge_planner::ReceiveMergePlan;
use tidefs_local_object_store::ObjectKey;

/// Gate relaxation check for incremental receive with a merge plan.
///
/// Returns `true` when the receive should proceed with the merge plan instead
/// of failing closed on the base root authority check.
///
/// When no merge plan is provided, the caller must run the standard
/// `verify_incremental_base_root_authority` and fail closed per
/// `docs/RECEIVE_STREAM_MERGE_POLICY.md` §1.3.
#[must_use]
pub fn merge_plan_gate_for_incremental_receive(
    merge_plan: Option<&ReceiveMergePlan>,
) -> bool {
    merge_plan.is_some()
}

/// Per-object import decision for the receive execution path.
///
/// When a merge plan is present, consult it to decide whether the given
/// object should be imported from the stream:
///
/// - `KeepLocal` → `false` (skip — target's version is preserved)
/// - `KeepRemote` → `true` (import — stream's version overwrites)
/// - `AutoMerge` / not in plan → `true` (import — no conflict)
///
/// When no merge plan is present, all objects are imported (`true`).
#[must_use]
pub fn should_import_object(
    merge_plan: Option<&ReceiveMergePlan>,
    object_key: &ObjectKey,
) -> bool {
    match merge_plan {
        Some(plan) => !plan.should_skip(object_key),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{ConflictInventory, ConflictEntry, ConflictClass, ConflictDivergence, InodeIdentityDivergence};
    use crate::receive_merge_planner::{ReceiveMergePolicy, resolve_merge_policy};

    fn make_test_inventory() -> ConflictInventory {
        ConflictInventory {
            common_ancestor_transaction_id: 1,
            common_ancestor_generation: 10,
            entries: vec![
                ConflictEntry {
                    class: ConflictClass::InodeIdentity,
                    divergence: ConflictDivergence::InodeIdentity(
                        InodeIdentityDivergence::DifferentContentIdentity,
                    ),
                    stream_identity: "inode 100".into(),
                    target_identity: "inode 100".into(),
                    stream_txg: Some(5),
                    target_txg: Some(3),
                    stream_object_key: Some(ObjectKey::from_bytes32([0x01; 32])),
                    target_object_key: None,
                },
            ],
        }
    }

    #[test]
    fn gate_relaxation_returns_true_when_plan_present() {
        let inventory = make_test_inventory();
        let plan = resolve_merge_policy(&inventory, ReceiveMergePolicy::KeepRemote).unwrap();
        assert!(merge_plan_gate_for_incremental_receive(Some(&plan)));
    }

    #[test]
    fn gate_relaxation_returns_false_when_plan_absent() {
        assert!(!merge_plan_gate_for_incremental_receive(None));
    }

    #[test]
    fn should_import_object_skips_keep_local() {
        let inventory = make_test_inventory();
        let plan = resolve_merge_policy(&inventory, ReceiveMergePolicy::KeepLocal).unwrap();
        let key = ObjectKey::from_bytes32([0x01; 32]);
        assert!(!should_import_object(Some(&plan), &key));
    }

    #[test]
    fn should_import_object_imports_keep_remote() {
        let inventory = make_test_inventory();
        let plan = resolve_merge_policy(&inventory, ReceiveMergePolicy::KeepRemote).unwrap();
        let key = ObjectKey::from_bytes32([0x01; 32]);
        assert!(should_import_object(Some(&plan), &key));
    }

    #[test]
    fn should_import_object_imports_unknown_key() {
        let inventory = make_test_inventory();
        let plan = resolve_merge_policy(&inventory, ReceiveMergePolicy::KeepLocal).unwrap();
        let unknown = ObjectKey::from_bytes32([0xFF; 32]);
        assert!(should_import_object(Some(&plan), &unknown));
    }

    #[test]
    fn should_import_object_imports_all_when_no_plan() {
        let key = ObjectKey::from_bytes32([0x01; 32]);
        assert!(should_import_object(None, &key));
    }
}
