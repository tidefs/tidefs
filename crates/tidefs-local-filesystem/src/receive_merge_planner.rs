// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeMap;
use std::fmt;

use crate::error::FileSystemError;
use crate::types::{ChangedRecordExport, CommittedRootSummary, RecoveryAuditReport};

pub const RECEIVE_MERGE_NO_COMMON_ANCESTOR_OPERATOR_ACTIONS: &str =
    "delete-and-re-receive into a fresh target, or receive into a new empty target";

const RECEIVE_MERGE_NO_COMMON_ANCESTOR_UNSUPPORTED_REASON: &str =
    "no_common_ancestor: no committed-root identity is present in both the stream lineage manifest and target recovery audit; delete-and-re-receive into a fresh target, or receive into a new empty target";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ReceiveMergeRootIdentity {
    pub transaction_id: u64,
    pub generation: u64,
    pub superblock_checksum: u64,
}

impl ReceiveMergeRootIdentity {
    #[must_use]
    pub fn from_summary(summary: &CommittedRootSummary) -> Self {
        Self {
            transaction_id: summary.transaction_id,
            generation: summary.generation,
            superblock_checksum: summary.superblock_checksum.get(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveMergeStreamLineageManifest {
    roots: Vec<CommittedRootSummary>,
}

impl ReceiveMergeStreamLineageManifest {
    #[must_use]
    pub fn from_changed_record_export(export: &ChangedRecordExport) -> Self {
        Self {
            roots: export
                .roots
                .iter()
                .map(|root| root.source_root.clone())
                .collect(),
        }
    }

    #[must_use]
    pub fn from_roots(roots: Vec<CommittedRootSummary>) -> Self {
        Self { roots }
    }

    #[must_use]
    pub fn roots(&self) -> &[CommittedRootSummary] {
        &self.roots
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveMergeCommonAncestor {
    pub identity: ReceiveMergeRootIdentity,
    pub stream_root: CommittedRootSummary,
    pub target_root: CommittedRootSummary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveMergePlannerError {
    NoCommonAncestor {
        stream_root_count: usize,
        target_root_count: usize,
        highest_stream_txg: Option<u64>,
        highest_target_txg: Option<u64>,
        operator_action_guidance: &'static str,
    },
}

impl fmt::Display for ReceiveMergePlannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCommonAncestor {
                stream_root_count,
                target_root_count,
                highest_stream_txg,
                highest_target_txg,
                operator_action_guidance,
            } => write!(
                f,
                "no_common_ancestor: stream lineage roots={stream_root_count}, target recovery roots={target_root_count}, highest_stream_txg={}, highest_target_txg={}; operator actions: {operator_action_guidance}",
                format_optional_txg(*highest_stream_txg),
                format_optional_txg(*highest_target_txg)
            ),
        }
    }
}

impl std::error::Error for ReceiveMergePlannerError {}

impl From<ReceiveMergePlannerError> for FileSystemError {
    fn from(err: ReceiveMergePlannerError) -> Self {
        match err {
            ReceiveMergePlannerError::NoCommonAncestor { .. } => Self::Unsupported {
                operation: "receive merge planning",
                reason: RECEIVE_MERGE_NO_COMMON_ANCESTOR_UNSUPPORTED_REASON,
            },
        }
    }
}

pub fn locate_common_ancestor(
    stream_lineage: &ReceiveMergeStreamLineageManifest,
    target_recovery_audit: &RecoveryAuditReport,
) -> Result<ReceiveMergeCommonAncestor, ReceiveMergePlannerError> {
    let mut stream_roots_by_identity = BTreeMap::new();
    for root in stream_lineage.roots() {
        stream_roots_by_identity
            .entry(ReceiveMergeRootIdentity::from_summary(root))
            .or_insert(root);
    }

    let mut common_ancestor = None;
    for target_root in &target_recovery_audit.valid_committed_roots {
        let identity = ReceiveMergeRootIdentity::from_summary(target_root);
        let Some(stream_root) = stream_roots_by_identity.get(&identity) else {
            continue;
        };
        let is_higher = common_ancestor
            .as_ref()
            .map(|ancestor: &ReceiveMergeCommonAncestor| identity > ancestor.identity)
            .unwrap_or(true);
        if is_higher {
            common_ancestor = Some(ReceiveMergeCommonAncestor {
                identity,
                stream_root: (*stream_root).clone(),
                target_root: target_root.clone(),
            });
        }
    }

    common_ancestor.ok_or_else(|| ReceiveMergePlannerError::NoCommonAncestor {
        stream_root_count: stream_lineage.roots().len(),
        target_root_count: target_recovery_audit.valid_committed_roots.len(),
        highest_stream_txg: stream_lineage
            .roots()
            .iter()
            .map(|root| root.transaction_id)
            .max(),
        highest_target_txg: target_recovery_audit
            .valid_committed_roots
            .iter()
            .map(|root| root.transaction_id)
            .max(),
        operator_action_guidance: RECEIVE_MERGE_NO_COMMON_ANCESTOR_OPERATOR_ACTIONS,
    })
}

fn format_optional_txg(txg: Option<u64>) -> String {
    txg.map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_local_object_store::IntegrityDigest64;

    fn root(
        transaction_id: u64,
        generation: u64,
        superblock_checksum: u64,
    ) -> CommittedRootSummary {
        CommittedRootSummary {
            slot: transaction_id % 4,
            transaction_id,
            generation,
            next_inode_id: 10,
            inode_count: 3,
            superblock_checksum: IntegrityDigest64(superblock_checksum),
            has_transaction_manifest: true,
            manifest_checksum: IntegrityDigest64(superblock_checksum ^ 0xa5a5),
            manifest_entry_count: 4,
            has_root_authentication: true,
            root_authentication_policy_epoch: Some(1),
            root_authentication_algorithm_suite_id: Some(1),
            superblock_digest: None,
            manifest_digest: None,
            root_authentication_code: None,
        }
    }

    fn audit(roots: Vec<CommittedRootSummary>) -> RecoveryAuditReport {
        let mut audit = RecoveryAuditReport::empty();
        audit.valid_committed_roots = roots;
        audit
    }

    #[test]
    fn locates_highest_shared_transaction_group() {
        let stream_txg_2 = root(2, 20, 0x20);
        let stream_txg_4 = root(4, 40, 0x40);
        let stream_txg_7 = root(7, 70, 0x70);
        let stream_lineage = ReceiveMergeStreamLineageManifest::from_roots(vec![
            stream_txg_2.clone(),
            stream_txg_4.clone(),
            stream_txg_7.clone(),
        ]);
        let target_audit = audit(vec![
            root(1, 10, 0x10),
            stream_txg_4.clone(),
            stream_txg_7.clone(),
        ]);

        let ancestor =
            locate_common_ancestor(&stream_lineage, &target_audit).expect("common ancestor");

        assert_eq!(ancestor.identity.transaction_id, 7);
        assert_eq!(ancestor.stream_root, stream_txg_7);
        assert_eq!(ancestor.target_root, stream_txg_7);
    }

    #[test]
    fn root_identity_requires_checksum_match_at_same_txg() {
        let shared_txg_3 = root(3, 30, 0x30);
        let stream_lineage = ReceiveMergeStreamLineageManifest::from_roots(vec![
            shared_txg_3.clone(),
            root(5, 50, 0x5000),
        ]);
        let target_audit = audit(vec![shared_txg_3.clone(), root(5, 50, 0x5fff)]);

        let ancestor =
            locate_common_ancestor(&stream_lineage, &target_audit).expect("common ancestor");

        assert_eq!(
            ancestor.identity,
            ReceiveMergeRootIdentity::from_summary(&shared_txg_3)
        );
    }

    #[test]
    fn no_common_ancestor_is_classified_with_operator_actions() {
        let stream_lineage = ReceiveMergeStreamLineageManifest::from_roots(vec![root(8, 80, 0x80)]);
        let target_audit = audit(vec![root(9, 90, 0x90)]);

        let err =
            locate_common_ancestor(&stream_lineage, &target_audit).expect_err("no common ancestor");

        assert_eq!(
            err,
            ReceiveMergePlannerError::NoCommonAncestor {
                stream_root_count: 1,
                target_root_count: 1,
                highest_stream_txg: Some(8),
                highest_target_txg: Some(9),
                operator_action_guidance: RECEIVE_MERGE_NO_COMMON_ANCESTOR_OPERATOR_ACTIONS,
            }
        );
        let message = err.to_string();
        assert!(
            message.contains("no_common_ancestor")
                && message.contains("delete-and-re-receive")
                && message.contains("fresh target"),
            "classified error must name operator recovery paths: {message}"
        );
    }
}
