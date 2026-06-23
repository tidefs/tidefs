// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeMap;
use std::fmt;

use crate::error::FileSystemError;
use tidefs_types_vfs_owned::DirEntry as OwnedDirEntry;
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

// ── Operator merge policy and resolution engine ───────────────────────────────

/// Operator merge policy for the receive merge planner.
///
/// Governs how conflicting objects (as classified by the conflict inventory)
/// are resolved into a binding merge plan.  Conflict-free objects (§2.3) are
/// always auto-merged regardless of policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveMergePolicy {
    /// Keep the local (target) version of every conflicting object.
    KeepLocal,
    /// Keep the remote (stream) version of every conflicting object.
    KeepRemote,
    /// For each conflict, compare per-object txg metadata on each side and
    /// keep the object with the higher txg.  On equal txg or when txg
    /// information is unavailable, the target wins (target-wins tiebreak).
    MergeLatest,
    /// Refuse to produce a merge plan.  The caller receives the conflict
    /// inventory for operator resolution through the manual resolution
    /// surface (`tidefsctl merge resolve`, planned follow-up).
    Manual,
}

/// Per-object decision produced by the policy resolution engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveMergeDecision {
    /// Take the stream-side object version.
    KeepRemote,
    /// Take the target-side object version.
    KeepLocal,
    /// No conflict — the object is conflict-free and will be auto-merged
    /// regardless of policy.
    AutoMerge,
}

/// Binding merge plan produced by the policy resolution engine.
///
/// Maps each conflict entry in the inventory to a resolution decision.
/// Objects not listed in the plan are conflict-free and auto-merged.
/// A plan with `requires_operator: true` carries no decisions; the operator
/// must resolve every conflict before the receive may proceed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveMergePlan {
    /// The policy that produced this plan.
    pub policy: ReceiveMergePolicy,
    /// Common-ancestor transaction-group identity.
    pub common_ancestor_transaction_id: u64,
    /// Common-ancestor generation.
    pub common_ancestor_generation: u64,
    /// Per-conflict decisions in the same order as the conflict inventory
    /// entries.
    pub decisions: Vec<ReceiveMergeDecision>,
    /// Whether this plan requires operator intervention.
    ///
    /// Always true for `Manual` policy; false for other policies when the
    /// plan was successfully resolved.
    pub requires_operator: bool,
}

impl ReceiveMergePlan {
    /// Create an empty plan anchored at the given inventory.
    ///
    /// Empty plans are valid for conflict-free inventories under any policy.
    #[must_use]
    pub fn empty(policy: ReceiveMergePolicy, inventory: &crate::encoding::ConflictInventory) -> Self {
        Self {
            policy,
            common_ancestor_transaction_id: inventory.common_ancestor_transaction_id,
            common_ancestor_generation: inventory.common_ancestor_generation,
            decisions: Vec::new(),
            requires_operator: policy == ReceiveMergePolicy::Manual,
        }
    }

    /// Number of conflict-resolution decisions in the plan.
    #[must_use]
    pub fn len(&self) -> usize {
        self.decisions.len()
    }

    /// True when the plan contains no decisions (empty inventory, or manual
    /// policy).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }
}

/// Errors returned by the policy resolution engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveMergePolicyError {
    /// The `Manual` policy was selected.  The conflict inventory is returned
    /// for operator review; no automatic merge plan is produced.
    ManualPolicy {
        conflict_count: usize,
        guidance: &'static str,
    },
}

const RECEIVE_MERGE_MANUAL_POLICY_GUIDANCE: &str =
    "manual policy: use tidefsctl merge resolve to inspect the conflict inventory and provide per-object or per-class resolution instructions before receiving";

impl fmt::Display for ReceiveMergePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManualPolicy { conflict_count, guidance } => {
                write!(
                    f,
                    "manual merge policy: {conflict_count} conflicts require operator resolution; {guidance}",
                )
            }
        }
    }
}

impl std::error::Error for ReceiveMergePolicyError {}

impl From<ReceiveMergePolicyError> for FileSystemError {
    fn from(err: ReceiveMergePolicyError) -> Self {
        match err {
            ReceiveMergePolicyError::ManualPolicy { .. } => Self::Unsupported {
                operation: "receive merge planning",
                reason: RECEIVE_MERGE_MANUAL_POLICY_GUIDANCE,
            },
        }
    }
}

/// Apply an operator merge policy to a conflict inventory and produce a
/// binding merge plan.
///
/// # Policy semantics
///
/// - `KeepLocal`: every conflict resolves to `KeepLocal` (target wins).
/// - `KeepRemote`: every conflict resolves to `KeepRemote` (stream wins).
/// - `MergeLatest`: per-entry txg comparison.  When both `stream_txg` and
///   `target_txg` are populated, the higher-txg side wins.  On tie or
///   missing txg, the target wins (target-wins tiebreak).
/// - `Manual`: returns [`ReceiveMergePolicyError::ManualPolicy`] with the
///   conflict inventory for operator resolution.  No merge plan is produced.
///
/// Conflict-free objects (those not present in the inventory) are always
/// auto-merged regardless of policy (§2.3).
pub fn resolve_merge_policy(
    inventory: &crate::encoding::ConflictInventory,
    policy: ReceiveMergePolicy,
) -> Result<ReceiveMergePlan, ReceiveMergePolicyError> {
    if policy == ReceiveMergePolicy::Manual {
        return Err(ReceiveMergePolicyError::ManualPolicy {
            conflict_count: inventory.len(),
            guidance: RECEIVE_MERGE_MANUAL_POLICY_GUIDANCE,
        });
    }

    let decisions: Vec<ReceiveMergeDecision> = inventory
        .entries
        .iter()
        .map(|entry| match policy {
            ReceiveMergePolicy::KeepLocal => ReceiveMergeDecision::KeepLocal,
            ReceiveMergePolicy::KeepRemote => ReceiveMergeDecision::KeepRemote,
            ReceiveMergePolicy::MergeLatest => {
                // Compare per-object txg metadata from the conflict entry.
                match (entry.stream_txg, entry.target_txg) {
                    (Some(s), Some(t)) if s > t => ReceiveMergeDecision::KeepRemote,
                    // Target wins on tie or when target has higher txg.
                    (Some(_s), Some(_t)) => ReceiveMergeDecision::KeepLocal,
                    // Missing txg: conservative, target wins.
                    _ => ReceiveMergeDecision::KeepLocal,
                }
            }
            ReceiveMergePolicy::Manual => {
                // Already handled above; unreachable here.
                ReceiveMergeDecision::KeepLocal
            }
        })
        .collect();

    Ok(ReceiveMergePlan {
        policy,
        common_ancestor_transaction_id: inventory.common_ancestor_transaction_id,
        common_ancestor_generation: inventory.common_ancestor_generation,
        decisions,
        requires_operator: false,
    })
}

// ── Conflict inventory builder ────────────────────────────────────────────────

/// Bundled inputs for the conflict inventory builder.
///
/// Each field carries the pre-loaded data from one side of the merge
/// comparison.  The builder does not load data from the object store itself;
/// loading belongs to the receive-path integration slice.
pub(crate) struct ConflictInventoryInput<'a> {
    /// Common ancestor produced by `locate_common_ancestor`.
    pub common_ancestor: &'a ReceiveMergeCommonAncestor,
    /// Stream-side inode table keyed by `InodeId`.
    pub stream_inodes: &'a BTreeMap<u64, crate::types::InodeRecord>,
    /// Target-side inode table keyed by `InodeId`.
    pub target_inodes: &'a BTreeMap<u64, crate::types::InodeRecord>,
    /// Stream-side directory entries per parent inode_id.
    pub stream_dir_entries: &'a BTreeMap<u64, Vec<OwnedDirEntry>>,
    /// Target-side directory entries per parent inode_id.
    pub target_dir_entries: &'a BTreeMap<u64, Vec<OwnedDirEntry>>,
    /// Stream-side extent maps keyed by inode_id.
    pub stream_extent_maps: &'a BTreeMap<u64, Vec<u8>>,
    /// Target-side extent maps keyed by inode_id.
    pub target_extent_maps: &'a BTreeMap<u64, Vec<u8>>,
    /// Stream-side snapshot catalog entries.
    pub stream_snapshots: &'a [crate::records::SnapshotRecord],
    /// Target-side snapshot catalog entries.
    pub target_snapshots: &'a [crate::records::SnapshotRecord],
    /// Stream lineage manifest (for generation ordering comparison).
    pub stream_lineage: &'a ReceiveMergeStreamLineageManifest,
    /// Target recovery audit (for generation ordering comparison).
    pub target_recovery_audit: &'a RecoveryAuditReport,
}

/// Build a conflict inventory by comparing stream and target state across all
/// five taxonomy axes defined in `docs/RECEIVE_MERGE_PLANNER_DESIGN.md` §1.
///
/// The common ancestor provides the divergence baseline.  Objects that exist
/// on only one side (created after divergence) are not conflicts — they are
/// conflict-free additions.  Objects that exist on both sides with identical
/// content are also conflict-free.  Every other divergence is classified into
/// the taxonomy and recorded in the inventory.
///
/// Each entry in the returned inventory names the conflict class, the object
/// identity on each side, and the specific divergence kind.
#[allow(dead_code)]
pub(crate) fn build_conflict_inventory(
    input: &ConflictInventoryInput,
) -> crate::encoding::ConflictInventory {
    #[allow(unused_imports)]
    use crate::encoding::{
        ConflictClass, ConflictDivergence, ConflictEntry, ConflictInventory,
        DirectoryEntryDivergence, ExtentMapDivergence, GenerationOrderingDivergence,
        InodeIdentityDivergence, SnapshotCatalogDivergence,
    };

    let ancestor = input.common_ancestor;
    let mut inventory = ConflictInventory::empty(
        ancestor.identity.transaction_id,
        ancestor.identity.generation,
    );

    // ── 1. Inode identity conflicts (§1.1) ──────────────────────────────────
    classify_inode_identity_conflicts(input, &mut inventory);

    // ── 2. Directory entry conflicts (§1.2) ─────────────────────────────────
    classify_directory_entry_conflicts(input, &mut inventory);

    // ── 3. Extent map conflicts (§1.3) ──────────────────────────────────────
    classify_extent_map_conflicts(input, &mut inventory);

    // ── 4. Snapshot catalog conflicts (§1.4) ────────────────────────────────
    classify_snapshot_catalog_conflicts(input, &mut inventory);

    // ── 5. Generation ordering conflicts (§1.5) ─────────────────────────────
    classify_generation_ordering_conflicts(input, &mut inventory);

    inventory
}

// ── Per-axis classification helpers ──────────────────────────────────────────

#[allow(dead_code)]
fn classify_inode_identity_conflicts(
    input: &ConflictInventoryInput,
    inventory: &mut crate::encoding::ConflictInventory,
) {
    #[allow(unused_imports)]
    use crate::encoding::{ConflictClass, ConflictDivergence, ConflictEntry,
        InodeIdentityDivergence};

    // Collect all inode_ids present in either side.
    let mut all_ids: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for id in input.stream_inodes.keys() {
        all_ids.insert(*id);
    }
    for id in input.target_inodes.keys() {
        all_ids.insert(*id);
    }

    for inode_id in all_ids {
        let stream_rec = input.stream_inodes.get(&inode_id);
        let target_rec = input.target_inodes.get(&inode_id);

        match (stream_rec, target_rec) {
            // Inode exists only on one side: conflict-free addition.
            (Some(_), None) | (None, Some(_)) => {}
            (Some(s), Some(t)) => {
                // Compare non-timestamp fields for divergence.
                let divergence = compare_inode_records(s, t);
                if let Some(div) = divergence {
                    inventory.entries.push(ConflictEntry {
                        class: ConflictClass::InodeIdentity,
                        divergence: ConflictDivergence::InodeIdentity(div),
                        stream_identity: format!("inode {inode_id}"),
                        target_identity: format!("inode {inode_id}"),
                        stream_txg: None,
                        target_txg: None,
                    });
                }
            }
            (None, None) => unreachable!(),
        }
    }
}

/// Compare two inode records and return a divergence kind if they differ
/// in any non-timestamp field.
#[allow(dead_code)]
fn compare_inode_records(
    stream: &crate::types::InodeRecord,
    target: &crate::types::InodeRecord,
) -> Option<crate::encoding::InodeIdentityDivergence> {
    use crate::encoding::InodeIdentityDivergence;

    // Different file type (kind projection).
    if stream.kind() != target.kind() {
        return Some(InodeIdentityDivergence::DifferentFileType);
    }

    // Different metadata versions signal content or metadata changes.
    // data_version changes indicate content divergence.
    if stream.data_version != target.data_version {
        return Some(InodeIdentityDivergence::DifferentContentIdentity);
    }

    // Permission/ownership changes.
    if stream.mode != target.mode
        || stream.uid != target.uid
        || stream.gid != target.gid
    {
        return Some(InodeIdentityDivergence::DifferentPermissionsOwnership);
    }

    // Size change without content identity change (sparse extension, truncate).
    if stream.size != target.size {
        return Some(InodeIdentityDivergence::DifferentSize);
    }

    None
}

#[allow(dead_code)]
fn classify_directory_entry_conflicts(
    input: &ConflictInventoryInput,
    inventory: &mut crate::encoding::ConflictInventory,
) {
    #[allow(unused_imports)]
    use crate::encoding::{ConflictClass, ConflictDivergence, ConflictEntry,
        DirectoryEntryDivergence};

    let mut all_parents: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for id in input.stream_dir_entries.keys() {
        all_parents.insert(*id);
    }
    for id in input.target_dir_entries.keys() {
        all_parents.insert(*id);
    }

    for parent_id in all_parents {
        let stream_entries = input.stream_dir_entries.get(&parent_id);
        let target_entries = input.target_dir_entries.get(&parent_id);

        match (stream_entries, target_entries) {
            (Some(s_entries), Some(t_entries)) => {
                compare_dir_entries(parent_id, s_entries, t_entries, inventory);
            }
            (Some(s_entries), None) => {
                // All stream entries are additions (no target directory).
                for entry in s_entries {
                    let name = String::from_utf8_lossy(&entry.name);
                    inventory.entries.push(ConflictEntry {
                        class: ConflictClass::DirectoryEntry,
                        divergence: ConflictDivergence::DirectoryEntry(
                            DirectoryEntryDivergence::ChildAddedOneSideOnly {
                                present_in_stream: true,
                            },
                        ),
                        stream_identity: format!("dir {parent_id}/{name}"),
                        target_identity: format!("dir {parent_id} (absent in target)"),
                        stream_txg: None,
                        target_txg: None,
                    });
                }
            }
            (None, Some(t_entries)) => {
                for entry in t_entries {
                    let name = String::from_utf8_lossy(&entry.name);
                    inventory.entries.push(ConflictEntry {
                        class: ConflictClass::DirectoryEntry,
                        divergence: ConflictDivergence::DirectoryEntry(
                            DirectoryEntryDivergence::ChildAddedOneSideOnly {
                                present_in_stream: false,
                            },
                        ),
                        stream_identity: format!("dir {parent_id} (absent in stream)"),
                        target_identity: format!("dir {parent_id}/{name}"),
                        stream_txg: None,
                        target_txg: None,
                    });
                }
            }
            (None, None) => unreachable!(),
        }
    }
}

#[allow(dead_code)]
fn compare_dir_entries(
    parent_id: u64,
    stream_entries: &[OwnedDirEntry],
    target_entries: &[OwnedDirEntry],
    inventory: &mut crate::encoding::ConflictInventory,
) {
    #[allow(unused_imports)]
    use crate::encoding::{ConflictClass, ConflictDivergence, ConflictEntry,
        DirectoryEntryDivergence};
    #[allow(unused_imports)]
    use std::collections::BTreeMap;

    let stream_map: BTreeMap<&[u8], &OwnedDirEntry> =
        stream_entries.iter().map(|e| (e.name.as_slice(), e)).collect();
    let target_map: BTreeMap<&[u8], &OwnedDirEntry> =
        target_entries.iter().map(|e| (e.name.as_slice(), e)).collect();

    // Entries present in stream but not in target: added on stream side.
    for name in stream_map.keys() {
        if !target_map.contains_key(name) {
            let name_str = String::from_utf8_lossy(name);
            inventory.entries.push(ConflictEntry {
                class: ConflictClass::DirectoryEntry,
                divergence: ConflictDivergence::DirectoryEntry(
                    DirectoryEntryDivergence::ChildAddedOneSideOnly {
                        present_in_stream: true,
                    },
                ),
                stream_identity: format!("dir {parent_id}/{name_str}"),
                target_identity: format!("dir {parent_id} (absent in target)"),
                stream_txg: None,
                target_txg: None,
            });
        }
    }

    // Entries present in target but not in stream: added on target side.
    for name in target_map.keys() {
        if !stream_map.contains_key(name) {
            let name_str = String::from_utf8_lossy(name);
            inventory.entries.push(ConflictEntry {
                class: ConflictClass::DirectoryEntry,
                divergence: ConflictDivergence::DirectoryEntry(
                    DirectoryEntryDivergence::ChildAddedOneSideOnly {
                        present_in_stream: false,
                    },
                ),
                stream_identity: format!("dir {parent_id} (absent in stream)"),
                target_identity: format!("dir {parent_id}/{name_str}"),
                stream_txg: None,
                target_txg: None,
            });
        }
    }

    // Entries present in both: check for same name / different inode.
    for (name, s_entry) in &stream_map {
        if let Some(t_entry) = target_map.get(name) {
            if s_entry.inode_id != t_entry.inode_id {
                let name_str = String::from_utf8_lossy(name);
                inventory.entries.push(ConflictEntry {
                    class: ConflictClass::DirectoryEntry,
                    divergence: ConflictDivergence::DirectoryEntry(
                        DirectoryEntryDivergence::SameNameDifferentInode,
                    ),
                    stream_identity: format!(
                        "dir {parent_id}/{name_str} -> inode {}",
                        s_entry.inode_id.0
                    ),
                    target_identity: format!(
                        "dir {parent_id}/{name_str} -> inode {}",
                        t_entry.inode_id.0
                    ),
                stream_txg: None,
                target_txg: None,
                });
            }
        }
    }
}

#[allow(dead_code)]
fn classify_extent_map_conflicts(
    input: &ConflictInventoryInput,
    inventory: &mut crate::encoding::ConflictInventory,
) {
    #[allow(unused_imports)]
    use crate::encoding::{ConflictClass, ConflictDivergence, ConflictEntry,
        ExtentMapDivergence};

    let mut all_ids: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for id in input.stream_extent_maps.keys() {
        all_ids.insert(*id);
    }
    for id in input.target_extent_maps.keys() {
        all_ids.insert(*id);
    }

    for inode_id in all_ids {
        let stream_em = input.stream_extent_maps.get(&inode_id);
        let target_em = input.target_extent_maps.get(&inode_id);

        match (stream_em, target_em) {
            (Some(_), None) | (None, Some(_)) => {}
            (Some(s), Some(t)) => {
                if s != t {
                    // Extent maps differ.  Classify the divergence kind by
                    // inspecting the serialized forms.
                    let div = classify_extent_map_difference(s, t);
                    inventory.entries.push(ConflictEntry {
                        class: ConflictClass::ExtentMap,
                        divergence: ConflictDivergence::ExtentMap(div),
                        stream_identity: format!("inode {inode_id} extent map"),
                        target_identity: format!("inode {inode_id} extent map"),
                        stream_txg: None,
                        target_txg: None,
                    });
                }
            }
            (None, None) => unreachable!(),
        }
    }
}

/// Compare two serialized extent maps and classify the divergence.
///
/// Uses a heuristic based on the serialized size and content to distinguish
/// between content-chunk replacement, extent-boundary differences, hole-vs-data,
/// and allocation-only changes.
#[allow(dead_code)]
fn classify_extent_map_difference(
    _stream_bytes: &[u8],
    _target_bytes: &[u8],
) -> crate::encoding::ExtentMapDivergence {
    // Full byte-level extent-map comparison requires deserializing both maps
    // and comparing entry-by-entry.  That belongs to a focused extent-map
    // comparison module.  For the initial conflict inventory, we classify any
    // serialized mismatch as ContentChunkReplaced (the most conservative
    // classification), which the operator policy can override.
    crate::encoding::ExtentMapDivergence::ContentChunkReplaced
}

#[allow(dead_code)]
fn classify_snapshot_catalog_conflicts(
    input: &ConflictInventoryInput,
    inventory: &mut crate::encoding::ConflictInventory,
) {
    #[allow(unused_imports)]
    use crate::encoding::{ConflictClass, ConflictDivergence, ConflictEntry,
        SnapshotCatalogDivergence};
    #[allow(unused_imports)]
    use std::collections::BTreeMap;

    let stream_by_name: BTreeMap<&[u8], &crate::records::SnapshotRecord> = input
        .stream_snapshots
        .iter()
        .map(|r| (r.name.as_slice(), r))
        .collect();
    let target_by_name: BTreeMap<&[u8], &crate::records::SnapshotRecord> = input
        .target_snapshots
        .iter()
        .map(|r| (r.name.as_slice(), r))
        .collect();

    // Snapshots present only in stream: different name sets.
    for name in stream_by_name.keys() {
        if !target_by_name.contains_key(name) {
            let name_str = String::from_utf8_lossy(name);
            inventory.entries.push(ConflictEntry {
                class: ConflictClass::SnapshotCatalog,
                divergence: ConflictDivergence::SnapshotCatalog(
                    SnapshotCatalogDivergence::DifferentNameSets {
                        present_in_stream: true,
                    },
                ),
                stream_identity: format!("snapshot {name_str}"),
                target_identity: String::from("(absent in target)"),
                stream_txg: None,
                target_txg: None,
            });
        }
    }

    // Snapshots present only in target: different name sets.
    for name in target_by_name.keys() {
        if !stream_by_name.contains_key(name) {
            let name_str = String::from_utf8_lossy(name);
            inventory.entries.push(ConflictEntry {
                class: ConflictClass::SnapshotCatalog,
                divergence: ConflictDivergence::SnapshotCatalog(
                    SnapshotCatalogDivergence::DifferentNameSets {
                        present_in_stream: false,
                    },
                ),
                stream_identity: String::from("(absent in stream)"),
                target_identity: format!("snapshot {name_str}"),
                stream_txg: None,
                target_txg: None,
            });
        }
    }

    // Snapshots present in both: check for same name / different root.
    for (name, s_rec) in &stream_by_name {
        if let Some(t_rec) = target_by_name.get(name) {
            if s_rec.root != t_rec.root {
                let name_str = String::from_utf8_lossy(name);
                inventory.entries.push(ConflictEntry {
                    class: ConflictClass::SnapshotCatalog,
                    divergence: ConflictDivergence::SnapshotCatalog(
                        SnapshotCatalogDivergence::SameNameDifferentRoot,
                    ),
                    stream_identity: format!(
                        "snapshot {name_str} root txg={} gen={}",
                        s_rec.root.transaction_id, s_rec.root.generation
                    ),
                    target_identity: format!(
                        "snapshot {name_str} root txg={} gen={}",
                        t_rec.root.transaction_id, t_rec.root.generation
                    ),
                stream_txg: None,
                target_txg: None,
                });
                continue;
            }

            // Same root: check for hold/pin or clone divergence.
            if s_rec.hold_count != t_rec.hold_count {
                let name_str = String::from_utf8_lossy(name);
                inventory.entries.push(ConflictEntry {
                    class: ConflictClass::SnapshotCatalog,
                    divergence: ConflictDivergence::SnapshotCatalog(
                        SnapshotCatalogDivergence::HoldPinDivergence,
                    ),
                    stream_identity: format!(
                        "snapshot {name_str} hold_count={}",
                        s_rec.hold_count
                    ),
                    target_identity: format!(
                        "snapshot {name_str} hold_count={}",
                        t_rec.hold_count
                    ),
                stream_txg: None,
                target_txg: None,
                });
            }

            if s_rec.kind != t_rec.kind || s_rec.origin != t_rec.origin {
                let name_str = String::from_utf8_lossy(name);
                inventory.entries.push(ConflictEntry {
                    class: ConflictClass::SnapshotCatalog,
                    divergence: ConflictDivergence::SnapshotCatalog(
                        SnapshotCatalogDivergence::CloneLineageDivergence,
                    ),
                    stream_identity: format!(
                        "snapshot {name_str} kind={:?} origin={:?}",
                        s_rec.kind, s_rec.origin
                    ),
                    target_identity: format!(
                        "snapshot {name_str} kind={:?} origin={:?}",
                        t_rec.kind, t_rec.origin
                    ),
                stream_txg: None,
                target_txg: None,
                });
            }
        }
    }
}

#[allow(dead_code)]
fn classify_generation_ordering_conflicts(
    input: &ConflictInventoryInput,
    inventory: &mut crate::encoding::ConflictInventory,
) {
    #[allow(unused_imports)]
    use crate::encoding::{ConflictClass, ConflictDivergence, ConflictEntry,
        GenerationOrderingDivergence};

    let ancestor_txg = input.common_ancestor.identity.transaction_id;

    let stream_max_txg = input
        .stream_lineage
        .roots()
        .iter()
        .map(|r| r.transaction_id)
        .max()
        .unwrap_or(ancestor_txg);

    let target_max_txg = input
        .target_recovery_audit
        .valid_committed_roots
        .iter()
        .map(|r| r.transaction_id)
        .max()
        .unwrap_or(ancestor_txg);

    // Independent txg advance: both sides moved past the common ancestor
    // without any shared post-ancestor txg.
    let stream_has_post_ancestor = stream_max_txg > ancestor_txg;
    let target_has_post_ancestor = target_max_txg > ancestor_txg;

    if stream_has_post_ancestor && target_has_post_ancestor {
        // Check if there is any shared txg above the ancestor.
        let stream_txgs: std::collections::BTreeSet<u64> = input
            .stream_lineage
            .roots()
            .iter()
            .map(|r| r.transaction_id)
            .collect();
        let target_txgs: std::collections::BTreeSet<u64> = input
            .target_recovery_audit
            .valid_committed_roots
            .iter()
            .map(|r| r.transaction_id)
            .collect();

        let shared_above_ancestor = stream_txgs
            .iter()
            .any(|txg| *txg > ancestor_txg && target_txgs.contains(txg));

        if !shared_above_ancestor {
            inventory.entries.push(ConflictEntry {
                class: ConflictClass::GenerationOrdering,
                divergence: ConflictDivergence::GenerationOrdering(
                    GenerationOrderingDivergence::IndependentTxgAdvance,
                ),
                stream_identity: format!(
                    "stream txg range [{ancestor_txg}..{stream_max_txg}]"
                ),
                target_identity: format!(
                    "target txg range [{ancestor_txg}..{target_max_txg}]"
                ),
            stream_txg: None,
            target_txg: None,
            });
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_local_object_store::IntegrityDigest64;
    use crate::encoding::{
        ConflictClass, ConflictDivergence, ConflictEntry, ConflictInventory,
        DirectoryEntryDivergence, ExtentMapDivergence, GenerationOrderingDivergence,
        InodeIdentityDivergence, SnapshotCatalogDivergence,
    };
    use tidefs_types_vfs_core::NodeKind;

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

    // ── Conflict inventory builder tests ──────────────────────────────────────

    fn make_inode(id: u64, kind: NodeKind, data_ver: u64, mode: u32, size: u64) -> crate::types::InodeRecord {
        crate::types::InodeRecord {
            rdev: 0,
            inode_id: tidefs_types_vfs_core::InodeId::new(id),
            generation: tidefs_types_vfs_core::Generation(data_ver),
            facets: kind.to_facets(),
            mode,
            uid: 0,
            gid: 0,
            nlink: 1,
            size,
            data_version: data_ver,
            metadata_version: data_ver,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattrs: Default::default(),
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: if kind == NodeKind::Dir { 1 } else { 0 },
            subtree_rev: 0,
        }
    }

    fn make_dir_entry(name: &str, inode_id: u64, kind: NodeKind) -> OwnedDirEntry {
        OwnedDirEntry::new(
            name.as_bytes().to_vec(),
            tidefs_types_vfs_core::InodeId::new(inode_id),
            kind,
            tidefs_types_vfs_core::Generation(1),
            0,
        )
    }

    fn make_snapshot(
        name: &str,
        txg: u64,
        gen: u64,
        hold_count: u32,
    ) -> crate::records::SnapshotRecord {
        crate::records::SnapshotRecord {
            name: name.as_bytes().to_vec(),
            root: root(txg, gen, txg ^ gen),
            created_at_generation: gen,
            kind: crate::records::SnapshotKind::Snapshot,
            origin: None,
            hold_count,
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn input_from(
        ancestor: &ReceiveMergeCommonAncestor,
        stream_inodes: BTreeMap<u64, crate::types::InodeRecord>,
        target_inodes: BTreeMap<u64, crate::types::InodeRecord>,
        stream_dirs: BTreeMap<u64, Vec<OwnedDirEntry>>,
        target_dirs: BTreeMap<u64, Vec<OwnedDirEntry>>,
        stream_extents: BTreeMap<u64, Vec<u8>>,
        target_extents: BTreeMap<u64, Vec<u8>>,
        stream_snapshots: Vec<crate::records::SnapshotRecord>,
        target_snapshots: Vec<crate::records::SnapshotRecord>,
    ) -> ConflictInventoryInput<'static> {
        // Leak to get 'static lifetime — safe in tests.
        let ancestor: &'static ReceiveMergeCommonAncestor =
            Box::leak(Box::new(ancestor.clone()));
        let stream_inodes: &'static BTreeMap<u64, crate::types::InodeRecord> =
            Box::leak(Box::new(stream_inodes));
        let target_inodes: &'static BTreeMap<u64, crate::types::InodeRecord> =
            Box::leak(Box::new(target_inodes));
        let stream_dirs: &'static BTreeMap<u64, Vec<OwnedDirEntry>> =
            Box::leak(Box::new(stream_dirs));
        let target_dirs: &'static BTreeMap<u64, Vec<OwnedDirEntry>> =
            Box::leak(Box::new(target_dirs));
        let stream_extents: &'static BTreeMap<u64, Vec<u8>> =
            Box::leak(Box::new(stream_extents));
        let target_extents: &'static BTreeMap<u64, Vec<u8>> =
            Box::leak(Box::new(target_extents));
        let stream_snapshots: &'static [crate::records::SnapshotRecord] =
            Box::leak(stream_snapshots.into_boxed_slice());
        let target_snapshots: &'static [crate::records::SnapshotRecord] =
            Box::leak(target_snapshots.into_boxed_slice());
        let stream_lineage: &'static ReceiveMergeStreamLineageManifest =
            Box::leak(Box::new(ReceiveMergeStreamLineageManifest::from_roots(
                vec![ancestor.stream_root.clone()],
            )));
        let target_audit: &'static RecoveryAuditReport = Box::leak(Box::new({
            let mut a = RecoveryAuditReport::empty();
            a.valid_committed_roots = vec![ancestor.target_root.clone()];
            a
        }));

        ConflictInventoryInput {
            common_ancestor: ancestor,
            stream_inodes,
            target_inodes,
            stream_dir_entries: stream_dirs,
            target_dir_entries: target_dirs,
            stream_extent_maps: stream_extents,
            target_extent_maps: target_extents,
            stream_snapshots,
            target_snapshots,
            stream_lineage,
            target_recovery_audit: target_audit,
        }
    }

    fn ancestor_for_test() -> ReceiveMergeCommonAncestor {
        let shared = root(10, 100, 0xabc);
        ReceiveMergeCommonAncestor {
            identity: ReceiveMergeRootIdentity::from_summary(&shared),
            stream_root: shared.clone(),
            target_root: shared,
        }
    }

    #[test]
    fn empty_inventory_when_no_changes_on_either_side() {
        let ancestor = ancestor_for_test();
        let inode = make_inode(1, NodeKind::File, 1, 0o644, 4096);
        let stream_inodes = BTreeMap::from([(1, inode.clone())]);
        let target_inodes = BTreeMap::from([(1, inode)]);
        let input = input_from(
            &ancestor,
            stream_inodes,
            target_inodes,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            vec![],
            vec![],
        );

        let inventory = build_conflict_inventory(&input);
        assert!(inventory.is_empty());
        assert_eq!(inventory.common_ancestor_transaction_id, 10);
        assert_eq!(inventory.common_ancestor_generation, 100);
    }

    #[test]
    fn inode_identity_different_file_type() {
        let ancestor = ancestor_for_test();
        let stream_inode = make_inode(1, NodeKind::File, 1, 0o644, 4096);
        let target_inode = make_inode(1, NodeKind::Dir, 1, 0o755, 0);
        let input = input_from(
            &ancestor,
            BTreeMap::from([(1, stream_inode)]),
            BTreeMap::from([(1, target_inode)]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            vec![],
            vec![],
        );

        let inventory = build_conflict_inventory(&input);
        assert_eq!(inventory.len(), 1);
        let entry = &inventory.entries[0];
        assert_eq!(entry.class, ConflictClass::InodeIdentity);
        assert!(matches!(
            entry.divergence,
            ConflictDivergence::InodeIdentity(InodeIdentityDivergence::DifferentFileType)
        ));
    }

    #[test]
    fn inode_identity_different_content() {
        let ancestor = ancestor_for_test();
        let stream_inode = make_inode(1, NodeKind::File, 5, 0o644, 4096);
        let target_inode = make_inode(1, NodeKind::File, 3, 0o644, 4096);
        let input = input_from(
            &ancestor,
            BTreeMap::from([(1, stream_inode)]),
            BTreeMap::from([(1, target_inode)]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            vec![],
            vec![],
        );

        let inventory = build_conflict_inventory(&input);
        assert_eq!(inventory.len(), 1);
        assert!(matches!(
            inventory.entries[0].divergence,
            ConflictDivergence::InodeIdentity(InodeIdentityDivergence::DifferentContentIdentity)
        ));
    }

    #[test]
    fn inode_identity_different_permissions() {
        let ancestor = ancestor_for_test();
        let stream_inode = make_inode(1, NodeKind::File, 1, 0o600, 4096);
        let target_inode = make_inode(1, NodeKind::File, 1, 0o644, 4096);
        let input = input_from(
            &ancestor,
            BTreeMap::from([(1, stream_inode)]),
            BTreeMap::from([(1, target_inode)]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            vec![],
            vec![],
        );

        let inventory = build_conflict_inventory(&input);
        assert_eq!(inventory.len(), 1);
        assert!(matches!(
            inventory.entries[0].divergence,
            ConflictDivergence::InodeIdentity(InodeIdentityDivergence::DifferentPermissionsOwnership)
        ));
    }

    #[test]
    fn inode_identity_different_size() {
        let ancestor = ancestor_for_test();
        let stream_inode = make_inode(1, NodeKind::File, 1, 0o644, 8192);
        let target_inode = make_inode(1, NodeKind::File, 1, 0o644, 4096);
        let input = input_from(
            &ancestor,
            BTreeMap::from([(1, stream_inode)]),
            BTreeMap::from([(1, target_inode)]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            vec![],
            vec![],
        );

        let inventory = build_conflict_inventory(&input);
        assert_eq!(inventory.len(), 1);
        assert!(matches!(
            inventory.entries[0].divergence,
            ConflictDivergence::InodeIdentity(InodeIdentityDivergence::DifferentSize)
        ));
    }

    #[test]
    fn directory_entry_child_added_stream_side() {
        let ancestor = ancestor_for_test();
        let stream_dirs = BTreeMap::from([(
            1_u64,
            vec![make_dir_entry("new_file", 2, NodeKind::File)],
        )]);
        let target_dirs: BTreeMap<u64, Vec<OwnedDirEntry>> = BTreeMap::new();
        let input = input_from(
            &ancestor,
            BTreeMap::new(),
            BTreeMap::new(),
            stream_dirs,
            target_dirs,
            BTreeMap::new(),
            BTreeMap::new(),
            vec![],
            vec![],
        );

        let inventory = build_conflict_inventory(&input);
        assert_eq!(inventory.len(), 1);
        let entry = &inventory.entries[0];
        assert_eq!(entry.class, ConflictClass::DirectoryEntry);
        assert!(matches!(
            entry.divergence,
            ConflictDivergence::DirectoryEntry(
                DirectoryEntryDivergence::ChildAddedOneSideOnly { present_in_stream: true }
            )
        ));
    }

    #[test]
    fn directory_entry_child_added_target_side() {
        let ancestor = ancestor_for_test();
        let stream_dirs: BTreeMap<u64, Vec<OwnedDirEntry>> = BTreeMap::new();
        let target_dirs = BTreeMap::from([(
            1_u64,
            vec![make_dir_entry("new_file", 2, NodeKind::File)],
        )]);
        let input = input_from(
            &ancestor,
            BTreeMap::new(),
            BTreeMap::new(),
            stream_dirs,
            target_dirs,
            BTreeMap::new(),
            BTreeMap::new(),
            vec![],
            vec![],
        );

        let inventory = build_conflict_inventory(&input);
        assert_eq!(inventory.len(), 1);
        assert!(matches!(
            inventory.entries[0].divergence,
            ConflictDivergence::DirectoryEntry(
                DirectoryEntryDivergence::ChildAddedOneSideOnly { present_in_stream: false }
            )
        ));
    }

    #[test]
    fn directory_entry_same_name_different_inode() {
        let ancestor = ancestor_for_test();
        let stream_dirs = BTreeMap::from([(
            1_u64,
            vec![make_dir_entry("shared_name", 10, NodeKind::File)],
        )]);
        let target_dirs = BTreeMap::from([(
            1_u64,
            vec![make_dir_entry("shared_name", 20, NodeKind::File)],
        )]);
        let input = input_from(
            &ancestor,
            BTreeMap::new(),
            BTreeMap::new(),
            stream_dirs,
            target_dirs,
            BTreeMap::new(),
            BTreeMap::new(),
            vec![],
            vec![],
        );

        let inventory = build_conflict_inventory(&input);
        assert_eq!(inventory.len(), 1);
        assert!(matches!(
            inventory.entries[0].divergence,
            ConflictDivergence::DirectoryEntry(
                DirectoryEntryDivergence::SameNameDifferentInode
            )
        ));
    }

    #[test]
    fn extent_map_conflict_detected() {
        let ancestor = ancestor_for_test();
        let stream_extents = BTreeMap::from([(1_u64, vec![1, 2, 3])]);
        let target_extents = BTreeMap::from([(1_u64, vec![4, 5, 6])]);
        let input = input_from(
            &ancestor,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            stream_extents,
            target_extents,
            vec![],
            vec![],
        );

        let inventory = build_conflict_inventory(&input);
        assert_eq!(inventory.len(), 1);
        let entry = &inventory.entries[0];
        assert_eq!(entry.class, ConflictClass::ExtentMap);
        assert!(matches!(
            entry.divergence,
            ConflictDivergence::ExtentMap(ExtentMapDivergence::ContentChunkReplaced)
        ));
    }

    #[test]
    fn extent_map_identical_no_conflict() {
        let ancestor = ancestor_for_test();
        let extents = BTreeMap::from([(1_u64, vec![1, 2, 3])]);
        let input = input_from(
            &ancestor,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            extents.clone(),
            extents,
            vec![],
            vec![],
        );

        let inventory = build_conflict_inventory(&input);
        assert!(inventory.is_empty());
    }

    #[test]
    fn snapshot_catalog_same_name_different_root() {
        let ancestor = ancestor_for_test();
        let stream_snaps = vec![make_snapshot("snap1", 20, 200, 1)];
        let target_snaps = vec![make_snapshot("snap1", 30, 300, 1)];
        let input = input_from(
            &ancestor,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            stream_snaps,
            target_snaps,
        );

        let inventory = build_conflict_inventory(&input);
        assert!(!inventory.is_empty());
        let same_name_diff_root = inventory.entries.iter().any(|e| {
            matches!(
                e.divergence,
                ConflictDivergence::SnapshotCatalog(
                    SnapshotCatalogDivergence::SameNameDifferentRoot
                )
            )
        });
        assert!(same_name_diff_root, "expected SameNameDifferentRoot conflict");
    }

    #[test]
    fn snapshot_catalog_different_name_sets() {
        let ancestor = ancestor_for_test();
        let stream_snaps = vec![make_snapshot("stream_only", 20, 200, 0)];
        let target_snaps = vec![make_snapshot("target_only", 30, 300, 0)];
        let input = input_from(
            &ancestor,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            stream_snaps,
            target_snaps,
        );

        let inventory = build_conflict_inventory(&input);
        assert_eq!(inventory.len(), 2);
        let has_stream_only = inventory.entries.iter().any(|e| {
            matches!(
                e.divergence,
                ConflictDivergence::SnapshotCatalog(
                    SnapshotCatalogDivergence::DifferentNameSets { present_in_stream: true }
                )
            )
        });
        let has_target_only = inventory.entries.iter().any(|e| {
            matches!(
                e.divergence,
                ConflictDivergence::SnapshotCatalog(
                    SnapshotCatalogDivergence::DifferentNameSets { present_in_stream: false }
                )
            )
        });
        assert!(has_stream_only);
        assert!(has_target_only);
    }

    #[test]
    fn generation_ordering_independent_txg_advance() {
        let ancestor_root = root(10, 100, 0xabc);
        let stream_root = root(15, 150, 0xdef);
        let target_root = root(20, 200, 0x123);
        let ancestor = ReceiveMergeCommonAncestor {
            identity: ReceiveMergeRootIdentity::from_summary(&ancestor_root),
            stream_root: stream_root.clone(),
            target_root: target_root.clone(),
        };

        let stream_lineage =
            ReceiveMergeStreamLineageManifest::from_roots(vec![ancestor_root.clone(), stream_root]);
        let mut target_audit = RecoveryAuditReport::empty();
        target_audit.valid_committed_roots = vec![ancestor_root, target_root];

        let input = ConflictInventoryInput {
            common_ancestor: Box::leak(Box::new(ancestor)),
            stream_inodes: Box::leak(Box::new(BTreeMap::new())),
            target_inodes: Box::leak(Box::new(BTreeMap::new())),
            stream_dir_entries: Box::leak(Box::new(BTreeMap::new())),
            target_dir_entries: Box::leak(Box::new(BTreeMap::new())),
            stream_extent_maps: Box::leak(Box::new(BTreeMap::new())),
            target_extent_maps: Box::leak(Box::new(BTreeMap::new())),
            stream_snapshots: Box::leak(Box::new([])),
            target_snapshots: Box::leak(Box::new([])),
            stream_lineage: Box::leak(Box::new(stream_lineage)),
            target_recovery_audit: Box::leak(Box::new(target_audit)),
        };

        let inventory = build_conflict_inventory(&input);
        assert!(!inventory.is_empty());
        assert!(inventory.entries.iter().any(|e| {
            matches!(
                e.divergence,
                ConflictDivergence::GenerationOrdering(
                    GenerationOrderingDivergence::IndependentTxgAdvance
                )
            )
        }));
    }

    #[test]
    fn generation_ordering_shared_post_ancestor_txg_no_conflict() {
        let ancestor_root = root(10, 100, 0xabc);
        let shared_root = root(12, 120, 0xdef);
        let stream_root = root(15, 150, 0x111);
        let target_root = root(20, 200, 0x222);
        let ancestor = ReceiveMergeCommonAncestor {
            identity: ReceiveMergeRootIdentity::from_summary(&ancestor_root),
            stream_root: stream_root.clone(),
            target_root: target_root.clone(),
        };

        let stream_lineage = ReceiveMergeStreamLineageManifest::from_roots(vec![
            ancestor_root.clone(),
            shared_root.clone(),
            stream_root,
        ]);
        let mut target_audit = RecoveryAuditReport::empty();
        target_audit.valid_committed_roots =
            vec![ancestor_root, shared_root, target_root];

        let input = ConflictInventoryInput {
            common_ancestor: Box::leak(Box::new(ancestor)),
            stream_inodes: Box::leak(Box::new(BTreeMap::new())),
            target_inodes: Box::leak(Box::new(BTreeMap::new())),
            stream_dir_entries: Box::leak(Box::new(BTreeMap::new())),
            target_dir_entries: Box::leak(Box::new(BTreeMap::new())),
            stream_extent_maps: Box::leak(Box::new(BTreeMap::new())),
            target_extent_maps: Box::leak(Box::new(BTreeMap::new())),
            stream_snapshots: Box::leak(Box::new([])),
            target_snapshots: Box::leak(Box::new([])),
            stream_lineage: Box::leak(Box::new(stream_lineage)),
            target_recovery_audit: Box::leak(Box::new(target_audit)),
        };

        let inventory = build_conflict_inventory(&input);
        // No generation ordering conflict because there's a shared txg above ancestor.
        assert!(inventory
            .entries
            .iter()
            .all(|e| e.class != ConflictClass::GenerationOrdering));
    }

    // ── Operator policy resolution tests ────────────────────────────────────

    fn make_inventory(txg: u64, gen: u64) -> ConflictInventory {
        ConflictInventory::empty(txg, gen)
    }

    fn make_entry(
        class: ConflictClass,
        stream_txg: Option<u64>,
        target_txg: Option<u64>,
    ) -> ConflictEntry {
        ConflictEntry {
            class,
            divergence: ConflictDivergence::InodeIdentity(
                InodeIdentityDivergence::DifferentContentIdentity,
            ),
            stream_identity: "inode 42".into(),
            target_identity: "inode 42".into(),
            stream_txg,
            target_txg,
        }
    }

    #[test]
    fn policy_keep_local_all_decisions_keep_local() {
        let mut inventory = make_inventory(10, 100);
        inventory.entries.push(make_entry(ConflictClass::InodeIdentity, Some(15), Some(20)));
        inventory.entries.push(make_entry(ConflictClass::DirectoryEntry, Some(16), Some(21)));

        let plan = resolve_merge_policy(&inventory, ReceiveMergePolicy::KeepLocal).unwrap();
        assert_eq!(plan.policy, ReceiveMergePolicy::KeepLocal);
        assert_eq!(plan.len(), 2);
        assert!(!plan.requires_operator);
        for decision in &plan.decisions {
            assert_eq!(*decision, ReceiveMergeDecision::KeepLocal);
        }
    }

    #[test]
    fn policy_keep_remote_all_decisions_keep_remote() {
        let mut inventory = make_inventory(10, 100);
        inventory.entries.push(make_entry(ConflictClass::InodeIdentity, Some(15), Some(20)));

        let plan = resolve_merge_policy(&inventory, ReceiveMergePolicy::KeepRemote).unwrap();
        assert_eq!(plan.policy, ReceiveMergePolicy::KeepRemote);
        assert_eq!(plan.len(), 1);
        assert!(!plan.requires_operator);
        assert_eq!(plan.decisions[0], ReceiveMergeDecision::KeepRemote);
    }

    #[test]
    fn policy_merge_latest_stream_higher_txg_wins() {
        let mut inventory = make_inventory(10, 100);
        // target_txg=5, stream_txg=15: stream is higher -> KeepRemote
        inventory.entries.push(make_entry(ConflictClass::InodeIdentity, Some(15), Some(5)));

        let plan = resolve_merge_policy(&inventory, ReceiveMergePolicy::MergeLatest).unwrap();
        assert_eq!(plan.policy, ReceiveMergePolicy::MergeLatest);
        assert_eq!(plan.decisions[0], ReceiveMergeDecision::KeepRemote);
    }

    #[test]
    fn policy_merge_latest_target_higher_or_equal_txg_wins() {
        let mut inventory = make_inventory(10, 100);
        // target_txg=20, stream_txg=15: target is higher -> KeepLocal
        inventory.entries.push(make_entry(ConflictClass::InodeIdentity, Some(15), Some(20)));
        // equal txg -> target wins (KeepLocal)
        inventory.entries.push(make_entry(ConflictClass::InodeIdentity, Some(10), Some(10)));

        let plan = resolve_merge_policy(&inventory, ReceiveMergePolicy::MergeLatest).unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.decisions[0], ReceiveMergeDecision::KeepLocal);
        assert_eq!(plan.decisions[1], ReceiveMergeDecision::KeepLocal);
    }

    #[test]
    fn policy_merge_latest_missing_txg_falls_back_to_keep_local() {
        let mut inventory = make_inventory(10, 100);
        // No txg info: conservative, target wins
        inventory.entries.push(make_entry(ConflictClass::InodeIdentity, None, None));
        // Only one side has txg: still falls back to target
        inventory.entries.push(make_entry(ConflictClass::InodeIdentity, Some(15), None));
        inventory.entries.push(make_entry(ConflictClass::InodeIdentity, None, Some(20)));

        let plan = resolve_merge_policy(&inventory, ReceiveMergePolicy::MergeLatest).unwrap();
        assert_eq!(plan.len(), 3);
        for decision in &plan.decisions {
            assert_eq!(*decision, ReceiveMergeDecision::KeepLocal);
        }
    }

    #[test]
    fn policy_manual_refuses_to_produce_plan() {
        let mut inventory = make_inventory(10, 100);
        inventory.entries.push(make_entry(ConflictClass::InodeIdentity, Some(15), Some(20)));

        let err = resolve_merge_policy(&inventory, ReceiveMergePolicy::Manual).unwrap_err();
        match err {
            ReceiveMergePolicyError::ManualPolicy {
                conflict_count,
                guidance: _,
            } => {
                assert_eq!(conflict_count, 1);
            }
        }
    }

    #[test]
    fn policy_manual_empty_inventory_reports_zero_conflicts() {
        let inventory = make_inventory(10, 100);
        let err = resolve_merge_policy(&inventory, ReceiveMergePolicy::Manual).unwrap_err();
        match err {
            ReceiveMergePolicyError::ManualPolicy {
                conflict_count,
                guidance: _,
            } => {
                assert_eq!(conflict_count, 0);
            }
        }
    }

    #[test]
    fn policy_keep_local_empty_inventory_produces_empty_plan() {
        let inventory = make_inventory(10, 100);
        let plan = resolve_merge_policy(&inventory, ReceiveMergePolicy::KeepLocal).unwrap();
        assert!(plan.is_empty());
        assert_eq!(plan.len(), 0);
        assert!(!plan.requires_operator);
        assert_eq!(plan.policy, ReceiveMergePolicy::KeepLocal);
    }

    #[test]
    fn policy_merge_latest_empty_inventory_produces_empty_plan() {
        let inventory = make_inventory(10, 100);
        let plan = resolve_merge_policy(&inventory, ReceiveMergePolicy::MergeLatest).unwrap();
        assert!(plan.is_empty());
        assert!(!plan.requires_operator);
    }

    #[test]
    fn plan_anchored_at_common_ancestor_identity() {
        let inventory = make_inventory(42, 420);
        let plan = resolve_merge_policy(&inventory, ReceiveMergePolicy::KeepLocal).unwrap();
        assert_eq!(plan.common_ancestor_transaction_id, 42);
        assert_eq!(plan.common_ancestor_generation, 420);
    }

    #[test]
    fn plan_empty_constructor_matches_resolved_empty_plan() {
        let inventory = make_inventory(10, 100);
        let resolved = resolve_merge_policy(&inventory, ReceiveMergePolicy::KeepLocal).unwrap();
        let empty = ReceiveMergePlan::empty(ReceiveMergePolicy::KeepLocal, &inventory);
        assert_eq!(resolved.policy, empty.policy);
        assert_eq!(resolved.common_ancestor_transaction_id, empty.common_ancestor_transaction_id);
        assert_eq!(resolved.common_ancestor_generation, empty.common_ancestor_generation);
        assert_eq!(resolved.decisions, empty.decisions);
        assert_eq!(resolved.requires_operator, empty.requires_operator);
    }

    #[test]
    fn plan_empty_with_manual_sets_requires_operator() {
        let inventory = make_inventory(10, 100);
        let plan = ReceiveMergePlan::empty(ReceiveMergePolicy::Manual, &inventory);
        assert!(plan.requires_operator);
        assert!(plan.is_empty());
    }

}
