// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Released-root deadlist derivation.
//!
//! This module only derives dead-object candidates. It does not enqueue,
//! drain, free, schedule, or otherwise mutate reclaim state.

use std::collections::BTreeSet;

use tidefs_dataset_lifecycle::{BlockPointer, TraversalRoot, TraversalRootType};
use tidefs_local_object_store::ObjectKey;
use tidefs_types_reclaim_queue_core::ObjectKey as ReclaimObjectKey;

use crate::error::FileSystemError;
use crate::recovery::object_keys_for_committed_root_summary;
use crate::types::CommittedRootSummary;
use crate::{LocalFileSystem, Result};

/// Released snapshot or clone root to compare against the live-root set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeadlistReleasedRoot {
    pub root: CommittedRootSummary,
    pub traversal_root: TraversalRoot,
}

impl DeadlistReleasedRoot {
    #[must_use]
    pub fn snapshot_or_clone(root: CommittedRootSummary) -> Self {
        let traversal_root = snapshot_traversal_root_for_summary(&root);
        Self {
            root,
            traversal_root,
        }
    }
}

/// Why a committed root is live for deadlist subtraction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadlistLiveRootSource {
    CurrentCommittedDatasetRoot,
    LifecyclePin { traversal_root: TraversalRoot },
    Explicit,
}

/// A committed root that must be subtracted from released-root reachability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeadlistLiveRoot {
    pub root: CommittedRootSummary,
    pub source: DeadlistLiveRootSource,
}

impl DeadlistLiveRoot {
    #[must_use]
    pub fn current_committed(root: CommittedRootSummary) -> Self {
        Self {
            root,
            source: DeadlistLiveRootSource::CurrentCommittedDatasetRoot,
        }
    }

    #[must_use]
    pub fn lifecycle_pin(root: CommittedRootSummary, traversal_root: TraversalRoot) -> Self {
        Self {
            root,
            source: DeadlistLiveRootSource::LifecyclePin { traversal_root },
        }
    }

    #[must_use]
    pub fn explicit(root: CommittedRootSummary) -> Self {
        Self {
            root,
            source: DeadlistLiveRootSource::Explicit,
        }
    }
}

/// Derivation request for a released snapshot or clone root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeadlistDerivationInput {
    pub released: DeadlistReleasedRoot,
    pub live_roots: Vec<DeadlistLiveRoot>,
}

impl DeadlistDerivationInput {
    #[must_use]
    pub fn new(released: DeadlistReleasedRoot, live_roots: Vec<DeadlistLiveRoot>) -> Self {
        Self {
            released,
            live_roots,
        }
    }
}

/// Stable identity carried with candidates for later queue integration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeadlistReleasedRootIdentity {
    pub traversal_root: TraversalRoot,
    pub transaction_id: u64,
    pub generation: u64,
    pub manifest_checksum: tidefs_local_object_store::IntegrityDigest64,
    pub manifest_entry_count: u64,
}

impl DeadlistReleasedRootIdentity {
    #[must_use]
    pub fn from_released(released: &DeadlistReleasedRoot) -> Self {
        Self {
            traversal_root: released.traversal_root,
            transaction_id: released.root.transaction_id,
            generation: released.root.generation,
            manifest_checksum: released.root.manifest_checksum,
            manifest_entry_count: released.root.manifest_entry_count,
        }
    }
}

/// Candidate object key that is reachable only from the released root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeadlistCandidate {
    pub object_key: ObjectKey,
    pub released_root: DeadlistReleasedRootIdentity,
}

impl DeadlistCandidate {
    #[must_use]
    pub fn reclaim_object_key(&self) -> ReclaimObjectKey {
        ReclaimObjectKey(*self.object_key.as_bytes())
    }
}

/// Result of subtracting live-root reachability from a released root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeadlistDerivationReport {
    pub released: DeadlistReleasedRoot,
    pub live_roots: Vec<DeadlistLiveRoot>,
    pub released_object_count: usize,
    pub live_object_count: usize,
    pub candidates: Vec<DeadlistCandidate>,
}

impl DeadlistDerivationReport {
    #[must_use]
    pub fn candidate_keys(&self) -> Vec<ObjectKey> {
        self.candidates
            .iter()
            .map(|candidate| candidate.object_key)
            .collect()
    }
}

/// Derive released-root dead-object candidates using an explicit root walker.
///
/// `object_keys_for_root` must return every object reachable from the supplied
/// committed root. The caller controls which live roots are subtracted through
/// [`DeadlistDerivationInput::live_roots`].
pub fn derive_released_root_deadlist_candidates_with(
    input: DeadlistDerivationInput,
    mut object_keys_for_root: impl FnMut(&CommittedRootSummary) -> Result<BTreeSet<ObjectKey>>,
) -> Result<DeadlistDerivationReport> {
    validate_released_root(&input.released)?;
    validate_live_roots(&input.live_roots)?;

    let released_keys = object_keys_for_root(&input.released.root)?;
    let mut live_keys = BTreeSet::new();
    for live_root in &input.live_roots {
        live_keys.extend(object_keys_for_root(&live_root.root)?);
    }

    let released_root = DeadlistReleasedRootIdentity::from_released(&input.released);
    let candidates = released_keys
        .difference(&live_keys)
        .map(|object_key| DeadlistCandidate {
            object_key: *object_key,
            released_root: released_root.clone(),
        })
        .collect();

    Ok(DeadlistDerivationReport {
        released: input.released,
        live_roots: input.live_roots,
        released_object_count: released_keys.len(),
        live_object_count: live_keys.len(),
        candidates,
    })
}

impl LocalFileSystem {
    /// Derive dead-object candidates from an explicitly supplied live-root set.
    pub fn derive_released_root_deadlist_candidates(
        &mut self,
        input: DeadlistDerivationInput,
    ) -> Result<DeadlistDerivationReport> {
        let root_authentication_key = self.root_authentication_key;
        let store = self.store.raw_primary_store_mut();
        derive_released_root_deadlist_candidates_with(input, |root| {
            object_keys_for_committed_root_summary(&mut *store, root, root_authentication_key)
        })
    }

    /// Build the local live-root set from the current committed root plus
    /// lifecycle snapshot/clone pins, then derive released-root candidates.
    pub fn derive_released_root_deadlist_candidates_against_local_live_roots(
        &mut self,
        released: DeadlistReleasedRoot,
    ) -> Result<DeadlistDerivationReport> {
        let input = DeadlistDerivationInput::new(released, self.deadlist_local_live_roots()?);
        self.derive_released_root_deadlist_candidates(input)
    }

    /// Enumerate roots that must be protected by local deadlist derivation.
    pub fn deadlist_local_live_roots(&mut self) -> Result<Vec<DeadlistLiveRoot>> {
        let mut live_roots = vec![DeadlistLiveRoot::current_committed(
            self.selected_current_root_summary()?,
        )];

        for pinned_root in self.lifecycle.gc_pin_set().pinned_roots() {
            let matching_roots: Vec<_> = self
                .state
                .snapshots
                .values()
                .filter(|record| crate::snapshot::snapshot_record_retains_data(record))
                .filter(|record| {
                    crate::snapshot::snapshot_record_traversal_root(record) == *pinned_root
                })
                .map(|record| record.root.clone())
                .collect();
            if matching_roots.is_empty() {
                return Err(FileSystemError::CorruptState {
                    reason: "deadlist derivation found a lifecycle pin without a snapshot root",
                });
            }
            for root in matching_roots {
                live_roots.push(DeadlistLiveRoot::lifecycle_pin(root, *pinned_root));
            }
        }

        Ok(live_roots)
    }
}

#[must_use]
pub fn snapshot_traversal_root_for_summary(summary: &CommittedRootSummary) -> TraversalRoot {
    TraversalRoot::new(
        TraversalRootType::SnapshotCatalog,
        BlockPointer(summary.transaction_id),
        summary.generation,
    )
}

fn validate_released_root(released: &DeadlistReleasedRoot) -> Result<()> {
    if released.traversal_root != snapshot_traversal_root_for_summary(&released.root) {
        return Err(FileSystemError::CorruptState {
            reason: "released deadlist root does not match its traversal root",
        });
    }
    Ok(())
}

fn validate_live_roots(live_roots: &[DeadlistLiveRoot]) -> Result<()> {
    for live_root in live_roots {
        if let DeadlistLiveRootSource::LifecyclePin { traversal_root } = live_root.source {
            if traversal_root != snapshot_traversal_root_for_summary(&live_root.root) {
                return Err(FileSystemError::CorruptState {
                    reason: "deadlist live lifecycle root does not match its traversal root",
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tidefs_local_object_store::IntegrityDigest64;

    fn summary(transaction_id: u64, generation: u64) -> CommittedRootSummary {
        CommittedRootSummary {
            slot: transaction_id % 2,
            transaction_id,
            generation,
            next_inode_id: 1,
            inode_count: 1,
            superblock_checksum: IntegrityDigest64(transaction_id),
            has_transaction_manifest: true,
            manifest_checksum: IntegrityDigest64(transaction_id + 100),
            manifest_entry_count: 1,
            has_root_authentication: false,
            root_authentication_policy_epoch: None,
            root_authentication_algorithm_suite_id: None,
            superblock_digest: None,
            manifest_digest: None,
            root_authentication_code: None,
        }
    }

    fn key(byte: u8) -> ObjectKey {
        let mut bytes = [0_u8; 32];
        bytes[31] = byte;
        ObjectKey::from_bytes32(bytes)
    }

    fn keys(bytes: &[u8]) -> BTreeSet<ObjectKey> {
        bytes.iter().copied().map(key).collect()
    }

    fn derive_with_roots(
        input: DeadlistDerivationInput,
        roots: BTreeMap<u64, BTreeSet<ObjectKey>>,
    ) -> DeadlistDerivationReport {
        derive_released_root_deadlist_candidates_with(input, |root| {
            Ok(roots
                .get(&root.transaction_id)
                .cloned()
                .expect("test root must be present"))
        })
        .expect("derive candidates")
    }

    #[test]
    fn deleted_only_root_returns_all_released_objects() {
        let released = summary(10, 7);
        let current = summary(20, 8);
        let input = DeadlistDerivationInput::new(
            DeadlistReleasedRoot::snapshot_or_clone(released.clone()),
            vec![DeadlistLiveRoot::current_committed(current.clone())],
        );
        let roots = BTreeMap::from([
            (released.transaction_id, keys(&[1, 2])),
            (current.transaction_id, keys(&[3])),
        ]);

        let report = derive_with_roots(input, roots);

        assert_eq!(report.candidate_keys(), vec![key(1), key(2)]);
        assert_eq!(report.released_object_count, 2);
        assert_eq!(report.live_object_count, 1);
    }

    #[test]
    fn root_still_pinned_by_clone_returns_no_candidates() {
        let released = summary(10, 7);
        let shared_clone = released.clone();
        let traversal_root = snapshot_traversal_root_for_summary(&shared_clone);
        let input = DeadlistDerivationInput::new(
            DeadlistReleasedRoot::snapshot_or_clone(released.clone()),
            vec![DeadlistLiveRoot::lifecycle_pin(
                shared_clone.clone(),
                traversal_root,
            )],
        );
        let roots = BTreeMap::from([(released.transaction_id, keys(&[1, 2, 3]))]);

        let report = derive_with_roots(input, roots);

        assert!(report.candidates.is_empty());
        assert_eq!(report.released_object_count, 3);
        assert_eq!(report.live_object_count, 3);
    }

    #[test]
    fn current_root_and_pins_are_subtracted_from_released_root() {
        let released = summary(10, 7);
        let current = summary(20, 8);
        let pinned = summary(30, 6);
        let input = DeadlistDerivationInput::new(
            DeadlistReleasedRoot::snapshot_or_clone(released.clone()),
            vec![
                DeadlistLiveRoot::current_committed(current.clone()),
                DeadlistLiveRoot::lifecycle_pin(
                    pinned.clone(),
                    snapshot_traversal_root_for_summary(&pinned),
                ),
            ],
        );
        let roots = BTreeMap::from([
            (released.transaction_id, keys(&[1, 2, 3])),
            (current.transaction_id, keys(&[3, 4])),
            (pinned.transaction_id, keys(&[2, 5])),
        ]);

        let report = derive_with_roots(input, roots);

        assert_eq!(report.candidate_keys(), vec![key(1)]);
        assert_eq!(report.released_object_count, 3);
        assert_eq!(report.live_object_count, 4);
    }
}
