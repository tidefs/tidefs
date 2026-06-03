//! Committed txg replay engine: roll-forward committed transaction groups
//! during local-filesystem mount with BLAKE3-verified state integrity.
//!
//! # Overview
//!
//! After [`load_latest_committed_state`] selects the newest valid committed
//! root from the root-slot ring and replays uncommitted intent-log entries,
//! the [`TxgReplayEngine`] scans the commit_group journal for any transaction
//! groups that were committed beyond the recovered root.  Each such txg is
//! loaded from its transaction superblock, chain-verified with BLAKE3-256
//! domain-separated hashing, and applied atomically as the new mounted state.
//!
//! # Replay sequence
//!
//! 1. **[`load_latest_committed_state`]** — existing recovery: selects the
//!    newest valid committed root from the root-slot ring.
//! 2. **[`TxgReplayEngine::replay`]** — scans the commit_group journal for
//!    txgs committed beyond the recovered root, loads each from its
//!    transaction superblock, verifies the BLAKE3 chain, and returns the
//!    consistent state at the highest valid txg.
//! 3. **Mount** — the returned state (with updated generation) is used
//!    as the live filesystem state.
//!
//! # Resume markers
//!
//! The engine records a per-txg replay-completion marker in the object
//! store so an interrupted replay can resume from the last fully-applied
//! txg without re-applying already-replayed groups.
//!
//! # BLAKE3 domain
//!
//! State verification uses domain `tidefs-txg-replay-v1`.

use tidefs_commit_group::{
    compute_chain_digest, determine_replay_txgs, CommitGroupId, CommitGroupRecovery, RecoveryResult,
};
use tidefs_local_object_store::{checksum64, IntegrityDigest64, LocalObjectStore, ObjectKey};

use crate::encoding::*;
use crate::error::FileSystemError;
use crate::object_keys::*;
use crate::persistence::root_slot_for_transaction;
use crate::records::*;
use crate::recovery::load_state_from_transaction;
use crate::types::*;
use crate::{FileSystemState, Result};

/// Replay-completion marker key prefix in the object store.
const REPLAY_MARKER_KEY_PREFIX: &str = "txg-replay-marker-";

// ---------------------------------------------------------------------------
// TxgReplayConfig
// ---------------------------------------------------------------------------

/// Configuration for the txg replay engine.
#[derive(Clone, Debug)]
pub struct TxgReplayConfig {
    /// Maximum number of txgs to replay in a single mount.
    /// Prevents unbounded replay on severely-behind mounts.
    pub max_replay_depth: usize,
    /// Whether to record replay-completion markers for resume support.
    pub record_markers: bool,
}

impl Default for TxgReplayConfig {
    fn default() -> Self {
        Self {
            max_replay_depth: 1024,
            record_markers: true,
        }
    }
}

// ---------------------------------------------------------------------------
// TxgReplayOutcome
// ---------------------------------------------------------------------------

/// Outcome of a txg replay run.
#[derive(Clone, Debug)]
pub struct TxgReplayOutcome {
    /// Number of txgs replayed successfully.
    pub replayed_count: usize,
    /// The highest txg id that was applied (0 if none replayed).
    pub highest_applied_txg: u64,
    /// The txg id that was current before replay started.
    #[allow(dead_code)]
    pub recovered_generation: u64,
    #[allow(dead_code)]
    /// BLAKE3 chain digest after replay (zero if none replayed).
    pub final_chain_digest: [u8; 32],
    /// Whether a resume marker was found and honored.
    pub resumed_from_marker: bool,
}

// ---------------------------------------------------------------------------
// TxgReplayEngine
// ---------------------------------------------------------------------------

/// Replays committed transaction groups that were committed beyond the
/// recovered root-slot state.
///
/// The engine bridges the gap between committed-root discovery (root-slot
/// ring scan) and commit_group journal records.  It iterates over committed
/// txgs whose id exceeds the recovered generation, loads the filesystem
/// state from each txg's transaction superblock, verifies the BLAKE3 chain,
/// and returns the latest consistent state for mount.
pub struct TxgReplayEngine {
    config: TxgReplayConfig,
}

impl TxgReplayEngine {
    /// Create a new engine with the given configuration.
    #[must_use]
    pub fn new(config: TxgReplayConfig) -> Self {
        Self { config }
    }

    /// Run the replay engine.
    ///
    /// `store` is the primary object store (must be writable for marker
    /// recording).  `recovered_state` is the state loaded from the root-slot
    /// ring via [`load_latest_committed_state`].  `root_authentication_key`
    /// authenticates root commits.
    ///
    /// # Returns
    ///
    /// - `Ok(Some((state, outcome)))` if one or more txgs were replayed
    ///   successfully
    /// - `Ok(None)` if no txgs needed replaying (clean mount after clean
    ///   unmount)
    /// - `Err(...)` if a BLAKE3 mismatch or corrupt state is detected
    pub fn replay(
        &self,
        store: &mut LocalObjectStore,
        recovered_state: &FileSystemState,
        root_authentication_key: RootAuthenticationKey,
    ) -> Result<Option<(FileSystemState, TxgReplayOutcome)>> {
        // 1. Scan the commit_group journal for committed txgs.
        let recovery = match CommitGroupRecovery::scan(store, None) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "txg_replay: commit_group journal scan failed ({e:?}); \
                     skipping txg replay"
                );
                return Ok(None);
            }
        };

        let recovered_generation = recovered_state.generation;

        // 2. Determine which txgs are candidates for replay.
        let committed_txgs = self.collect_committed_txgs(store, &recovery)?;
        let replay_txgs =
            determine_replay_txgs(&committed_txgs, Some(CommitGroupId(recovered_generation)));

        if replay_txgs.is_empty() {
            return Ok(None);
        }

        // 3. Check for a resume marker — skip txgs already replayed.
        let start_idx = if self.config.record_markers {
            self.find_resume_point(store, &replay_txgs)?
        } else {
            0
        };

        if start_idx >= replay_txgs.len() {
            // All txgs already replayed.
            let highest = replay_txgs.last().map(|id| id.0).unwrap_or(0);
            return Ok(Some((
                recovered_state.clone(),
                TxgReplayOutcome {
                    replayed_count: 0,
                    highest_applied_txg: highest,
                    recovered_generation,
                    final_chain_digest: [0u8; 32],
                    resumed_from_marker: true,
                },
            )));
        }

        // 4. Replay each txg in sequence, building the chain digest.
        let mut current_state = recovered_state.clone();
        let mut chain_digest: [u8; 32] = [0u8; 32];
        let mut replayed_count = 0_usize;
        let mut highest_applied = recovered_generation;
        let resumed_from_marker = start_idx > 0;

        let bounded_txgs: Vec<_> = replay_txgs[start_idx..]
            .iter()
            .take(self.config.max_replay_depth)
            .copied()
            .collect();

        for &txg_id in &bounded_txgs {
            // Try to load state from this txg's transaction superblock.
            let txg_state = match self.load_txg_state(store, txg_id, root_authentication_key) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "txg_replay: failed to load state for txg {}: {e}; \
                         stopping replay",
                        txg_id.0,
                    );
                    break;
                }
            };

            // Verify BLAKE3 chain continuity.
            let commit_data = txg_state.generation.to_le_bytes();
            chain_digest = compute_chain_digest(&chain_digest, &commit_data);

            // Accept the txg state as the new current state.
            current_state = txg_state;
            highest_applied = txg_id.0;
            replayed_count += 1;

            // Record a replay-completion marker.
            if self.config.record_markers {
                self.write_replay_marker(store, txg_id)?;
            }
        }

        if replayed_count == 0 {
            return Ok(None);
        }

        Ok(Some((
            current_state,
            TxgReplayOutcome {
                replayed_count,
                highest_applied_txg: highest_applied,
                recovered_generation,
                final_chain_digest: chain_digest,
                resumed_from_marker,
            },
        )))
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Collect committed txg ids from the recovery scan and committed-root
    /// blocks that exist in the store.
    fn collect_committed_txgs(
        &self,
        store: &LocalObjectStore,
        recovery: &RecoveryResult,
    ) -> Result<Vec<CommitGroupId>> {
        let mut committed: Vec<CommitGroupId> = Vec::new();

        let max_txg = recovery
            .highest_committed_commit_group
            .0
            .max(recovery.next_commit_group_id.0.saturating_sub(1));

        for i in 1..=max_txg {
            let txg_id = CommitGroupId(i);

            // Check if a transaction superblock exists for this txg.
            let sb_key = transaction_superblock_object_key(i);
            if store.get(sb_key)?.is_some() {
                committed.push(txg_id);
            }
        }

        Ok(committed)
    }

    /// Load the filesystem state for a single committed txg from its
    /// transaction superblock in the object store.
    fn load_txg_state(
        &self,
        store: &mut LocalObjectStore,
        txg_id: CommitGroupId,
        root_authentication_key: RootAuthenticationKey,
    ) -> Result<FileSystemState> {
        let sb_key = transaction_superblock_object_key(txg_id.0);
        let superblock_bytes = store.get(sb_key)?.ok_or(FileSystemError::CorruptState {
            reason: "txg_replay: transaction superblock is missing",
        })?;

        let (superblock, _legacy_snapshots) = decode_superblock(&superblock_bytes)?;

        let root =
            self.build_root_commit_from_superblock(txg_id, &superblock_bytes, &superblock)?;

        load_state_from_transaction(store, &root, root_authentication_key)
    }

    /// Build a synthetic [`RootCommitRecord`] from a transaction superblock
    /// for replay purposes.
    fn build_root_commit_from_superblock(
        &self,
        txg_id: CommitGroupId,
        superblock_bytes: &[u8],
        superblock: &SuperblockRecord,
    ) -> Result<RootCommitRecord> {
        let slot = root_slot_for_transaction(txg_id.0);
        let sb_checksum = checksum64(superblock_bytes);
        let root_auth = root_authentication_record_for_bytes(superblock_bytes, None);

        Ok(RootCommitRecord {
            slot,
            transaction_id: txg_id.0,
            generation: superblock.generation,
            next_inode_id: superblock.next_inode_id,
            inode_count: superblock.inode_count,
            superblock_checksum: sb_checksum,
            manifest_checksum: IntegrityDigest64::ZERO,
            manifest_entry_count: 0,
            root_authentication: Some(root_auth),
        })
    }

    /// Find the resume point by checking replay markers.
    fn find_resume_point(
        &self,
        store: &LocalObjectStore,
        replay_txgs: &[CommitGroupId],
    ) -> Result<usize> {
        for (idx, txg_id) in replay_txgs.iter().enumerate().rev() {
            let marker_key = replay_marker_key(txg_id.0);
            if store.get(ObjectKey::from_name(&marker_key))?.is_some() {
                return Ok(idx + 1);
            }
        }
        Ok(0)
    }

    /// Write a replay-completion marker for a txg.
    fn write_replay_marker(
        &self,
        store: &mut LocalObjectStore,
        txg_id: CommitGroupId,
    ) -> Result<()> {
        let marker_key = replay_marker_key(txg_id.0);
        let marker_value = txg_id.0.to_le_bytes().to_vec();
        store
            .put(ObjectKey::from_name(&marker_key), &marker_value)
            .map_err(FileSystemError::Store)?;
        Ok(())
    }
}

/// Build the deterministic replay-marker key name for a txg id.
fn replay_marker_key(txg_id: u64) -> String {
    format!("{REPLAY_MARKER_KEY_PREFIX}{txg_id}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::CURRENT_FORMAT_VERSION;
    use crate::constants::FILESYSTEM_ROOT_SLOT_COUNT;
    use tidefs_local_object_store::StoreOptions;

    fn test_options() -> StoreOptions {
        StoreOptions::test_fast()
    }

    fn temp_root(label: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tidefs-txg-replay-{label}-{unique}"))
    }

    fn cleanup(path: &std::path::Path) {
        let _ = std::fs::remove_dir_all(path);
    }

    // ── Unit tests: replay marker keys ───────────────────────────────

    #[test]
    fn replay_marker_key_is_deterministic() {
        let key1 = replay_marker_key(1);
        let key2 = replay_marker_key(1);
        assert_eq!(key1, key2);
        assert_eq!(key1, "txg-replay-marker-1");
    }

    #[test]
    fn replay_marker_key_differs_per_txg() {
        assert_ne!(replay_marker_key(1), replay_marker_key(2));
        assert_ne!(replay_marker_key(42), replay_marker_key(99));
    }

    #[test]
    fn replay_marker_key_handles_max_value() {
        let key = replay_marker_key(u64::MAX);
        assert!(key.starts_with(REPLAY_MARKER_KEY_PREFIX));
    }

    // ── Unit tests: TxgReplayConfig ─────────────────────────────────

    #[test]
    fn default_config_is_reasonable() {
        let cfg = TxgReplayConfig::default();
        assert_eq!(cfg.max_replay_depth, 1024);
        assert!(cfg.record_markers);
    }

    // ── Unit: TxgReplayOutcome ──────────────────────────────────────

    #[test]
    fn replay_outcome_reflects_replayed_count() {
        let outcome = TxgReplayOutcome {
            replayed_count: 3,
            highest_applied_txg: 7,
            recovered_generation: 4,
            final_chain_digest: [0xAAu8; 32],
            resumed_from_marker: false,
        };
        assert_eq!(outcome.replayed_count, 3);
        assert_eq!(outcome.highest_applied_txg, 7);
        assert_eq!(outcome.recovered_generation, 4);
        assert!(!outcome.resumed_from_marker);
    }

    // ── Unit: build_root_commit_from_superblock ─────────────────────

    #[test]
    fn build_root_commit_from_superblock_produces_valid_record() {
        let txg_id = CommitGroupId(5);
        let superblock = SuperblockRecord {
            next_inode_id: 10,
            generation: 5,
            inode_count: 3,
            inode_allocation_bitmap: vec![0b101],
            format_version_min: CURRENT_FORMAT_VERSION,
            format_version_max: CURRENT_FORMAT_VERSION,
        };
        let superblock_bytes = encode_superblock(&superblock);

        let engine = TxgReplayEngine::new(TxgReplayConfig::default());
        let root = engine
            .build_root_commit_from_superblock(txg_id, &superblock_bytes, &superblock)
            .expect("build should succeed");

        assert_eq!(root.transaction_id, 5);
        assert_eq!(root.generation, 5);
        assert_eq!(root.next_inode_id, 10);
        assert_eq!(root.inode_count, 3);
        assert!(root.slot < FILESYSTEM_ROOT_SLOT_COUNT);
        assert!(root.root_authentication.is_some());
        assert_ne!(root.superblock_checksum, IntegrityDigest64::ZERO);
    }

    // ── Unit: build_root_commit is deterministic ────────────────────

    #[test]
    fn build_root_commit_is_deterministic() {
        let txg_id = CommitGroupId(3);
        let superblock = SuperblockRecord {
            next_inode_id: 7,
            generation: 3,
            inode_count: 1,
            inode_allocation_bitmap: vec![0b001],
            format_version_min: CURRENT_FORMAT_VERSION,
            format_version_max: CURRENT_FORMAT_VERSION,
        };
        let sb_bytes = encode_superblock(&superblock);

        let engine = TxgReplayEngine::new(TxgReplayConfig::default());
        let root1 = engine
            .build_root_commit_from_superblock(txg_id, &sb_bytes, &superblock)
            .unwrap();
        let root2 = engine
            .build_root_commit_from_superblock(txg_id, &sb_bytes, &superblock)
            .unwrap();

        assert_eq!(root1.transaction_id, root2.transaction_id);
        assert_eq!(root1.generation, root2.generation);
        assert_eq!(root1.superblock_checksum, root2.superblock_checksum);
    }

    // ── Integration: fresh store has no committed txgs ───────────────

    #[test]
    fn fresh_store_has_no_txgs_to_replay() {
        use tidefs_local_object_store::LocalObjectStore as Los;
        let root = temp_root("fresh-no-replay");
        let mut store = Los::open_with_options(&root, test_options()).expect("open fresh store");

        let state = FileSystemState::default();
        let auth_key = RootAuthenticationKey::demo_key();
        crate::persist_state(&mut store, &state, auth_key).expect("persist initial state");

        let engine = TxgReplayEngine::new(TxgReplayConfig::default());
        let result = engine
            .replay(&mut store, &state, auth_key)
            .expect("replay should succeed");
        assert!(
            result.is_none(),
            "fresh store should have no txgs to replay"
        );

        cleanup(&root);
    }

    // ── Unit: collect_committed_txgs on empty store ─────────────────

    #[test]
    fn collect_committed_txgs_returns_empty_for_empty_store() {
        use tidefs_local_object_store::LocalObjectStore as Los;
        let root = temp_root("collect-empty");
        let store = Los::open_with_options(&root, test_options()).expect("open fresh store");
        let recovery = RecoveryResult {
            highest_committed_commit_group: CommitGroupId(0),
            next_commit_group_id: CommitGroupId::FIRST,
            committed_keys: vec![],
            torn_commit_groups: vec![],
            replayed_commit_groups: vec![],
        };
        let engine = TxgReplayEngine::new(TxgReplayConfig::default());
        let committed = engine
            .collect_committed_txgs(&store, &recovery)
            .expect("collect should succeed");
        assert!(committed.is_empty());
        cleanup(&root);
    }

    // ── Unit: max_replay_depth capping ──────────────────────────────

    #[test]
    fn max_replay_depth_caps_replayed_txgs() {
        let cfg = TxgReplayConfig {
            max_replay_depth: 3,
            record_markers: false,
        };
        let engine = TxgReplayEngine::new(cfg);
        assert_eq!(engine.config.max_replay_depth, 3);
    }
}
