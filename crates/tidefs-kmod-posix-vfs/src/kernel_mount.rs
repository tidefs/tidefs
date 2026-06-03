//! Kernel-side mount initialization sequence.
//!
//! Orchestrates the full no-daemon mount(2) path by chaining:
//!
//! 1. [`PoolImportContext`] — scans the block device's label buffer,
//!    validates the TideFS pool label, and locates the superblock region.
//! 2. [`MountRootSelector`] — reads the committed-root ledger from the
//!    superblock region, validates each candidate, and selects the most
//!    recent valid committed root.
//! 3. [`KernelIntentReplay`] — replays intent-log records from the
//!    selected committed root forward through VfsEngine.
//!
//! After this sequence completes, the mounted namespace is crash-consistent
//! and ready for normal VFS operations. No userspace daemon, helper, or
//! upcall is required at any point.
//!
//! # Error handling during mount
//!
//! If intent-log replay fails (corrupt log, engine I/O error, or dispatch
//! failure), the mount is refused with [`MountSequenceError::Replay`] which
//! maps to `EIO`. The kernel log receives a ratelimited warning via the
//! caller's logging path. An operator diagnosing a refused mount should
//! inspect the kernel log for the replay error detail.
//!
//! When `recovery_mode` is disabled or no intent records are provided, replay
//! is skipped silently and the namespace reflects the committed-root state
//! as-is. This is the normal path for read-only mounts and clean exports.
//!
//! # No-daemon boundary
//!
//! All three phases execute entirely in kernel context through the
//! kmod-bridge substrate. The only external inputs are the raw device
//! label buffer and superblock region buffer — both obtained via the
//! kernel's block-device read path during mount(2).

use crate::TideString as String;
use core::fmt;

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use tidefs_kmod_bridge::kernel_types::RequestCtx;
use tidefs_kmod_bridge::kernel_types::{VfsEngine, VfsEngineStatFs};

use crate::intent_replay::{KernelIntentReplay, ReplayError, ReplayOutcome};
use crate::mount::{
    LedgerError, MountRootSelector, PoolClusterInfo, PoolImportContext, PoolImportError,
};
use crate::mount_options::{EngineAuthorityMode, FeatureFlags, MountOptionError, TransportCarrier};
use crate::superblock::{CommittedRootAnchor, SuperblockInfo};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

// ---------------------------------------------------------------------------
// Mount sequence error
// ---------------------------------------------------------------------------

/// Errors produced during the kernel mount initialization sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountSequenceError {
    /// Pool label import failed.
    PoolImport(PoolImportError),
    /// Committed-root ledger parsing failed.
    Ledger(LedgerError),
    /// Intent-log replay failed.
    Replay(ReplayError),
    /// A requested feature is not supported by the current engine.
    FeatureRefused(MountOptionError),
    /// The superblock region buffer was empty or malformed.
    SuperblockRegionEmpty,
    /// A required mount component is missing.
    MissingComponent { detail: String },
    /// The pool label has CLUSTER_POOL_INCOMPAT set but no cluster_node_id
    /// mount option was provided.  Clustered pools require explicit
    /// cluster membership declaration.
    ClusteredPoolRefused { pool_name: String },
}

impl fmt::Display for MountSequenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PoolImport(e) => write!(f, "pool import failed: {e}"),
            Self::Ledger(e) => write!(f, "committed-root ledger error: {e}"),
            Self::Replay(e) => write!(f, "intent-log replay failed: {e}"),
            Self::FeatureRefused(e) => write!(f, "feature refused: {e}"),
            Self::SuperblockRegionEmpty => f.write_str("superblock region buffer is empty"),
            Self::MissingComponent { detail } => {
                write!(f, "missing mount component: {detail}")
            }
            Self::ClusteredPoolRefused { pool_name } => {
                write!(
                    f,
                    "clustered pool '{pool_name}' requires cluster_node_id mount option"
                )
            }
        }
    }
}

impl From<PoolImportError> for MountSequenceError {
    fn from(e: PoolImportError) -> Self {
        Self::PoolImport(e)
    }
}

impl From<MountOptionError> for MountSequenceError {
    fn from(e: MountOptionError) -> Self {
        Self::FeatureRefused(e)
    }
}

impl From<LedgerError> for MountSequenceError {
    fn from(e: LedgerError) -> Self {
        Self::Ledger(e)
    }
}

impl From<ReplayError> for MountSequenceError {
    fn from(e: ReplayError) -> Self {
        Self::Replay(e)
    }
}

// ---------------------------------------------------------------------------
// KernelMountResult
// ---------------------------------------------------------------------------

/// The result of a successful kernel mount initialization sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelMountResult {
    /// The pool name extracted from the device label.
    pub pool_name: String,
    /// The selected committed-root anchor for mount.
    pub root_anchor: CommittedRootAnchor,
    /// Superblock metadata derived during mount.
    pub superblock: SuperblockInfo,
    /// Outcome of intent-log replay.
    pub replay_outcome: ReplayOutcome,
    /// Whether the pool was cleanly exported.
    pub clean_export: bool,
    /// Cluster context from the pool label during import.
    pub cluster: PoolClusterInfo,
    /// Transport carrier disclosed for inter-node communication.
    pub transport_carrier: TransportCarrier,
    /// Inode table root locator from the committed-root VRBT block, if decoded.
    pub inode_table_root: u64,
    /// Extent map root locator from the committed-root VRBT block, if decoded.
    pub extent_map_root: u64,
    /// Intent-log head (most recent record) from the committed-root VRBT, if decoded.
    pub intent_log_head: u64,
    /// Intent-log tail (oldest replayable record) from the committed-root VRBT, if decoded.
    pub intent_log_tail: u64,
}

// ---------------------------------------------------------------------------
// KernelMountSequence
// ---------------------------------------------------------------------------

/// Executes the full kernel mount initialization sequence.
///
/// # Usage
///
/// ```ignore
/// let mut seq = KernelMountSequence::new(engine);
/// let (result, _engine) = seq.mount(&device_label_buf, &superblock_region_buf, &intent_records, &ctx)?;
/// // result.root_anchor can be used for mount validation.
/// ```
///
/// # Recovery mode
///
/// When `recovery_mode` is enabled, the sequence replays intent-log records
/// from the committed root forward. When disabled (read-only mount),
/// intent replay is skipped and the namespace reflects the committed-root
/// state as-is.
pub struct KernelMountSequence<E> {
    engine: E,
    /// Whether recovery-mode intent replay is enabled.
    recovery_mode: bool,
    /// Features supported by this engine; empty means none.
    supported_features: FeatureFlags,
    /// Engine authority mode for mixed-mode disclosure.
    authority_mode: EngineAuthorityMode,
    /// Cluster node identity for clustered pool mounts.
    cluster_node_id: String,
    /// Transport carrier for inter-node communication disclosure.
    transport_carrier: TransportCarrier,
}

impl<E: VfsEngine + VfsEngineStatFs> KernelMountSequence<E> {
    /// Create a new mount sequence wrapping a VfsEngine.
    ///
    /// `recovery_mode` enables intent-log replay from the committed root
    /// forward. Set to `false` for read-only mounts.
    pub fn new(engine: E, recovery_mode: bool) -> Self {
        Self {
            engine,
            supported_features: FeatureFlags::NONE,
            authority_mode: EngineAuthorityMode::Unspecified,
            cluster_node_id: String::new(),
            transport_carrier: TransportCarrier::None,
            recovery_mode,
        }
    }

    /// Declare the features supported by this engine.
    ///
    /// Features not in this set that are requested via mount options
    /// will cause [`MountSequenceError::FeatureRefused`] during mount.
    pub fn with_supported_features(mut self, features: FeatureFlags) -> Self {
        self.supported_features = features;
        self
    }

    /// Declare the cluster node identity for clustered pool mounts.
    pub fn with_cluster_node_id(mut self, node_id: String) -> Self {
        self.cluster_node_id = node_id;
        self
    }

    /// Declare the transport carrier for inter-node communication disclosure.
    pub fn with_transport_carrier(mut self, carrier: TransportCarrier) -> Self {
        self.transport_carrier = carrier;
        self
    }

    /// Declare the engine authority mode for mixed-mode disclosure.
    pub fn with_authority_mode(mut self, mode: EngineAuthorityMode) -> Self {
        self.authority_mode = mode;
        self
    }

    /// Return the current engine authority mode.
    pub fn authority_mode(&self) -> EngineAuthorityMode {
        self.authority_mode
    }

    /// Verify requested features against the engine's supported set.
    pub fn refuse_unsupported(
        &self,
        options: &crate::mount_options::MountOptions,
    ) -> Result<(), MountSequenceError> {
        options
            .refuse_unsupported_features(self.supported_features)
            .map_err(MountSequenceError::from)
    }

    /// Execute the full mount initialization sequence.
    ///
    /// # Arguments
    ///
    /// - `device_label_buf`: Raw bytes from the device label region
    ///   (at least `POOL_LABEL_SIZE` bytes, typically 256 KiB).
    /// - `superblock_region_buf`: Raw bytes from the superblock region
    ///   (located via `system_area_pointer` in the pool label).
    /// - `intent_records`: Encoded intent-log records to replay (may be
    ///   empty if no intent log exists or recovery_mode is disabled).
    /// - `ctx`: Request context for permission checks during replay.
    pub fn mount(
        self,
        device_label_buf: &[u8],
        superblock_region_buf: &[u8],
        intent_records: &[&[u8]],
        ctx: &RequestCtx,
    ) -> Result<(KernelMountResult, E), MountSequenceError> {
        // Phase 1: Import pool label.
        let pool_ctx = PoolImportContext::import_full(device_label_buf, 0)?;

        // Phase 1b: Refuse clustered pools opened without cluster membership.
        if pool_ctx.cluster.mode == crate::mount::ClusterMode::ClusteredIncompat
            && self.cluster_node_id.is_empty()
        {
            return Err(MountSequenceError::ClusteredPoolRefused {
                pool_name: pool_ctx.pool_name.clone(),
            });
        }

        // Phase 2: Select committed root from the ledger.
        if superblock_region_buf.is_empty() {
            return Err(MountSequenceError::SuperblockRegionEmpty);
        }
        let root_anchor = MountRootSelector::select_root(superblock_region_buf)?;

        // Phase 2b: Decode the committed-root VRBT block from the superblock
        // region to obtain canonical inode-table, extent-map, and intent-log
        // authority pointers.  The VRBT is at offset 3 * block_size within the
        // superblock region (after VCRL at offset 0, VCRP primary at offset
        // block_size, VCRP backup at offset 2*block_size).
        let (inode_table_root, extent_map_root, intent_log_head, intent_log_tail) =
            Self::try_decode_vrbt_from_region(superblock_region_buf, pool_ctx.superblock_size);

        // Phase 3: Build superblock metadata.
        // Derive a SuperblockInfo from the pool label context.
        // The label's pool_guid forms the UUID; magic is the first 8 bytes.
        let mut sb_uuid = [0u8; 32];
        sb_uuid[0..16].copy_from_slice(pool_ctx.pool_guid());
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&sb_uuid[0..8]);
        let superblock = SuperblockInfo {
            magic,
            uuid: sb_uuid,
            block_size: pool_ctx.superblock_size as u32,
            committed_txg: root_anchor.txg,
        };

        // Move engine into a local so it can be recovered after replay.
        let engine = self.engine;

        // Phase 4: Replay intent log (if recovery mode is enabled).
        let (replay_outcome, engine) = if self.recovery_mode && !intent_records.is_empty() {
            let mut replayer = KernelIntentReplay::new(engine, root_anchor.txg);
            replayer.replay_records(intent_records, ctx)?;
            let outcome = replayer.outcome.clone();
            let engine = replayer.into_engine();
            (outcome, engine)
        } else {
            (
                ReplayOutcome {
                    replayed: 0,
                    skipped: 0,
                    errored: 0,
                },
                engine,
            )
        };

        Ok((
            KernelMountResult {
                pool_name: pool_ctx.pool_name.clone(),
                root_anchor,
                superblock,
                replay_outcome,
                clean_export: pool_ctx.is_clean_export(),
                cluster: pool_ctx.cluster.clone(),
                transport_carrier: self.transport_carrier,
                inode_table_root,
                extent_map_root,
                intent_log_head,
                intent_log_tail,
            },
            engine,
        ))
    }

    /// Try to decode the VRBT committed-root block from the superblock region.
    ///
    /// The VRBT sits at offset `3 * block_size` within the superblock region
    /// (VCRL at 0, VCRP at block_size, VCRP backup at 2*block_size).
    /// Returns (inode_table_root, extent_map_root, intent_log_head, intent_log_tail).
    /// Falls back to zeros when the VRBT is absent or the region is too small.
    fn try_decode_vrbt_from_region(
        superblock_region_buf: &[u8],
        superblock_size: u64,
    ) -> (u64, u64, u64, u64) {
        use crate::replay_integration;
        // VRBT offset within superblock: the ledger (VCRL) is at offset 0,
        // VCRP records follow, VRBT is at 3 * block_size.  We try at a
        // conservative offset of superblock_size.saturating_sub(4096) when
        // the exact block_size is not yet available from the pool label.
        let block_size: u64 = if superblock_size > 4096 { 4096 } else { 512 };
        let vrbt_offset: usize = (3u64.saturating_mul(block_size)) as usize;
        let vrbt_end = vrbt_offset.saturating_add(replay_integration::VRBT_WIRE_SIZE);
        if superblock_region_buf.len() >= vrbt_end {
            if let Ok(vrbt) =
                replay_integration::decode_vrbt(&superblock_region_buf[vrbt_offset..vrbt_end])
            {
                return (
                    vrbt.inode_table_root,
                    vrbt.extent_map_root,
                    vrbt.intent_log_head,
                    vrbt.intent_log_tail,
                );
            }
        }
        (0, 0, 0, 0)
    }

    /// Return a reference to the underlying engine.
    pub fn engine(&self) -> &E {
        &self.engine
    }

    /// Return whether recovery mode is enabled.
    pub fn is_recovery_mode(&self) -> bool {
        self.recovery_mode
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount::MountRootSelector;
    use crate::superblock::CommittedRootAnchor;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use crate::TideVec as Vec;
    use alloc::vec; // Kbuild: use crate::TideVec;
    use tidefs_kmod_bridge::kernel_types::{Errno, InodeAttr, InodeId, StatFs};
    use tidefs_types_pool_label_core::{
        encode_label, seal_label, PoolLabelV1, PoolState, POOL_LABEL_SIZE,
        POOL_LABEL_V1_EXT_WIRE_SIZE,
    };

    fn make_label_buf(state: PoolState, commit_group: u64) -> Vec<u8> {
        let mut label = PoolLabelV1::new([0xAA; 16], [0xBB; 16], "testpool");
        label.pool_state = state;
        label.commit_group = commit_group;
        label.label_commit_group = commit_group;
        label.device_index = 0;
        label.device_count = 1;
        label.topology_generation = 1;
        label.device_capacity_bytes = 1024 * 1024 * 1024;
        label.system_area_pointer = POOL_LABEL_SIZE as u64;
        label.system_area_size = 4096 * 64;
        let label = seal_label(label).unwrap();
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&label, &mut buf).unwrap();
        buf.to_vec()
    }

    fn make_ledger(anchors: &[CommittedRootAnchor]) -> Vec<u8> {
        MountRootSelector::encode_ledger(anchors)
    }

    fn make_intent_create(parent: u64, name: &[u8], mode: u32, ino: u64) -> Vec<u8> {
        let mut buf = vec![4u8]; // DISC_CREATE
        buf.extend_from_slice(&parent.to_le_bytes());
        buf.push(name.len().min(255) as u8);
        buf.extend_from_slice(&name[..name.len().min(255)]);
        buf.extend_from_slice(&mode.to_le_bytes());
        buf.extend_from_slice(&ino.to_le_bytes());
        buf
    }

    fn build_engine() -> MockEngine {
        let mut e = MockEngine::new();
        e.root_ino = InodeId::new(1);
        let ra = MockEngine::dir_attr(1);
        e.getattr_fn = Box::new(move |ino, _, _| {
            if ino == InodeId::new(1) {
                Ok(ra)
            } else {
                Err(Errno::ENOENT)
            }
        });
        e.statfs_fn = Box::new(|_| {
            Ok(StatFs::new(
                4096, 4096, 1000, 500, 500, 100, 50, 255, 0x12345678, 0x9ABCDEF0,
            ))
        });
        e.create_fn = Box::new(|_, _, _, _, _| {
            Ok((
                InodeAttr {
                    inode_id: InodeId::new(42),
                    ..Default::default()
                },
                tidefs_kmod_bridge::kernel_types::EngineFileHandle::default(),
            ))
        });
        e.unlink_fn = Box::new(|_, _, _| Ok(()));
        e.mkdir_fn = Box::new(|_, _, _, _| {
            Ok(InodeAttr {
                inode_id: InodeId::new(50),
                ..Default::default()
            })
        });
        e.rmdir_fn = Box::new(|_, _, _| Ok(()));
        e.rename_fn = Box::new(|_, _, _, _, _, _| Ok(()));
        e.setattr_fn = Box::new(|_, _, _, _| {
            Ok(InodeAttr {
                inode_id: InodeId::new(1),
                ..Default::default()
            })
        });
        e
    }

    fn test_ctx() -> RequestCtx {
        MockEngine::test_ctx()
    }

    // ── Full mount sequence tests ─────────────────────────────────────

    #[test]
    fn full_mount_sequence_succeeds() {
        let engine = build_engine();
        let label_buf = make_label_buf(PoolState::Active, 7);

        let anchor = CommittedRootAnchor::new(
            InodeId::new(1),
            {
                let mut u = [0u8; 32];
                u[0..16].copy_from_slice(&[0xAA; 16]);
                u
            },
            7,
        );
        let ledger_buf = make_ledger(&[anchor]);
        let intent = make_intent_create(1, b"file", 0o644, 42);

        let (result, _engine) = KernelMountSequence::new(engine, true)
            .mount(&label_buf, &ledger_buf, &[&intent], &test_ctx())
            .unwrap();

        assert_eq!(result.pool_name, "testpool");
        assert_eq!(result.root_anchor.txg, 7);
        assert_eq!(result.replay_outcome.replayed, 1);
        assert_eq!(result.replay_outcome.skipped, 0);
        assert!(!result.clean_export);
        // VRBT fields are zero when no VRBT is in the superblock region
        assert_eq!(result.inode_table_root, 0);
        assert_eq!(result.extent_map_root, 0);
    }

    #[test]
    fn mount_sequence_without_recovery_skips_replay() {
        let engine = build_engine();
        let label_buf = make_label_buf(PoolState::Active, 3);

        let anchor = CommittedRootAnchor::new(
            InodeId::new(1),
            {
                let mut u = [0u8; 32];
                u[0..16].copy_from_slice(&[0xAA; 16]);
                u
            },
            3,
        );
        let ledger_buf = make_ledger(&[anchor]);
        let intent = make_intent_create(1, b"file", 0o644, 10);

        let (result, _engine) = KernelMountSequence::new(engine, false)
            .mount(&label_buf, &ledger_buf, &[&intent], &test_ctx())
            .unwrap();

        assert_eq!(result.replay_outcome.replayed, 0);
        assert_eq!(result.replay_outcome.skipped, 0);
        // VRBT fields are zero without a VRBT in the region
        assert_eq!(result.inode_table_root, 0);
    }

    #[test]
    fn mount_destroyed_pool_rejected() {
        let engine = build_engine();
        let label_buf = make_label_buf(PoolState::Destroyed, 0);

        let anchor = CommittedRootAnchor::new(
            InodeId::new(1),
            {
                let mut u = [0u8; 32];
                u[0..16].copy_from_slice(&[0xAA; 16]);
                u
            },
            0,
        );
        let ledger_buf = make_ledger(&[anchor]);

        let result = KernelMountSequence::new(engine, false)
            .mount(&label_buf, &ledger_buf, &[], &test_ctx())
            .map(|(r, _e)| r);
        assert!(result.is_err());
        match result.unwrap_err() {
            MountSequenceError::PoolImport(PoolImportError::PoolNotImportable { .. }) => {}
            other => panic!("expected PoolNotImportable, got {other:?}"),
        }
    }

    #[test]
    fn mount_empty_superblock_region_rejected() {
        let engine = build_engine();
        let label_buf = make_label_buf(PoolState::Active, 1);

        let result = KernelMountSequence::new(engine, false)
            .mount(&label_buf, &[], &[], &test_ctx())
            .map(|(r, _e)| r);
        assert!(result.is_err());
        match result.unwrap_err() {
            MountSequenceError::SuperblockRegionEmpty => {}
            other => panic!("expected SuperblockRegionEmpty, got {other:?}"),
        }
    }

    #[test]
    fn mount_sequence_error_display() {
        let e = MountSequenceError::SuperblockRegionEmpty;
        assert!(alloc::format!("{e}").contains("superblock"));
        let e = MountSequenceError::MissingComponent {
            detail: String::from("ledger"),
        };
        assert!(alloc::format!("{e}").contains("ledger"));
    }

    #[test]
    fn mount_sequence_from_pool_import_error() {
        let e = PoolImportError::BadMagic;
        let mse: MountSequenceError = e.into();
        assert!(matches!(mse, MountSequenceError::PoolImport(_)));
    }

    #[test]
    fn kernel_mount_result_fields() {
        let anchor = CommittedRootAnchor::new(InodeId::new(10), [0xCC; 32], 5);
        let sb = SuperblockInfo {
            magic: [0xAA; 8],
            uuid: [0xBB; 32],
            block_size: 4096,
            committed_txg: 5,
        };
        let replay = ReplayOutcome {
            replayed: 3,
            skipped: 1,
            errored: 0,
        };
        let result = KernelMountResult {
            pool_name: String::from("mypool"),
            root_anchor: anchor.clone(),
            superblock: sb,
            replay_outcome: replay,
            clean_export: true,
            inode_table_root: 0,
            extent_map_root: 0,
            intent_log_head: 0,
            intent_log_tail: 0,
            cluster: PoolClusterInfo {
                mode: crate::mount::ClusterMode::Standalone,
                pool_guid: [0xAAu8; 16],
                device_guid: [0xBBu8; 16],
            },
            transport_carrier: TransportCarrier::None,
        };
        assert_eq!(result.pool_name, "mypool");
        assert_eq!(result.root_anchor.txg, 5);
        assert_eq!(result.replay_outcome.total(), 4);
        assert!(result.clean_export);
        assert_eq!(result.inode_table_root, 0);
    }

    #[test]
    fn kernel_mount_sequence_new_stores_recovery_mode() {
        let engine = build_engine();
        let seq = KernelMountSequence::new(engine, true);
        assert!(seq.is_recovery_mode());

        let engine2 = build_engine();
        let seq2 = KernelMountSequence::new(engine2, false);
        assert!(!seq2.is_recovery_mode());
    }
}
