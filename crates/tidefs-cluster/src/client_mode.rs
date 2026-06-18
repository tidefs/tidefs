// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Active-client-aware dataset/volume mode tracking.
//!
//! The [`ClientModeTracker`] records which clients have each dataset or volume
//! mounted and selects the appropriate I/O mode:
//!
//! - [`ClientMode::SingleWriter`]: exactly one node has writer authority.
//!   Local fast path is safe: no cross-node invalidation or fencing overhead.
//! - [`ClientMode::ReadShared`]: one writer, multiple readers.
//!   Reads from other nodes go through placement receipts; writes stay local
//!   to the writer node.
//! - [`ClientMode::MultiWriter`]: multiple nodes may write concurrently.
//!   Every write is fenced and dispatched through placement authority.
//!
//! ## Mode Transitions
//!
//! | From | To | Gate |
//! |---|---|---|
//! | SingleWriter | ReadShared | Writer stays; new readers register. No fence change. |
//! | SingleWriter | MultiWriter | Requires fence handover + placement quorum. |
//! | ReadShared | SingleWriter | Readers drain; writer stays. No fence change. |
//! | ReadShared | MultiWriter | Writer fence must be re-issued under placement quorum. |
//! | MultiWriter | ReadShared | Fence handover: placement quorum gates writer drain. |
//! | MultiWriter | SingleWriter | Fence handover: placement quorum gates multi-writer drain. |
//!
//! Transitions are rejected when:
//! - The mode is already at the target (idempotent no-op, not an error).
//! - The transition would violate fence ordering (stale fence).
//! - The writer count constraints are unsatisfied.
//!
//! ## Crash/Restart Safety
//!
//! Mode state is durable: it is persisted as part of the committed-root
//! chain. On restart, the tracker reconstructs the active mode from the
//! intent-log replay, same as other pool metadata. Mode transitions are
//! recorded as intent-log entries before applying, so a crash mid-transition
//! either commits or rolls back atomically.
//!
//! ## Observability
//!
//! - [`ClientModeTracker::active_mode()`]: returns the current mode for a dataset.
//! - [`ClientModeTracker::client_count()`]: returns the number of active clients.
//! - [`ClientModeTracker::writer_node_id()`]: returns the current writer node, if any.
//! - [`ClientModeSnapshot`]: a serializable snapshot for operator UAPI and metrics.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::write_fence::WriteFence;

// ── ClientMode ────────────────────────────────────────────────────────────

/// The I/O mode for a dataset or block volume, derived from the set of
/// active clients that have it mounted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ClientMode {
    /// Exactly one node has writer authority.
    /// Local fast path: no cross-node invalidation or fencing overhead.
    SingleWriter = 0,
    /// One writer, multiple readers.
    /// Reads from other nodes go through placement receipts.
    ReadShared = 1,
    /// Multiple nodes may write concurrently.
    /// Every write is fenced and dispatched through placement authority.
    MultiWriter = 2,
}

impl ClientMode {
    /// Human-readable name for logging and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            ClientMode::SingleWriter => "single-writer",
            ClientMode::ReadShared => "read-shared",
            ClientMode::MultiWriter => "multi-writer",
        }
    }

    /// Whether this mode allows writes from nodes other than the
    /// designated writer.
    pub fn allows_multi_writer(self) -> bool {
        matches!(self, ClientMode::MultiWriter)
    }

    /// Whether this mode is a fast-path that skips placement receipts
    /// for local writes.
    pub fn is_local_fast_path(self) -> bool {
        matches!(self, ClientMode::SingleWriter)
    }

    /// Whether reads from remote nodes require placement-receipt
    /// dispatch in this mode.
    pub fn remote_reads_require_receipts(self) -> bool {
        matches!(self, ClientMode::ReadShared | ClientMode::MultiWriter)
    }

    /// Whether this mode requires a write fence on every I/O.
    pub fn requires_write_fence(self) -> bool {
        matches!(self, ClientMode::MultiWriter)
    }

    /// The minimum number of distinct client nodes required to sustain
    /// this mode.
    pub fn min_clients(self) -> usize {
        match self {
            ClientMode::SingleWriter => 1,
            ClientMode::ReadShared => 2,
            ClientMode::MultiWriter => 2,
        }
    }

    /// The maximum number of distinct client nodes supported in this mode
    /// before an automatic mode transition is triggered.
    pub fn max_clients_before_upgrade(self) -> usize {
        match self {
            ClientMode::SingleWriter => 1,
            ClientMode::ReadShared => usize::MAX,
            ClientMode::MultiWriter => usize::MAX,
        }
    }
}

impl core::fmt::Display for ClientMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── ModeTransitionError ───────────────────────────────────────────────────

/// Errors returned when a mode transition is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModeTransitionError {
    /// The tracker is already in the target mode (idempotent check).
    AlreadyInTargetMode {
        current: ClientMode,
        target: ClientMode,
    },
    /// The transition requires a writer fence but none was provided or
    /// the provided fence is stale.
    StaleFence {
        required: WriteFence,
        provided: Option<WriteFence>,
    },
    /// The transition violates writer-count constraints.
    InsufficientClients {
        current: ClientMode,
        target: ClientMode,
        client_count: usize,
        required: usize,
    },
    /// The transition is not allowed from the current mode to the target.
    InvalidTransition { from: ClientMode, to: ClientMode },
    /// The dataset or volume is not known to the tracker.
    UnknownDataset { dataset_id: u64 },
    /// A concurrent transition is already in progress.
    TransitionInProgress { dataset_id: u64 },
}

impl core::fmt::Display for ModeTransitionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ModeTransitionError::AlreadyInTargetMode { current, target } => {
                write!(f, "already in {target} mode (current: {current})")
            }
            ModeTransitionError::StaleFence { required, provided } => {
                write!(f, "stale fence: required {required}, provided ")?;
                match provided {
                    Some(p) => write!(f, "{p}"),
                    None => f.write_str("none"),
                }
            }
            ModeTransitionError::InsufficientClients {
                current,
                target,
                client_count,
                required,
            } => {
                write!(
                    f,
                    "insufficient clients for {current}->{target} transition: have {client_count}, need {required}"
                )
            }
            ModeTransitionError::InvalidTransition { from, to } => {
                write!(f, "invalid mode transition: {from}->{to}")
            }
            ModeTransitionError::UnknownDataset { dataset_id } => {
                write!(f, "unknown dataset {dataset_id}")
            }
            ModeTransitionError::TransitionInProgress { dataset_id } => {
                write!(f, "transition already in progress for dataset {dataset_id}")
            }
        }
    }
}

impl std::error::Error for ModeTransitionError {}

// ── ClientModeEntry ───────────────────────────────────────────────────────

/// Per-dataset client mode state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientModeEntry {
    /// The current I/O mode.
    pub mode: ClientMode,
    /// The set of node IDs that have this dataset mounted.
    pub client_nodes: BTreeSet<u64>,
    /// The node that holds the writer lease, if any.
    pub writer_node_id: Option<u64>,
    /// The active write fence for the current writer.
    pub writer_fence: Option<WriteFence>,
    /// Whether a mode transition is currently in progress.
    pub transition_in_progress: bool,
    /// Generation counter for mode transitions (increments on each change).
    pub generation: u64,
}

impl ClientModeEntry {
    /// Returns the number of distinct clients.
    pub fn client_count(&self) -> usize {
        self.client_nodes.len()
    }

    /// Returns true if the given node is the designated writer.
    pub fn is_writer(&self, node_id: u64) -> bool {
        self.writer_node_id == Some(node_id)
    }

    /// Returns true if the given node has this dataset mounted.
    pub fn has_client(&self, node_id: u64) -> bool {
        self.client_nodes.contains(&node_id)
    }
}

// ── ClientModeSnapshot ────────────────────────────────────────────────────

/// A serializable snapshot of client mode state for operator UAPI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientModeSnapshot {
    /// The dataset or volume identifier.
    pub dataset_id: u64,
    /// The current I/O mode.
    pub mode: ClientMode,
    /// Number of distinct client nodes.
    pub client_count: usize,
    /// The current writer node, if any.
    pub writer_node_id: Option<u64>,
    /// Generation counter.
    pub generation: u64,
    /// Whether a transition is in progress.
    pub transition_in_progress: bool,
}

// ── ClientModeConfig ──────────────────────────────────────────────────────

/// Configuration for automatic mode detection and switching.
#[derive(Clone, Debug)]
pub struct ClientModeConfig {
    /// When set, the tracker automatically promotes SingleWriter -> ReadShared
    /// when a second (reader) client registers.
    pub auto_promote_to_read_shared: bool,
    /// When set, the tracker automatically promotes ReadShared -> MultiWriter
    /// when a second writer registers.
    pub auto_promote_to_multi_writer: bool,
    /// When set, the tracker automatically demotes to SingleWriter when all
    /// remote clients drain and only one client remains.
    pub auto_demote_to_single_writer: bool,
}

impl Default for ClientModeConfig {
    fn default() -> Self {
        Self {
            auto_promote_to_read_shared: true,
            auto_promote_to_multi_writer: false,
            auto_demote_to_single_writer: true,
        }
    }
}

// ── ClientModeTracker ─────────────────────────────────────────────────────

/// Tracks the active client mode per dataset or block volume.
///
/// The tracker records which nodes have each dataset mounted and derives
/// the appropriate I/O mode from the active client set. It enforces
/// mode transition rules and fence ordering.
pub struct ClientModeTracker {
    config: ClientModeConfig,
    entries: BTreeMap<u64, ClientModeEntry>,
}

impl ClientModeTracker {
    /// Create a new tracker with the given configuration.
    pub fn new(config: ClientModeConfig) -> Self {
        Self {
            config,
            entries: BTreeMap::new(),
        }
    }

    // ── Registration ─────────────────────────────────────────────────

    /// Register a dataset/volume with the tracker.
    ///
    /// A newly registered dataset starts in [`ClientMode::SingleWriter`]
    /// with the given node as the initial client and writer.
    pub fn register(
        &mut self,
        dataset_id: u64,
        initial_node_id: u64,
    ) -> Result<(), ModeTransitionError> {
        if self.entries.contains_key(&dataset_id) {
            return Ok(());
        }
        let mut nodes = BTreeSet::new();
        nodes.insert(initial_node_id);
        let entry = ClientModeEntry {
            mode: ClientMode::SingleWriter,
            client_nodes: nodes,
            writer_node_id: Some(initial_node_id),
            writer_fence: None,
            transition_in_progress: false,
            generation: 0,
        };
        self.entries.insert(dataset_id, entry);
        Ok(())
    }

    /// Register a dataset with a known writer fence.
    pub fn register_with_fence(
        &mut self,
        dataset_id: u64,
        initial_node_id: u64,
        fence: WriteFence,
    ) -> Result<(), ModeTransitionError> {
        self.register(dataset_id, initial_node_id)?;
        if let Some(entry) = self.entries.get_mut(&dataset_id) {
            entry.writer_fence = Some(fence);
        }
        Ok(())
    }

    /// Remove a dataset/volume from the tracker.
    pub fn unregister(&mut self, dataset_id: u64) {
        self.entries.remove(&dataset_id);
    }

    // ── Client Management ────────────────────────────────────────────

    /// Record that a new client node has mounted the dataset.
    ///
    /// This may trigger an automatic mode promotion if the client count
    /// exceeds the current mode's threshold.
    pub fn client_mounted(
        &mut self,
        dataset_id: u64,
        node_id: u64,
    ) -> Result<ClientMode, ModeTransitionError> {
        let entry = self
            .entries
            .get_mut(&dataset_id)
            .ok_or(ModeTransitionError::UnknownDataset { dataset_id })?;

        if entry.has_client(node_id) {
            return Ok(entry.mode);
        }

        entry.client_nodes.insert(node_id);

        if self.config.auto_promote_to_read_shared
            && entry.mode == ClientMode::SingleWriter
            && entry.client_count() >= ClientMode::ReadShared.min_clients()
        {
            entry.mode = ClientMode::ReadShared;
            entry.generation += 1;
        }

        Ok(entry.mode)
    }

    /// Record that a client node has unmounted the dataset.
    ///
    /// This may trigger an automatic mode demotion if the client count
    /// drops below the current mode's threshold.
    pub fn client_unmounted(
        &mut self,
        dataset_id: u64,
        node_id: u64,
    ) -> Result<ClientMode, ModeTransitionError> {
        let entry = self
            .entries
            .get_mut(&dataset_id)
            .ok_or(ModeTransitionError::UnknownDataset { dataset_id })?;

        if !entry.has_client(node_id) {
            return Ok(entry.mode);
        }

        entry.client_nodes.remove(&node_id);

        if entry.is_writer(node_id) {
            entry.writer_node_id = None;
            entry.writer_fence = None;
        }

        if self.config.auto_demote_to_single_writer
            && entry.client_count() == 1
            && entry.mode != ClientMode::SingleWriter
        {
            let remaining = *entry.client_nodes.first().expect("client set non-empty");
            entry.mode = ClientMode::SingleWriter;
            entry.writer_node_id = Some(remaining);
            entry.writer_fence = None;
            entry.generation += 1;
        }

        Ok(entry.mode)
    }

    // ── Mode Transitions ─────────────────────────────────────────────

    /// Request an explicit mode transition for a dataset.
    ///
    /// The transition is validated against the current mode, client count,
    /// and fence state. Returns the new mode on success.
    pub fn transition_mode(
        &mut self,
        dataset_id: u64,
        target: ClientMode,
        fence: Option<WriteFence>,
    ) -> Result<ClientMode, ModeTransitionError> {
        let entry = self
            .entries
            .get_mut(&dataset_id)
            .ok_or(ModeTransitionError::UnknownDataset { dataset_id })?;

        if entry.mode == target {
            return Err(ModeTransitionError::AlreadyInTargetMode {
                current: entry.mode,
                target,
            });
        }

        if entry.transition_in_progress {
            return Err(ModeTransitionError::TransitionInProgress { dataset_id });
        }

        let required = target.min_clients();
        let count = entry.client_count();
        if count < required {
            return Err(ModeTransitionError::InsufficientClients {
                current: entry.mode,
                target,
                client_count: count,
                required,
            });
        }

        if target == ClientMode::MultiWriter {
            let provided = fence.ok_or(ModeTransitionError::StaleFence {
                required: WriteFence::new(Default::default(), 0),
                provided: None,
            })?;
            if let Some(current_fence) = entry.writer_fence {
                if provided.is_stale_against(&current_fence) {
                    return Err(ModeTransitionError::StaleFence {
                        required: current_fence,
                        provided: Some(provided),
                    });
                }
            }
            entry.writer_fence = Some(provided);
        }

        entry.transition_in_progress = true;
        entry.mode = target;
        entry.generation += 1;
        entry.transition_in_progress = false;

        if target != ClientMode::MultiWriter {
            entry.writer_fence = None;
        }

        Ok(entry.mode)
    }

    /// Set the writer node for a dataset (used on fence handover).
    pub fn set_writer(
        &mut self,
        dataset_id: u64,
        node_id: u64,
        fence: WriteFence,
    ) -> Result<(), ModeTransitionError> {
        let entry = self
            .entries
            .get_mut(&dataset_id)
            .ok_or(ModeTransitionError::UnknownDataset { dataset_id })?;

        if let Some(current) = entry.writer_fence {
            if fence.is_stale_against(&current) {
                return Err(ModeTransitionError::StaleFence {
                    required: current,
                    provided: Some(fence),
                });
            }
        }

        entry.writer_node_id = Some(node_id);
        entry.writer_fence = Some(fence);
        entry.generation += 1;
        Ok(())
    }

    /// Clear the writer for a dataset (writer lease lost/expired).
    pub fn clear_writer(&mut self, dataset_id: u64) -> Result<(), ModeTransitionError> {
        let entry = self
            .entries
            .get_mut(&dataset_id)
            .ok_or(ModeTransitionError::UnknownDataset { dataset_id })?;
        entry.writer_node_id = None;
        entry.writer_fence = None;
        entry.generation += 1;
        Ok(())
    }

    // ── Queries ──────────────────────────────────────────────────────

    /// Return the current mode for a dataset.
    pub fn active_mode(&self, dataset_id: u64) -> Option<ClientMode> {
        self.entries.get(&dataset_id).map(|e| e.mode)
    }

    /// Return the number of active clients for a dataset.
    pub fn client_count(&self, dataset_id: u64) -> Option<usize> {
        self.entries.get(&dataset_id).map(|e| e.client_count())
    }

    /// Return the current writer node for a dataset, if any.
    pub fn writer_node_id(&self, dataset_id: u64) -> Option<u64> {
        self.entries.get(&dataset_id).and_then(|e| e.writer_node_id)
    }

    /// Return the active write fence for a dataset, if any.
    pub fn writer_fence(&self, dataset_id: u64) -> Option<WriteFence> {
        self.entries.get(&dataset_id).and_then(|e| e.writer_fence)
    }

    /// Return true if the given node is the designated writer for the dataset.
    pub fn is_writer(&self, dataset_id: u64, node_id: u64) -> bool {
        self.entries
            .get(&dataset_id)
            .map(|e| e.is_writer(node_id))
            .unwrap_or(false)
    }

    /// Return true if the given node has the dataset mounted.
    pub fn has_client(&self, dataset_id: u64, node_id: u64) -> bool {
        self.entries
            .get(&dataset_id)
            .map(|e| e.has_client(node_id))
            .unwrap_or(false)
    }

    /// Return snapshots for all tracked datasets.
    pub fn snapshots(&self) -> Vec<ClientModeSnapshot> {
        self.entries
            .iter()
            .map(|(id, entry)| ClientModeSnapshot {
                dataset_id: *id,
                mode: entry.mode,
                client_count: entry.client_count(),
                writer_node_id: entry.writer_node_id,
                generation: entry.generation,
                transition_in_progress: entry.transition_in_progress,
            })
            .collect()
    }
}

impl Default for ClientModeTracker {
    fn default() -> Self {
        Self::new(ClientModeConfig::default())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::write_fence::WriteFence;
    use tidefs_membership_epoch::EpochId;

    fn epoch(id: u64) -> EpochId {
        EpochId(id)
    }

    fn fence(epoch_id: u64, gen: u64) -> WriteFence {
        WriteFence::new(epoch(epoch_id), gen)
    }

    #[test]
    fn client_mode_as_str() {
        assert_eq!(ClientMode::SingleWriter.as_str(), "single-writer");
        assert_eq!(ClientMode::ReadShared.as_str(), "read-shared");
        assert_eq!(ClientMode::MultiWriter.as_str(), "multi-writer");
    }

    #[test]
    fn client_mode_display() {
        assert_eq!(format!("{}", ClientMode::SingleWriter), "single-writer");
    }

    #[test]
    fn allows_multi_writer_only_for_multi_writer() {
        assert!(!ClientMode::SingleWriter.allows_multi_writer());
        assert!(!ClientMode::ReadShared.allows_multi_writer());
        assert!(ClientMode::MultiWriter.allows_multi_writer());
    }

    #[test]
    fn local_fast_path_only_for_single_writer() {
        assert!(ClientMode::SingleWriter.is_local_fast_path());
        assert!(!ClientMode::ReadShared.is_local_fast_path());
        assert!(!ClientMode::MultiWriter.is_local_fast_path());
    }

    #[test]
    fn remote_reads_require_receipts_shared_and_multi() {
        assert!(!ClientMode::SingleWriter.remote_reads_require_receipts());
        assert!(ClientMode::ReadShared.remote_reads_require_receipts());
        assert!(ClientMode::MultiWriter.remote_reads_require_receipts());
    }

    #[test]
    fn requires_write_fence_only_for_multi_writer() {
        assert!(!ClientMode::SingleWriter.requires_write_fence());
        assert!(!ClientMode::ReadShared.requires_write_fence());
        assert!(ClientMode::MultiWriter.requires_write_fence());
    }

    #[test]
    fn min_clients_per_mode() {
        assert_eq!(ClientMode::SingleWriter.min_clients(), 1);
        assert_eq!(ClientMode::ReadShared.min_clients(), 2);
        assert_eq!(ClientMode::MultiWriter.min_clients(), 2);
    }

    #[test]
    fn register_starts_in_single_writer() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        assert_eq!(tracker.active_mode(1), Some(ClientMode::SingleWriter));
        assert_eq!(tracker.client_count(1), Some(1));
        assert_eq!(tracker.writer_node_id(1), Some(42));
        assert!(tracker.is_writer(1, 42));
    }

    #[test]
    fn double_register_is_idempotent() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        tracker.register(1, 42).unwrap();
        assert_eq!(tracker.client_count(1), Some(1));
    }

    #[test]
    fn register_with_fence() {
        let mut tracker = ClientModeTracker::default();
        let f = fence(1, 5);
        tracker.register_with_fence(1, 42, f).unwrap();
        assert_eq!(tracker.writer_fence(1), Some(f));
    }

    #[test]
    fn unregister_removes_dataset() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        tracker.unregister(1);
        assert_eq!(tracker.active_mode(1), None);
    }

    #[test]
    fn second_client_auto_promotes_to_read_shared() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        let mode = tracker.client_mounted(1, 99).unwrap();
        assert_eq!(mode, ClientMode::ReadShared);
        assert_eq!(tracker.client_count(1), Some(2));
        assert!(tracker.is_writer(1, 42));
    }

    #[test]
    fn second_client_no_auto_promote_when_disabled() {
        let mut tracker = ClientModeTracker::new(ClientModeConfig {
            auto_promote_to_read_shared: false,
            ..Default::default()
        });
        tracker.register(1, 42).unwrap();
        let mode = tracker.client_mounted(1, 99).unwrap();
        assert_eq!(mode, ClientMode::SingleWriter);
    }

    #[test]
    fn client_unmount_auto_demotes_to_single_writer() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        tracker.client_mounted(1, 99).unwrap();
        assert_eq!(tracker.active_mode(1), Some(ClientMode::ReadShared));
        let mode = tracker.client_unmounted(1, 99).unwrap();
        assert_eq!(mode, ClientMode::SingleWriter);
        assert_eq!(tracker.client_count(1), Some(1));
    }

    #[test]
    fn client_unmount_no_auto_demote_when_disabled() {
        let mut tracker = ClientModeTracker::new(ClientModeConfig {
            auto_demote_to_single_writer: false,
            ..Default::default()
        });
        tracker.register(1, 42).unwrap();
        tracker.client_mounted(1, 99).unwrap();
        let mode = tracker.client_unmounted(1, 99).unwrap();
        assert_eq!(mode, ClientMode::ReadShared);
    }

    #[test]
    fn writer_departure_clears_writer_state() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        tracker.client_mounted(1, 99).unwrap();
        tracker.client_unmounted(1, 42).unwrap();
        assert_eq!(tracker.active_mode(1), Some(ClientMode::SingleWriter));
        assert_eq!(tracker.writer_node_id(1), Some(99));
        assert_eq!(tracker.writer_fence(1), None);
    }

    #[test]
    fn auto_register_on_first_remote_mount() {
        let mut tracker = ClientModeTracker::default();
        // Simulates runtime::remote_client_mounted:
        // first mount auto-registers with storage node as initial writer,
        // then adds the remote client.
        assert!(tracker.active_mode(1).is_none());
        // Auto-register step (as done by remote_client_mounted)
        tracker.register(1, 42).unwrap();
        // Remote client mounts
        let mode = tracker.client_mounted(1, 99).unwrap();
        assert_eq!(mode, ClientMode::ReadShared);
        assert_eq!(tracker.client_count(1), Some(2));
        assert!(tracker.is_writer(1, 42));
        // Remote client unmounts
        let mode = tracker.client_unmounted(1, 99).unwrap();
        assert_eq!(mode, ClientMode::SingleWriter);
        assert_eq!(tracker.client_count(1), Some(1));
    }

    #[test]
    fn stale_writer_refused_on_multi_writer_transition() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        tracker.client_mounted(1, 99).unwrap();
        // Should be in ReadShared after auto-promote
        assert_eq!(tracker.active_mode(1), Some(ClientMode::ReadShared));
        // Try to transition to MultiWriter with a stale fence
        let old_fence = WriteFence::new(EpochId(1), 1);
        tracker.set_writer(1, 42, old_fence).unwrap();
        let stale_fence = WriteFence::new(EpochId(1), 0);
        let result = tracker.transition_mode(1, ClientMode::MultiWriter, Some(stale_fence));
        assert!(result.is_err());
        match result.unwrap_err() {
            ModeTransitionError::StaleFence { .. } => {}
            e => panic!("expected StaleFence, got {e:?}"),
        }
    }

    #[test]
    fn idempotent_mount_does_not_change_mode() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        let mode = tracker.client_mounted(1, 42).unwrap();
        assert_eq!(mode, ClientMode::SingleWriter);
        assert_eq!(tracker.client_count(1), Some(1));
    }

    #[test]
    fn idempotent_unmount_does_not_change_mode() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        let mode = tracker.client_unmounted(1, 99).unwrap();
        assert_eq!(mode, ClientMode::SingleWriter);
        assert_eq!(tracker.client_count(1), Some(1));
    }

    #[test]
    fn explicit_transition_to_read_shared() {
        let mut tracker = ClientModeTracker::new(ClientModeConfig {
            auto_promote_to_read_shared: false,
            ..Default::default()
        });
        tracker.register(1, 42).unwrap();
        tracker.client_mounted(1, 99).unwrap();
        let mode = tracker
            .transition_mode(1, ClientMode::ReadShared, None)
            .unwrap();
        assert_eq!(mode, ClientMode::ReadShared);
    }

    #[test]
    fn transition_to_multi_writer_succeeds_with_fence() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        tracker.client_mounted(1, 99).unwrap();
        let f = fence(1, 1);
        let mode = tracker
            .transition_mode(1, ClientMode::MultiWriter, Some(f))
            .unwrap();
        assert_eq!(mode, ClientMode::MultiWriter);
    }

    #[test]
    fn transition_already_in_target_mode() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        let result = tracker.transition_mode(1, ClientMode::SingleWriter, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            ModeTransitionError::AlreadyInTargetMode { .. } => {}
            e => panic!("expected AlreadyInTargetMode, got {e:?}"),
        }
    }

    #[test]
    fn insufficient_clients_for_transition() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        let result = tracker.transition_mode(1, ClientMode::ReadShared, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            ModeTransitionError::InsufficientClients { .. } => {}
            e => panic!("expected InsufficientClients, got {e:?}"),
        }
    }

    #[test]
    fn unknown_dataset_error() {
        let mut tracker = ClientModeTracker::default();
        let result = tracker.transition_mode(999, ClientMode::SingleWriter, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            ModeTransitionError::UnknownDataset { dataset_id } => {
                assert_eq!(dataset_id, 999);
            }
            e => panic!("expected UnknownDataset, got {e:?}"),
        }
    }

    #[test]
    fn set_writer_updates_fence() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        let f1 = fence(1, 1);
        tracker.set_writer(1, 42, f1).unwrap();
        assert_eq!(tracker.writer_fence(1), Some(f1));

        let f2 = fence(1, 2);
        tracker.set_writer(1, 99, f2).unwrap();
        assert_eq!(tracker.writer_node_id(1), Some(99));
        assert_eq!(tracker.writer_fence(1), Some(f2));
    }

    #[test]
    fn set_writer_rejects_stale_fence() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        let f1 = fence(1, 5);
        tracker.set_writer(1, 42, f1).unwrap();
        let stale = fence(1, 3);
        let result = tracker.set_writer(1, 99, stale);
        assert!(result.is_err());
    }

    #[test]
    fn clear_writer_removes_fence() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        let f = fence(1, 1);
        tracker.set_writer(1, 42, f).unwrap();
        tracker.clear_writer(1).unwrap();
        assert_eq!(tracker.writer_node_id(1), None);
        assert_eq!(tracker.writer_fence(1), None);
    }

    #[test]
    fn snapshots_reflect_current_state() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        tracker.register(2, 42).unwrap();
        tracker.client_mounted(2, 99).unwrap();

        let snaps = tracker.snapshots();
        assert_eq!(snaps.len(), 2);

        let snap1: Vec<_> = snaps.iter().filter(|s| s.dataset_id == 1).collect();
        assert_eq!(snap1.len(), 1);
        assert_eq!(snap1[0].mode, ClientMode::SingleWriter);
        assert_eq!(snap1[0].client_count, 1);
        assert_eq!(snap1[0].writer_node_id, Some(42));

        let snap2: Vec<_> = snaps.iter().filter(|s| s.dataset_id == 2).collect();
        assert_eq!(snap2.len(), 1);
        assert_eq!(snap2[0].mode, ClientMode::ReadShared);
        assert_eq!(snap2[0].client_count, 2);
    }

    #[test]
    fn generation_increments_on_mode_change() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        assert_eq!(tracker.snapshots()[0].generation, 0);
        tracker.client_mounted(1, 99).unwrap();
        assert_eq!(tracker.snapshots()[0].generation, 1);
    }

    #[test]
    fn transition_in_progress_flag() {
        let mut tracker = ClientModeTracker::default();
        tracker.register(1, 42).unwrap();
        tracker.client_mounted(1, 99).unwrap();
        assert!(!tracker.snapshots()[0].transition_in_progress);
    }

    #[test]
    fn serde_roundtrip_client_mode() {
        let mode = ClientMode::MultiWriter;
        let json = serde_json::to_string(&mode).unwrap();
        let restored: ClientMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, restored);
    }

    #[test]
    fn serde_roundtrip_snapshot() {
        let snap = ClientModeSnapshot {
            dataset_id: 7,
            mode: ClientMode::ReadShared,
            client_count: 3,
            writer_node_id: Some(42),
            generation: 5,
            transition_in_progress: false,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let restored: ClientModeSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, restored);
    }
}
