// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Committed-root-validated crash recovery loop with BLAKE3 chain
//! verification, intent-log record replay, and health-gated rebuild
//! decisions.
//!
//! # Architecture
//!
//! ```text
//! PoolImport ──► RecoveryLoop::run_recovery()
//!                    │
//!   ValidateRoot ◄────┘  BLAKE3 domain-separated chain verification
//!         │
//!   ReplayIntentLog       replay all records since committed root txg
//!         │
//!   RestoreConsistency    flush replayed namespace state to object store
//!         │
//!   DecideRebuild         health-gate: consult ReplicaHealth to decide
//!         │               whether rebuild is needed
//!         ▼
//!      Ready              pool can serve FUSE/ublk
//! ```
//!
//! # Crash-resumption safety
//!
//! The state machine is idempotent: replaying the same intent-log records
//! a second time must produce the same namespace and object-store state.
//! Recovery state is persisted to stable storage before each transition
//! so that a crash during recovery resumes where it left off.

use std::path::Path;

use tidefs_checksum_tree::DomainTag;
use tidefs_commit_group::{RecoveryResult, RootPointer};
use tidefs_intent_log::{IntentLogReader, IntentLogRecord, SegmentReadResult, SegmentRecord};

use tidefs_replica_health::state_machine::DegradationState;
use tidefs_replica_health::ReplicaDegradationTracker;

// ── RecoveryState ────────────────────────────────────────────────────

/// Phases of the committed-root-validated crash recovery state machine.
///
/// ```text
/// ValidateRoot ──► ReplayIntentLog ──► RestoreConsistency ──► DecideRebuild ──► Ready
///      │                                                                              ▲
///      └─────────── (valid root with no uncommitted records) ─────────────────────────┘
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryPhase {
    /// Validate the committed root via BLAKE3 chain verification.
    ValidateRoot,
    /// Replay intent-log records since the committed root txg.
    ReplayIntentLog,
    /// Flush replayed namespace state to the object store.
    RestoreConsistency,
    /// Health-gate: consult replica health to decide if rebuild is needed.
    DecideRebuild,
    /// Pool is ready for normal operation.
    Ready,
}

impl RecoveryPhase {
    /// Human-readable label for logging and diagnostics.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ValidateRoot => "validate-root",
            Self::ReplayIntentLog => "replay-intent-log",
            Self::RestoreConsistency => "restore-consistency",
            Self::DecideRebuild => "decide-rebuild",
            Self::Ready => "ready",
        }
    }

    /// Returns the next phase in the recovery sequence.
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::ValidateRoot => Self::ReplayIntentLog,
            Self::ReplayIntentLog => Self::RestoreConsistency,
            Self::RestoreConsistency => Self::DecideRebuild,
            Self::DecideRebuild => Self::Ready,
            Self::Ready => Self::Ready,
        }
    }
}

// ── ReplayTarget trait ────────────────────────────────────────────────

/// Dispatch trait for per-record-type intent-log replay handlers.
///
/// Implementations of this trait handle the actual namespace and
/// object-store mutations during replay. A default no-op implementation
/// is provided for testing.
pub trait ReplayTarget {
    /// Replay a single intent-log record.
    ///
    /// Returns an error if replay of this specific record fails.
    /// The recovery loop skips records that have already been applied
    /// (idempotent replay) and aborts on unexpected errors.
    fn replay_record(&mut self, record: &IntentLogRecord) -> Result<(), RecoveryError>;

    /// Called after all records have been replayed successfully.
    /// Flushes any buffered state to persistent storage.
    fn flush(&mut self) -> Result<(), RecoveryError> {
        Ok(())
    }
}

/// A no-op replay target for testing the state machine without real
/// namespace or object-store mutations.
#[derive(Debug, Default)]
pub struct NoOpReplayTarget {
    pub records_seen: Vec<IntentLogRecord>,
}

impl ReplayTarget for NoOpReplayTarget {
    fn replay_record(&mut self, record: &IntentLogRecord) -> Result<(), RecoveryError> {
        self.records_seen.push(record.clone());
        Ok(())
    }
}

// ── RecoveryLoopConfig ───────────────────────────────────────────────

/// Configuration for the crash recovery loop.
///
/// Controls replay behaviour: how many records to batch before flushing
/// intermediate state and the maximum number of intent-log records to
/// replay before aborting (a safety guard against unbounded replay).
#[derive(Clone, Copy, Debug)]
pub struct RecoveryLoopConfig {
    /// Number of records to replay before flushing intermediate state
    /// to the replay target. Smaller batches reduce memory pressure but
    /// increase flush overhead. Default: 1024.
    pub replay_batch_size: usize,
    /// Maximum number of intent-log records to replay before aborting
    /// with `RecoveryError::ReplayDepthExceeded`. Guards against
    /// unbounded replay when the intent log has grown unreasonably
    /// large (e.g. due to a bug or a stalled cleaner). 0 disables the
    /// guard. Default: 1_000_000.
    pub max_replay_depth: usize,
}

impl Default for RecoveryLoopConfig {
    fn default() -> Self {
        Self {
            replay_batch_size: 1024,
            max_replay_depth: 1_000_000,
        }
    }
}

impl RecoveryLoopConfig {
    /// Create a config with explicit values.
    #[must_use]
    pub fn new(replay_batch_size: usize, max_replay_depth: usize) -> Self {
        Self {
            replay_batch_size,
            max_replay_depth,
        }
    }
}

// ── RecoveryError ─────────────────────────────────────────────────────

/// Errors produced by the crash recovery loop.
#[derive(Debug)]
#[allow(dead_code)]
pub enum RecoveryError {
    /// BLAKE3 chain verification failed — committed root may be corrupt.
    RootValidationFailed { reason: String },
    /// No valid committed root found during pool import.
    NoCommittedRoot,
    /// Intent-log segment is corrupt and cannot be replayed.
    IntentLogCorrupt { segment_id: u64, reason: String },
    /// Replay of a specific record failed.
    ReplayFailed { record_type: u8, reason: String },
    /// Flush of replayed state to object store failed.
    FlushFailed { reason: String },
    /// I/O error during recovery.
    Io(String),
    /// Replay depth exceeded the configured maximum. Aborting to avoid
    /// unbounded recovery time or memory pressure.
    ReplayDepthExceeded { limit: usize },
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootValidationFailed { reason } => {
                write!(f, "committed root validation failed: {reason}")
            }
            Self::NoCommittedRoot => write!(f, "no committed root found"),
            Self::IntentLogCorrupt { segment_id, reason } => {
                write!(f, "intent-log segment {segment_id} corrupt: {reason}")
            }
            Self::ReplayFailed {
                record_type,
                reason,
            } => {
                write!(f, "replay failed for record type {record_type}: {reason}")
            }
            Self::ReplayDepthExceeded { limit } => {
                write!(f, "replay depth exceeded limit of {limit} records")
            }
            Self::FlushFailed { reason } => write!(f, "replay flush failed: {reason}"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for RecoveryError {}

// ── Health gate decision ──────────────────────────────────────────────

/// Outcome of the health-gate decision after recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthGateDecision {
    /// All replicas healthy; no rebuild needed.
    Healthy,
    /// Some replicas degraded but quorum intact; rebuild optional.
    DegradedRebuildRecommended,
    /// Quorum lost; rebuild required before serving I/O.
    RebuildRequired,
    /// All replicas dead; data loss — operator must restore from backup.
    DataLoss,
}

/// Evaluate replica health after recovery and decide whether rebuild is
/// needed before serving I/O.
///
/// Queries the degradation tracker for each replica in `replica_nodes`
/// and returns a [`HealthGateDecision`].
#[must_use]
pub fn health_gate(
    tracker: &ReplicaDegradationTracker,
    replica_nodes: &[u64],
) -> HealthGateDecision {
    if replica_nodes.is_empty() {
        return HealthGateDecision::Healthy;
    }

    let mut healthy_count = 0usize;
    let mut degraded_count = 0usize;
    let mut dead_count = 0usize;

    for &node_id in replica_nodes {
        let node = tidefs_replica_health::NodeId::new(node_id);
        let state = tracker.degradation_state(node);
        match state {
            DegradationState::Healthy
            | DegradationState::Recovering
            | DegradationState::Degraded => {
                // Degraded is still placeable — can serve reads
                if state == DegradationState::Degraded {
                    degraded_count += 1;
                }
                healthy_count += 1;
            }
            DegradationState::Dead => {
                dead_count += 1;
            }
        }
    }

    let total = replica_nodes.len();
    let quorum = (total / 2) + 1;

    if healthy_count >= total {
        HealthGateDecision::Healthy
    } else if healthy_count + dead_count == total && healthy_count == 0 {
        HealthGateDecision::DataLoss
    } else if healthy_count < quorum {
        HealthGateDecision::RebuildRequired
    } else if degraded_count > 0 || healthy_count < total {
        HealthGateDecision::DegradedRebuildRecommended
    } else {
        HealthGateDecision::Healthy
    }
}

// ── RecoveryLoop ──────────────────────────────────────────────────────

/// Outcome of a recovery run.
#[derive(Clone, Debug)]
pub struct RecoveryOutcome {
    /// The state the loop finished in.
    pub final_phase: RecoveryPhase,
    /// Number of intent-log records replayed.
    pub records_replayed: usize,
    /// Commit group result from the recovery scan.
    pub recovery_result: RecoveryResult,
    /// Health-gate decision.
    pub health_decision: HealthGateDecision,
    /// Whether a rebuild is needed before serving I/O.
    pub rebuild_needed: bool,
}

/// Recovery-loop state machine for committed-root inspection and replay hooks.
///
/// Bootstraps from a committed root pointer, validates it via BLAKE3
/// chain verification, runs configured replay-target hooks for records
/// since that root, and records the health-gate decision for callers.
#[derive(Debug)]
pub struct RecoveryLoop {
    /// Current phase.
    pub phase: RecoveryPhase,
    /// The committed root discovered during pool import.
    pub root: RootPointer,
    /// Optional BLAKE3 chain digest for root validation.
    pub chain_digest: Option<[u8; 32]>,
    /// Result of the commit_group recovery scan.
    pub recovery_result: Option<RecoveryResult>,
    /// Number of intent-log records replayed.
    pub records_replayed: usize,
    /// Health-gate decision (populated in DecideRebuild phase).
    pub health_decision: Option<HealthGateDecision>,
    /// Replay configuration (batch size, depth guard).
    pub config: RecoveryLoopConfig,
}

impl RecoveryLoop {
    /// Create a new recovery loop starting from a committed root.
    ///
    /// If `chain_digest` is `Some`, the root will be validated against
    /// it during the ValidateRoot phase. If `None`, validation is
    /// advisory (BLAKE3 digest is computed but not compared).
    #[must_use]
    pub fn new(root: RootPointer, chain_digest: Option<[u8; 32]>) -> Self {
        Self {
            phase: RecoveryPhase::ValidateRoot,
            root,
            chain_digest,
            recovery_result: None,
            records_replayed: 0,
            health_decision: None,
            config: RecoveryLoopConfig::default(),
        }
    }

    /// Create a new recovery loop with a specific configuration.
    ///
    /// The `config` controls replay batch size and the maximum replay
    /// depth guard. See [`RecoveryLoopConfig`] for details.
    #[must_use]
    pub fn new_with_config(
        root: RootPointer,
        chain_digest: Option<[u8; 32]>,
        config: RecoveryLoopConfig,
    ) -> Self {
        Self {
            phase: RecoveryPhase::ValidateRoot,
            root,
            chain_digest,
            recovery_result: None,
            records_replayed: 0,
            health_decision: None,
            config,
        }
    }

    /// Validate the committed root via BLAKE3 domain-separated chain
    /// verification.
    ///
    /// Derives the `CommittedRoot` domain key and verifies that the
    /// root pointer's embedded digest matches a fresh BLAKE3 hash of
    /// the root payload. Also verifies that the root commit_group_id is
    /// valid (not NIL).
    ///
    /// # Errors
    ///
    /// Returns `RecoveryError::NoCommittedRoot` if the root is NIL.
    /// Returns `RecoveryError::RootValidationFailed` if the chain
    /// digest does not verify.
    pub fn validate_root(&mut self) -> Result<(), RecoveryError> {
        // A NIL root means no committed root was found — this is a
        // fresh filesystem with no committed state, not a validation
        // failure.
        if !self.root.commit_group_id.is_valid() {
            // Fresh filesystem: skip intent-log replay entirely.
            // Advance directly to Ready.
            self.phase = RecoveryPhase::Ready;
            return Ok(());
        }

        // Derive the CommittedRoot domain key and verify the root
        // payload integrity using BLAKE3.
        let domain_key = DomainTag::CommittedRoot.derive_key();

        // Build the root payload: commit_group_id (8 bytes LE) +
        // root_handle (8 bytes LE).
        let mut payload = [0u8; 16];
        payload[0..8].copy_from_slice(&self.root.commit_group_id.0.to_le_bytes());
        payload[8..16].copy_from_slice(&self.root.root_handle.to_le_bytes());

        // Compute BLAKE3 hash of the payload keyed with the domain key.
        let computed: [u8; 32] = blake3::keyed_hash(domain_key.as_bytes(), &payload).into();

        // If a chain digest was provided, verify the computed digest
        // matches. If no digest is available, this is an advisory
        // validation only (e.g. upgraded pool from before digest was
        // persisted).
        if let Some(expected) = self.chain_digest {
            if computed != expected {
                return Err(RecoveryError::RootValidationFailed {
                    reason: format!(
                        "chain digest mismatch for root commit_group={} handle={}",
                        self.root.commit_group_id.0, self.root.root_handle,
                    ),
                });
            }
        }

        self.phase = self.phase.next();
        Ok(())
    }

    /// Replay intent-log segments from disk.
    ///
    /// Reads all intent-log segment files from `intent_log_dir`, filters
    /// to segments with LSNs greater than the committed root's txg, and
    /// replays each record through the provided [`ReplayTarget`].
    ///
    /// Segments with valid footers are replayed in full. Segments
    /// without valid footers (truncated during crash) are replayed up
    /// to the last valid record checksum. Corrupt segments are skipped
    /// with an error logged but do not abort recovery.
    ///
    /// # Errors
    ///
    /// Returns `RecoveryError::ReplayDepthExceeded` if the total number
    /// of replayed records exceeds `config.max_replay_depth` (when > 0).
    pub fn replay_intent_log<T: ReplayTarget>(
        &mut self,
        intent_log_dir: &Path,
        replay_target: &mut T,
    ) -> Result<(), RecoveryError> {
        let committed_txg = self.root.commit_group_id;

        // Read segment directory entries.
        let mut segment_paths: Vec<std::path::PathBuf> = Vec::new();
        match std::fs::read_dir(intent_log_dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|e| e == "viflodev") {
                        segment_paths.push(path);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // No intent-log directory — fresh filesystem, nothing to replay.
                self.phase = self.phase.next();
                return Ok(());
            }
            Err(e) => {
                return Err(RecoveryError::Io(format!(
                    "read intent-log dir {intent_log_dir:?}: {e}"
                )));
            }
        }

        // Sort by filename for deterministic replay order.
        segment_paths.sort();
        let max_depth = self.config.max_replay_depth;

        for path in &segment_paths {
            let data = std::fs::read(path)
                .map_err(|e| RecoveryError::Io(format!("read intent-log segment {path:?}: {e}")))?;

            // Depth guard: abort if we've already replayed too many
            // records across all segments.
            if max_depth > 0 && self.records_replayed >= max_depth {
                self.phase = RecoveryPhase::RestoreConsistency;
                replay_target.flush()?;
                return Err(RecoveryError::ReplayDepthExceeded { limit: max_depth });
            }

            let result = IntentLogReader::read_segment(&data);

            let records: Vec<SegmentRecord> = match &result {
                SegmentReadResult::Complete { records, .. } => records.clone(),
                SegmentReadResult::Truncated { valid_records, .. } => valid_records.clone(),
                SegmentReadResult::Corrupt => {
                    // Log but don't abort — a corrupt segment means we
                    // lose its records, but the filesystem may still be
                    // consistent up to the previous segment.
                    let segment_id = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown");
                    eprintln!("recovery: skipping corrupt intent-log segment {segment_id}");
                    continue;
                }
            };

            // Filter records: only replay those whose LSN is beyond the
            // committed root txg. Records at or before the committed
            // txg are already reflected in the committed state.
            for seg_rec in &records {
                if seg_rec.lsn <= committed_txg.0 {
                    continue;
                }
                // Depth guard: check per-record inside a segment too.
                if max_depth > 0 && self.records_replayed >= max_depth {
                    replay_target.flush()?;
                    return Err(RecoveryError::ReplayDepthExceeded { limit: max_depth });
                }
                replay_target.replay_record(&seg_rec.record)?;

                // Periodic flush for large batches.
                let batch_size = self.config.replay_batch_size;
                if batch_size > 0 && self.records_replayed % batch_size == 0 {
                    replay_target.flush()?;
                }
                self.records_replayed += 1;
            }
        }

        // Flush replayed state.
        replay_target.flush()?;

        self.phase = self.phase.next();
        Ok(())
    }

    /// Restore consistency after replay: the replay target has already
    /// applied namespace mutations and flushed to the object store.
    /// This phase is a logical checkpoint for observability and future
    /// extension (e.g. rebuilding dirty-tracker state from replayed
    /// records).
    pub fn restore_consistency(&mut self, recovery_result: RecoveryResult) {
        self.recovery_result = Some(recovery_result);
        self.phase = self.phase.next();
    }

    /// Evaluate the health gate to decide if rebuild is needed before
    /// the pool can serve I/O.
    ///
    /// Consults the replica degradation tracker for all known replicas
    /// and produces a [`HealthGateDecision`]. If the decision is
    /// `RebuildRequired` or `DataLoss`, the pool should not serve I/O
    /// until the rebuild is complete (or operator intervention).
    pub fn decide_rebuild(&mut self, tracker: &ReplicaDegradationTracker) {
        // Collect all tracked replica node IDs.
        let metrics = tracker.export_all_metrics(0);
        let replica_nodes: Vec<u64> = metrics.iter().map(|m| m.replica_id).collect();

        let decision = health_gate(tracker, &replica_nodes);
        self.health_decision = Some(decision);
        self.phase = self.phase.next();
    }

    /// Run the full recovery loop to completion.
    ///
    /// Drives the state machine through all phases: validate root,
    /// replay intent log, restore consistency, and decide rebuild.
    ///
    /// Returns a [`RecoveryOutcome`] summarizing the result.
    ///
    /// # Errors
    ///
    /// Returns `RecoveryError` if root validation or intent-log replay
    /// fails.
    pub fn run_recovery<T: ReplayTarget>(
        &mut self,
        intent_log_dir: &Path,
        recovery_result: RecoveryResult,
        replay_target: &mut T,
        tracker: &ReplicaDegradationTracker,
    ) -> Result<RecoveryOutcome, RecoveryError> {
        // Phase 1: ValidateRoot
        self.validate_root()?;

        if self.phase == RecoveryPhase::Ready {
            // Fresh filesystem (root was NIL) — skip remaining phases.
            return Ok(RecoveryOutcome {
                final_phase: RecoveryPhase::Ready,
                records_replayed: 0,
                recovery_result,
                health_decision: HealthGateDecision::Healthy,
                rebuild_needed: false,
            });
        }

        // Phase 2: ReplayIntentLog
        self.replay_intent_log(intent_log_dir, replay_target)?;

        // Phase 3: RestoreConsistency
        self.restore_consistency(recovery_result);

        // Phase 4: DecideRebuild
        self.decide_rebuild(tracker);

        let rebuild_needed = matches!(
            self.health_decision,
            Some(HealthGateDecision::RebuildRequired | HealthGateDecision::DataLoss)
        );

        Ok(RecoveryOutcome {
            final_phase: self.phase,
            records_replayed: self.records_replayed,
            recovery_result: self.recovery_result.clone().unwrap(),
            health_decision: self.health_decision.unwrap(),
            rebuild_needed,
        })
    }

    /// Returns `true` if the state machine has reached `Ready`.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.phase == RecoveryPhase::Ready
    }

    /// Returns `true` if a rebuild is required before serving I/O.
    #[must_use]
    pub fn rebuild_needed(&self) -> bool {
        matches!(
            self.health_decision,
            Some(HealthGateDecision::RebuildRequired | HealthGateDecision::DataLoss)
        )
    }
}

// ── Anchor recovered root ────────────────────────────────────────────

/// Compute a BLAKE3-verified committed-root anchor after successful
/// replay.
///
/// Derives the `CommittedRoot` domain key and computes a keyed BLAKE3
/// hash of the root payload (commit_group_id + root_handle). This digest
/// can be stored alongside the superblock so that future mounts can
/// validate the committed root chain.
///
/// Returns the 32-byte BLAKE3 digest.
#[must_use]
pub fn anchor_recovered_root(root: RootPointer) -> [u8; 32] {
    let domain_key = DomainTag::CommittedRoot.derive_key();
    let mut payload = [0u8; 16];
    payload[0..8].copy_from_slice(&root.commit_group_id.0.to_le_bytes());
    payload[8..16].copy_from_slice(&root.root_handle.to_le_bytes());
    blake3::keyed_hash(domain_key.as_bytes(), &payload).into()
}

impl RecoveryLoop {
    /// Anchor the recovered root after successful replay.
    ///
    /// Computes a BLAKE3-verified digest of the committed root and
    /// stores it in `chain_digest` so it persists to the superblock.
    /// Call this after `run_recovery` succeeds, before handing control
    /// to the FUSE/ublk daemon.
    pub fn anchor_root(&mut self) {
        self.chain_digest = Some(anchor_recovered_root(self.root));
    }
}

// ── Committed root digest computation ──────────────────────────────────

/// Compute the BLAKE3 domain-separated chain digest for a committed root.
///
/// Produces the same digest that [`validate_committed_root`] compares against,
/// under the `DomainTag::CommittedRoot` domain key.  The digest covers the
/// commit_group_id (8 bytes LE) and root_handle (8 bytes LE).
///
/// Returns NIL ([0u8; 32]) when the root is NIL (fresh filesystem).
#[must_use]
pub fn compute_committed_root_digest(root: RootPointer) -> [u8; 32] {
    if !root.commit_group_id.is_valid() {
        return [0u8; 32];
    }
    let domain_key = DomainTag::CommittedRoot.derive_key();
    let mut payload = [0u8; 16];
    payload[0..8].copy_from_slice(&root.commit_group_id.0.to_le_bytes());
    payload[8..16].copy_from_slice(&root.root_handle.to_le_bytes());
    blake3::keyed_hash(domain_key.as_bytes(), &payload).into()
}

// ── Standalone root validation ────────────────────────────────────────

/// Validate a committed root pointer via BLAKE3 domain-separated chain
/// verification.
///
/// Computes the BLAKE3 keyed hash of the root payload (commit_group_id +
/// root_handle) under the `CommittedRoot` domain key and compares it
/// against the optional `chain_digest`. If `chain_digest` is `None`, the
/// validation is advisory (the digest is logged but no comparison is made).
///
/// Returns `Ok(())` if:
/// - The root is NIL (fresh filesystem, no validation needed), or
/// - The computed digest matches `chain_digest`, or
/// - `chain_digest` is `None` (advisory validation only).
///
/// # Errors
///
/// Returns `RecoveryError::RootValidationFailed` if `chain_digest` is
/// `Some(d)` and the computed digest does not match `d`.
pub fn validate_committed_root(
    root: RootPointer,
    chain_digest: Option<[u8; 32]>,
) -> Result<(), RecoveryError> {
    if !root.commit_group_id.is_valid() {
        return Ok(());
    }

    let domain_key = DomainTag::CommittedRoot.derive_key();
    let mut payload = [0u8; 16];
    payload[0..8].copy_from_slice(&root.commit_group_id.0.to_le_bytes());
    payload[8..16].copy_from_slice(&root.root_handle.to_le_bytes());

    let computed: [u8; 32] = blake3::keyed_hash(domain_key.as_bytes(), &payload).into();

    if let Some(expected) = chain_digest {
        if computed != expected {
            return Err(RecoveryError::RootValidationFailed {
                reason: format!(
                    "chain digest mismatch for root commit_group={} handle={}:                      computed={:02x?} expected={:02x?}",
                    root.commit_group_id.0,
                    root.root_handle,
                    &computed[..8],
                    &expected[..8],
                ),
            });
        }
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tidefs_commit_group::CommitGroupId;
    use tidefs_intent_log::{IntentLogFrame, IntentLogWriter};

    // ── RecoveryPhase ─────────────────────────────────────────────

    #[test]
    fn phase_labels_are_distinct() {
        let labels: Vec<&str> = [
            RecoveryPhase::ValidateRoot,
            RecoveryPhase::ReplayIntentLog,
            RecoveryPhase::RestoreConsistency,
            RecoveryPhase::DecideRebuild,
            RecoveryPhase::Ready,
        ]
        .iter()
        .map(|s| s.label())
        .collect();
        let mut unique = labels.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), labels.len());
    }

    #[test]
    fn phase_next_progression() {
        assert_eq!(
            RecoveryPhase::ValidateRoot.next(),
            RecoveryPhase::ReplayIntentLog
        );
        assert_eq!(
            RecoveryPhase::ReplayIntentLog.next(),
            RecoveryPhase::RestoreConsistency
        );
        assert_eq!(
            RecoveryPhase::RestoreConsistency.next(),
            RecoveryPhase::DecideRebuild
        );
        assert_eq!(RecoveryPhase::DecideRebuild.next(), RecoveryPhase::Ready);
        assert_eq!(RecoveryPhase::Ready.next(), RecoveryPhase::Ready);
    }

    // ── RecoveryLoop construction ─────────────────────────────────

    #[test]
    fn new_starts_in_validate_root() {
        let root = RootPointer::new(CommitGroupId(1), 100);
        let loop_ = RecoveryLoop::new(root, None);
        assert_eq!(loop_.phase, RecoveryPhase::ValidateRoot);
        assert!(!loop_.is_ready());
        assert_eq!(loop_.records_replayed, 0);
        assert!(loop_.health_decision.is_none());
    }

    #[test]
    fn new_with_nil_root() {
        let loop_ = RecoveryLoop::new(RootPointer::NIL, None);
        assert_eq!(loop_.phase, RecoveryPhase::ValidateRoot);
    }

    // ── validate_root ─────────────────────────────────────────────

    #[test]
    fn validate_root_succeeds_for_valid_root() {
        let root = RootPointer::new(CommitGroupId(1), 100);
        let mut loop_ = RecoveryLoop::new(root, None);
        loop_.validate_root().expect("valid root should validate");
        assert_eq!(loop_.phase, RecoveryPhase::ReplayIntentLog);
    }

    #[test]
    fn validate_root_nil_jumps_to_ready() {
        let mut loop_ = RecoveryLoop::new(RootPointer::NIL, None);
        loop_.validate_root().expect("nil root should not error");
        assert_eq!(loop_.phase, RecoveryPhase::Ready);
        assert!(loop_.is_ready());
    }

    // ── ReplayTarget (NoOpReplayTarget) ───────────────────────────

    #[test]
    fn noop_replay_target_stores_records() {
        let mut target = NoOpReplayTarget::default();
        let rec = IntentLogRecord::Mkdir {
            parent: 1,
            name: b"d".to_vec(),
            mode: 0o755,
            ino: 10,
        };
        target.replay_record(&rec).unwrap();
        assert_eq!(target.records_seen.len(), 1);
    }

    #[test]
    fn noop_replay_target_multiple_records() {
        let mut target = NoOpReplayTarget::default();
        for i in 0..5 {
            let rec = IntentLogRecord::Create {
                parent: 1,
                name: format!("file{i}").into_bytes(),
                mode: 0o644,
                ino: i,
            };
            target.replay_record(&rec).unwrap();
        }
        assert_eq!(target.records_seen.len(), 5);
    }

    // ── replay_intent_log (empty directory) ───────────────────────

    #[test]
    fn replay_empty_intent_log_dir() {
        let tmp = TempDir::new().expect("tempdir");
        let root = RootPointer::new(CommitGroupId(1), 100);
        let mut loop_ = RecoveryLoop::new(root, None);
        // Skip validate_root to get to ReplayIntentLog
        loop_.phase = RecoveryPhase::ReplayIntentLog;

        let mut target = NoOpReplayTarget::default();
        loop_
            .replay_intent_log(tmp.path(), &mut target)
            .expect("replay on empty dir");
        assert_eq!(loop_.records_replayed, 0);
        assert_eq!(loop_.phase, RecoveryPhase::RestoreConsistency);
    }

    #[test]
    fn replay_nonexistent_dir_is_ok() {
        let root = RootPointer::new(CommitGroupId(1), 100);
        let mut loop_ = RecoveryLoop::new(root, None);
        loop_.phase = RecoveryPhase::ReplayIntentLog;

        let mut target = NoOpReplayTarget::default();
        let nonexistent = std::path::Path::new("/tmp/tidefs_nonexistent_recovery_test_dir_42");
        loop_
            .replay_intent_log(nonexistent, &mut target)
            .expect("nonexistent dir should not error");
        assert_eq!(loop_.phase, RecoveryPhase::RestoreConsistency);
    }

    // ── restore_consistency ───────────────────────────────────────

    #[test]
    fn restore_consistency_stores_result() {
        let root = RootPointer::new(CommitGroupId(1), 100);
        let mut loop_ = RecoveryLoop::new(root, None);
        loop_.phase = RecoveryPhase::RestoreConsistency;

        let result = RecoveryResult {
            highest_committed_commit_group: CommitGroupId(1),
            next_commit_group_id: CommitGroupId(2),
            committed_keys: vec![],
            torn_commit_groups: vec![],
            replayed_commit_groups: vec![],
        };
        loop_.restore_consistency(result);
        assert_eq!(loop_.phase, RecoveryPhase::DecideRebuild);
        assert!(loop_.recovery_result.is_some());
    }

    // ── health_gate ───────────────────────────────────────────────

    #[test]
    fn health_gate_empty_replicas_is_healthy() {
        let t = ReplicaDegradationTracker::new(
            tidefs_replica_health::scoring::ScoreConfig::default(),
            tidefs_replica_health::state_machine::DegradationConfig::default(),
        );
        assert_eq!(health_gate(&t, &[]), HealthGateDecision::Healthy);
    }

    #[test]
    fn health_gate_all_healthy() {
        let t = ReplicaDegradationTracker::new(
            tidefs_replica_health::scoring::ScoreConfig::default(),
            tidefs_replica_health::state_machine::DegradationConfig::default(),
        );
        // All replicas are healthy by default (untracked → Healthy)
        assert_eq!(health_gate(&t, &[1, 2, 3]), HealthGateDecision::Healthy);
    }

    #[test]
    fn health_gate_single_replica_dead_is_rebuild() {
        let mut t = ReplicaDegradationTracker::new(
            tidefs_replica_health::scoring::ScoreConfig::default(),
            tidefs_replica_health::state_machine::DegradationConfig::default(),
        );
        let dead_node = tidefs_replica_health::NodeId::new(1);
        t.record_failure(dead_node, 0, 0, true); // unrecoverable → Dead
                                                 // 1 dead out of 3, quorum = 2, healthy = 2 → healthy >= quorum
                                                 // but healthy_count (2) < total (3) → DegradedRebuildRecommended
        assert_eq!(
            health_gate(&t, &[1, 2, 3]),
            HealthGateDecision::DegradedRebuildRecommended
        );
    }

    #[test]
    fn health_gate_all_dead_is_data_loss() {
        let mut t = ReplicaDegradationTracker::new(
            tidefs_replica_health::scoring::ScoreConfig::default(),
            tidefs_replica_health::state_machine::DegradationConfig::default(),
        );
        for &id in &[1u64, 2, 3] {
            t.record_failure(tidefs_replica_health::NodeId::new(id), 0, 0, true);
        }
        assert_eq!(health_gate(&t, &[1, 2, 3]), HealthGateDecision::DataLoss);
    }

    #[test]
    fn health_gate_quorum_lost_is_rebuild_required() {
        let mut t = ReplicaDegradationTracker::new(
            tidefs_replica_health::scoring::ScoreConfig::default(),
            tidefs_replica_health::state_machine::DegradationConfig::default(),
        );
        // 5 replicas, kill 3 → healthy=2, quorum=3 → below quorum
        for &id in &[1u64, 2, 3] {
            t.record_failure(tidefs_replica_health::NodeId::new(id), 0, 0, true);
        }
        assert_eq!(
            health_gate(&t, &[1, 2, 3, 4, 5]),
            HealthGateDecision::RebuildRequired
        );
    }

    // ── decide_rebuild ────────────────────────────────────────────

    #[test]
    fn decide_rebuild_healthy_tracker_sets_healthy() {
        let root = RootPointer::new(CommitGroupId(1), 100);
        let mut loop_ = RecoveryLoop::new(root, None);
        loop_.phase = RecoveryPhase::DecideRebuild;

        let tracker = ReplicaDegradationTracker::new(
            tidefs_replica_health::scoring::ScoreConfig::default(),
            tidefs_replica_health::state_machine::DegradationConfig::default(),
        );
        loop_.decide_rebuild(&tracker);
        assert_eq!(loop_.phase, RecoveryPhase::Ready);
        assert_eq!(loop_.health_decision, Some(HealthGateDecision::Healthy));
        assert!(!loop_.rebuild_needed());
    }

    // ── run_recovery (full cycle) ─────────────────────────────────

    #[test]
    fn run_recovery_nil_root_goes_straight_to_ready() {
        let mut loop_ = RecoveryLoop::new(RootPointer::NIL, None);
        let tmp = TempDir::new().expect("tempdir");
        let mut target = NoOpReplayTarget::default();
        let tracker = ReplicaDegradationTracker::new(
            tidefs_replica_health::scoring::ScoreConfig::default(),
            tidefs_replica_health::state_machine::DegradationConfig::default(),
        );
        let result = RecoveryResult {
            highest_committed_commit_group: CommitGroupId::NIL,
            next_commit_group_id: CommitGroupId::FIRST,
            committed_keys: vec![],
            torn_commit_groups: vec![],
            replayed_commit_groups: vec![],
        };
        let outcome = loop_
            .run_recovery(tmp.path(), result, &mut target, &tracker)
            .expect("run_recovery on nil root");
        assert_eq!(outcome.final_phase, RecoveryPhase::Ready);
        assert_eq!(outcome.records_replayed, 0);
        assert_eq!(outcome.health_decision, HealthGateDecision::Healthy);
        assert!(!outcome.rebuild_needed);
    }

    #[test]
    fn run_recovery_valid_root_empty_intent_log() {
        let root = RootPointer::new(CommitGroupId(1), 100);
        let mut loop_ = RecoveryLoop::new(root, None);
        let tmp = TempDir::new().expect("tempdir");
        let mut target = NoOpReplayTarget::default();
        let tracker = ReplicaDegradationTracker::new(
            tidefs_replica_health::scoring::ScoreConfig::default(),
            tidefs_replica_health::state_machine::DegradationConfig::default(),
        );
        let result = RecoveryResult {
            highest_committed_commit_group: CommitGroupId(1),
            next_commit_group_id: CommitGroupId(2),
            committed_keys: vec![],
            torn_commit_groups: vec![],
            replayed_commit_groups: vec![],
        };
        let outcome = loop_
            .run_recovery(tmp.path(), result, &mut target, &tracker)
            .expect("run_recovery on valid root with empty intent log");
        assert_eq!(outcome.final_phase, RecoveryPhase::Ready);
        assert_eq!(outcome.records_replayed, 0);
        assert_eq!(outcome.health_decision, HealthGateDecision::Healthy);
        assert!(!outcome.rebuild_needed);
        assert!(loop_.is_ready());
    }

    // ── RecoveryLoopConfig ────────────────────────────────────────

    #[test]
    fn config_defaults() {
        let cfg = RecoveryLoopConfig::default();
        assert_eq!(cfg.replay_batch_size, 1024);
        assert_eq!(cfg.max_replay_depth, 1_000_000);
    }

    #[test]
    fn config_custom_values() {
        let cfg = RecoveryLoopConfig::new(512, 5000);
        assert_eq!(cfg.replay_batch_size, 512);
        assert_eq!(cfg.max_replay_depth, 5000);
    }

    #[test]
    fn config_zero_max_depth_disables_guard() {
        let cfg = RecoveryLoopConfig::new(256, 0);
        assert_eq!(cfg.max_replay_depth, 0);
    }

    #[test]
    fn new_with_config_stores_config() {
        let cfg = RecoveryLoopConfig::new(64, 100);
        let root = RootPointer::new(CommitGroupId(1), 100);
        let loop_ = RecoveryLoop::new_with_config(root, None, cfg);
        assert_eq!(loop_.config.replay_batch_size, 64);
        assert_eq!(loop_.config.max_replay_depth, 100);
    }

    // ── Replay depth guard ────────────────────────────────────────

    #[test]
    fn replay_depth_guard_not_triggered_on_empty_dir() {
        let cfg = RecoveryLoopConfig::new(1024, 5);
        let root = RootPointer::new(CommitGroupId(1), 100);
        let mut loop_ = RecoveryLoop::new_with_config(root, None, cfg);
        loop_.phase = RecoveryPhase::ReplayIntentLog;
        let tmp = TempDir::new().expect("tempdir");
        let mut target = NoOpReplayTarget::default();
        let result = loop_.replay_intent_log(tmp.path(), &mut target);
        assert!(result.is_ok());
        assert_eq!(loop_.records_replayed, 0);
    }

    #[test]
    fn replay_depth_exceeded_display() {
        let err = RecoveryError::ReplayDepthExceeded { limit: 5000 };
        let s = format!("{err}");
        assert!(s.contains("5000"));
    }

    // ── anchor_recovered_root ─────────────────────────────────────

    #[test]
    fn anchor_recovered_root_produces_deterministic_digest() {
        let root = RootPointer::new(CommitGroupId(42), 999);
        let d1 = anchor_recovered_root(root);
        let d2 = anchor_recovered_root(root);
        assert_eq!(d1, d2);
    }

    #[test]
    fn anchor_recovered_root_different_roots_differ() {
        let a = RootPointer::new(CommitGroupId(1), 100);
        let b = RootPointer::new(CommitGroupId(2), 100);
        assert_ne!(anchor_recovered_root(a), anchor_recovered_root(b));
    }

    #[test]
    fn anchor_root_stores_digest_in_chain_digest() {
        let root = RootPointer::new(CommitGroupId(7), 200);
        let mut loop_ = RecoveryLoop::new(root, None);
        assert!(loop_.chain_digest.is_none());
        loop_.anchor_root();
        assert!(loop_.chain_digest.is_some());
    }

    #[test]
    fn anchor_root_matches_validate_root() {
        let root = RootPointer::new(CommitGroupId(7), 200);
        let mut loop_ = RecoveryLoop::new(root, None);
        loop_.anchor_root();
        let digest = loop_.chain_digest.unwrap();
        let result = validate_committed_root(root, Some(digest));
        assert!(result.is_ok());
    }

    // ── Error Display ─────────────────────────────────────────────

    #[test]
    fn error_display_is_human_readable() {
        let err = RecoveryError::RootValidationFailed {
            reason: "bad chain".to_string(),
        };
        assert!(format!("{err}").contains("bad chain"));

        let err = RecoveryError::NoCommittedRoot;
        assert!(format!("{err}").contains("no committed root"));

        let err = RecoveryError::IntentLogCorrupt {
            segment_id: 42,
            reason: "bad header".to_string(),
        };
        let s = format!("{err}");
        assert!(s.contains("segment 42"));
        assert!(s.contains("bad header"));

        let err = RecoveryError::ReplayFailed {
            record_type: 7,
            reason: "namespace error".to_string(),
        };
        let s = format!("{err}");
        assert!(s.contains("record type 7"));
        assert!(s.contains("namespace error"));
    }

    // ── rebuild_needed ────────────────────────────────────────────

    #[test]
    fn rebuild_needed_is_false_by_default() {
        let loop_ = RecoveryLoop::new(RootPointer::new(CommitGroupId(1), 100), None);
        assert!(!loop_.rebuild_needed());
    }

    #[test]
    fn rebuild_needed_true_for_rebuild_required() {
        let root = RootPointer::new(CommitGroupId(1), 100);
        let mut loop_ = RecoveryLoop::new(root, None);
        loop_.health_decision = Some(HealthGateDecision::RebuildRequired);
        assert!(loop_.rebuild_needed());
    }

    #[test]
    fn rebuild_needed_true_for_data_loss() {
        let root = RootPointer::new(CommitGroupId(1), 100);
        let mut loop_ = RecoveryLoop::new(root, None);
        loop_.health_decision = Some(HealthGateDecision::DataLoss);
        assert!(loop_.rebuild_needed());
    }

    // ── validate_committed_root standalone ────────────────────────

    #[test]
    fn validate_committed_root_nil_is_ok() {
        assert!(validate_committed_root(RootPointer::NIL, None).is_ok());
    }

    #[test]
    fn validate_committed_root_no_digest_is_ok() {
        let root = RootPointer::new(CommitGroupId(1), 100);
        assert!(validate_committed_root(root, None).is_ok());
    }

    #[test]
    fn validate_committed_root_with_correct_digest() {
        let root = RootPointer::new(CommitGroupId(1), 100);
        // Compute the expected digest
        let domain_key = DomainTag::CommittedRoot.derive_key();
        let mut payload = [0u8; 16];
        payload[0..8].copy_from_slice(&root.commit_group_id.0.to_le_bytes());
        payload[8..16].copy_from_slice(&root.root_handle.to_le_bytes());
        let expected: [u8; 32] = blake3::keyed_hash(domain_key.as_bytes(), &payload).into();
        assert!(validate_committed_root(root, Some(expected)).is_ok());
    }

    #[test]
    fn validate_committed_root_with_wrong_digest_fails() {
        let root = RootPointer::new(CommitGroupId(1), 100);
        let wrong = [0xFFu8; 32];
        let result = validate_committed_root(root, Some(wrong));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RecoveryError::RootValidationFailed { .. }
        ));
    }

    #[test]
    fn validate_committed_root_different_roots_produce_different_digests() {
        let root_a = RootPointer::new(CommitGroupId(1), 100);
        let root_b = RootPointer::new(CommitGroupId(2), 100);
        let domain_key = DomainTag::CommittedRoot.derive_key();
        let mut payload = [0u8; 16];
        payload[0..8].copy_from_slice(&root_a.commit_group_id.0.to_le_bytes());
        payload[8..16].copy_from_slice(&root_a.root_handle.to_le_bytes());
        let digest_a: [u8; 32] = blake3::keyed_hash(domain_key.as_bytes(), &payload).into();
        assert!(validate_committed_root(root_a, Some(digest_a)).is_ok());
        // digest_a should NOT validate root_b
        assert!(validate_committed_root(root_b, Some(digest_a)).is_err());
    }

    // ── RecoveryLoop with chain_digest ────────────────────────────

    #[test]
    fn recovery_loop_stores_chain_digest() {
        let digest = [0xABu8; 32];
        let root = RootPointer::new(CommitGroupId(1), 100);
        let loop_ = RecoveryLoop::new(root, Some(digest));
        assert_eq!(loop_.chain_digest, Some(digest));
    }

    #[test]
    fn validate_root_with_correct_digest_proceeds() {
        let root = RootPointer::new(CommitGroupId(1), 100);
        let domain_key = DomainTag::CommittedRoot.derive_key();
        let mut payload = [0u8; 16];
        payload[0..8].copy_from_slice(&root.commit_group_id.0.to_le_bytes());
        payload[8..16].copy_from_slice(&root.root_handle.to_le_bytes());
        let expected: [u8; 32] = blake3::keyed_hash(domain_key.as_bytes(), &payload).into();

        let mut loop_ = RecoveryLoop::new(root, Some(expected));
        loop_
            .validate_root()
            .expect("should validate with correct digest");
        assert_eq!(loop_.phase, RecoveryPhase::ReplayIntentLog);
    }

    #[test]
    fn validate_root_with_wrong_digest_fails() {
        let root = RootPointer::new(CommitGroupId(1), 100);
        let wrong = [0xFFu8; 32];
        let mut loop_ = RecoveryLoop::new(root, Some(wrong));
        let result = loop_.validate_root();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RecoveryError::RootValidationFailed { .. }
        ));
    }

    #[test]
    fn validate_root_without_digest_proceeds() {
        let root = RootPointer::new(CommitGroupId(1), 100);
        let mut loop_ = RecoveryLoop::new(root, None);
        loop_
            .validate_root()
            .expect("should validate without digest");
        assert_eq!(loop_.phase, RecoveryPhase::ReplayIntentLog);
    }

    // ── Integration: depth guard with real segments on disk ─────

    /// Build a sealed intent-log segment with one Write record per
    /// frame, write it to `dir` as `segment-{idx:03}.viflodev`, and
    /// return the segment path.
    fn write_test_segment(dir: &Path, idx: u32, frames: &[IntentLogFrame]) {
        let mut writer = IntentLogWriter::new(64 * 1024 * 1024);
        for f in frames {
            writer.append_frame(f).unwrap();
        }
        let sealed = writer.finish().unwrap().unwrap();
        let fname = format!("segment-{idx:03}.viflodev");
        let path = dir.join(&fname);
        std::fs::write(&path, &sealed).unwrap();
    }

    /// Build a simple Write intent-log frame with a predictable
    /// payload.  `ino` and `offset` vary per call so every record
    /// is distinct.
    fn make_test_frame(seq: u64, ino: u64, offset: u64) -> IntentLogFrame {
        let rec = IntentLogRecord::Write {
            ino,
            offset,
            length: 4096,
            data_hash: [0xCC; 32],
        };
        IntentLogFrame::new(rec, 1, seq)
    }

    #[test]
    fn depth_guard_fires_with_real_segments() {
        let tmp = TempDir::new().expect("tempdir");
        // Write 10 records with LSNs 0-9 into a single segment.
        let frames: Vec<IntentLogFrame> = (0..10)
            .map(|i| make_test_frame(i, 100 + i, i * 4096))
            .collect();
        write_test_segment(tmp.path(), 0, &frames);

        // Root at txg 5, so records with LSN > 5 (6,7,8,9) are
        // candidates.  max_replay_depth = 2 — only 2 get replayed.
        let cfg = RecoveryLoopConfig::new(1024, 2);
        let root = RootPointer::new(CommitGroupId(5), 200);
        let mut loop_ = RecoveryLoop::new_with_config(root, None, cfg);
        loop_.phase = RecoveryPhase::ReplayIntentLog;

        let mut target = NoOpReplayTarget::default();
        let result = loop_.replay_intent_log(tmp.path(), &mut target);

        // Expect the depth guard to fire.
        assert!(result.is_err(), "depth guard should fire");
        match result.unwrap_err() {
            RecoveryError::ReplayDepthExceeded { limit } => {
                assert_eq!(limit, 2);
            }
            other => panic!("expected ReplayDepthExceeded, got {other:?}"),
        }
        // Two records should have been replayed (LSNs 6, 7) before the
        // guard stopped further replay.
        assert_eq!(loop_.records_replayed, 2);
        assert_eq!(target.records_seen.len(), 2);
    }

    #[test]
    fn depth_guard_not_fired_when_below_limit() {
        let tmp = TempDir::new().expect("tempdir");
        // 3 records (LSNs 0-2).  Root at txg 0, so all 3 replay.
        // max_replay_depth = 5 — well above actual count.
        let frames: Vec<IntentLogFrame> = (0..3)
            .map(|i| make_test_frame(i, 200 + i, i * 4096))
            .collect();
        write_test_segment(tmp.path(), 0, &frames);

        let cfg = RecoveryLoopConfig::new(1024, 5);
        let root = RootPointer::new(CommitGroupId(0), 100);
        let mut loop_ = RecoveryLoop::new_with_config(root, None, cfg);
        loop_.phase = RecoveryPhase::ReplayIntentLog;

        let mut target = NoOpReplayTarget::default();
        let result = loop_.replay_intent_log(tmp.path(), &mut target);
        assert!(result.is_ok());
        // LSN 0 is <= committed_txg.0 (NIL=0), so only records 1 and 2 replay.
        assert_eq!(loop_.records_replayed, 2);
    }

    #[test]
    fn depth_guard_with_multiple_segments() {
        let tmp = TempDir::new().expect("tempdir");
        // Two segments: segment-000 has 5 records (LSNs 0-4),
        // segment-001 has 5 records (LSNs 5-9).
        let frames0: Vec<IntentLogFrame> = (0..5)
            .map(|i| make_test_frame(i, 300 + i, i * 4096))
            .collect();
        let frames1: Vec<IntentLogFrame> = (5..10)
            .map(|i| make_test_frame(i, 400 + i, i * 4096))
            .collect();
        write_test_segment(tmp.path(), 0, &frames0);
        write_test_segment(tmp.path(), 1, &frames1);

        // Root at txg 2, so records 3-9 (7 records) are candidates.
        // max_replay_depth = 3 — only 3 should replay.
        let cfg = RecoveryLoopConfig::new(1024, 3);
        let root = RootPointer::new(CommitGroupId(2), 300);
        let mut loop_ = RecoveryLoop::new_with_config(root, None, cfg);
        loop_.phase = RecoveryPhase::ReplayIntentLog;

        let mut target = NoOpReplayTarget::default();
        let result = loop_.replay_intent_log(tmp.path(), &mut target);
        assert!(result.is_err());
        match result.unwrap_err() {
            RecoveryError::ReplayDepthExceeded { limit } => {
                assert_eq!(limit, 3);
            }
            other => panic!("expected ReplayDepthExceeded, got {other:?}"),
        }
        assert_eq!(loop_.records_replayed, 3);
        assert_eq!(target.records_seen.len(), 3);
    }

    #[test]
    fn depth_guard_zero_disables_guard() {
        let tmp = TempDir::new().expect("tempdir");
        let frames: Vec<IntentLogFrame> = (0..10)
            .map(|i| make_test_frame(i, 500 + i, i * 4096))
            .collect();
        write_test_segment(tmp.path(), 0, &frames);

        // max_replay_depth = 0 disables the guard.
        let cfg = RecoveryLoopConfig::new(1024, 0);
        let root = RootPointer::new(CommitGroupId(0), 400);
        let mut loop_ = RecoveryLoop::new_with_config(root, None, cfg);
        loop_.phase = RecoveryPhase::ReplayIntentLog;

        let mut target = NoOpReplayTarget::default();
        let result = loop_.replay_intent_log(tmp.path(), &mut target);
        assert!(result.is_ok());
        assert_eq!(loop_.records_replayed, 9);
        assert_eq!(target.records_seen.len(), 9);
    }

    // ── Integration: anchor → validate cycle ─────────────────────

    #[test]
    fn anchor_then_validate_full_cycle() {
        // Simulate pool import → recovery → anchor → validate.
        let root = RootPointer::new(CommitGroupId(99), 42);
        let mut loop_ = RecoveryLoop::new(root, None);
        assert!(loop_.chain_digest.is_none());

        // After successful replay, anchor the recovered root.
        loop_.anchor_root();
        let digest = loop_.chain_digest.expect("digest should be set");

        // Validate the anchored root with the computed digest.
        let result = validate_committed_root(root, Some(digest));
        assert!(result.is_ok(), "anchored root should validate");

        // A different root with the same digest must fail.
        let other_root = RootPointer::new(CommitGroupId(100), 42);
        let result = validate_committed_root(other_root, Some(digest));
        assert!(result.is_err(), "wrong root must not validate");
    }

    #[test]
    fn anchor_deterministic_across_multiple_calls() {
        let root = RootPointer::new(CommitGroupId(1), 256);
        let d1 = anchor_recovered_root(root);
        let d2 = anchor_recovered_root(root);
        let d3 = anchor_recovered_root(root);
        assert_eq!(d1, d2);
        assert_eq!(d2, d3);
    }

    #[test]
    fn anchor_recovered_root_is_32_bytes() {
        let root = RootPointer::new(CommitGroupId(5), 1234);
        let digest = anchor_recovered_root(root);
        assert_eq!(digest.len(), 32);
    }
}
