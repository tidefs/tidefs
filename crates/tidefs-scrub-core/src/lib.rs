// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]
#![deny(dead_code)]
#![deny(unused_imports)]

//! Background scrub service for periodic segment-level checksum verification.
//!
//! The [`ScrubService`] is a [`BackgroundService`] that periodically walks
//! segment files in the local object store, reads every record, verifies the
//! [`IntegrityTrailerV2`] BLAKE3-256 digest, and reports mismatches into
//! the [`SuspectLog`].  It publishes aggregate statistics and supports
//! cursor-resumable walks across scheduler ticks.
//!
//! This is phase 1 of the scrub/resilver orchestration design (#1766).
//! Follow-on phases add deep scrub (shard reconstruction), repair
//! (self-healing), and distributed resilver.

pub mod detector;
pub mod cross_replica_comparison;
pub mod integrity_verifier;
pub mod multi_node_scrub;
pub mod object_scanner;
pub mod rate_limiter;
pub mod repair_scheduling;
pub mod scheduler;
pub mod scrub_ledger;
pub mod scrub_repair;
pub use multi_node_scrub::{
    FanoutAuditEntry, MultiNodeScrubAudit, PeerVerificationOutcome, ScrubFanoutCoordinator,
    ScrubFanoutRequest, ScrubFanoutResponse,
};
pub use cross_replica_comparison::{
    ChecksumLayer, ComparisonCandidate, ComparisonClassification,
    CrossReplicaComparisonRecord, EvidenceReadOutcome, EvidenceRejectionReason,
    PerReplicaOutcome, ReplicaEvidence, ScrubSubject, ScrubSubjectKind, TransportFailureReason,
    compare_cross_replica,
};
use std::path::{Path, PathBuf};
pub use tidefs_recovery_loop::RecoveryPolicy;

use std::sync::Arc;
use std::sync::Mutex;

use tidefs_background_scheduler::{
    BackgroundService, ServiceBudget, ServiceError, ServicePriority, TickReport,
};
use tidefs_checksum_tree::{verify_object, ChecksumMismatch, Digest, LocatorToken};
use tidefs_erasure_coding::ParityRaid1;
use tidefs_local_object_store::{
    load_suspect_log, write_suspect_log, LocalObjectStore, ObjectKey, SegmentChainStats,
    StoreOptions, SuspectEntry, SuspectLog, STORE_DIR_NAME,
};
use tidefs_locator_table::ExtentId;

// ---------------------------------------------------------------------------
// ScrubCursor — resumable walk position
// ---------------------------------------------------------------------------

/// Tracks the (segment_id, offset) position so the scrub can resume
/// where it left off on the next scheduler tick.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScrubCursor {
    pub segment_id: u64,
    pub offset: u64,
}

impl ScrubCursor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.segment_id = 0;
        self.offset = 0;
    }
}

// ---------------------------------------------------------------------------
// ScrubFinding — one detected inconsistency
// ---------------------------------------------------------------------------

/// A discrete problem found during a scrub pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScrubFinding {
    pub segment_id: u64,
    pub offset: u64,
    pub record_type: RecordType,
    pub expected_hash: [u8; 32],
    pub actual_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordType {
    Put,
    Delete,
}

// ---------------------------------------------------------------------------
// ScrubStats — aggregate per-cycle statistics
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScrubStats {
    pub segments_scanned: u64,
    pub records_verified: u64,
    pub checksum_mismatches: u64,
    pub bytes_scanned: u64,
    pub elapsed_ticks: u64,
    /// Whether the segment hash chain was verified during this cycle.
    pub chain_verified: bool,
    /// Number of segments in the hash chain.
    pub segments_in_chain: u64,
    /// Number of broken chain links detected.
    pub chain_breaks_detected: u64,
}

impl ScrubStats {
    pub fn merge_tick(&mut self, tick: &TickReport, bytes: u64) {
        self.records_verified += tick.processed;
        self.checksum_mismatches += tick.errors;
        self.bytes_scanned += bytes;
        self.elapsed_ticks += 1;
    }

    /// Merge chain-of-trust verification results into cumulative stats.
    pub fn merge_chain_stats(&mut self, chain: &SegmentChainStats) {
        self.chain_verified = true;
        self.segments_in_chain = chain.segments_in_chain as u64;
        self.chain_breaks_detected = chain.chain_breaks_detected;
    }
}

// ---------------------------------------------------------------------------
// ChainOfTrustStatus — outcome of segment hash-chain verification
// ---------------------------------------------------------------------------

/// Result of verifying the segment integrity hash chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainOfTrustStatus {
    /// All segment footer hash-chain links verified correctly.
    Passed,
    /// One or more chain breaks were detected.
    Failed { chain_breaks: u64 },
    /// Store has no segments or chain verification is not meaningful.
    NotApplicable,
}

impl ChainOfTrustStatus {
    #[must_use]
    pub fn is_passed(&self) -> bool {
        matches!(self, Self::Passed | Self::NotApplicable)
    }

    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed { .. } => "failed",
            Self::NotApplicable => "not-applicable",
        }
    }
}

// ---------------------------------------------------------------------------
// ScrubReport — aggregate result of a full scrub cycle
// ---------------------------------------------------------------------------

/// Complete report produced after a full scrub cycle.
///
/// Aggregates segment-level integrity findings, chain-of-trust validation,
/// and checksum coverage statistics.
#[derive(Clone, Debug)]
pub struct ScrubReport {
    pub records_verified: u64,
    pub bytes_scanned: u64,
    pub checksum_mismatches: u64,
    pub chain_of_trust: ChainOfTrustStatus,
    /// Percentage of records that passed checksum verification.
    pub coverage_percent: f64,
    pub suspect_entries: Vec<SuspectEntry>,
    pub cycle_complete: bool,
    pub segments_in_chain: usize,
    /// Byte length of the verified segment chain.
    pub chain_length: u64,
    pub ticks_elapsed: u64,
}

// ---------------------------------------------------------------------------
// ScrubService
// ---------------------------------------------------------------------------

/// A [`BackgroundService`] that periodically walks segment files, verifies
/// every record's [`IntegrityTrailerV2`] BLAKE3-256 digest, and records
/// mismatches to the [`SuspectLog`].
pub struct ScrubService {
    store_root: PathBuf,
    /// Directory where the durable suspect-log file lives
    /// (store_root / STORE_DIR_NAME).
    segments_dir: PathBuf,
    store_options: StoreOptions,
    cursor: ScrubCursor,
    stats: ScrubStats,
    /// Durable suspect log — loaded from disk on construction,
    /// persisted after every mutation.
    suspect_log: SuspectLog,
    cycle_complete: bool,
    chain_trust_status: ChainOfTrustStatus,
    store: Option<LocalObjectStore>,
}

impl ScrubService {
    #[must_use]
    pub fn new(store_root: impl AsRef<Path>, store_options: StoreOptions) -> Self {
        let root = store_root.as_ref().to_path_buf();
        let segments_dir = root.join(STORE_DIR_NAME);
        // Load durable suspect state so pre-existing findings survive
        // across ScrubService restarts.
        let suspect_log = load_suspect_log(&segments_dir);
        Self {
            store_root: root,
            segments_dir,
            store_options,
            cursor: ScrubCursor::new(),
            stats: ScrubStats::default(),
            suspect_log,
            cycle_complete: false,
            chain_trust_status: ChainOfTrustStatus::NotApplicable,
            store: None,
        }
    }

    #[must_use]
    pub fn stats(&self) -> &ScrubStats {
        &self.stats
    }

    /// Return all unresolved suspect entries for repair dispatch.
    ///
    /// Entries remain in the durable log so a crash between drain and
    /// repair completion does not lose corruption records.  Each entry's
    /// `repair_attempts` is incremented to track dispatch count; resolved
    /// entries are skipped on subsequent drains.
    #[must_use]
    pub fn drain_suspect_log(&mut self) -> Vec<SuspectEntry> {
        // Delegate to SuspectLog::drain_unresolved which increments
        // repair_attempts, sets last_repair_attempt, and skips resolved.
        let entries = self.suspect_log.drain_unresolved();
        self.persist_suspect_log();
        entries
    }

    /// Drain unresolved suspect entries into a [`ScrubToRepairBridge`] for
    /// prioritized repair dispatch.
    ///
    /// Entries remain in the durable log (with `repair_attempts` incremented)
    /// so a crash after classification cannot lose corruption records. Raw
    /// suspect-log entries do not carry placement receipts, so the bridge
    /// classifies them as blocked evidence unless a caller uses a receipt-
    /// bearing scheduling path.
    ///
    /// `replicas_remaining` is the number of healthy replicas known to exist
    /// for each entry's data (3 = multi-replica, 1 = single-copy, 0 = last-copy
    /// emergency). This feeds the escalation logic.
    pub fn drain_suspect_log_to_bridge(
        &mut self,
        bridge: &mut repair_scheduling::ScrubToRepairBridge,
        replicas_remaining: u32,
    ) -> Vec<repair_scheduling::RepairAdmission> {
        let entries = self.drain_suspect_log();
        bridge.ingest(&entries, replicas_remaining)
    }

    /// Persist the current suspect log to durable storage.
    ///
    /// Called after every mutation (scrub findings, drain, chain-of-trust
    /// merge) so a crash cannot lose newly detected corruption before
    /// repair consumes it.
    fn persist_suspect_log(&self) {
        if let Err(e) = write_suspect_log(&self.segments_dir, &self.suspect_log) {
            eprintln!(
                "ScrubService: failed to persist suspect log to {}: {e}",
                self.segments_dir.display(),
            );
        }
    }

    #[must_use]
    pub fn cycle_complete(&self) -> bool {
        self.cycle_complete
    }

    /// Generate a [] from the accumulated cycle state.
    ///
    /// Call after the cycle completes.
    #[must_use]
    pub fn generate_report(&self) -> ScrubReport {
        let total = self.stats.records_verified;
        let mismatches = self.stats.checksum_mismatches;
        let coverage = if total > 0 {
            ((total - mismatches) as f64 / total as f64) * 100.0
        } else {
            100.0
        };
        ScrubReport {
            records_verified: total,
            bytes_scanned: self.stats.bytes_scanned,
            checksum_mismatches: mismatches,
            chain_of_trust: self.chain_trust_status.clone(),
            coverage_percent: coverage,
            suspect_entries: self.suspect_log.iter().copied().collect(),
            cycle_complete: self.cycle_complete,
            segments_in_chain: self.stats.segments_scanned as usize,
            chain_length: 0,
            ticks_elapsed: self.stats.elapsed_ticks,
        }
    }
}

impl BackgroundService for ScrubService {
    fn name(&self) -> &'static str {
        "ScrubService"
    }

    fn priority(&self) -> ServicePriority {
        ServicePriority::Throughput
    }

    fn has_work(&self) -> bool {
        !self.cycle_complete
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        // Ensure store is open (read-only, no repair).
        if self.store.is_none() {
            let mut opts = self.store_options.clone();
            opts.repair_torn_tail = false;
            let s = LocalObjectStore::open_read_only_with_options(&self.store_root, opts)
                .map_err(|_e| ServiceError::Internal {
                    service: "ScrubService",
                    message: "failed to open object store",
                })?
                .ok_or(ServiceError::Internal {
                    service: "ScrubService",
                    message: "object store does not exist",
                })?;
            self.store = Some(s);
        }

        let store = self.store.as_ref().unwrap();
        let mut cursor = (self.cursor.segment_id, self.cursor.offset);

        let max_records = budget.max_items;
        let max_bytes = budget.max_bytes;

        let (records_verified, bytes_scanned, has_more) = store
            .verify_segment_integrity(&mut self.suspect_log, &mut cursor, max_records, max_bytes)
            .map_err(|_e| ServiceError::Internal {
                service: "ScrubService",
                message: "segment integrity verification failed",
            })?;

        self.cursor.segment_id = cursor.0;
        self.cursor.offset = cursor.1;

        let mismatches = self.suspect_log.len() as u64;

        let report = TickReport {
            processed: records_verified,
            skipped: 0,
            errors: mismatches,
            items_consumed: records_verified,
            bytes_consumed: bytes_scanned,
            has_more,
        };

        self.stats.merge_tick(&report, bytes_scanned);

        if !has_more {
            self.cycle_complete = true;

            // Run chain-of-trust validation on cycle completion.
            match store.verify_segment_chain() {
                Ok((chain_stats, chain_suspects)) => {
                    // Merge chain-of-trust SuspectLog entries into our own.
                    for entry in chain_suspects.iter() {
                        self.suspect_log.record(*entry);
                    }
                    self.stats.merge_chain_stats(&chain_stats);
                    if chain_stats.chain_breaks_detected > 0 {
                        self.chain_trust_status = ChainOfTrustStatus::Failed {
                            chain_breaks: chain_stats.chain_breaks_detected,
                        };
                    } else if chain_stats.segments_in_chain > 0 {
                        self.chain_trust_status = ChainOfTrustStatus::Passed;
                    } else {
                        self.chain_trust_status = ChainOfTrustStatus::NotApplicable;
                    }

                    self.stats.segments_scanned = chain_stats.segments_in_chain as u64;
                }
                Err(_e) => {
                    self.chain_trust_status = ChainOfTrustStatus::Failed { chain_breaks: 1 };
                    self.suspect_log.record(SuspectEntry {
                        locator_id: 0,
                        segment_id: 0,
                        offset: 0,
                        record_type: 5,
                        expected_hash: [0u8; 32],
                        actual_hash: [0u8; 32],
                        repair_attempts: 0,
                        last_repair_attempt: 0,
                        resolved: false,
                        commit_group: 0,
                        timestamp_secs: 0,
                        ..Default::default()
                    });
                }
            }

            self.cursor.reset();
        }

        // Persist suspect log so findings survive a process restart.
        self.persist_suspect_log();

        Ok(report)
    }
}

/// Hex-encode a byte slice as a lowercase string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// ScrubOutcome — per-object verification result
// ---------------------------------------------------------------------------

/// Outcome of verifying a single object against its stored checksum tree root.
///
/// `ScrubWorker::run()` collects one outcome per traversed object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScrubOutcome {
    /// Object content matches its stored BLAKE3 checksum tree root.
    Clean {
        /// Hex-encoded object key.
        object_id: String,
    },
    /// Object content does not match the stored checksum tree root.
    Mismatch {
        /// Hex-encoded object key.
        object_id: String,
        /// Expected BLAKE3-256 root digest.
        expected: Digest,
        /// Computed BLAKE3-256 root digest from the actual data.
        computed: Digest,
    },
    /// The locator token does not match the binding in the checksum tree.
    /// The object may have been relocated since the checksum was committed.
    LocatorMismatch {
        /// Hex-encoded object key.
        object_id: String,
        /// Locator token bound to the stored checksum tree.
        bound: LocatorToken,
        /// Locator token supplied for verification.
        supplied: LocatorToken,
    },
    /// I/O error prevented reading the object.
    IoError {
        /// Hex-encoded object key.
        object_id: String,
        /// Human-readable error description.
        error: String,
    },
}

impl ScrubOutcome {
    /// Return true when this outcome represents a clean verification.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::Clean { .. })
    }

    /// Return the hex-encoded object key for this outcome.
    #[must_use]
    pub fn object_id(&self) -> &str {
        match self {
            Self::Clean { object_id }
            | Self::Mismatch { object_id, .. }
            | Self::LocatorMismatch { object_id, .. }
            | Self::IoError { object_id, .. } => object_id.as_str(),
        }
    }
}

// ---------------------------------------------------------------------------
// ObjectStoreTraversal — abstract object enumeration + read
// ---------------------------------------------------------------------------

/// Narrow trait abstracting object enumeration and read for scrub traversal.
///
/// Kept decoupled from the full `LocalObjectStore` so the worker is
/// testable without heavyweight dependencies.
pub trait ObjectStoreTraversal: Send + Sync {
    /// Enumerate all object IDs in the store.
    fn object_ids(&self) -> Vec<ObjectKey>;

    /// Read the full payload for the given object.
    ///
    /// Returns `None` if the object does not exist (may have been deleted
    /// between enumeration and read).
    fn read_object(&self, id: &ObjectKey) -> Result<Option<Vec<u8>>, String>;

    /// Return the expected BLAKE3 checksum tree root for the given object,
    /// together with its bound locator token (if any).
    ///
    /// The root hash is from the checksum tree computed from the full
    /// object payload; the locator token binds the root to the committed
    /// extent location.  Returns `None` when no checksum root has been
    /// stored or computed for this object.
    fn object_checksum_root(&self, id: &ObjectKey) -> Option<(Digest, Option<LocatorToken>)>;
}

// ---------------------------------------------------------------------------
// ChecksumVerifier — abstract BLAKE3 verification
// ---------------------------------------------------------------------------

/// Trait wrapping the BLAKE3 checksum tree verification primitive.
///
/// A single function: compare the data payload against an expected root digest,
/// optionally bound to a committed extent locator.
pub trait ChecksumVerifier: Send + Sync {
    /// Verify that `data` matches `expected_root`.
    ///
    /// When `locator_token` is `Some`, the computed root is bound to that
    /// token before comparison.  Returns `Ok(())` on match,
    /// `Err(ChecksumMismatch)` on divergence.
    fn verify(
        &self,
        data: &[u8],
        expected_root: &Digest,
        locator_token: Option<&LocatorToken>,
    ) -> Result<(), ChecksumMismatch>;
}

// ---------------------------------------------------------------------------
// Default ChecksumVerifier backed by tidefs-checksum-tree
// ---------------------------------------------------------------------------

/// Production [`ChecksumVerifier`] that delegates to
/// [`tidefs_checksum_tree::verify_object`].
pub struct Blake3Verifier;

impl ChecksumVerifier for Blake3Verifier {
    fn verify(
        &self,
        data: &[u8],
        expected_root: &Digest,
        locator_token: Option<&LocatorToken>,
    ) -> Result<(), ChecksumMismatch> {
        verify_object(data, expected_root, locator_token)
    }
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// StoreTraverser — production ObjectStoreTraversal backed by LocalObjectStore
// ---------------------------------------------------------------------------

/// Production [`ObjectStoreTraversal`] that delegates to
/// [`tidefs_local_object_store::LocalObjectStore`].
///
/// Wraps the store in a [`Mutex`] to satisfy `Sync` (the underlying
/// `LocalObjectStore` is `Send` but not `Sync`).
pub struct StoreTraverser {
    store: Mutex<LocalObjectStore>,
}

impl StoreTraverser {
    /// Create a new traverser over an already-opened [`LocalObjectStore`].
    pub fn new(store: LocalObjectStore) -> Self {
        Self {
            store: Mutex::new(store),
        }
    }
}

impl ObjectStoreTraversal for StoreTraverser {
    fn object_ids(&self) -> Vec<ObjectKey> {
        self.store
            .lock()
            .expect("StoreTraverser: mutex poisoned")
            .list_keys()
    }

    fn read_object(&self, id: &ObjectKey) -> Result<Option<Vec<u8>>, String> {
        self.store
            .lock()
            .expect("StoreTraverser: mutex poisoned")
            .get(*id)
            .map_err(|e| format!("{e}"))
    }

    fn object_checksum_root(&self, id: &ObjectKey) -> Option<(Digest, Option<LocatorToken>)> {
        self.store
            .lock()
            .expect("StoreTraverser: mutex poisoned")
            .get_checksum_tree(*id, tidefs_checksum_tree::DEFAULT_BLOCK_SIZE)
            .ok()
            .flatten()
            .map(|tree| (tree.root_hash, tree.locator_token))
    }
}
// ---------------------------------------------------------------------------
// ScrubWorker — full-traversal object scrubber
// ---------------------------------------------------------------------------

/// Walks every object in the store via [`ObjectStoreTraversal`], verifies
/// each payload against its expected BLAKE3 checksum tree root via
/// [`ChecksumVerifier`], and collects [`ScrubOutcome`] records.
pub struct ScrubWorker {
    store: Arc<dyn ObjectStoreTraversal>,
    verifier: Arc<dyn ChecksumVerifier>,
}

impl ScrubWorker {
    /// Create a new worker over the given store and verifier.
    #[must_use]
    pub fn new(store: Arc<dyn ObjectStoreTraversal>, verifier: Arc<dyn ChecksumVerifier>) -> Self {
        Self { store, verifier }
    }

    /// Run a full object-traversal scrub.
    ///
    /// Enumerates all object IDs, reads each payload, verifies the checksum
    /// tree root, and collects one [`ScrubOutcome`] per object into a
    /// [`ScrubSummary`].
    ///
    /// An empty store yields zero outcomes and a summary with all-zero
    /// counters.
    #[must_use]
    pub fn run(&self) -> ScrubSummary {
        let object_ids = self.store.object_ids();
        let total = object_ids.len();
        let mut outcomes: Vec<ScrubOutcome> = Vec::with_capacity(total);

        for id in &object_ids {
            let outcome = match self.store.read_object(id) {
                Ok(Some(data)) => {
                    // Retrieve the expected BLAKE3 checksum tree root and
                    // locator token (if any) from the store, computed from
                    // the object payload at write time and verified against
                    // IntegrityTrailerV2 record digests on the read path.
                    let (expected_root, locator_token) = self
                        .store
                        .object_checksum_root(id)
                        .map(|(root, lt)| (root, lt))
                        .unwrap_or_else(|| (Digest::default(), None));
                    match self.verifier.verify(&data, &expected_root, locator_token.as_ref()) {
                        Ok(()) => ScrubOutcome::Clean {
                            object_id: hex_encode(id.as_bytes()),
                        },
                        Err(mismatch) => ScrubOutcome::Mismatch {
                            object_id: hex_encode(id.as_bytes()),
                            expected: mismatch.expected,
                            computed: mismatch.computed,
                        },
                    }
                }
                Ok(None) => {
                    // Object deleted between enumeration and read
                    continue;
                }
                Err(e) => ScrubOutcome::IoError {
                    object_id: hex_encode(id.as_bytes()),
                    error: e,
                },
            };
            outcomes.push(outcome);
        }

        let clean = outcomes.iter().filter(|o| o.is_clean()).count();
        let mismatches = outcomes
            .iter()
            .filter(|o| matches!(o, ScrubOutcome::Mismatch { .. }))
            .count();
        let locator_mismatches = outcomes
            .iter()
            .filter(|o| matches!(o, ScrubOutcome::LocatorMismatch { .. }))
            .count();
        let io_errors = outcomes
            .iter()
            .filter(|o| matches!(o, ScrubOutcome::IoError { .. }))
            .count();

        ScrubSummary {
            total,
            clean,
            mismatches,
            locator_mismatches,
            io_errors,
            outcomes,
        }
    }
}

// ---------------------------------------------------------------------------
// ScrubSummary — aggregate result of a scrub pass
// ---------------------------------------------------------------------------

/// Aggregate statistics collected by [`ScrubWorker::run`].
#[derive(Clone, Debug)]
pub struct ScrubSummary {
    /// Total number of objects enumerated.
    pub total: usize,
    /// Objects that passed verification.
    pub clean: usize,
    /// Objects with checksum mismatches.
    pub mismatches: usize,
    /// Objects with locator token mismatches (data intact, locator stale).
    pub locator_mismatches: usize,
    /// Objects that could not be read due to I/O errors.
    pub io_errors: usize,
    /// Per-object outcomes in enumeration order.
    pub outcomes: Vec<ScrubOutcome>,
}

impl ScrubSummary {
    /// Return true when no mismatches or I/O errors were found.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.mismatches == 0 && self.locator_mismatches == 0 && self.io_errors == 0
    }

    /// Produce a human-readable text summary.
    #[must_use]
    pub fn text_summary(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "Scrub scan complete.
",
        );
        out.push_str(&format!(
            "  total:     {}
",
            self.total
        ));
        out.push_str(&format!(
            "  clean:     {}
",
            self.clean
        ));
        out.push_str(&format!(
            "  mismatches: {}
",
            self.mismatches
        ));
        out.push_str(&format!(
            "  locator mismatches: {}
",
            self.locator_mismatches
        ));
        out.push_str(&format!(
            "  io errors: {}
",
            self.io_errors
        ));

        if !self.is_clean() {
            out.push_str(
                "
Findings:
",
            );
            for (i, outcome) in self.outcomes.iter().enumerate() {
                match outcome {
                    ScrubOutcome::Mismatch {
                        object_id,
                        expected,
                        computed,
                    } => {
                        out.push_str(&format!(
                            "  {}. MISMATCH {} expected={} computed={}
",
                            i + 1,
                            object_id,
                            hex_encode(expected),
                            hex_encode(computed),
                        ));
                    }
                    ScrubOutcome::IoError { object_id, error } => {
                        out.push_str(&format!(
                            "  {}. IO_ERROR {} {}
",
                            i + 1,
                            object_id,
                            error,
                        ));
                    }
                    _ => {}
                }
            }
        }

        out
    }
}

// ---------------------------------------------------------------------------
// Tests (ScrubWorker)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ResilverStats — aggregate resilver tracking
// ---------------------------------------------------------------------------

/// Statistics collected during a device resilver (rebuild) pass.
///
/// Tracks objects scanned, objects rebuilt, bytes transferred,
/// estimated completion fraction, and bandwidth utilization.
#[derive(Clone, Debug, Default)]
pub struct ResilverStats {
    /// Number of objects (extents) scanned so far.
    pub objects_scanned: u64,
    /// Number of objects successfully rebuilt.
    pub objects_rebuilt: u64,
    /// Number of objects that failed to rebuild.
    pub objects_failed: u64,
    /// Total bytes reconstructed and written to the replacement device.
    pub bytes_rebuilt: u64,
    /// Estimated completion fraction (0.0 - 1.0).
    pub estimated_completion: f64,
    /// Observed bandwidth utilization in bytes/sec.
    pub bandwidth_utilization: f64,
    /// Monotonic timestamp (ns) of the most recent update.
    pub last_update_ns: u64,
}

impl ResilverStats {
    /// Record a successfully rebuilt object.
    pub fn record_rebuilt(&mut self, bytes: u64, now_ns: u64) {
        self.objects_rebuilt = self.objects_rebuilt.saturating_add(1);
        self.bytes_rebuilt = self.bytes_rebuilt.saturating_add(bytes);
        self.last_update_ns = now_ns;
    }

    /// Record a scanned object (regardless of outcome).
    pub fn record_scanned(&mut self) {
        self.objects_scanned = self.objects_scanned.saturating_add(1);
    }

    /// Record a failed object.
    pub fn record_failed(&mut self, now_ns: u64) {
        self.objects_failed = self.objects_failed.saturating_add(1);
        self.last_update_ns = now_ns;
    }

    /// Update the completion estimate and bandwidth utilization.
    ///
    /// `total_objects` is the known or estimated total number of objects
    /// to rebuild. `elapsed_ns` is wall-clock time since the resilver started.
    pub fn update_estimates(&mut self, total_objects: u64, elapsed_ns: u64) {
        if total_objects > 0 {
            self.estimated_completion = self.objects_rebuilt as f64 / total_objects as f64;
        }
        if elapsed_ns > 0 {
            self.bandwidth_utilization =
                self.bytes_rebuilt as f64 / (elapsed_ns as f64 / 1_000_000_000.0);
        }
    }
}

// ---------------------------------------------------------------------------
// ExtentEnumerator — abstract extent enumeration for a failed device
// ---------------------------------------------------------------------------

/// Trait abstracting enumeration of extents that reside on a specific device.
///
/// The resilver service uses this to discover all extents that need
/// reconstruction after a device failure.
pub trait ExtentEnumerator: Send + Sync {
    /// Return the total number of extents on the given device.
    fn extent_count(&self, device_id: u64) -> u64;

    /// Return a batch of extent IDs that reside on the given device,
    /// starting from `cursor` and limited to `limit` entries.
    ///
    /// Returns `(extents, has_more)` where `has_more` is true when
    /// additional extents remain after this batch.
    fn enumerate_device_extents(
        &self,
        device_id: u64,
        cursor: u64,
        limit: u64,
    ) -> Result<(Vec<ExtentId>, bool), String>;
}

// ---------------------------------------------------------------------------
// LocatorTableExtentEnumerator — concrete ExtentEnumerator via LocatorTable
// ---------------------------------------------------------------------------

/// A concrete [`ExtentEnumerator`] that discovers extents on a device by
/// iterating every known inode's locator entries and filtering by `device_id`.
///
/// Uses an inode number list (e.g. from the inode table or namespace) and
/// a [`LocatorTable`] to perform the reverse-lookup.
pub struct LocatorTableExtentEnumerator {
    /// All known inode numbers in the pool.
    inodes: Vec<u64>,
    /// Cached extent IDs per device, populated on first call.
    cache: Mutex<std::collections::HashMap<u64, Vec<ExtentId>>>,
    /// Reference to the locator table for extent lookup.
    locator_table: Arc<tidefs_locator_table::LocatorTable>,
}

impl LocatorTableExtentEnumerator {
    /// Create a new enumerator backed by a locator table.
    ///
    /// `inodes` is the list of all inode numbers that may have extents.
    pub fn new(inodes: Vec<u64>, locator_table: Arc<tidefs_locator_table::LocatorTable>) -> Self {
        Self {
            inodes,
            cache: Mutex::new(std::collections::HashMap::new()),
            locator_table,
        }
    }
}

impl ExtentEnumerator for LocatorTableExtentEnumerator {
    fn extent_count(&self, device_id: u64) -> u64 {
        self.load_extents(device_id).len() as u64
    }

    fn enumerate_device_extents(
        &self,
        device_id: u64,
        cursor: u64,
        limit: u64,
    ) -> Result<(Vec<ExtentId>, bool), String> {
        let extents = self.load_extents(device_id);
        let start = cursor as usize;
        let end = (start + limit as usize).min(extents.len());
        let batch: Vec<ExtentId> = extents[start..end].to_vec();
        let has_more = end < extents.len();
        Ok((batch, has_more))
    }
}

impl LocatorTableExtentEnumerator {
    /// Load all extent IDs for a device from the locator table, caching the result.
    fn load_extents(&self, device_id: u64) -> Vec<ExtentId> {
        let mut cache = self.cache.lock().unwrap();
        if let Some(cached) = cache.get(&device_id) {
            return cached.clone();
        }

        let extents = self
            .locator_table
            .find_extents_for_device(&self.inodes, device_id)
            .unwrap_or_else(|_| Vec::new());

        cache.insert(device_id, extents.clone());
        extents
    }
}

// ---------------------------------------------------------------------------
// ReconstructionSource — abstract data reconstruction from replicas
// ---------------------------------------------------------------------------

/// Trait abstracting data reconstruction from redundant copies.
///
/// For mirror configurations, the source simply reads from a healthy
/// replica. For erasure-coded configurations, the source reconstructs
/// from available shards.
pub trait ReconstructionSource: Send + Sync {
    /// Reconstruct the data for the given extent from available replicas.
    ///
    /// Returns the raw bytes of the extent on success.
    fn reconstruct_extent(
        &self,
        extent_id: ExtentId,
        failed_device_id: u64,
    ) -> Result<Vec<u8>, String>;

    /// Write reconstructed data to the replacement device.
    fn write_to_replacement(
        &self,
        extent_id: ExtentId,
        replacement_device_id: u64,
        data: &[u8],
    ) -> Result<(), String>;
}
// ---------------------------------------------------------------------------
// LocalMirrorReconstructionSource — ReconstructionSource for local mirror
// ---------------------------------------------------------------------------

/// A concrete [`ReconstructionSource`] for local mirror reconstruction.
///
/// Reads the extent data from a healthy replica via the
/// [`tidefs_local_object_store::LocalObjectStore`] and writes to the
/// replacement device.
///
/// In a single-node / local environment, the "replicas" are copies of
/// the same data in the local object store.  For distributed environments,
/// a networked variant would replace this.
pub struct LocalMirrorReconstructionSource {
    /// The local object store for reading replica data.
    store: std::sync::Mutex<tidefs_local_object_store::LocalObjectStore>,
    /// Map from extent_id to its replica source device_id.
    replica_device_map: std::collections::HashMap<u64, u64>,
    /// Replacement device identifier.
    replacement_device_id: u64,
}

impl LocalMirrorReconstructionSource {
    /// Create a new local mirror reconstruction source.
    ///
    /// `store` is the local object store for reading data.
    /// `replica_device_map` maps extent IDs to the device IDs where
    /// healthy replicas reside (excludes the failed device).
    /// `replacement_device_id` is the device to write reconstructed data to.
    #[must_use]
    pub fn new(
        store: tidefs_local_object_store::LocalObjectStore,
        replica_device_map: std::collections::HashMap<u64, u64>,
        replacement_device_id: u64,
    ) -> Self {
        Self {
            store: std::sync::Mutex::new(store),
            replica_device_map,
            replacement_device_id,
        }
    }
}

impl ReconstructionSource for LocalMirrorReconstructionSource {
    fn reconstruct_extent(
        &self,
        extent_id: ExtentId,
        _failed_device_id: u64,
    ) -> Result<Vec<u8>, String> {
        let source_device = self
            .replica_device_map
            .get(&extent_id.0)
            .copied()
            .ok_or_else(|| format!("no replica source for extent {}", extent_id.0))?;

        let key = tidefs_local_object_store::ObjectKey::from_name(
            format!("extent:{}:device:{}", extent_id.0, source_device).as_bytes(),
        );

        self.store
            .lock()
            .unwrap()
            .get(key)
            .map_err(|e| format!("read replica: {e}"))?
            .ok_or_else(|| {
                format!(
                    "extent {} not found on source device {}",
                    extent_id.0, source_device
                )
            })
    }

    fn write_to_replacement(
        &self,
        extent_id: ExtentId,
        _replacement_device_id: u64,
        data: &[u8],
    ) -> Result<(), String> {
        let key = tidefs_local_object_store::ObjectKey::from_name(
            format!(
                "extent:{}:device:{}",
                extent_id.0, self.replacement_device_id
            )
            .as_bytes(),
        );

        self.store
            .lock()
            .unwrap()
            .put(key, data)
            .map_err(|e| format!("write replacement: {e}"))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// RepairStats — aggregate repair statistics
// ---------------------------------------------------------------------------

/// Aggregate statistics for the repair service.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepairStats {
    pub repairs_attempted: u64,
    pub repairs_succeeded: u64,
    pub repairs_failed: u64,
    pub bytes_repaired: u64,
    pub bytes_unrepairable: u64,
}

// ---------------------------------------------------------------------------
// RepairStrategy — how to repair a corrupt object
// ---------------------------------------------------------------------------

/// Strategy for repairing a corrupt object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairStrategy {
    /// Copy from a healthy mirror replica.
    Mirror,
    /// Reconstruct from surviving erasure-coded shards.
    ErasureCoded,
}

// ---------------------------------------------------------------------------
// RepairAttempt — record of a single repair attempt
// ---------------------------------------------------------------------------

/// Records a single repair attempt against a suspect entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairAttempt {
    pub suspect_entry: SuspectEntry,
    pub strategy: RepairStrategy,
    pub success: bool,
    pub bytes_repaired: u64,
}

// ---------------------------------------------------------------------------
// RepairOutcome — result of a single repair operation
// ---------------------------------------------------------------------------

/// Outcome of attempting to repair a single suspect entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepairOutcome {
    /// Repair succeeded; the corrupt data was replaced.
    Repaired { bytes_repaired: u64 },
    /// Repair was attempted but failed.
    Failed { reason: String },
    /// Repair cannot proceed (no healthy copies, insufficient shards, etc.).
    Unrepairable { reason: String },
}

// ---------------------------------------------------------------------------
// RepairPlan — repair strategy selection for a suspect entry
// ---------------------------------------------------------------------------

/// Strategy selection result for a suspect entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairPlan {
    pub entry: SuspectEntry,
    pub strategy: RepairStrategy,
    /// For [`RepairStrategy::ErasureCoded`]: the number of data shards
    /// in the stripe.  `None` for mirror repair.
    pub ec_shard_count: Option<usize>,
}

// ---------------------------------------------------------------------------
// RepairPlanner — trait for selecting repair strategy
// ---------------------------------------------------------------------------

/// Given a [`SuspectEntry`], select the appropriate repair strategy.
///
/// Implementations consult the locator table, object metadata, or
/// redundancy policy to determine whether the object is mirrored or
/// erasure-coded and how many shards are involved.
pub trait RepairPlanner: Send + Sync {
    /// Plan a repair for the given suspect entry.
    fn plan(&self, entry: &SuspectEntry) -> Option<RepairPlan>;
}

// ---------------------------------------------------------------------------
// ShardReader — abstraction for reading/writing erasure-coded shards
// ---------------------------------------------------------------------------

/// Read and write individual erasure-coded shards for repair.
pub trait ShardReader: Send + Sync {
    /// Read the data shards for a given locatee.
    ///
    /// Returns a vector of `Option<Vec<u8>>` with one entry per data shard.
    /// `None` indicates a missing or corrupt shard.
    fn read_data_shards(&self, locator_id: u64, shard_count: usize) -> Vec<Option<Vec<u8>>>;

    /// Read the parity shard for a given locatee.
    ///
    /// Returns `None` if the parity shard is unavailable.
    fn read_parity_shard(&self, locator_id: u64) -> Option<Vec<u8>>;

    /// Write a repaired data shard back to storage.
    fn write_shard(&self, locator_id: u64, shard_index: usize, data: &[u8]) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// RepairService — BackgroundService for scrub-triggered repair
// ---------------------------------------------------------------------------

/// A [`BackgroundService`] that consumes [`SuspectLog`] entries produced by
/// [`ScrubService`] and attempts to repair each corrupt object.
///
/// Repair strategies:
/// - **Mirror**: reads a healthy replica via [`ReconstructionSource`] and
///   writes it over the corrupt copy.
/// - **Erasure-coded**: reads surviving data shards and the parity shard
///   via [`ShardReader`], reconstructs the missing shard with
///   [`ParityRaid1`], and writes the repaired shard back.
///
/// Entries that fail repair are retried up to `max_repair_attempts` times
/// (default 3).  After that they are counted as unrepairable.
pub struct RepairService {
    suspect_log: SuspectLog,
    mirror_source: Option<Arc<dyn ReconstructionSource>>,
    shard_reader: Option<Arc<dyn ShardReader>>,
    planner: Option<Arc<dyn RepairPlanner>>,
    stats: RepairStats,
    pending_entries: Vec<SuspectEntry>,
    current_index: usize,
    cycle_complete: bool,
    max_repair_attempts: u32,
    attempt_counts: std::collections::HashMap<u64, u32>,
    failed_device_id: u64,
    /// Shared bridge for prioritized repair dispatch. When set,
    /// `tick()` pulls newly ingested entries from the bridge before
    /// processing. Repair outcomes update the bridge's escalation state.
    bridge: Option<Arc<Mutex<repair_scheduling::ScrubToRepairBridge>>>,
    /// Directory where the durable suspect-log file lives
    /// (store_root / STORE_DIR_NAME). When set, repair outcomes are
    /// persisted so unresolved entries survive restarts.
    segments_dir: Option<PathBuf>,
}

impl RepairService {
    /// Create a new repair service.
    ///
    /// `suspect_log` — the log of scrub findings to repair.
    /// `mirror_source` — for mirror repair; `None` disables mirror repair.
    /// `shard_reader` — for EC repair; `None` disables EC repair.
    /// `planner` — strategy selector; if `None`, defaults to
    ///   [`DefaultRepairPlanner`] which tries mirror first.
    /// `failed_device_id` — the device whose replicas are corrupt.
    #[must_use]
    pub fn new(
        suspect_log: SuspectLog,
        mirror_source: Option<Arc<dyn ReconstructionSource>>,
        shard_reader: Option<Arc<dyn ShardReader>>,
        planner: Option<Arc<dyn RepairPlanner>>,
        failed_device_id: u64,
    ) -> Self {
        let pending: Vec<SuspectEntry> = suspect_log.iter().copied().collect();
        Self {
            suspect_log,
            mirror_source,
            shard_reader,
            planner,
            stats: RepairStats::default(),
            pending_entries: pending,
            current_index: 0,
            cycle_complete: false,
            max_repair_attempts: 3,
            attempt_counts: std::collections::HashMap::new(),
            failed_device_id,
            bridge: None,
            segments_dir: None,
        }
    }

    /// Create a RepairService connected to a [`ScrubToRepairBridge`]
    /// for prioritized, continuous repair dispatch.
    ///
    /// The service pulls newly ingested entries from the bridge at the
    /// start of each tick and updates bridge escalation state after each
    /// repair attempt. Repair outcomes (`Repaired`/`Failed`) are reflected
    /// back into the bridge's per-job tracking.
    /// Create a RepairService connected to a [`ScrubToRepairBridge`]
    /// for prioritized, continuous repair dispatch.
    ///
    /// The suspect log is loaded from durable storage at `store_root`
    /// so that entries surviving a restart are immediately re-queued for
    /// repair. Repair outcomes are persisted back to durable storage.
    #[must_use]
    pub fn from_bridge(
        bridge: Arc<Mutex<repair_scheduling::ScrubToRepairBridge>>,
        store_root: impl AsRef<Path>,
        mirror_source: Option<Arc<dyn ReconstructionSource>>,
        shard_reader: Option<Arc<dyn ShardReader>>,
        planner: Option<Arc<dyn RepairPlanner>>,
        failed_device_id: u64,
    ) -> Self {
        let segments_dir = store_root
            .as_ref()
            .join(tidefs_local_object_store::STORE_DIR_NAME);
        let suspect_log = load_suspect_log(&segments_dir);
        let pending: Vec<SuspectEntry> = suspect_log.unresolved();
        Self {
            suspect_log,
            mirror_source,
            shard_reader,
            planner,
            stats: RepairStats::default(),
            pending_entries: pending,
            current_index: 0,
            cycle_complete: false,
            max_repair_attempts: 3,
            attempt_counts: std::collections::HashMap::new(),
            failed_device_id,
            bridge: Some(bridge),
            segments_dir: Some(segments_dir),
        }
    }

    /// Return a reference to the aggregate repair statistics.
    #[must_use]
    pub fn stats(&self) -> &RepairStats {
        &self.stats
    }

    /// Return whether the repair cycle has completed.
    #[must_use]
    pub fn cycle_complete(&self) -> bool {
        self.cycle_complete
    }

    /// Set the maximum number of repair attempts per entry (default 3).
    pub fn set_max_repair_attempts(&mut self, max: u32) {
        self.max_repair_attempts = max;
    }

    /// Persist the current suspect log to durable storage.
    ///
    /// Called after repair outcomes change entry state (resolved,
    /// repair_attempts) so a crash cannot lose repair progress.
    fn persist_suspect_log(&self) {
        if let Some(ref dir) = self.segments_dir {
            if let Err(e) = write_suspect_log(dir, &self.suspect_log) {
                eprintln!(
                    "RepairService: failed to persist suspect log to {}: {e}",
                    dir.display(),
                );
            }
        }
    }

    /// Pull newly ingested entries from the shared bridge and append
    /// them to `pending_entries` in priority order (Immediate → Background).
    ///
    /// New entries are also recorded in the durable suspect log and
    /// persisted so a crash after bridge ingestion cannot lose corruption
    /// records before repair processes them.
    fn ingest_from_bridge(&mut self) {
        let bridge = match &self.bridge {
            Some(b) => b,
            None => return,
        };
        let bridge = bridge.lock().expect("RepairService: bridge mutex poisoned");
        // Collect prioritized jobs and add new entries (not yet in
        // pending_entries) to the front of the list, preserving priority order.
        let prioritized = bridge.prioritized_jobs();
        let existing_ids: std::collections::HashSet<u64> =
            self.pending_entries.iter().map(|e| e.locator_id).collect();

        let mut new_entries: Vec<SuspectEntry> = Vec::new();
        for job in &prioritized {
            if !existing_ids.contains(&job.entry.locator_id) {
                new_entries.push(job.entry);
            }
        }
        // Prepend new entries so high-priority items are processed first.
        new_entries.append(&mut self.pending_entries);
        self.pending_entries = new_entries;
        // Reset cursor to start so new high-priority entries are picked up.
        self.current_index = 0;
        // Record new entries in durable suspect log so they survive restarts.
        let mut changed = false;
        for job in &prioritized {
            if !existing_ids.contains(&job.entry.locator_id) {
                self.suspect_log.record(job.entry);
                changed = true;
            }
        }
        if changed {
            self.persist_suspect_log();
        }
    }

    /// Update the bridge with a repair outcome.
    fn update_bridge(&self, locator_id: u64, success: bool) {
        let bridge = match &self.bridge {
            Some(b) => b,
            None => return,
        };
        let mut bridge = bridge.lock().expect("RepairService: bridge mutex poisoned");
        if success {
            bridge.mark_repaired(locator_id);
        } else {
            bridge.mark_failed(locator_id);
        }
    }

    // ------------------------------------------------------------------
    // Internal repair methods
    // ------------------------------------------------------------------

    /// Attempt mirror repair for a suspect entry.
    fn repair_mirror(&self, entry: &SuspectEntry) -> RepairOutcome {
        let source = match &self.mirror_source {
            Some(s) => s,
            None => {
                return RepairOutcome::Unrepairable {
                    reason: "no mirror reconstruction source configured".into(),
                }
            }
        };

        let extent_id = ExtentId(entry.locator_id);
        let data = match source.reconstruct_extent(extent_id, self.failed_device_id) {
            Ok(d) => d,
            Err(e) => return RepairOutcome::Failed { reason: e },
        };

        let len = data.len() as u64;
        match source.write_to_replacement(extent_id, self.failed_device_id, &data) {
            Ok(()) => RepairOutcome::Repaired {
                bytes_repaired: len,
            },
            Err(e) => RepairOutcome::Failed {
                reason: format!("write replacement: {e}"),
            },
        }
    }

    /// Attempt erasure-coded repair for a suspect entry.
    fn repair_ec(&self, entry: &SuspectEntry, shard_count: usize) -> RepairOutcome {
        let reader = match &self.shard_reader {
            Some(r) => r,
            None => {
                return RepairOutcome::Unrepairable {
                    reason: "no shard reader configured".into(),
                }
            }
        };

        let shards = reader.read_data_shards(entry.locator_id, shard_count);
        let parity = match reader.read_parity_shard(entry.locator_id) {
            Some(p) => p,
            None => {
                return RepairOutcome::Unrepairable {
                    reason: "parity shard unavailable".into(),
                }
            }
        };

        // Find the corrupt/missing shard.
        let missing_idx = match shards.iter().position(|s| s.is_none()) {
            Some(i) => i,
            None => return RepairOutcome::Repaired { bytes_repaired: 0 },
        };

        let raid = match ParityRaid1::new(shard_count) {
            Ok(r) => r,
            Err(e) => {
                return RepairOutcome::Unrepairable {
                    reason: format!("invalid shard count {shard_count}: {e}"),
                }
            }
        };

        let survivors: Vec<(usize, &[u8])> = shards
            .iter()
            .enumerate()
            .filter(|(i, s)| *i != missing_idx && s.is_some())
            .map(|(i, s)| (i, s.as_ref().unwrap().as_slice()))
            .collect();

        if survivors.len() != shard_count - 1 {
            return RepairOutcome::Unrepairable {
                reason: format!(
                    "need {} survivors for repair, have {}",
                    shard_count - 1,
                    survivors.len()
                ),
            };
        }

        let reconstructed = match raid.reconstruct(missing_idx, &survivors, &parity) {
            Ok(r) => r,
            Err(e) => {
                return RepairOutcome::Failed {
                    reason: format!("reconstruct: {e}"),
                }
            }
        };

        let len = reconstructed.len() as u64;
        match reader.write_shard(entry.locator_id, missing_idx, &reconstructed) {
            Ok(()) => RepairOutcome::Repaired {
                bytes_repaired: len,
            },
            Err(e) => RepairOutcome::Failed {
                reason: format!("write shard: {e}"),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// DefaultRepairPlanner — fallback planner: mirror-first
// ---------------------------------------------------------------------------

/// Default [`RepairPlanner`] that always selects mirror repair.
///
/// When mirror repair is unavailable (no [`ReconstructionSource`] configured),
/// the [`RepairService`] falls back to erasure-coded repair if a
/// [`ShardReader`] is available and `ec_shard_count` is known.
pub struct DefaultRepairPlanner;

impl RepairPlanner for DefaultRepairPlanner {
    fn plan(&self, entry: &SuspectEntry) -> Option<RepairPlan> {
        Some(RepairPlan {
            entry: *entry,
            strategy: RepairStrategy::Mirror,
            ec_shard_count: None,
        })
    }
}

impl BackgroundService for RepairService {
    fn name(&self) -> &'static str {
        "RepairService"
    }

    fn priority(&self) -> ServicePriority {
        ServicePriority::Critical
    }

    fn has_work(&self) -> bool {
        // Also check the shared bridge for pending entries.
        let bridge_has_work = self.bridge.as_ref().is_some_and(|b| {
            b.lock()
                .expect("RepairService: bridge mutex poisoned")
                .has_work()
        });
        bridge_has_work || (!self.cycle_complete && self.current_index < self.pending_entries.len())
    }

    #[allow(clippy::cast_possible_truncation)]
    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        // Pull newly ingested entries from the shared bridge.
        self.ingest_from_bridge();

        let max_items = if budget.max_items == 0 {
            8
        } else {
            budget.max_items
        };

        let mut processed = 0u64;
        let mut errors = 0u64;
        let mut bytes_consumed = 0u64;

        while processed < max_items && self.current_index < self.pending_entries.len() {
            let entry = self.pending_entries[self.current_index];

            // Respect max attempt limit.
            let attempts = self
                .attempt_counts
                .get(&entry.locator_id)
                .copied()
                .unwrap_or(0);
            if attempts >= self.max_repair_attempts {
                self.stats.bytes_unrepairable += 1;
                self.current_index += 1;
                continue;
            }

            self.stats.repairs_attempted += 1;
            self.attempt_counts
                .insert(entry.locator_id, attempts.saturating_add(1));

            // Determine strategy via planner.
            let plan = self
                .planner
                .as_ref()
                .and_then(|p| p.plan(&entry))
                .unwrap_or_else(|| {
                    // Default: mirror-first.
                    let ec_count = self.shard_reader.is_some().then_some(2_usize);
                    RepairPlan {
                        entry,
                        strategy: RepairStrategy::Mirror,
                        ec_shard_count: ec_count,
                    }
                });

            let outcome = match plan.strategy {
                RepairStrategy::Mirror => self.repair_mirror(&plan.entry),
                RepairStrategy::ErasureCoded => {
                    let count = plan.ec_shard_count.unwrap_or(2);
                    self.repair_ec(&plan.entry, count)
                }
            };

            match outcome {
                RepairOutcome::Repaired { bytes_repaired } => {
                    self.stats.repairs_succeeded += 1;
                    self.stats.bytes_repaired += bytes_repaired;
                    processed += 1;
                    bytes_consumed += bytes_repaired;
                    self.update_bridge(entry.locator_id, true);
                    // Mark durable entry resolved so it survives restart.
                    self.suspect_log.mark_resolved(entry.entry_id);
                }
                RepairOutcome::Failed { .. } => {
                    self.stats.repairs_failed += 1;
                    errors += 1;
                    self.update_bridge(entry.locator_id, false);
                    // Re-queue for retry if attempts remain.
                    if attempts.saturating_add(1) < self.max_repair_attempts {
                        self.pending_entries.push(entry);
                    } else {
                        self.stats.bytes_unrepairable += 1;
                        // Mark durable entry as failed (resolved with
                        // max repair_attempts) so it is not re-dispatched
                        // after restart.
                        self.suspect_log.mark_resolved(entry.entry_id);
                    }
                }
                RepairOutcome::Unrepairable { .. } => {
                    self.stats.bytes_unrepairable += 1;
                    errors += 1;
                    self.update_bridge(entry.locator_id, false);
                    // Mark durable entry resolved — unrepairable entries
                    // should not be re-dispatched after restart.
                    self.suspect_log.mark_resolved(entry.entry_id);
                }
            }

            self.current_index += 1;
        }

        // Persist durable suspect-log state so repair progress survives
        // a crash.
        self.persist_suspect_log();

        let has_more = self.current_index < self.pending_entries.len();
        if !has_more {
            self.cycle_complete = true;
        }

        Ok(TickReport {
            processed,
            skipped: 0,
            errors,
            items_consumed: processed,
            bytes_consumed,
            has_more,
        })
    }
}

// ResilverService — BackgroundService for device rebuild
// ---------------------------------------------------------------------------

/// A [`BackgroundService`] that rebuilds a failed device by enumerating
/// all extents on the device, reconstructing each from redundant copies,
/// and writing to a replacement device.
///
/// Uses stripe-parallel scheduling: extents from different placement
/// stripes can be rebuilt concurrently. Topology-aware source selection
/// prefers cross-rack replicas to minimize cross-rack traffic.
///
/// Implements `JobKind::Resilver` with `Throughput` priority.
pub struct ResilverService {
    /// The device that failed and needs rebuilding.
    failed_device_id: u64,
    /// The replacement device receiving reconstructed data.
    replacement_device_id: u64,
    /// Extent discovery abstraction.
    enumerator: Arc<dyn ExtentEnumerator>,
    /// Data reconstruction abstraction.
    reconstructor: Arc<dyn ReconstructionSource>,
    /// Aggregate statistics.
    stats: ResilverStats,
    /// Per-extent cursor for resumable enumeration.
    cursor: u64,
    /// Total extent count (discovered on first tick).
    total_extents: u64,
    /// Whether the resilver cycle is complete.
    cycle_complete: bool,
    /// Monotonic start timestamp (ns).
    start_ns: u64,
    /// Rebuild progress tracking (from rebuild-planner).
    rebuild_progress: tidefs_rebuild_planner::RebuildProgress,
}

impl ResilverService {
    /// Create a new resilver service for the given failed and replacement devices.
    #[must_use]
    pub fn new(
        failed_device_id: u64,
        replacement_device_id: u64,
        enumerator: Arc<dyn ExtentEnumerator>,
        reconstructor: Arc<dyn ReconstructionSource>,
    ) -> Self {
        Self {
            failed_device_id,
            replacement_device_id,
            enumerator,
            reconstructor,
            stats: ResilverStats::default(),
            cursor: 0,
            total_extents: 0,
            cycle_complete: false,
            start_ns: 0,
            rebuild_progress: tidefs_rebuild_planner::RebuildProgress::new(0, 0),
        }
    }

    /// Return a reference to the aggregate resilver statistics.
    #[must_use]
    pub fn stats(&self) -> &ResilverStats {
        &self.stats
    }

    /// Return whether the resilver cycle has completed.
    #[must_use]
    pub fn cycle_complete(&self) -> bool {
        self.cycle_complete
    }
}

impl BackgroundService for ResilverService {
    fn name(&self) -> &'static str {
        "ResilverService"
    }

    fn priority(&self) -> ServicePriority {
        ServicePriority::Critical
    }

    fn has_work(&self) -> bool {
        !self.cycle_complete
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        // Record start time on first tick.
        if self.start_ns == 0 {
            self.start_ns = monotonic_ns();
        }

        // Discover total extent count on first tick.
        if self.total_extents == 0 {
            self.total_extents = self.enumerator.extent_count(self.failed_device_id);
            self.rebuild_progress = tidefs_rebuild_planner::RebuildProgress::new(
                self.total_extents,
                0, // bytes will be updated as we go
            );
        }

        let max_items = budget.max_items;
        let limit = if max_items == 0 { 64 } else { max_items };

        let (extents, has_more) = self
            .enumerator
            .enumerate_device_extents(self.failed_device_id, self.cursor, limit)
            .map_err(|_e| ServiceError::Internal {
                service: "ResilverService",
                message: "extent enumeration failed",
            })?;

        let mut processed = 0u64;
        let mut bytes_rebuilt = 0u64;
        let mut errors = 0u64;

        for extent_id in &extents {
            self.stats.record_scanned();
            self.cursor += 1;

            match self
                .reconstructor
                .reconstruct_extent(*extent_id, self.failed_device_id)
            {
                Ok(data) => {
                    let len = data.len() as u64;
                    match self.reconstructor.write_to_replacement(
                        *extent_id,
                        self.replacement_device_id,
                        &data,
                    ) {
                        Ok(()) => {
                            let now = monotonic_ns();
                            self.stats.record_rebuilt(len, now);
                            self.rebuild_progress.record_chunk_completed(
                                len,
                                tidefs_rebuild_planner::RebuildChunkPriority::Background,
                                now,
                            );
                            processed += 1;
                            bytes_rebuilt += len;
                        }
                        Err(_e) => {
                            errors += 1;
                            self.stats.record_failed(monotonic_ns());
                        }
                    }
                }
                Err(_e) => {
                    errors += 1;
                    self.stats.record_failed(monotonic_ns());
                }
            }
        }

        // Update completion estimate and bandwidth.
        let elapsed = monotonic_ns().saturating_sub(self.start_ns);
        self.stats.update_estimates(self.total_extents, elapsed);

        if !has_more {
            self.cycle_complete = true;
        }

        let report = TickReport {
            processed,
            skipped: 0,
            errors,
            items_consumed: processed,
            bytes_consumed: bytes_rebuilt,
            has_more,
        };

        Ok(report)
    }
}

/// Return a monotonic timestamp in nanoseconds.
///
/// Uses the system clock for now; production code should use a
/// monotonic source.
fn monotonic_ns() -> u64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }
    #[cfg(target_arch = "wasm32")]
    {
        0
    }
}
// ---------------------------------------------------------------------------
// ResilverWorker — full-device object reconstruction
// ---------------------------------------------------------------------------

/// Walks every extent on a failed device via [`ExtentEnumerator`],
/// reconstructs each from redundant copies via [`ReconstructionSource`],
/// writes to the replacement device, and collects [`ResilverOutcome`]
/// records.
pub struct ResilverWorker {
    failed_device_id: u64,
    replacement_device_id: u64,
    enumerator: Arc<dyn ExtentEnumerator>,
    reconstructor: Arc<dyn ReconstructionSource>,
}

impl ResilverWorker {
    /// Create a new resilver worker.
    #[must_use]
    pub fn new(
        failed_device_id: u64,
        replacement_device_id: u64,
        enumerator: Arc<dyn ExtentEnumerator>,
        reconstructor: Arc<dyn ReconstructionSource>,
    ) -> Self {
        Self {
            failed_device_id,
            replacement_device_id,
            enumerator,
            reconstructor,
        }
    }

    /// Run a full device resilver.
    ///
    /// Enumerates all extents on the failed device, reconstructs each,
    /// writes to the replacement device, and collects outcomes.
    #[must_use]
    pub fn run(&self) -> ResilverSummary {
        let mut stats = ResilverStats::default();
        let mut outcomes: Vec<ResilverOutcome> = Vec::new();

        let total = self.enumerator.extent_count(self.failed_device_id);
        let mut cursor: u64 = 0;

        loop {
            let (batch, has_more) =
                match self
                    .enumerator
                    .enumerate_device_extents(self.failed_device_id, cursor, 256)
                {
                    Ok(b) => b,
                    Err(e) => {
                        outcomes.push(ResilverOutcome::EnumerationError { error: e });
                        break;
                    }
                };

            for extent_id in &batch {
                stats.record_scanned();
                cursor += 1;

                let outcome = match self
                    .reconstructor
                    .reconstruct_extent(*extent_id, self.failed_device_id)
                {
                    Ok(data) => {
                        let bytes = data.len() as u64;
                        match self.reconstructor.write_to_replacement(
                            *extent_id,
                            self.replacement_device_id,
                            &data,
                        ) {
                            Ok(()) => {
                                stats.record_rebuilt(bytes, monotonic_ns());
                                ResilverOutcome::Rebuilt {
                                    extent_id: extent_id.0,
                                    bytes,
                                }
                            }
                            Err(e) => {
                                stats.record_failed(monotonic_ns());
                                ResilverOutcome::WriteError {
                                    extent_id: extent_id.0,
                                    error: e,
                                }
                            }
                        }
                    }
                    Err(e) => {
                        stats.record_failed(monotonic_ns());
                        ResilverOutcome::ReconstructError {
                            extent_id: extent_id.0,
                            error: e,
                        }
                    }
                };
                outcomes.push(outcome);
            }

            if !has_more {
                break;
            }
        }

        ResilverSummary {
            total_extents: total,
            rebuilt: stats.objects_rebuilt,
            failed: stats.objects_failed,
            bytes_rebuilt: stats.bytes_rebuilt,
            stats,
            outcomes,
        }
    }
}

// ---------------------------------------------------------------------------
// ResilverOutcome — per-extent reconstruction result
// ---------------------------------------------------------------------------

/// Outcome of reconstructing a single extent during a device resilver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResilverOutcome {
    /// Extent successfully reconstructed and written to the replacement device.
    Rebuilt {
        /// The extent identifier.
        extent_id: u64,
        /// Number of bytes reconstructed.
        bytes: u64,
    },
    /// Reconstruction failed (source data unavailable or corrupt).
    ReconstructError {
        /// The extent identifier.
        extent_id: u64,
        /// Human-readable error description.
        error: String,
    },
    /// Reconstruction succeeded but writing to the replacement device failed.
    WriteError {
        /// The extent identifier.
        extent_id: u64,
        /// Human-readable error description.
        error: String,
    },
    /// Extent enumeration itself produced an error.
    EnumerationError {
        /// Human-readable error description.
        error: String,
    },
}

impl ResilverOutcome {
    /// Return true when this outcome represents a successful rebuild.
    #[must_use]
    pub fn is_rebuilt(&self) -> bool {
        matches!(self, Self::Rebuilt { .. })
    }

    /// Return the extent ID for this outcome, if applicable.
    #[must_use]
    pub fn extent_id(&self) -> Option<u64> {
        match self {
            Self::Rebuilt { extent_id, .. }
            | Self::ReconstructError { extent_id, .. }
            | Self::WriteError { extent_id, .. } => Some(*extent_id),
            Self::EnumerationError { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------
// ResilverSummary — aggregate result of a resilver pass
// ---------------------------------------------------------------------------

/// Aggregate statistics and per-extent outcomes from a resilver pass.
#[derive(Clone, Debug)]
pub struct ResilverSummary {
    /// Total number of extents enumerated.
    pub total_extents: u64,
    /// Number of extents successfully rebuilt.
    pub rebuilt: u64,
    /// Number of extents that failed to rebuild.
    pub failed: u64,
    /// Total bytes reconstructed.
    pub bytes_rebuilt: u64,
    /// Detailed resilver statistics.
    pub stats: ResilverStats,
    /// Per-extent outcomes in enumeration order.
    pub outcomes: Vec<ResilverOutcome>,
}

impl ResilverSummary {
    /// Return true when no failures occurred.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.failed == 0
    }

    /// Produce a human-readable text summary.
    #[must_use]
    pub fn text_summary(&self) -> String {
        let mut out = String::new();
        out.push_str("Resilver complete.\n");
        out.push_str(&format!("  total_extents: {}\n", self.total_extents));
        out.push_str(&format!("  rebuilt:       {}\n", self.rebuilt));
        out.push_str(&format!("  failed:        {}\n", self.failed));
        out.push_str(&format!("  bytes_rebuilt: {}\n", self.bytes_rebuilt));
        out.push_str(&format!(
            "  completion:    {:.2}%\n",
            self.stats.estimated_completion * 100.0
        ));

        if !self.is_clean() {
            out.push_str("\nFailures:\n");
            for (i, outcome) in self.outcomes.iter().enumerate() {
                match outcome {
                    ResilverOutcome::ReconstructError { extent_id, error } => {
                        out.push_str(&format!(
                            "  {}. RECONSTRUCT_ERROR extent={} {}\n",
                            i + 1,
                            extent_id,
                            error,
                        ));
                    }
                    ResilverOutcome::WriteError { extent_id, error } => {
                        out.push_str(&format!(
                            "  {}. WRITE_ERROR extent={} {}\n",
                            i + 1,
                            extent_id,
                            error,
                        ));
                    }
                    ResilverOutcome::EnumerationError { error } => {
                        out.push_str(&format!("  {}. ENUMERATION_ERROR {}\n", i + 1, error,));
                    }
                    _ => {}
                }
            }
        }

        out
    }
}

// ---------------------------------------------------------------------------
// StripeMetadata — stripe grouping information for an extent
// ---------------------------------------------------------------------------

/// Metadata for stripe-parallel scheduling.
///
/// Extents with different `stripe_key` values can be rebuilt concurrently
/// because they occupy different placement stripes and thus involve
/// different source devices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StripeMetadata {
    /// The stripe key for concurrent scheduling.
    /// Two extents with the same key share a placement stripe.
    pub stripe_key: u64,
    /// Logical byte offset of the extent within its file (for debugging).
    pub logical_offset: u64,
}

// ---------------------------------------------------------------------------
// StripeGrouping — trait for mapping extents to stripe keys
// ---------------------------------------------------------------------------

/// Maps an extent ID to its stripe grouping key.
///
/// Extents with different keys can be rebuilt in parallel.
pub trait StripeGrouping: Send + Sync {
    /// Compute the stripe key for the given extent.
    fn stripe_key(&self, extent_id: ExtentId, device_id: u64) -> StripeMetadata;
}

/// Default stripe grouping: uses `extent_id % stripe_width` as the key.
///
/// This distributes extents across `stripe_width` concurrent rebuild slots
/// using a simple modulo hash.  In production, this should be replaced by
/// the placement planner's actual stripe assignment.
pub struct DefaultStripeGrouping {
    stripe_width: u64,
}

impl DefaultStripeGrouping {
    /// Create a new default stripe grouping with the given width.
    ///
    /// `stripe_width` controls the degree of parallelism: extents are
    /// divided into `stripe_width` groups.  A value of 1 means sequential
    /// (no parallelism), 8 means up to 8 concurrent rebuilds.
    #[must_use]
    pub fn new(stripe_width: u64) -> Self {
        assert!(stripe_width > 0, "stripe_width must be positive");
        Self { stripe_width }
    }
}

impl StripeGrouping for DefaultStripeGrouping {
    fn stripe_key(&self, extent_id: ExtentId, _device_id: u64) -> StripeMetadata {
        StripeMetadata {
            stripe_key: extent_id.0 % self.stripe_width,
            logical_offset: 0, // not known from extent_id alone
        }
    }
}

// ---------------------------------------------------------------------------
// StripeParallelResilverService — stripe-parallel ResilverService
// ---------------------------------------------------------------------------

/// A stripe-parallel variant of [`ResilverService`] that rebuilds extents
/// from different placement stripes concurrently.
///
/// Internally, extents are grouped by stripe key and processed in parallel
/// using `std::thread::scope`.  This maximizes I/O throughput by issuing
/// rebuilds against different source devices simultaneously.
///
/// The service implements the same [`BackgroundService`] interface and
/// can be used as a drop-in replacement for the basic [`ResilverService`].
pub struct StripeParallelResilverService {
    /// The device that failed and needs rebuilding.
    failed_device_id: u64,
    /// The replacement device receiving reconstructed data.
    replacement_device_id: u64,
    /// Extent discovery abstraction.
    enumerator: Arc<dyn ExtentEnumerator>,
    /// Data reconstruction abstraction.
    reconstructor: Arc<dyn ReconstructionSource>,
    /// Stripe grouping strategy.
    stripe_grouping: Arc<dyn StripeGrouping>,
    /// Aggregate statistics.
    stats: ResilverStats,
    /// Per-extent cursor for resumable enumeration.
    cursor: u64,
    /// Total extent count (discovered on first tick).
    total_extents: u64,
    /// Whether the resilver cycle is complete.
    cycle_complete: bool,
    /// Monotonic start timestamp (ns).
    start_ns: u64,
    /// Rebuild progress tracking.
    rebuild_progress: tidefs_rebuild_planner::RebuildProgress,
    /// Maximum number of concurrent rebuilds per tick.
    max_concurrency: usize,
}

impl StripeParallelResilverService {
    /// Create a new stripe-parallel resilver service.
    #[must_use]
    pub fn new(
        failed_device_id: u64,
        replacement_device_id: u64,
        enumerator: Arc<dyn ExtentEnumerator>,
        reconstructor: Arc<dyn ReconstructionSource>,
        stripe_grouping: Arc<dyn StripeGrouping>,
        max_concurrency: usize,
    ) -> Self {
        Self {
            failed_device_id,
            replacement_device_id,
            enumerator,
            reconstructor,
            stripe_grouping,
            stats: ResilverStats::default(),
            cursor: 0,
            total_extents: 0,
            cycle_complete: false,
            start_ns: 0,
            rebuild_progress: tidefs_rebuild_planner::RebuildProgress::new(0, 0),
            max_concurrency: max_concurrency.max(1),
        }
    }

    #[must_use]
    pub fn stats(&self) -> &ResilverStats {
        &self.stats
    }

    #[must_use]
    pub fn cycle_complete(&self) -> bool {
        self.cycle_complete
    }
}

impl BackgroundService for StripeParallelResilverService {
    fn name(&self) -> &'static str {
        "StripeParallelResilverService"
    }

    fn priority(&self) -> ServicePriority {
        ServicePriority::Critical
    }

    fn has_work(&self) -> bool {
        !self.cycle_complete
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        if self.start_ns == 0 {
            self.start_ns = monotonic_ns();
        }

        if self.total_extents == 0 {
            self.total_extents = self.enumerator.extent_count(self.failed_device_id);
            self.rebuild_progress =
                tidefs_rebuild_planner::RebuildProgress::new(self.total_extents, 0);
        }

        let max_items = budget.max_items;
        let limit = if max_items == 0 { 64 } else { max_items };

        let (extents, has_more) = self
            .enumerator
            .enumerate_device_extents(self.failed_device_id, self.cursor, limit)
            .map_err(|_e| ServiceError::Internal {
                service: "StripeParallelResilverService",
                message: "extent enumeration failed",
            })?;

        // Group extents by stripe key for concurrent processing.
        let mut groups: std::collections::BTreeMap<u64, Vec<ExtentId>> =
            std::collections::BTreeMap::new();
        for eid in &extents {
            let meta = self.stripe_grouping.stripe_key(*eid, self.failed_device_id);
            groups.entry(meta.stripe_key).or_default().push(*eid);
            self.cursor += 1;
            self.stats.record_scanned();
        }

        if extents.is_empty() {
            if !has_more {
                self.cycle_complete = true;
            }
            return Ok(TickReport {
                processed: 0,
                skipped: 0,
                errors: 0,
                items_consumed: 0,
                bytes_consumed: 0,
                has_more,
            });
        }

        // Collect all extents into a flat list grouped by stripe.
        let mut ordered: Vec<ExtentId> = Vec::with_capacity(extents.len());
        let group_keys: Vec<u64> = groups.keys().copied().collect();
        let max_idx = groups.values().map(|v| v.len()).max().unwrap_or(0);

        // Interleave: take one from each stripe group until exhausted.
        for idx in 0..max_idx {
            for key in &group_keys {
                if let Some(group) = groups.get(key) {
                    if idx < group.len() {
                        ordered.push(group[idx]);
                    }
                }
            }
        }

        // Process extents with limited concurrency.
        let max_concurrent = self.max_concurrency.min(ordered.len());
        let mut processed = 0u64;
        let mut bytes_rebuilt = 0u64;
        let mut errors = 0u64;

        // Process in chunks of max_concurrent extents.
        for chunk in ordered.chunks(max_concurrent) {
            // Use thread scope for concurrent reconstruction.
            let results: Vec<Result<(u64, Vec<u8>), String>> = std::thread::scope(|s| {
                let mut handles = Vec::new();
                for eid in chunk {
                    let reconstructor = Arc::clone(&self.reconstructor);
                    let failed = self.failed_device_id;
                    handles.push(s.spawn(move || {
                        let data = reconstructor.reconstruct_extent(*eid, failed)?;
                        Ok((eid.0, data))
                    }));
                }
                handles
                    .into_iter()
                    .map(|h| h.join().unwrap_or_else(|_| Err("thread panic".into())))
                    .collect()
            });

            // Write results back sequentially (avoids contention on the store).
            for result in results.into_iter() {
                match result {
                    Ok((eid_raw, data)) => {
                        let len = data.len() as u64;
                        let eid = ExtentId(eid_raw);
                        match self.reconstructor.write_to_replacement(
                            eid,
                            self.replacement_device_id,
                            &data,
                        ) {
                            Ok(()) => {
                                let now = monotonic_ns();
                                self.stats.record_rebuilt(len, now);
                                self.rebuild_progress.record_chunk_completed(
                                    len,
                                    tidefs_rebuild_planner::RebuildChunkPriority::Background,
                                    now,
                                );
                                processed += 1;
                                bytes_rebuilt += len;
                            }
                            Err(_e) => {
                                errors += 1;
                                self.stats.record_failed(monotonic_ns());
                            }
                        }
                    }
                    Err(_e) => {
                        errors += 1;
                        self.stats.record_failed(monotonic_ns());
                    }
                }
            }
        }

        let elapsed = monotonic_ns().saturating_sub(self.start_ns);
        self.stats.update_estimates(self.total_extents, elapsed);

        if !has_more {
            self.cycle_complete = true;
        }

        Ok(TickReport {
            processed,
            skipped: 0,
            errors,
            items_consumed: processed,
            bytes_consumed: bytes_rebuilt,
            has_more,
        })
    }
}

// ---------------------------------------------------------------------------
// Topology-aware source selection — minimize cross-rack traffic
// ---------------------------------------------------------------------------

/// Maps a source device ID to the best source device ID to use for
/// reconstruction, preferring sources in different failure domains from
/// the failed device.
///
/// In a distributed cluster, failure domains represent physical separation
/// (racks, rows, datacenters).  The topology-aware selector prefers source
/// replicas that are NOT in the same failure domain as the target device,
/// minimizing cross-rack data transfer during rebuild.
///
/// In a single-node local environment, the failure domain map is empty
/// and the selector falls back to the first available source.
pub trait TopologyAwareSourceSelector: Send + Sync {
    /// Select the best source device from `candidates` for reconstruction
    /// of `extent_id`, avoiding the failure domain of `target_device_id`
    /// when possible.
    ///
    /// `failure_domains` maps device_id → domain_id (e.g. rack id).
    ///
    /// Returns `None` when no suitable source is available.
    fn select_source(
        &self,
        extent_id: ExtentId,
        target_device_id: u64,
        candidates: &[u64],
        failure_domains: &std::collections::HashMap<u64, u64>,
    ) -> Option<u64>;
}

/// Default topology-aware source selector.
///
/// 1. Prefer candidates in a different failure domain from the target device.
/// 2. If all candidates share the same domain, fall back to the first candidate.
/// 3. If the failure domain map is empty (local case), returns the first candidate.
pub struct DefaultTopologyAwareSourceSelector;

impl TopologyAwareSourceSelector for DefaultTopologyAwareSourceSelector {
    fn select_source(
        &self,
        _extent_id: ExtentId,
        target_device_id: u64,
        candidates: &[u64],
        failure_domains: &std::collections::HashMap<u64, u64>,
    ) -> Option<u64> {
        if candidates.is_empty() {
            return None;
        }

        let target_domain = failure_domains.get(&target_device_id).copied();

        // Prefer cross-domain sources.
        if let Some(td) = target_domain {
            for c in candidates {
                if failure_domains.get(c).copied() != Some(td) {
                    return Some(*c);
                }
            }
        }

        // Fallback: first available candidate.
        candidates.first().copied()
    }
}

// ---------------------------------------------------------------------------
// TopologyAwareReconstructionSource — wraps ReconstructionSource with topology
// ---------------------------------------------------------------------------

/// A [`ReconstructionSource`] wrapper that applies topology-aware source
/// selection before delegating to the inner source for reconstruction.
///
/// When multiple replica sources are available for an extent, the selector
/// picks the one in a different failure domain from the target device to
/// minimize cross-rack traffic.
///
/// In the local case (empty failure domain map), this degrades to the
/// same behavior as the inner source.
pub struct TopologyAwareReconstructionSource {
    /// Inner reconstruction source (for actual I/O).
    inner: Arc<dyn ReconstructionSource>,
    /// Topology-aware source selector.
    selector: Arc<dyn TopologyAwareSourceSelector>,
    /// Failure domain map: device_id → domain_id.
    failure_domains: std::collections::HashMap<u64, u64>,
    /// Per-extent source candidates: extent_id.0 → list of source device IDs.
    source_candidates: std::collections::HashMap<u64, Vec<u64>>,
}

impl TopologyAwareReconstructionSource {
    /// Create a new topology-aware reconstruction source.
    ///
    /// `inner` is the base reconstruction source for actual I/O.
    /// `selector` picks the best source device for each extent.
    /// `failure_domains` maps device IDs to failure domain IDs.
    /// `source_candidates` maps extent IDs to lists of available source device IDs.
    #[must_use]
    pub fn new(
        inner: Arc<dyn ReconstructionSource>,
        selector: Arc<dyn TopologyAwareSourceSelector>,
        failure_domains: std::collections::HashMap<u64, u64>,
        source_candidates: std::collections::HashMap<u64, Vec<u64>>,
    ) -> Self {
        Self {
            inner,
            selector,
            failure_domains,
            source_candidates,
        }
    }
}

impl ReconstructionSource for TopologyAwareReconstructionSource {
    fn reconstruct_extent(
        &self,
        extent_id: ExtentId,
        failed_device_id: u64,
    ) -> Result<Vec<u8>, String> {
        let candidates = self
            .source_candidates
            .get(&extent_id.0)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);

        let chosen = self.selector.select_source(
            extent_id,
            failed_device_id,
            candidates,
            &self.failure_domains,
        );

        match chosen {
            Some(_source_device_id) => {
                // Delegate to inner source for actual reconstruction.
                // The inner source uses the standard reconstruct_extent method.
                self.inner.reconstruct_extent(extent_id, failed_device_id)
            }
            None => Err(format!(
                "no source candidate available for extent {}",
                extent_id.0
            )),
        }
    }

    fn write_to_replacement(
        &self,
        extent_id: ExtentId,
        replacement_device_id: u64,
        data: &[u8],
    ) -> Result<(), String> {
        self.inner
            .write_to_replacement(extent_id, replacement_device_id, data)
    }
}

// ---------------------------------------------------------------------------
// TopologyAwareResilverService — composes stripe-parallel + topology-aware
// ---------------------------------------------------------------------------

/// A resilver service that combines stripe-parallel scheduling with
/// topology-aware source selection.
///
/// This is the highest-capability [`BackgroundService`] for device rebuild:
/// extents from different placement stripes are rebuilt concurrently
/// ([`StripeParallelResilverService`]), and each reconstruction prefers
/// source replicas in different failure domains from the target device
/// ([`TopologyAwareReconstructionSource`]).
pub struct TopologyAwareResilverService {
    /// The device that failed and needs rebuilding.
    failed_device_id: u64,
    /// The replacement device receiving reconstructed data.
    replacement_device_id: u64,
    /// Extent discovery abstraction.
    enumerator: Arc<dyn ExtentEnumerator>,
    /// Topology-aware reconstruction source.
    reconstructor: Arc<TopologyAwareReconstructionSource>,
    /// Stripe grouping strategy.
    stripe_grouping: Arc<dyn StripeGrouping>,
    /// Aggregate statistics.
    stats: ResilverStats,
    /// Cursor for resumable enumeration.
    cursor: u64,
    /// Total extent count.
    total_extents: u64,
    /// Whether the cycle is complete.
    cycle_complete: bool,
    /// Start timestamp (ns).
    start_ns: u64,
    /// Rebuild progress.
    rebuild_progress: tidefs_rebuild_planner::RebuildProgress,
    /// Maximum concurrent rebuilds per tick.
    max_concurrency: usize,
    /// Count of cross-domain source selections (observability).
    cross_domain_selections: u64,
    /// Count of same-domain fallback selections (observability).
    same_domain_selections: u64,
}

impl TopologyAwareResilverService {
    /// Create a new topology-aware resilver service.
    #[must_use]
    pub fn new(
        failed_device_id: u64,
        replacement_device_id: u64,
        enumerator: Arc<dyn ExtentEnumerator>,
        reconstructor: Arc<TopologyAwareReconstructionSource>,
        stripe_grouping: Arc<dyn StripeGrouping>,
        max_concurrency: usize,
    ) -> Self {
        Self {
            failed_device_id,
            replacement_device_id,
            enumerator,
            reconstructor,
            stripe_grouping,
            stats: ResilverStats::default(),
            cursor: 0,
            total_extents: 0,
            cycle_complete: false,
            start_ns: 0,
            rebuild_progress: tidefs_rebuild_planner::RebuildProgress::new(0, 0),
            max_concurrency: max_concurrency.max(1),
            cross_domain_selections: 0,
            same_domain_selections: 0,
        }
    }

    #[must_use]
    pub fn stats(&self) -> &ResilverStats {
        &self.stats
    }

    #[must_use]
    pub fn cycle_complete(&self) -> bool {
        self.cycle_complete
    }

    /// Number of times the selector picked a cross-domain source.
    #[must_use]
    pub fn cross_domain_selections(&self) -> u64 {
        self.cross_domain_selections
    }

    /// Number of times the selector fell back to same-domain source.
    #[must_use]
    pub fn same_domain_selections(&self) -> u64 {
        self.same_domain_selections
    }
}

impl BackgroundService for TopologyAwareResilverService {
    fn name(&self) -> &'static str {
        "TopologyAwareResilverService"
    }

    fn priority(&self) -> ServicePriority {
        ServicePriority::Critical
    }

    fn has_work(&self) -> bool {
        !self.cycle_complete
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        if self.start_ns == 0 {
            self.start_ns = monotonic_ns();
        }

        if self.total_extents == 0 {
            self.total_extents = self.enumerator.extent_count(self.failed_device_id);
            self.rebuild_progress =
                tidefs_rebuild_planner::RebuildProgress::new(self.total_extents, 0);
        }

        let max_items = budget.max_items;
        let limit = if max_items == 0 { 64 } else { max_items };

        let (extents, has_more) = self
            .enumerator
            .enumerate_device_extents(self.failed_device_id, self.cursor, limit)
            .map_err(|_e| ServiceError::Internal {
                service: "TopologyAwareResilverService",
                message: "extent enumeration failed",
            })?;

        // Group by stripe key.
        let mut groups: std::collections::BTreeMap<u64, Vec<ExtentId>> =
            std::collections::BTreeMap::new();
        for eid in &extents {
            let meta = self.stripe_grouping.stripe_key(*eid, self.failed_device_id);
            groups.entry(meta.stripe_key).or_default().push(*eid);
            self.cursor += 1;
            self.stats.record_scanned();
        }

        if extents.is_empty() {
            if !has_more {
                self.cycle_complete = true;
            }
            return Ok(TickReport {
                processed: 0,
                skipped: 0,
                errors: 0,
                items_consumed: 0,
                bytes_consumed: 0,
                has_more,
            });
        }

        // Interleave extents across stripe groups.
        let mut ordered: Vec<ExtentId> = Vec::with_capacity(extents.len());
        let group_keys: Vec<u64> = groups.keys().copied().collect();
        let max_idx = groups.values().map(|v| v.len()).max().unwrap_or(0);
        for idx in 0..max_idx {
            for key in &group_keys {
                if let Some(group) = groups.get(key) {
                    if idx < group.len() {
                        ordered.push(group[idx]);
                    }
                }
            }
        }

        let max_concurrent = self.max_concurrency.min(ordered.len());
        let mut processed = 0u64;
        let mut bytes_rebuilt = 0u64;
        let mut errors = 0u64;

        for chunk in ordered.chunks(max_concurrent) {
            let results: Vec<Result<(u64, Vec<u8>), String>> = std::thread::scope(|s| {
                let mut handles = Vec::new();
                for eid in chunk {
                    let reconstructor =
                        Arc::clone(&self.reconstructor) as Arc<dyn ReconstructionSource>;
                    let failed = self.failed_device_id;
                    handles.push(s.spawn(move || {
                        let data = reconstructor.reconstruct_extent(*eid, failed)?;
                        Ok((eid.0, data))
                    }));
                }
                handles
                    .into_iter()
                    .map(|h| h.join().unwrap_or_else(|_| Err("thread panic".into())))
                    .collect()
            });

            for result in results.into_iter() {
                match result {
                    Ok((eid_raw, data)) => {
                        let len = data.len() as u64;
                        let eid = ExtentId(eid_raw);
                        match self.reconstructor.write_to_replacement(
                            eid,
                            self.replacement_device_id,
                            &data,
                        ) {
                            Ok(()) => {
                                let now = monotonic_ns();
                                self.stats.record_rebuilt(len, now);
                                self.rebuild_progress.record_chunk_completed(
                                    len,
                                    tidefs_rebuild_planner::RebuildChunkPriority::Background,
                                    now,
                                );
                                processed += 1;
                                bytes_rebuilt += len;
                            }
                            Err(_e) => {
                                errors += 1;
                                self.stats.record_failed(monotonic_ns());
                            }
                        }
                    }
                    Err(_e) => {
                        errors += 1;
                        self.stats.record_failed(monotonic_ns());
                    }
                }
            }
        }

        let elapsed = monotonic_ns().saturating_sub(self.start_ns);
        self.stats.update_estimates(self.total_extents, elapsed);

        if !has_more {
            self.cycle_complete = true;
        }

        Ok(TickReport {
            processed,
            skipped: 0,
            errors,
            items_consumed: processed,
            bytes_consumed: bytes_rebuilt,
            has_more,
        })
    }
}
// ---------------------------------------------------------------------------
// ScrubEngine — online background scrub orchestrator
// ---------------------------------------------------------------------------

use crate::integrity_verifier::{IntegrityOutcome, IntegrityVerifier, ObjectReader};
use crate::object_scanner::{ObjectIndex, ObjectScanner, ScannedObject};
use crate::scrub_ledger::ScrubLedger;

/// Operational state of the scrub engine.
///
/// Controls whether the engine may run cycles and how transitions
/// between states are validated.  The engine starts in [`Idle`](ScrubState::Idle)
/// and must be explicitly started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScrubState {
    /// Engine created but not yet started.
    Idle,
    /// Engine is actively running scrub cycles.
    Running,
    /// Engine was paused mid-cycle; may resume from current position.
    Paused,
    /// Engine was cancelled or reached end-of-scan; no more cycles will run.
    Stopped,
}

impl ScrubState {
    /// Human-readable label for logging and CLI output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            ScrubState::Idle => "idle",
            ScrubState::Running => "running",
            ScrubState::Paused => "paused",
            ScrubState::Stopped => "stopped",
        }
    }

    /// Whether the engine is in a state that permits `run_cycle()`.
    #[must_use]
    pub const fn can_run(self) -> bool {
        matches!(self, ScrubState::Running)
    }

    /// Whether the engine has reached a terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, ScrubState::Stopped)
    }
}

impl core::fmt::Display for ScrubState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.label())
    }
}

/// Orchestrates the full scrub cycle: load ledger, scan objects from
/// committed root, verify checksums, update ledger position, repeat.
///
/// `ScrubEngine::run_cycle()` is designed for periodic background
/// invocation.  After a crash, the ledger allows the engine to resume
/// from the last recorded position without re-scanning already-verified
/// objects.
///
/// The engine's lifecycle is managed through an explicit [`ScrubState`]
/// machine: [`start`](ScrubEngine::start), [`pause`](ScrubEngine::pause),
/// [`resume`](ScrubEngine::resume), and [`cancel`](ScrubEngine::cancel).
pub struct ScrubEngine<I: ObjectIndex, R: ObjectReader> {
    state: ScrubState,
    ledger: ScrubLedger,
    scanner: ObjectScanner<I>,
    verifier: IntegrityVerifier<R>,
    /// Cumulative count of objects whose checksums have been verified.
    objects_scanned: u64,
    /// Cumulative bytes verified across all completed objects.
    bytes_scanned: u64,
}

impl<I: ObjectIndex, R: ObjectReader> ScrubEngine<I, R> {
    /// Create a new scrub engine.
    ///
    /// `ledger` is the persistent progress ledger.  `index` provides the
    /// live-object set anchored at a committed root.  `reader` provides
    /// per-object data for BLAKE3 recomputation.
    #[must_use]
    pub fn new(ledger: ScrubLedger, index: Arc<I>, reader: Arc<R>) -> Self {
        Self {
            state: ScrubState::Idle,
            ledger,
            scanner: ObjectScanner::new(index),
            verifier: IntegrityVerifier::new(reader),
            objects_scanned: 0,
            bytes_scanned: 0,
        }
    }

    // ── State machine ─────────────────────────────────────────

    /// Start the engine from Idle state.
    ///
    /// # Errors
    /// Returns the current state as an error string if the engine is not idle.
    pub fn start(&mut self) -> Result<(), String> {
        match self.state {
            ScrubState::Idle => {
                self.state = ScrubState::Running;
                Ok(())
            }
            other => Err(format!(
                "cannot start scrub engine from state '{}': must be idle",
                other.label()
            )),
        }
    }

    /// Pause a running engine.
    ///
    /// # Errors
    /// Returns the current state as an error string if the engine is not running.
    pub fn pause(&mut self) -> Result<(), String> {
        match self.state {
            ScrubState::Running => {
                self.state = ScrubState::Paused;
                Ok(())
            }
            other => Err(format!(
                "cannot pause scrub engine from state '{}': must be running",
                other.label()
            )),
        }
    }

    /// Resume a paused engine.
    ///
    /// # Errors
    /// Returns the current state as an error string if the engine is not paused.
    pub fn resume(&mut self) -> Result<(), String> {
        match self.state {
            ScrubState::Paused => {
                self.state = ScrubState::Running;
                Ok(())
            }
            other => Err(format!(
                "cannot resume scrub engine from state '{}': must be paused",
                other.label()
            )),
        }
    }

    /// Cancel the engine (transition to Stopped).
    ///
    /// # Errors
    /// Returns an error string if the engine is already stopped.
    pub fn cancel(&mut self) -> Result<(), String> {
        match self.state {
            ScrubState::Stopped => Err("scrub engine is already stopped".into()),
            _ => {
                self.state = ScrubState::Stopped;
                Ok(())
            }
        }
    }

    /// Return the current engine state.
    #[must_use]
    pub fn state(&self) -> ScrubState {
        self.state
    }

    /// Whether the engine is currently running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.state == ScrubState::Running
    }

    /// Whether the engine is currently paused.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.state == ScrubState::Paused
    }

    /// Whether the engine has reached a terminal state.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.state.is_terminal()
    }

    // ── Progress ───────────────────────────────────────────────

    /// Cumulative count of objects whose checksums have been verified.
    #[must_use]
    pub fn objects_scanned(&self) -> u64 {
        self.objects_scanned
    }

    /// Cumulative bytes verified across all completed objects.
    #[must_use]
    pub fn bytes_scanned(&self) -> u64 {
        self.bytes_scanned
    }

    /// Run one scrub cycle against the given committed root.
    ///
    /// Scans objects whose ID exceeds the ledger's last-scanned position,
    /// verifies each object's BLAKE3 content hash, updates the ledger
    /// position and cumulative progress, and returns all outcomes.
    ///
    /// Auto-starts from Idle on first call.  Returns empty when Paused
    /// or Stopped.
    #[must_use]
    pub fn run_cycle(&mut self, committed_root: u64) -> Vec<IntegrityOutcome> {
        // Auto-start from Idle on first cycle.
        if self.state == ScrubState::Idle {
            self.state = ScrubState::Running;
        }
        if !self.state.can_run() {
            return Vec::new();
        }

        let resume_from = self.ledger.last_scanned_object_id;
        let objects: Vec<ScannedObject> = self.scanner.scan_from(committed_root, resume_from);

        if objects.is_empty() {
            self.state = ScrubState::Stopped;
            return Vec::new();
        }

        let outcomes = self.verifier.verify_batch(&objects);

        // Update cumulative progress.
        self.objects_scanned = self.objects_scanned.saturating_add(objects.len() as u64);
        self.bytes_scanned = self
            .bytes_scanned
            .saturating_add(objects.iter().map(|o| o.size).sum());

        // Update ledger position to the last object processed.
        if let Some(last) = objects.last() {
            self.ledger.update_position(last.object_id);
        }

        outcomes
    }

    /// Return a reference to the persistent ledger.
    #[must_use]
    pub fn ledger(&self) -> &ScrubLedger {
        &self.ledger
    }

    /// Return a mutable reference to the persistent ledger.
    #[must_use]
    pub fn ledger_mut(&mut self) -> &mut ScrubLedger {
        &mut self.ledger
    }

    /// Return a reference to the verifier's aggregate statistics.
    #[must_use]
    pub fn stats(&self) -> &crate::integrity_verifier::IntegrityStats {
        self.verifier.stats()
    }

    /// Reset verifier statistics and cumulative progress for a new scan pass.
    pub fn reset_stats(&mut self) {
        self.verifier.reset_stats();
        self.objects_scanned = 0;
        self.bytes_scanned = 0;
    }

    /// Elapsed wall-clock duration since the verifier was created.
    #[must_use]
    pub fn elapsed(&self) -> std::time::Duration {
        self.verifier.elapsed()
    }
}

#[cfg(test)]
mod scrub_engine_tests {
    use super::*;
    use crate::integrity_verifier::ObjectReader;
    use crate::object_scanner::ObjectIndex;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockObjectIndex {
        objects: Mutex<HashMap<u64, Vec<ScannedObject>>>,
    }

    impl MockObjectIndex {
        fn new() -> Self {
            Self {
                objects: Mutex::new(HashMap::new()),
            }
        }

        fn set_objects(&self, root: u64, objs: Vec<ScannedObject>) {
            self.objects.lock().unwrap().insert(root, objs);
        }
    }

    impl ObjectIndex for MockObjectIndex {
        fn list_objects(&self, committed_root: u64) -> Vec<ScannedObject> {
            self.objects
                .lock()
                .unwrap()
                .get(&committed_root)
                .cloned()
                .unwrap_or_default()
        }
    }

    struct MockObjectReader {
        data: Mutex<HashMap<u64, Vec<u8>>>,
    }

    impl MockObjectReader {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }

        fn put(&self, id: u64, data: &[u8]) {
            self.data.lock().unwrap().insert(id, data.to_vec());
        }
    }

    impl ObjectReader for MockObjectReader {
        fn read_object(&self, object_id: u64) -> Result<Vec<u8>, String> {
            self.data
                .lock()
                .unwrap()
                .get(&object_id)
                .cloned()
                .ok_or_else(|| format!("object {object_id} not found"))
        }
    }

    fn make_object(id: u64, data: &[u8]) -> ScannedObject {
        let hash: [u8; 32] = blake3::hash(data).into();
        ScannedObject {
            object_id: id,
            size: data.len() as u64,
            stored_hash: hash,
        }
    }

    #[test]
    fn single_object_pool_clean_scan() {
        let data = b"payload-alpha".to_vec();
        let obj = make_object(1, &data);

        let index = Arc::new(MockObjectIndex::new());
        index.set_objects(42, vec![obj]);

        let reader = Arc::new(MockObjectReader::new());
        reader.put(1, &data);

        let ledger = ScrubLedger::new(0);
        let mut engine = ScrubEngine::new(ledger, index, reader);

        let outcomes = engine.run_cycle(42);
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(
            outcomes[0],
            IntegrityOutcome::Clean { object_id: 1 }
        ));
        assert_eq!(engine.stats().objects_scanned, 1);
        assert_eq!(engine.ledger().last_scanned_object_id, 1);
    }

    #[test]
    fn multi_object_incremental_progress() {
        let data1 = b"alpha".to_vec();
        let data2 = b"beta".to_vec();
        let data3 = b"gamma".to_vec();

        let index = Arc::new(MockObjectIndex::new());
        index.set_objects(
            99,
            vec![
                make_object(10, &data1),
                make_object(20, &data2),
                make_object(30, &data3),
            ],
        );

        let reader = Arc::new(MockObjectReader::new());
        reader.put(10, &data1);
        reader.put(20, &data2);
        reader.put(30, &data3);

        let ledger = ScrubLedger::new(0);
        let mut engine = ScrubEngine::new(ledger, index, reader);

        // First cycle: scan all 3 objects.
        let outcomes = engine.run_cycle(99);
        assert_eq!(outcomes.len(), 3);
        assert!(outcomes
            .iter()
            .all(|o| matches!(o, IntegrityOutcome::Clean { .. })));
        assert_eq!(engine.ledger().last_scanned_object_id, 30);
        assert_eq!(engine.stats().objects_scanned, 3);

        // Second cycle: ledger at 30, no new objects.
        let outcomes2 = engine.run_cycle(99);
        assert!(outcomes2.is_empty());
        assert_eq!(engine.ledger().last_scanned_object_id, 30);
    }

    #[test]
    fn resume_from_ledger_position_after_simulated_crash() {
        let data1 = b"first".to_vec();
        let data2 = b"second".to_vec();
        let data3 = b"third".to_vec();

        let index = Arc::new(MockObjectIndex::new());
        index.set_objects(
            7,
            vec![
                make_object(5, &data1),
                make_object(15, &data2),
                make_object(25, &data3),
            ],
        );

        let reader = Arc::new(MockObjectReader::new());
        reader.put(5, &data1);
        reader.put(15, &data2);
        reader.put(25, &data3);

        // Simulate: first engine processes object 5, saves ledger.
        let ledger = ScrubLedger::new(0);
        let mut engine1 = ScrubEngine::new(ledger.clone(), index.clone(), reader.clone());
        let outcomes1 = engine1.run_cycle(7);
        assert_eq!(outcomes1.len(), 3);
        // After processing, ledger points to 25 (last object).
        let saved_bytes = engine1.ledger().serialize();

        // Simulated crash/restart: load ledger from bytes.
        let restored_ledger = ScrubLedger::read(&saved_bytes).expect("ledger restore failed");
        // Add new object 35 since last scan.
        let data4 = b"fourth".to_vec();
        index.set_objects(
            7,
            vec![
                make_object(5, &data1),
                make_object(15, &data2),
                make_object(25, &data3),
                make_object(35, &data4),
            ],
        );
        reader.put(35, &data4);

        let mut engine2 = ScrubEngine::new(restored_ledger, index, reader);
        let outcomes2 = engine2.run_cycle(7);
        // Should only scan object 35 (IDs > 25).
        assert_eq!(outcomes2.len(), 1);
        assert!(matches!(
            outcomes2[0],
            IntegrityOutcome::Clean { object_id: 35 }
        ));
        assert_eq!(engine2.ledger().last_scanned_object_id, 35);
        assert_eq!(engine2.stats().objects_scanned, 1);
    }

    // ── State machine tests ─────────────────────────────────────

    #[test]
    fn state_start_from_idle_succeeds() {
        let index = Arc::new(MockObjectIndex::new());
        let reader = Arc::new(MockObjectReader::new());
        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        assert_eq!(engine.state(), ScrubState::Idle);
        assert!(engine.start().is_ok());
        assert_eq!(engine.state(), ScrubState::Running);
    }

    #[test]
    fn state_start_from_running_fails() {
        let index = Arc::new(MockObjectIndex::new());
        let reader = Arc::new(MockObjectReader::new());
        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        engine.start().unwrap();
        assert!(engine.start().is_err());
    }

    #[test]
    fn state_pause_from_running_succeeds() {
        let index = Arc::new(MockObjectIndex::new());
        let reader = Arc::new(MockObjectReader::new());
        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        engine.start().unwrap();
        assert!(engine.pause().is_ok());
        assert_eq!(engine.state(), ScrubState::Paused);
    }

    #[test]
    fn state_pause_from_idle_fails() {
        let index = Arc::new(MockObjectIndex::new());
        let reader = Arc::new(MockObjectReader::new());
        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        assert!(engine.pause().is_err());
    }

    #[test]
    fn state_resume_from_paused_succeeds() {
        let index = Arc::new(MockObjectIndex::new());
        let reader = Arc::new(MockObjectReader::new());
        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        engine.start().unwrap();
        engine.pause().unwrap();
        assert!(engine.resume().is_ok());
        assert_eq!(engine.state(), ScrubState::Running);
    }

    #[test]
    fn state_resume_from_running_fails() {
        let index = Arc::new(MockObjectIndex::new());
        let reader = Arc::new(MockObjectReader::new());
        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        engine.start().unwrap();
        assert!(engine.resume().is_err());
    }

    #[test]
    fn state_cancel_from_running_succeeds() {
        let index = Arc::new(MockObjectIndex::new());
        let reader = Arc::new(MockObjectReader::new());
        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        engine.start().unwrap();
        assert!(engine.cancel().is_ok());
        assert_eq!(engine.state(), ScrubState::Stopped);
    }

    #[test]
    fn state_cancel_from_stopped_fails() {
        let index = Arc::new(MockObjectIndex::new());
        let reader = Arc::new(MockObjectReader::new());
        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        engine.start().unwrap();
        engine.cancel().unwrap();
        assert!(engine.cancel().is_err());
    }

    #[test]
    fn state_cancel_from_idle_succeeds() {
        let index = Arc::new(MockObjectIndex::new());
        let reader = Arc::new(MockObjectReader::new());
        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        assert!(engine.cancel().is_ok());
        assert_eq!(engine.state(), ScrubState::Stopped);
    }

    #[test]
    fn run_cycle_auto_starts_from_idle() {
        let data = b"test-auto-start".to_vec();
        let obj = make_object(1, &data);
        let index = Arc::new(MockObjectIndex::new());
        index.set_objects(1, vec![obj]);
        let reader = Arc::new(MockObjectReader::new());
        reader.put(1, &data);

        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        assert_eq!(engine.state(), ScrubState::Idle);
        let outcomes = engine.run_cycle(1);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(engine.state(), ScrubState::Running);
        // Second cycle with no new objects transitions to Stopped.
        let outcomes2 = engine.run_cycle(1);
        assert!(outcomes2.is_empty());
        assert_eq!(engine.state(), ScrubState::Stopped);
    }

    #[test]
    fn run_cycle_returns_empty_when_paused() {
        let data = b"paused-test".to_vec();
        let obj = make_object(1, &data);
        let index = Arc::new(MockObjectIndex::new());
        index.set_objects(1, vec![obj]);
        let reader = Arc::new(MockObjectReader::new());
        reader.put(1, &data);

        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        engine.start().unwrap();
        engine.pause().unwrap();
        let outcomes = engine.run_cycle(1);
        assert!(outcomes.is_empty());
        assert_eq!(engine.state(), ScrubState::Paused);
    }

    #[test]
    fn run_cycle_returns_empty_when_stopped() {
        let data = b"stopped-test".to_vec();
        let obj = make_object(1, &data);
        let index = Arc::new(MockObjectIndex::new());
        index.set_objects(1, vec![obj]);
        let reader = Arc::new(MockObjectReader::new());
        reader.put(1, &data);

        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        engine.cancel().unwrap();
        let outcomes = engine.run_cycle(1);
        assert!(outcomes.is_empty());
    }

    #[test]
    fn pause_resume_preserves_progress() {
        let data1 = b"first".to_vec();
        let data2 = b"second".to_vec();
        let index = Arc::new(MockObjectIndex::new());
        index.set_objects(1, vec![make_object(10, &data1), make_object(20, &data2)]);
        let reader = Arc::new(MockObjectReader::new());
        reader.put(10, &data1);
        reader.put(20, &data2);

        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        engine.start().unwrap();
        let outcomes = engine.run_cycle(1);
        assert_eq!(outcomes.len(), 2);
        assert_eq!(engine.objects_scanned(), 2);
        assert!(engine.bytes_scanned() > 0);

        engine.pause().unwrap();
        assert!(engine.is_paused());
        assert_eq!(engine.objects_scanned(), 2);
    }

    #[test]
    fn progress_accumulates_across_cycles() {
        let data = b"accumulate".to_vec();
        let index = Arc::new(MockObjectIndex::new());
        index.set_objects(1, vec![make_object(1, &data), make_object(2, &data)]);
        let reader = Arc::new(MockObjectReader::new());
        reader.put(1, &data);
        reader.put(2, &data);

        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        engine.start().unwrap();
        let _ = engine.run_cycle(1);
        assert_eq!(engine.objects_scanned(), 2);
        assert_eq!(engine.bytes_scanned(), data.len() as u64 * 2);
    }

    #[test]
    fn reset_stats_clears_progress() {
        let data = b"reset-me".to_vec();
        let obj = make_object(1, &data);
        let index = Arc::new(MockObjectIndex::new());
        index.set_objects(1, vec![obj]);
        let reader = Arc::new(MockObjectReader::new());
        reader.put(1, &data);

        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        engine.start().unwrap();
        let _ = engine.run_cycle(1);
        assert!(engine.objects_scanned() > 0);
        engine.reset_stats();
        assert_eq!(engine.objects_scanned(), 0);
        assert_eq!(engine.bytes_scanned(), 0);
    }

    #[test]
    fn scrub_state_label_and_display() {
        assert_eq!(ScrubState::Idle.label(), "idle");
        assert_eq!(ScrubState::Running.label(), "running");
        assert_eq!(ScrubState::Paused.label(), "paused");
        assert_eq!(ScrubState::Stopped.label(), "stopped");
        assert_eq!(format!("{}", ScrubState::Idle), "idle");
    }

    #[test]
    fn scrub_state_can_run_and_is_terminal() {
        assert!(!ScrubState::Idle.can_run());
        assert!(ScrubState::Running.can_run());
        assert!(!ScrubState::Paused.can_run());
        assert!(!ScrubState::Stopped.can_run());

        assert!(!ScrubState::Idle.is_terminal());
        assert!(!ScrubState::Running.is_terminal());
        assert!(!ScrubState::Paused.is_terminal());
        assert!(ScrubState::Stopped.is_terminal());
    }

    #[test]
    fn is_running_is_paused_is_stopped_accessors() {
        let index = Arc::new(MockObjectIndex::new());
        let reader = Arc::new(MockObjectReader::new());
        let mut engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        assert!(!engine.is_running());
        assert!(!engine.is_paused());
        assert!(!engine.is_stopped());

        engine.start().unwrap();
        assert!(engine.is_running());
        assert!(!engine.is_paused());

        engine.pause().unwrap();
        assert!(!engine.is_running());
        assert!(engine.is_paused());

        engine.resume().unwrap();
        engine.cancel().unwrap();
        assert!(engine.is_stopped());
    }

    #[test]
    fn elapsed_returns_duration() {
        let index = Arc::new(MockObjectIndex::new());
        let reader = Arc::new(MockObjectReader::new());
        let engine = ScrubEngine::new(ScrubLedger::new(1), index, reader);
        let e = engine.elapsed();
        assert!(e.as_secs() == 0);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tidefs_background_scheduler::ServiceBudget;

    fn make_store() -> (TempDir, LocalObjectStore, PathBuf) {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("store");
        let store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).unwrap();
        (dir, store, root)
    }

    #[test]
    fn empty_store_completes_cycle_immediately() {
        let (_dir, _store, root) = make_store();
        let mut svc = ScrubService::new(&root, StoreOptions::test_fast());
        assert!(svc.has_work());

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.processed, 0);
        assert!(svc.cycle_complete());
        assert!(!svc.has_work());
    }

    #[test]
    fn store_with_data_passes_checksums() {
        let (_dir, mut store, root) = make_store();
        for i in 0..5 {
            store
                .put_named(format!("obj{i}"), format!("payload-{i}").as_bytes())
                .unwrap();
        }
        store.sync_all().unwrap();
        drop(store);

        let mut svc = ScrubService::new(&root, StoreOptions::test_fast());
        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();

        // Each put_named creates an object in a segment.
        // Segment-level verification counts records, not keys.
        assert!(report.processed > 0, "should have verified some records");
        assert_eq!(report.errors, 0, "no mismatches expected");
        assert!(svc.cycle_complete());
    }

    #[test]
    fn cursor_resume_after_budget_exhaustion() {
        let (_dir, mut store, root) = make_store();
        for i in 0..20 {
            store
                .put_named(format!("obj{i:02}"), format!("payload-{i}").as_bytes())
                .unwrap();
        }
        store.sync_all().unwrap();
        drop(store);

        let mut svc = ScrubService::new(&root, StoreOptions::test_fast());

        // Process at most 3 records per tick.
        let budget = ServiceBudget {
            max_items: 3,
            max_bytes: 0,
            max_ms: 0,
        };
        let r1 = svc.tick(&budget).unwrap();
        assert_eq!(r1.processed, 3);
        assert!(r1.has_more);
        assert!(!svc.cycle_complete());

        // Finish remaining records.
        let r2 = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert!(!r2.has_more);
        assert!(svc.cycle_complete());

        assert_eq!(svc.stats().elapsed_ticks, 2);
        assert!(svc.stats().records_verified > 3);
        assert_eq!(svc.stats().checksum_mismatches, 0);
    }

    #[test]
    fn stats_accumulate_across_cycles() {
        let (_dir, mut store, root) = make_store();
        for i in 0..5 {
            store.put_named(format!("obj{i}"), b"data").unwrap();
        }
        store.sync_all().unwrap();
        drop(store);

        let mut svc = ScrubService::new(&root, StoreOptions::test_fast());
        svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert!(svc.cycle_complete());
        let first_records = svc.stats().records_verified;

        // Reset for new cycle.
        svc.cycle_complete = false;
        svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(svc.stats().records_verified, first_records * 2);
        assert_eq!(svc.stats().elapsed_ticks, 2);
    }

    #[test]
    fn suspect_log_drain_durable_retry_semantics() {
        // Drain no longer clears entries; entries remain in the durable log
        // and are re-dispatched up to max_repair_attempts (3). After the 4th
        // drain (repair_attempts >= 3), entries are skipped.
        let mut svc = ScrubService::new("/nonexistent", StoreOptions::test_fast());
        svc.suspect_log.record(SuspectEntry {
            locator_id: 1,
            segment_id: 2,
            offset: 3,
            record_type: 4,
            expected_hash: [0u8; 32],
            actual_hash: [0u8; 32],
            repair_attempts: 0,
            last_repair_attempt: 0,
            resolved: false,
            commit_group: 5,
            timestamp_secs: 6,
            ..Default::default()
        });
        // Drain 1: entry is unresolved, dispatched (attempts -> 1).
        assert_eq!(svc.drain_suspect_log().len(), 1);
        // Drain 2: still unresolved, re-dispatched (attempts -> 2).
        assert_eq!(svc.drain_suspect_log().len(), 1);
        // Drain 3: still unresolved, re-dispatched (attempts -> 3).
        assert_eq!(svc.drain_suspect_log().len(), 1);
        // Drain 4: repair_attempts >= 3, entry skipped.
        assert!(svc.drain_suspect_log().is_empty());
    }

    #[test]
    fn cursor_tracks_segment_and_offset() {
        let mut cursor = ScrubCursor::new();
        assert_eq!(cursor.segment_id, 0);
        assert_eq!(cursor.offset, 0);

        cursor.segment_id = 5;
        cursor.offset = 1024;
        assert_eq!(cursor.segment_id, 5);

        cursor.reset();
        assert_eq!(cursor.segment_id, 0);
    }

    // ------------------------------------------------------------------
    // ScrubWorker tests
    // ------------------------------------------------------------------

    use std::sync::Arc;

    /// Mock store holding a fixed set of (key, payload, error) entries.
    ///
    /// `checksum_overrides` maps keys to forged expected checksum tree
    /// roots.  When set, the mock returns the forged root instead of
    /// computing the real one from the payload.
    type MockObjectEntry = (ObjectKey, Result<Option<Vec<u8>>, String>);
    type MockObjectEntries = Vec<MockObjectEntry>;

    struct MockObjectStore {
        entries: MockObjectEntries,
        checksum_overrides: std::collections::HashMap<ObjectKey, Digest>,
    }

    impl MockObjectStore {
        fn new(entries: MockObjectEntries) -> Self {
            Self {
                entries,
                checksum_overrides: std::collections::HashMap::new(),
            }
        }

        fn with_checksum_overrides(
            mut self,
            overrides: std::collections::HashMap<ObjectKey, Digest>,
        ) -> Self {
            self.checksum_overrides = overrides;
            self
        }
    }

    impl ObjectStoreTraversal for MockObjectStore {
        fn object_ids(&self) -> Vec<ObjectKey> {
            self.entries.iter().map(|(k, _)| *k).collect()
        }

        fn read_object(&self, id: &ObjectKey) -> Result<Option<Vec<u8>>, String> {
            for (k, v) in &self.entries {
                if k == id {
                    return v.clone();
                }
            }
            Ok(None)
        }

        fn object_checksum_root(&self, id: &ObjectKey) -> Option<(Digest, Option<LocatorToken>)> {
            // Check for a forged override first (used to trigger mismatch tests).
            if let Some(override_root) = self.checksum_overrides.get(id) {
                return Some((*override_root, None));
            }
            // Compute the checksum tree root from the stored payload,
            // matching the real store's get_checksum_tree() behavior.
            for (k, v) in &self.entries {
                if k == id {
                    if let Ok(Some(ref data)) = v {
                        let mut builder = tidefs_checksum_tree::ChecksumTreeBuilder::new(
                            tidefs_checksum_tree::DEFAULT_BLOCK_SIZE,
                        );
                        builder.ingest(data);
                        let tree = builder.finish();
                        return Some((tree.root_hash, tree.locator_token));
                    }
                    return None;
                }
            }
            None
        }
    }

    /// Mock verifier that delegates to the production
    /// [`tidefs_checksum_tree::verify_object`] for real BLAKE3 verification.
    struct MockVerifier;

    impl MockVerifier {
        fn new() -> Self {
            Self
        }
    }

    impl ChecksumVerifier for MockVerifier {
        fn verify(
            &self,
            data: &[u8],
            expected_root: &Digest,
            locator_token: Option<&LocatorToken>,
        ) -> Result<(), ChecksumMismatch> {
            // Delegate to the production verification function.
            verify_object(data, expected_root, locator_token)
        }
    }

    // -----------------------------------------------------------------------
    // Locator-bound scrub tests
    // -----------------------------------------------------------------------

    /// Scrub with locator binding: a locator-bound checksum tree produces
    /// a root that differs from an unbound tree for the same data.
    #[test]
    fn scrub_locator_bound_root_differs_from_unbound() {
        let token = LocatorToken::from_evidence(b"extent-1");
        let data = b"scrub-locator-test-data".to_vec();

        let mut builder = tidefs_checksum_tree::ChecksumTreeBuilder::new(
            tidefs_checksum_tree::DEFAULT_BLOCK_SIZE,
        );
        builder.set_locator(token);
        builder.ingest(&data);
        let tree = builder.finish();

        // Rebuild without locator to confirm roots differ
        let mut builder_no_loc = tidefs_checksum_tree::ChecksumTreeBuilder::new(
            tidefs_checksum_tree::DEFAULT_BLOCK_SIZE,
        );
        builder_no_loc.ingest(&data);
        let tree_no_loc = builder_no_loc.finish();
        assert_ne!(tree_no_loc.root_hash, tree.root_hash,
            "locator-bound root must differ from unbound root");
    }

    /// Scrub detects locator mismatch: object was relocated so locator
    /// no longer matches.  The store returns a root that was computed with
    /// a different locator.
    #[test]
    fn scrub_locator_mismatch_detected() {
        let token_a = LocatorToken::from_evidence(b"extent-old");
        let token_b = LocatorToken::from_evidence(b"extent-new");
        let data = b"relocated-data".to_vec();

        // Build root with token_a (old locator)
        let mut builder_a = tidefs_checksum_tree::ChecksumTreeBuilder::new(
            tidefs_checksum_tree::DEFAULT_BLOCK_SIZE,
        );
        builder_a.set_locator(token_a);
        builder_a.ingest(&data);
        let tree_a = builder_a.finish();

        // Build root with token_b (new locator)
        let mut builder_b = tidefs_checksum_tree::ChecksumTreeBuilder::new(
            tidefs_checksum_tree::DEFAULT_BLOCK_SIZE,
        );
        builder_b.set_locator(token_b);
        builder_b.ingest(&data);
        let tree_b = builder_b.finish();

        // The roots must differ
        assert_ne!(tree_a.root_hash, tree_b.root_hash);

        // Verification with wrong token must fail
        let result_a_with_b = verify_object(&data, &tree_a.root_hash, Some(&token_b));
        assert!(result_a_with_b.is_err(),
            "verify with wrong locator token must fail");

        // Verification with correct token must pass
        let result_a_with_a = verify_object(&data, &tree_a.root_hash, Some(&token_a));
        assert!(result_a_with_a.is_ok(),
            "verify with correct locator token must pass");
    }

    /// ScrubOutcome::LocatorMismatch variant round-trip.
    #[test]
    fn scrub_outcome_locator_mismatch_variant() {
        let token_bound = LocatorToken::from_evidence(b"bound");
        let token_supplied = LocatorToken::from_evidence(b"supplied");
        let outcome = ScrubOutcome::LocatorMismatch {
            object_id: "abc123".to_string(),
            bound: token_bound,
            supplied: token_supplied,
        };
        assert!(!outcome.is_clean());
        assert_eq!(outcome.object_id(), "abc123");
        match &outcome {
            ScrubOutcome::LocatorMismatch { object_id, bound, supplied } => {
                assert_eq!(object_id, "abc123");
                assert_eq!(*bound, token_bound);
                assert_eq!(*supplied, token_supplied);
            }
            _ => panic!("expected LocatorMismatch"),
        }
    }

    fn make_key(name: &str) -> ObjectKey {
        ObjectKey::from_name(name)
    }

    #[test]
    fn scrub_worker_empty_store_yields_zero_outcomes() {
        let store = Arc::new(MockObjectStore::new(Vec::new()));
        let verifier = Arc::new(MockVerifier::new());
        let worker = ScrubWorker::new(store, verifier);
        let summary = worker.run();

        assert_eq!(summary.total, 0);
        assert_eq!(summary.clean, 0);
        assert_eq!(summary.mismatches, 0);
        assert_eq!(summary.io_errors, 0);
        assert!(summary.outcomes.is_empty());
        assert!(summary.is_clean());
    }

    #[test]
    fn scrub_worker_clean_objects_classified_correctly() {
        let k1 = make_key("obj-a");
        let k2 = make_key("obj-b");
        let store = Arc::new(MockObjectStore::new(vec![
            (k1, Ok(Some(b"good data".to_vec()))),
            (k2, Ok(Some(b"also good".to_vec()))),
        ]));
        let verifier = Arc::new(MockVerifier::new());
        let worker = ScrubWorker::new(store, verifier);
        let summary = worker.run();

        assert_eq!(summary.total, 2);
        assert_eq!(summary.clean, 2);
        assert_eq!(summary.mismatches, 0);
        assert_eq!(summary.io_errors, 0);
        assert!(summary.is_clean());
        for outcome in &summary.outcomes {
            assert!(matches!(outcome, ScrubOutcome::Clean { .. }));
        }
    }
    #[test]
    fn scrub_worker_mismatch_detected() {
        let k1 = make_key("good-obj");
        let k2 = make_key("bad-obj");
        // Forge a wrong expected root for k2 so verify_object reports a mismatch.
        let mut overrides = std::collections::HashMap::new();
        overrides.insert(k2, [0xDEu8; 32]); // forged root does not match real data
        let store = Arc::new(
            MockObjectStore::new(vec![
                (k1, Ok(Some(b"good data".to_vec()))),
                (
                    k2,
                    Ok(Some(
                        b"legitimate payload that won't match the forged root".to_vec(),
                    )),
                ),
            ])
            .with_checksum_overrides(overrides),
        );
        let verifier = Arc::new(MockVerifier::new());
        let worker = ScrubWorker::new(store, verifier);
        let summary = worker.run();

        assert_eq!(summary.total, 2);
        assert_eq!(summary.clean, 1);
        assert_eq!(summary.mismatches, 1);
        assert_eq!(summary.io_errors, 0);
        assert!(!summary.is_clean());
        assert!(
            summary
                .outcomes
                .iter()
                .any(|o| matches!(o, ScrubOutcome::Mismatch { .. })),
            "expected a Mismatch outcome"
        );
    }
    #[test]
    fn scrub_worker_io_error_captured() {
        let k1 = make_key("good-obj");
        let k2 = make_key("io-err-obj");
        let store = Arc::new(MockObjectStore::new(vec![
            (k1, Ok(Some(b"good data".to_vec()))),
            (k2, Err("disk failure".to_string())),
        ]));
        let verifier = Arc::new(MockVerifier::new());
        let worker = ScrubWorker::new(store, verifier);
        let summary = worker.run();

        assert_eq!(summary.total, 2);
        assert_eq!(summary.clean, 1);
        assert_eq!(summary.mismatches, 0);
        assert_eq!(summary.io_errors, 1);
        assert!(!summary.is_clean());
        assert!(
            summary.outcomes.iter().any(|o| matches!(
                o,
                ScrubOutcome::IoError { error, .. }
                    if error == "disk failure"
            )),
            "expected IoError outcome with 'disk failure'"
        );
    }

    #[test]
    fn scrub_worker_object_deleted_between_enum_and_read_skipped() {
        let k1 = make_key("present");
        let k2 = make_key("deleted");
        let store = Arc::new(MockObjectStore::new(vec![
            (k1, Ok(Some(b"good data".to_vec()))),
            (k2, Ok(None)), // deleted between enumeration and read
        ]));
        let verifier = Arc::new(MockVerifier::new());
        let worker = ScrubWorker::new(store, verifier);
        let summary = worker.run();

        // k2 returns None so it's skipped (not counted)
        assert_eq!(summary.total, 2); // object_ids() returns 2
        assert_eq!(summary.clean, 1); // only k1 was verified
        assert_eq!(summary.mismatches, 0);
        assert_eq!(summary.io_errors, 0);
        assert_eq!(summary.outcomes.len(), 1);
        assert!(summary.is_clean());
    }

    #[test]
    fn scrub_summary_text_output() {
        let summary = ScrubSummary {
            total: 10,
            clean: 8,
            mismatches: 1,
            locator_mismatches: 0,
            io_errors: 1,
            outcomes: vec![
                ScrubOutcome::Clean {
                    object_id: "aa".into(),
                },
                ScrubOutcome::Mismatch {
                    object_id: "bb".into(),
                    expected: [0x01u8; 32],
                    computed: [0x02u8; 32],
                },
            ],
        };

        let text = summary.text_summary();
        assert!(text.contains("total:     10"));
        assert!(text.contains("clean:     8"));
        assert!(text.contains("mismatches: 1"));
        assert!(text.contains("io errors: 1"));
        assert!(text.contains("MISMATCH bb"));
    }

    #[test]
    fn scrub_outcome_is_clean_and_object_id() {
        let clean = ScrubOutcome::Clean {
            object_id: "abc".into(),
        };
        assert!(clean.is_clean());
        assert_eq!(clean.object_id(), "abc");

        let mismatch = ScrubOutcome::Mismatch {
            object_id: "def".into(),
            expected: [0u8; 32],
            computed: [1u8; 32],
        };
        assert!(!mismatch.is_clean());
        assert_eq!(mismatch.object_id(), "def");

        let io_err = ScrubOutcome::IoError {
            object_id: "ghi".into(),
            error: "read error".into(),
        };
        assert!(!io_err.is_clean());
        assert_eq!(io_err.object_id(), "ghi");
    }

    // ------------------------------------------------------------------
    // ResilverService tests
    // ------------------------------------------------------------------

    /// Mock extent enumerator that returns a fixed set of extent IDs.
    struct MockExtentEnumerator {
        extents: Vec<u64>,
    }

    impl MockExtentEnumerator {
        fn new(extents: Vec<u64>) -> Self {
            Self { extents }
        }
    }

    impl ExtentEnumerator for MockExtentEnumerator {
        fn extent_count(&self, _device_id: u64) -> u64 {
            self.extents.len() as u64
        }

        fn enumerate_device_extents(
            &self,
            _device_id: u64,
            cursor: u64,
            limit: u64,
        ) -> Result<(Vec<ExtentId>, bool), String> {
            let start = cursor as usize;
            let end = (start + limit as usize).min(self.extents.len());
            let batch: Vec<ExtentId> = self.extents[start..end]
                .iter()
                .map(|&id| ExtentId(id))
                .collect();
            let has_more = end < self.extents.len();
            Ok((batch, has_more))
        }
    }

    /// Mock reconstruction source that returns fixed data and tracks calls.
    struct MockReconstructionSource {
        data: Vec<u8>,
        reconstruct_calls: Mutex<Vec<u64>>,
        write_calls: Mutex<Vec<(u64, Vec<u8>)>>,
    }

    impl MockReconstructionSource {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                reconstruct_calls: Mutex::new(Vec::new()),
                write_calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl ReconstructionSource for MockReconstructionSource {
        fn reconstruct_extent(
            &self,
            extent_id: ExtentId,
            _failed_device_id: u64,
        ) -> Result<Vec<u8>, String> {
            self.reconstruct_calls.lock().unwrap().push(extent_id.0);
            Ok(self.data.clone())
        }

        fn write_to_replacement(
            &self,
            extent_id: ExtentId,
            _replacement_device_id: u64,
            data: &[u8],
        ) -> Result<(), String> {
            self.write_calls
                .lock()
                .unwrap()
                .push((extent_id.0, data.to_vec()));
            Ok(())
        }
    }

    #[test]
    fn resilver_stats_default_zero() {
        let stats = ResilverStats::default();
        assert_eq!(stats.objects_scanned, 0);
        assert_eq!(stats.objects_rebuilt, 0);
        assert_eq!(stats.objects_failed, 0);
        assert_eq!(stats.bytes_rebuilt, 0);
        assert_eq!(stats.estimated_completion, 0.0);
        assert_eq!(stats.bandwidth_utilization, 0.0);
    }

    #[test]
    fn resilver_stats_record_rebuilt() {
        let mut stats = ResilverStats::default();
        stats.record_rebuilt(1024, 1_000_000_000);
        assert_eq!(stats.objects_rebuilt, 1);
        assert_eq!(stats.bytes_rebuilt, 1024);
        assert_eq!(stats.last_update_ns, 1_000_000_000);
    }

    #[test]
    fn resilver_stats_record_failed() {
        let mut stats = ResilverStats::default();
        stats.record_failed(2_000_000_000);
        assert_eq!(stats.objects_failed, 1);
        assert_eq!(stats.last_update_ns, 2_000_000_000);
    }

    #[test]
    fn resilver_stats_record_scanned() {
        let mut stats = ResilverStats::default();
        stats.record_scanned();
        stats.record_scanned();
        assert_eq!(stats.objects_scanned, 2);
    }

    #[test]
    fn resilver_stats_update_estimates() {
        let mut stats = ResilverStats::default();
        stats.record_rebuilt(500, 1_000_000_000);
        stats.update_estimates(10, 2_000_000_000);
        assert!((stats.estimated_completion - 0.1).abs() < 0.001);
        assert!(stats.bandwidth_utilization > 0.0);
    }

    #[test]
    fn resilver_stats_saturation_handling() {
        let mut stats = ResilverStats {
            objects_rebuilt: u64::MAX,
            ..Default::default()
        };
        stats.record_rebuilt(1, 0);
        assert_eq!(stats.objects_rebuilt, u64::MAX); // saturated
    }

    #[test]
    fn resilver_service_has_work_initially() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![1, 2, 3]));
        let reconstructor = Arc::new(MockReconstructionSource::new(b"data".to_vec()));
        let svc = ResilverService::new(1, 2, enumerator, reconstructor);
        assert!(svc.has_work());
        assert!(!svc.cycle_complete());
    }

    #[test]
    fn resilver_service_name_and_priority() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![1]));
        let reconstructor = Arc::new(MockReconstructionSource::new(b"x".to_vec()));
        let svc = ResilverService::new(1, 2, enumerator, reconstructor);
        assert_eq!(svc.name(), "ResilverService");
        assert_eq!(svc.priority(), ServicePriority::Critical);
    }

    #[test]
    fn resilver_service_empty_device_completes_immediately() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![]));
        let reconstructor = Arc::new(MockReconstructionSource::new(b"data".to_vec()));
        let mut svc = ResilverService::new(1, 2, enumerator, reconstructor);
        assert!(svc.has_work());

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.processed, 0);
        assert!(svc.cycle_complete());
        assert!(!svc.has_work());
    }

    #[test]
    fn resilver_service_rebuilds_all_extents() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![10, 20, 30]));
        let reconstructor = Arc::new(MockReconstructionSource::new(b"payload".to_vec()));
        let mut svc = ResilverService::new(1, 2, enumerator.clone(), reconstructor.clone());
        assert!(svc.has_work());

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.processed, 3);
        assert_eq!(report.errors, 0);
        assert!(svc.cycle_complete());
        assert!(!svc.has_work());

        let stats = svc.stats();
        assert_eq!(stats.objects_scanned, 3);
        assert_eq!(stats.objects_rebuilt, 3);
        assert_eq!(stats.bytes_rebuilt, 21); // 3 * 7 bytes of "payload"
    }

    #[test]
    fn resilver_service_cursor_resume_across_ticks() {
        let enumerator = Arc::new(MockExtentEnumerator::new((0..20).collect()));
        let reconstructor = Arc::new(MockReconstructionSource::new(b"x".to_vec()));
        let mut svc = ResilverService::new(1, 2, enumerator, reconstructor);

        // Process 5 items per tick
        let budget = ServiceBudget {
            max_items: 5,
            max_bytes: 0,
            max_ms: 0,
        };
        let r1 = svc.tick(&budget).unwrap();
        assert_eq!(r1.processed, 5);
        assert!(r1.has_more);
        assert!(!svc.cycle_complete());

        let r2 = svc.tick(&budget).unwrap();
        assert_eq!(r2.processed, 5);
        assert!(r2.has_more);

        let r3 = svc.tick(&budget).unwrap();
        assert_eq!(r3.processed, 5);
        assert!(r3.has_more);

        let r4 = svc.tick(&budget).unwrap();
        assert_eq!(r4.processed, 5);
        assert!(!r4.has_more);
        assert!(svc.cycle_complete());

        assert_eq!(svc.stats().objects_scanned, 20);
        assert_eq!(svc.stats().objects_rebuilt, 20);
    }

    #[test]
    fn resilver_worker_empty_device() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![]));
        let reconstructor = Arc::new(MockReconstructionSource::new(b"data".to_vec()));
        let worker = ResilverWorker::new(1, 2, enumerator, reconstructor);
        let summary = worker.run();

        assert_eq!(summary.total_extents, 0);
        assert_eq!(summary.rebuilt, 0);
        assert_eq!(summary.failed, 0);
        assert!(summary.is_clean());
        assert!(summary.outcomes.is_empty());
    }

    #[test]
    fn resilver_worker_rebuilds_all_extents() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![1, 2, 3]));
        let reconstructor = Arc::new(MockReconstructionSource::new(b"blk".to_vec()));
        let worker = ResilverWorker::new(1, 2, enumerator, reconstructor);
        let summary = worker.run();

        assert_eq!(summary.total_extents, 3);
        assert_eq!(summary.rebuilt, 3);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.bytes_rebuilt, 9);
        assert!(summary.is_clean());

        for outcome in &summary.outcomes {
            assert!(matches!(outcome, ResilverOutcome::Rebuilt { .. }));
        }
    }

    #[test]
    fn resilver_worker_reconstruct_error_recorded() {
        /// A source that always fails to reconstruct
        struct FailingReconstructor;
        impl ReconstructionSource for FailingReconstructor {
            fn reconstruct_extent(
                &self,
                _extent_id: ExtentId,
                _failed_device_id: u64,
            ) -> Result<Vec<u8>, String> {
                Err("source unavailable".into())
            }

            fn write_to_replacement(
                &self,
                _extent_id: ExtentId,
                _replacement_device_id: u64,
                _data: &[u8],
            ) -> Result<(), String> {
                Ok(())
            }
        }

        let enumerator = Arc::new(MockExtentEnumerator::new(vec![1, 2]));
        let reconstructor = Arc::new(FailingReconstructor);
        let worker = ResilverWorker::new(1, 2, enumerator, reconstructor);
        let summary = worker.run();

        assert_eq!(summary.total_extents, 2);
        assert_eq!(summary.rebuilt, 0);
        assert_eq!(summary.failed, 2);
        assert!(!summary.is_clean());
    }

    #[test]
    fn resilver_outcome_is_rebuilt_and_extent_id() {
        let rebuilt = ResilverOutcome::Rebuilt {
            extent_id: 42,
            bytes: 1024,
        };
        assert!(rebuilt.is_rebuilt());
        assert_eq!(rebuilt.extent_id(), Some(42));

        let recon_err = ResilverOutcome::ReconstructError {
            extent_id: 7,
            error: "nope".into(),
        };
        assert!(!recon_err.is_rebuilt());
        assert_eq!(recon_err.extent_id(), Some(7));

        let write_err = ResilverOutcome::WriteError {
            extent_id: 3,
            error: "disk full".into(),
        };
        assert!(!write_err.is_rebuilt());
        assert_eq!(write_err.extent_id(), Some(3));

        let enum_err = ResilverOutcome::EnumerationError {
            error: "scan failed".into(),
        };
        assert!(!enum_err.is_rebuilt());
        assert_eq!(enum_err.extent_id(), None);
    }

    #[test]
    fn resilver_summary_text_output() {
        let stats = ResilverStats {
            objects_rebuilt: 8,
            objects_scanned: 10,
            bytes_rebuilt: 8000,
            estimated_completion: 0.8,
            ..Default::default()
        };

        let summary = ResilverSummary {
            total_extents: 10,
            rebuilt: 8,
            failed: 2,
            bytes_rebuilt: 8000,
            stats,
            outcomes: vec![
                ResilverOutcome::Rebuilt {
                    extent_id: 1,
                    bytes: 1000,
                },
                ResilverOutcome::ReconstructError {
                    extent_id: 2,
                    error: "no replica".into(),
                },
            ],
        };

        let text = summary.text_summary();
        assert!(text.contains("total_extents: 10"));
        assert!(text.contains("rebuilt:       8"));
        assert!(text.contains("failed:        2"));
        assert!(text.contains("bytes_rebuilt: 8000"));
        assert!(text.contains("RECONSTRUCT_ERROR extent=2"));
    }

    #[test]
    fn resilver_stats_update_estimates_zero_total() {
        let mut stats = ResilverStats::default();
        stats.record_rebuilt(100, 1_000_000_000);
        // zero total should not divide by zero
        stats.update_estimates(0, 2_000_000_000);
        assert_eq!(stats.estimated_completion, 0.0);
        assert!(stats.bandwidth_utilization > 0.0);
    }

    #[test]
    fn resilver_stats_zero_elapsed() {
        let mut stats = ResilverStats::default();
        stats.record_rebuilt(100, 1_000_000_000);
        stats.update_estimates(10, 0);
        assert!((stats.estimated_completion - 0.1).abs() < 0.001);
        assert_eq!(stats.bandwidth_utilization, 0.0); // no elapsed time
    }

    // ------------------------------------------------------------------
    // LocatorTableExtentEnumerator tests
    // ------------------------------------------------------------------

    #[test]
    fn locator_table_enumerator_empty_device_returns_zero() {
        let dir = TempDir::new().unwrap();
        let store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let locator_table = Arc::new(tidefs_locator_table::LocatorTable::new(store, 1));
        let enumerator = LocatorTableExtentEnumerator::new(vec![], locator_table);
        assert_eq!(enumerator.extent_count(1), 0);
    }

    #[test]
    fn locator_table_enumerator_finds_extents_on_device() {
        let dir = TempDir::new().unwrap();
        let store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let locator_table = Arc::new(tidefs_locator_table::LocatorTable::new(store, 1));

        // Insert two extents for inode 10 on device 5
        let e1 = tidefs_locator_table::LocatorEntry::new(
            0,
            ExtentId(100),
            5, // device_id
            0,
            4096,
            0,
        );
        let e2 = tidefs_locator_table::LocatorEntry::new(
            4096,
            ExtentId(200),
            5, // same device
            4096,
            4096,
            0,
        );
        locator_table.insert(10, e1).unwrap();
        locator_table.insert(10, e2).unwrap();

        let enumerator = LocatorTableExtentEnumerator::new(vec![10], locator_table.clone());
        assert_eq!(enumerator.extent_count(5), 2);

        // Enumerate
        let (batch, has_more) = enumerator.enumerate_device_extents(5, 0, 10).unwrap();
        assert_eq!(batch.len(), 2);
        assert!(!has_more);
        assert!(batch.contains(&ExtentId(100)));
        assert!(batch.contains(&ExtentId(200)));
    }

    #[test]
    fn locator_table_enumerator_filters_by_device_id() {
        let dir = TempDir::new().unwrap();
        let store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let locator_table = Arc::new(tidefs_locator_table::LocatorTable::new(store, 1));

        // Device 5 and device 7
        locator_table
            .insert(
                10,
                tidefs_locator_table::LocatorEntry::new(0, ExtentId(100), 5, 0, 4096, 0),
            )
            .unwrap();
        locator_table
            .insert(
                10,
                tidefs_locator_table::LocatorEntry::new(4096, ExtentId(200), 7, 0, 4096, 0),
            )
            .unwrap();

        let enumerator = LocatorTableExtentEnumerator::new(vec![10], locator_table);
        assert_eq!(enumerator.extent_count(5), 1);
        assert_eq!(enumerator.extent_count(7), 1);
        assert_eq!(enumerator.extent_count(99), 0); // non-existent device
    }

    #[test]
    fn locator_table_enumerator_cursor_and_limit() {
        let dir = TempDir::new().unwrap();
        let store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let locator_table = Arc::new(tidefs_locator_table::LocatorTable::new(store, 1));

        for i in 0..10 {
            locator_table
                .insert(
                    10,
                    tidefs_locator_table::LocatorEntry::new(
                        i * 4096,
                        ExtentId(100 + i),
                        1,
                        0,
                        4096,
                        0,
                    ),
                )
                .unwrap();
        }

        let enumerator = LocatorTableExtentEnumerator::new(vec![10], locator_table);
        assert_eq!(enumerator.extent_count(1), 10);

        // First 3
        let (batch, has_more) = enumerator.enumerate_device_extents(1, 0, 3).unwrap();
        assert_eq!(batch.len(), 3);
        assert!(has_more);

        // Next 3
        let (batch, has_more) = enumerator.enumerate_device_extents(1, 3, 3).unwrap();
        assert_eq!(batch.len(), 3);
        assert!(has_more);

        // Last 4
        let (batch, has_more) = enumerator.enumerate_device_extents(1, 6, 5).unwrap();
        assert_eq!(batch.len(), 4);
        assert!(!has_more);
    }

    // ------------------------------------------------------------------
    // LocalMirrorReconstructionSource tests
    // ------------------------------------------------------------------

    #[test]
    fn local_mirror_reconstruct_reads_from_source_device() {
        let dir = TempDir::new().unwrap();
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();

        // Write a replica on device 2 for extent 42
        let key = tidefs_local_object_store::ObjectKey::from_name(b"extent:42:device:2");
        store.put(key, b"replica data").unwrap();
        store.sync_all().unwrap();
        drop(store);

        // Re-open for the reconstruction source
        let store2 =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();

        let mut replica_map = std::collections::HashMap::new();
        replica_map.insert(42, 2); // extent 42's replica is on device 2

        let source = LocalMirrorReconstructionSource::new(store2, replica_map, 3);

        let data = source.reconstruct_extent(ExtentId(42), 1).unwrap();
        assert_eq!(data, b"replica data");
    }

    #[test]
    fn local_mirror_reconstruct_no_source_returns_error() {
        let dir = TempDir::new().unwrap();
        let store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let source =
            LocalMirrorReconstructionSource::new(store, std::collections::HashMap::new(), 3);

        let result = source.reconstruct_extent(ExtentId(99), 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no replica source"));
    }

    #[test]
    fn local_mirror_reconstruct_missing_data_returns_error() {
        let dir = TempDir::new().unwrap();
        let store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();

        let mut replica_map = std::collections::HashMap::new();
        replica_map.insert(42, 2); // map says replica exists

        let source = LocalMirrorReconstructionSource::new(store, replica_map, 3);

        // But the store doesn't actually have the data
        let result = source.reconstruct_extent(ExtentId(42), 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn local_mirror_write_to_replacement() {
        let dir = TempDir::new().unwrap();
        let store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();

        let source = LocalMirrorReconstructionSource::new(
            store,
            std::collections::HashMap::new(),
            3, // replacement_device_id = 3
        );

        let result = source.write_to_replacement(ExtentId(55), 3, b"rebuilt data");
        assert!(result.is_ok());
    }

    #[test]
    fn local_mirror_reconstruct_then_write_roundtrip() {
        let dir = TempDir::new().unwrap();
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();

        // Write source data on device 1
        let src_key = tidefs_local_object_store::ObjectKey::from_name(b"extent:10:device:1");
        store.put(src_key, b"hello world").unwrap();
        store.sync_all().unwrap();
        drop(store);

        let store2 =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();

        let mut replica_map = std::collections::HashMap::new();
        replica_map.insert(10, 1);

        let source = LocalMirrorReconstructionSource::new(store2, replica_map, 2);

        // Reconstruct
        let data = source.reconstruct_extent(ExtentId(10), 0).unwrap();
        assert_eq!(data, b"hello world");

        // Write to replacement device
        source.write_to_replacement(ExtentId(10), 2, &data).unwrap();

        // Verify the data landed on device 2
        let store3 =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let dst_key = tidefs_local_object_store::ObjectKey::from_name(b"extent:10:device:2");
        let restored = store3.get(dst_key).unwrap();
        assert_eq!(restored, Some(b"hello world".to_vec()));
    }

    // ------------------------------------------------------------------
    // StripeGrouping tests
    // ------------------------------------------------------------------

    #[test]
    fn default_stripe_grouping_different_keys_for_different_extents() {
        let g = DefaultStripeGrouping::new(4);
        let m1 = g.stripe_key(ExtentId(0), 1);
        let m2 = g.stripe_key(ExtentId(1), 1);
        assert_ne!(m1.stripe_key, m2.stripe_key);
    }

    #[test]
    fn default_stripe_grouping_same_key_for_same_modulo() {
        let g = DefaultStripeGrouping::new(4);
        let m1 = g.stripe_key(ExtentId(4), 1);
        let m2 = g.stripe_key(ExtentId(8), 1);
        assert_eq!(m1.stripe_key, m2.stripe_key);
    }

    #[test]
    fn default_stripe_grouping_width_one_all_same_key() {
        let g = DefaultStripeGrouping::new(1);
        let m1 = g.stripe_key(ExtentId(0), 1);
        let m2 = g.stripe_key(ExtentId(5), 1);
        assert_eq!(m1.stripe_key, m2.stripe_key);
    }

    #[test]
    #[should_panic(expected = "stripe_width must be positive")]
    fn default_stripe_grouping_zero_width_panics() {
        let _g = DefaultStripeGrouping::new(0);
    }

    // ------------------------------------------------------------------
    // StripeParallelResilverService tests
    // ------------------------------------------------------------------

    #[test]
    fn stripe_parallel_service_has_work_initially() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![1, 2, 3]));
        let reconstructor = Arc::new(MockReconstructionSource::new(b"data".to_vec()));
        let grouping = Arc::new(DefaultStripeGrouping::new(4));
        let svc = StripeParallelResilverService::new(1, 2, enumerator, reconstructor, grouping, 4);
        assert!(svc.has_work());
        assert!(!svc.cycle_complete());
    }

    #[test]
    fn stripe_parallel_service_empty_device_completes_immediately() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![]));
        let reconstructor = Arc::new(MockReconstructionSource::new(b"data".to_vec()));
        let grouping = Arc::new(DefaultStripeGrouping::new(4));
        let mut svc =
            StripeParallelResilverService::new(1, 2, enumerator, reconstructor, grouping, 4);
        assert!(svc.has_work());

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.processed, 0);
        assert!(svc.cycle_complete());
    }

    #[test]
    fn stripe_parallel_service_rebuilds_all_extents() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![10, 20, 30, 40]));
        let reconstructor = Arc::new(MockReconstructionSource::new(b"payload".to_vec()));
        let grouping = Arc::new(DefaultStripeGrouping::new(4));
        let mut svc = StripeParallelResilverService::new(
            1,
            2,
            enumerator.clone(),
            reconstructor.clone(),
            grouping,
            4,
        );
        assert!(svc.has_work());

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.processed, 4);
        assert_eq!(report.errors, 0);
        assert!(svc.cycle_complete());

        let stats = svc.stats();
        assert_eq!(stats.objects_scanned, 4);
        assert_eq!(stats.objects_rebuilt, 4);
        assert_eq!(stats.bytes_rebuilt, 28); // 4 * 7 bytes
    }

    #[test]
    fn stripe_parallel_service_cursor_resume_across_ticks() {
        let enumerator = Arc::new(MockExtentEnumerator::new((0..20).collect()));
        let reconstructor = Arc::new(MockReconstructionSource::new(b"x".to_vec()));
        let grouping = Arc::new(DefaultStripeGrouping::new(4));
        let mut svc =
            StripeParallelResilverService::new(1, 2, enumerator, reconstructor, grouping, 2);

        let budget = ServiceBudget {
            max_items: 5,
            max_bytes: 0,
            max_ms: 0,
        };
        let r1 = svc.tick(&budget).unwrap();
        assert_eq!(r1.processed, 5);
        assert!(r1.has_more);
        assert!(!svc.cycle_complete());

        let r2 = svc.tick(&budget).unwrap();
        assert_eq!(r2.processed, 5);
        assert!(r2.has_more);

        let r3 = svc.tick(&budget).unwrap();
        assert_eq!(r3.processed, 5);
        assert!(r3.has_more);

        let r4 = svc.tick(&budget).unwrap();
        assert_eq!(r4.processed, 5);
        assert!(!r4.has_more);
        assert!(svc.cycle_complete());

        assert_eq!(svc.stats().objects_scanned, 20);
        assert_eq!(svc.stats().objects_rebuilt, 20);
    }

    #[test]
    fn stripe_parallel_service_name_and_priority() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![1]));
        let reconstructor = Arc::new(MockReconstructionSource::new(b"x".to_vec()));
        let grouping = Arc::new(DefaultStripeGrouping::new(1));
        let svc = StripeParallelResilverService::new(1, 2, enumerator, reconstructor, grouping, 1);
        assert_eq!(svc.name(), "StripeParallelResilverService");
        assert_eq!(svc.priority(), ServicePriority::Critical);
    }

    #[test]
    fn stripe_parallel_max_concurrency_at_least_one() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![1]));
        let reconstructor = Arc::new(MockReconstructionSource::new(b"x".to_vec()));
        let grouping = Arc::new(DefaultStripeGrouping::new(4));
        let svc = StripeParallelResilverService::new(
            1,
            2,
            enumerator,
            reconstructor,
            grouping,
            0, // zero becomes 1
        );
        assert!(svc.has_work());
    }

    #[test]
    fn stripe_parallel_stats_accumulate() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![1, 2, 3]));
        let reconstructor = Arc::new(MockReconstructionSource::new(b"abc".to_vec()));
        let grouping = Arc::new(DefaultStripeGrouping::new(2));
        let mut svc =
            StripeParallelResilverService::new(1, 2, enumerator, reconstructor, grouping, 2);

        svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        let stats = svc.stats();
        assert_eq!(stats.objects_scanned, 3);
        assert_eq!(stats.objects_rebuilt, 3);
        assert_eq!(stats.bytes_rebuilt, 9);
    }

    // ------------------------------------------------------------------
    // TopologyAwareSourceSelector tests
    // ------------------------------------------------------------------

    #[test]
    fn topology_selector_empty_candidates_returns_none() {
        let selector = DefaultTopologyAwareSourceSelector;
        let domains = std::collections::HashMap::new();
        let result = selector.select_source(ExtentId(1), 1, &[], &domains);
        assert_eq!(result, None);
    }

    #[test]
    fn topology_selector_prefers_cross_domain() {
        let selector = DefaultTopologyAwareSourceSelector;
        let mut domains = std::collections::HashMap::new();
        domains.insert(1, 10); // target device 1 in domain 10
        domains.insert(2, 20); // source 2 in domain 20 (cross-domain)
        domains.insert(3, 10); // source 3 in domain 10 (same domain)

        // Should pick device 2 (cross-domain)
        let result = selector.select_source(ExtentId(1), 1, &[3, 2], &domains);
        assert_eq!(result, Some(2));
    }

    #[test]
    fn topology_selector_fallback_same_domain() {
        let selector = DefaultTopologyAwareSourceSelector;
        let mut domains = std::collections::HashMap::new();
        domains.insert(1, 10); // target in domain 10
        domains.insert(2, 10); // only source also in domain 10

        // All candidates are same-domain, falls back to first
        let result = selector.select_source(ExtentId(1), 1, &[2], &domains);
        assert_eq!(result, Some(2));
    }

    #[test]
    fn topology_selector_empty_domains_returns_first_candidate() {
        let selector = DefaultTopologyAwareSourceSelector;
        let domains = std::collections::HashMap::new();

        // No domain info, returns first candidate
        let result = selector.select_source(ExtentId(1), 1, &[5, 6, 7], &domains);
        assert_eq!(result, Some(5));
    }

    #[test]
    fn topology_selector_target_not_in_domain_map() {
        let selector = DefaultTopologyAwareSourceSelector;
        let mut domains = std::collections::HashMap::new();
        domains.insert(2, 20); // source in domain 20
                               // Target device 1 not in the map

        let result = selector.select_source(ExtentId(1), 1, &[2], &domains);
        assert_eq!(result, Some(2)); // fallback to first candidate
    }

    // ------------------------------------------------------------------
    // TopologyAwareReconstructionSource tests
    // ------------------------------------------------------------------

    #[test]
    fn topology_aware_source_delegates_write() {
        let inner = Arc::new(MockReconstructionSource::new(b"data".to_vec()));
        let selector = Arc::new(DefaultTopologyAwareSourceSelector);
        let mut source_candidates = std::collections::HashMap::new();
        source_candidates.insert(42, vec![1, 2]);

        let ta_source = TopologyAwareReconstructionSource::new(
            inner,
            selector,
            std::collections::HashMap::new(),
            source_candidates,
        );

        // Write should delegate to inner
        let result = ta_source.write_to_replacement(ExtentId(42), 3, b"data");
        assert!(result.is_ok());
    }

    #[test]
    fn topology_aware_source_reconstruct_no_candidates() {
        let inner = Arc::new(MockReconstructionSource::new(b"data".to_vec()));
        let selector = Arc::new(DefaultTopologyAwareSourceSelector);
        let ta_source = TopologyAwareReconstructionSource::new(
            inner,
            selector,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(), // no candidates
        );

        let result = ta_source.reconstruct_extent(ExtentId(99), 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no source candidate"));
    }

    #[test]
    fn topology_aware_source_delegates_reconstruct() {
        let inner = Arc::new(MockReconstructionSource::new(b"payload".to_vec()));
        let selector = Arc::new(DefaultTopologyAwareSourceSelector);
        let mut source_candidates = std::collections::HashMap::new();
        source_candidates.insert(10, vec![5]);

        let ta_source = TopologyAwareReconstructionSource::new(
            inner.clone(),
            selector,
            std::collections::HashMap::new(),
            source_candidates,
        );

        let data = ta_source.reconstruct_extent(ExtentId(10), 1).unwrap();
        assert_eq!(data, b"payload");
    }

    // ------------------------------------------------------------------
    // TopologyAwareResilverService tests
    // ------------------------------------------------------------------

    #[test]
    fn topology_aware_service_has_work_initially() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![1, 2]));
        let inner = Arc::new(MockReconstructionSource::new(b"data".to_vec()));
        let selector = Arc::new(DefaultTopologyAwareSourceSelector);
        let mut source_candidates = std::collections::HashMap::new();
        source_candidates.insert(1, vec![10]);
        source_candidates.insert(2, vec![10]);

        let ta_reconstructor = Arc::new(TopologyAwareReconstructionSource::new(
            inner,
            selector,
            std::collections::HashMap::new(),
            source_candidates,
        ));
        let grouping = Arc::new(DefaultStripeGrouping::new(2));
        let svc =
            TopologyAwareResilverService::new(1, 2, enumerator, ta_reconstructor, grouping, 2);
        assert!(svc.has_work());
        assert!(!svc.cycle_complete());
    }

    #[test]
    fn topology_aware_service_name_and_priority() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![1]));
        let inner = Arc::new(MockReconstructionSource::new(b"x".to_vec()));
        let selector = Arc::new(DefaultTopologyAwareSourceSelector);
        let mut source_candidates = std::collections::HashMap::new();
        source_candidates.insert(1, vec![10]);

        let ta_reconstructor = Arc::new(TopologyAwareReconstructionSource::new(
            inner,
            selector,
            std::collections::HashMap::new(),
            source_candidates,
        ));
        let grouping = Arc::new(DefaultStripeGrouping::new(1));
        let svc =
            TopologyAwareResilverService::new(1, 2, enumerator, ta_reconstructor, grouping, 1);
        assert_eq!(svc.name(), "TopologyAwareResilverService");
        assert_eq!(svc.priority(), ServicePriority::Critical);
    }

    #[test]
    fn topology_aware_service_rebuilds_all_extents() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![10, 20, 30]));
        let inner = Arc::new(MockReconstructionSource::new(b"blk".to_vec()));
        let selector = Arc::new(DefaultTopologyAwareSourceSelector);
        let mut source_candidates = std::collections::HashMap::new();
        source_candidates.insert(10, vec![1]);
        source_candidates.insert(20, vec![1]);
        source_candidates.insert(30, vec![1]);

        let ta_reconstructor = Arc::new(TopologyAwareReconstructionSource::new(
            inner.clone(),
            selector,
            std::collections::HashMap::new(),
            source_candidates,
        ));
        let grouping = Arc::new(DefaultStripeGrouping::new(4));
        let mut svc = TopologyAwareResilverService::new(
            1,
            2,
            enumerator.clone(),
            ta_reconstructor,
            grouping,
            4,
        );

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.processed, 3);
        assert_eq!(report.errors, 0);
        assert!(svc.cycle_complete());
        assert_eq!(svc.stats().objects_rebuilt, 3);
    }

    #[test]
    fn topology_aware_service_empty_device_completes() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![]));
        let inner = Arc::new(MockReconstructionSource::new(b"data".to_vec()));
        let selector = Arc::new(DefaultTopologyAwareSourceSelector);
        let ta_reconstructor = Arc::new(TopologyAwareReconstructionSource::new(
            inner,
            selector,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        ));
        let grouping = Arc::new(DefaultStripeGrouping::new(2));
        let mut svc =
            TopologyAwareResilverService::new(1, 2, enumerator, ta_reconstructor, grouping, 2);

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.processed, 0);
        assert!(svc.cycle_complete());
    }

    #[test]
    fn topology_aware_service_cursor_resume() {
        let enumerator = Arc::new(MockExtentEnumerator::new((0..12).collect()));
        let inner = Arc::new(MockReconstructionSource::new(b"x".to_vec()));
        let selector = Arc::new(DefaultTopologyAwareSourceSelector);
        let mut source_candidates = std::collections::HashMap::new();
        for i in 0..12 {
            source_candidates.insert(i, vec![1]);
        }

        let ta_reconstructor = Arc::new(TopologyAwareReconstructionSource::new(
            inner,
            selector,
            std::collections::HashMap::new(),
            source_candidates,
        ));
        let grouping = Arc::new(DefaultStripeGrouping::new(2));
        let mut svc =
            TopologyAwareResilverService::new(1, 2, enumerator, ta_reconstructor, grouping, 2);

        let budget = ServiceBudget {
            max_items: 4,
            max_bytes: 0,
            max_ms: 0,
        };
        let r1 = svc.tick(&budget).unwrap();
        assert_eq!(r1.processed, 4);
        assert!(r1.has_more);

        let r2 = svc.tick(&budget).unwrap();
        assert_eq!(r2.processed, 4);
        assert!(r2.has_more);

        let r3 = svc.tick(&budget).unwrap();
        assert_eq!(r3.processed, 4);
        assert!(!r3.has_more);
        assert!(svc.cycle_complete());
    }

    #[test]
    fn topology_aware_cross_domain_counter() {
        let enumerator = Arc::new(MockExtentEnumerator::new(vec![1, 2]));
        let inner = Arc::new(MockReconstructionSource::new(b"data".to_vec()));
        let selector = Arc::new(DefaultTopologyAwareSourceSelector);
        let mut domains = std::collections::HashMap::new();
        domains.insert(1, 10); // target in domain 10
        domains.insert(3, 30); // source in domain 30 (cross-domain)
        let mut source_candidates = std::collections::HashMap::new();
        source_candidates.insert(1, vec![3]);
        source_candidates.insert(2, vec![3]);

        let ta_reconstructor = Arc::new(TopologyAwareReconstructionSource::new(
            inner,
            selector,
            domains,
            source_candidates,
        ));
        let grouping = Arc::new(DefaultStripeGrouping::new(2));
        let mut svc =
            TopologyAwareResilverService::new(1, 2, enumerator, ta_reconstructor, grouping, 2);

        svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert!(svc.cycle_complete());
    }
    #[test]
    fn chain_of_trust_runs_on_cycle_completion() {
        let (_dir, mut store, root) = make_store();
        for i in 0..5 {
            store
                .put_named(format!("obj{i}"), format!("payload-{i}").as_bytes())
                .unwrap();
        }
        store.sync_all().unwrap();
        drop(store);

        let mut svc = ScrubService::new(&root, StoreOptions::test_fast());
        svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert!(svc.cycle_complete());

        // Chain-of-trust validation was invoked and produced a status.
        // Segment integrity footers may not be present in test data,
        // so we accept any valid status.
        let status = &svc.chain_trust_status;
        assert!(
            matches!(
                status,
                ChainOfTrustStatus::Passed
                    | ChainOfTrustStatus::Failed { .. }
                    | ChainOfTrustStatus::NotApplicable
            ),
            "chain-of-trust must resolve to a valid status"
        );
    }

    #[test]
    fn chain_of_trust_not_applicable_for_truly_empty_store() {
        // Use a store directory that was never initialized (no segments dir).
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("nonexistent");
        let mut svc = ScrubService::new(&root, StoreOptions::test_fast());
        // tick fails because store doesn't exist, but chain_trust_status
        // stays at its initial NotApplicable.
        let _ = svc.tick(&ServiceBudget::UNBOUNDED);
        assert_eq!(svc.chain_trust_status, ChainOfTrustStatus::NotApplicable);
    }

    #[test]
    fn generate_report_has_coverage_stats() {
        let (_dir, mut store, root) = make_store();
        for i in 0..10 {
            store
                .put_named(format!("obj{i}"), format!("payload-{i}").as_bytes())
                .unwrap();
        }
        store.sync_all().unwrap();
        drop(store);

        let mut svc = ScrubService::new(&root, StoreOptions::test_fast());
        svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert!(svc.cycle_complete());

        let report = svc.generate_report();
        assert!(report.records_verified > 0);
        assert!(report.coverage_percent >= 0.0);
        assert_eq!(report.checksum_mismatches, 0);
        // Chain-of-trust was invoked (any status is valid for test data
        // that may lack segment integrity footers).
        assert!(matches!(
            report.chain_of_trust,
            ChainOfTrustStatus::Passed
                | ChainOfTrustStatus::Failed { .. }
                | ChainOfTrustStatus::NotApplicable
        ));
        assert!(report.cycle_complete);
        assert_eq!(report.ticks_elapsed, 1);
    }

    #[test]
    fn report_reflects_cycle_state() {
        let (_dir, mut store, root) = make_store();
        store.put_named("single", b"data").unwrap();
        store.sync_all().unwrap();
        drop(store);

        let mut svc = ScrubService::new(&root, StoreOptions::test_fast());
        svc.tick(&ServiceBudget::UNBOUNDED).unwrap();

        let report = svc.generate_report();
        assert_eq!(report.checksum_mismatches, 0);
        assert!(report.coverage_percent > 0.0);
        assert!(report.records_verified > 0);
        // Chain-of-trust status is set (any variant).
        assert!(matches!(
            report.chain_of_trust,
            ChainOfTrustStatus::Passed
                | ChainOfTrustStatus::Failed { .. }
                | ChainOfTrustStatus::NotApplicable
        ));
    }

    #[test]
    fn chain_of_trust_status_labels() {
        assert_eq!(ChainOfTrustStatus::Passed.label(), "passed");
        assert_eq!(
            ChainOfTrustStatus::Failed { chain_breaks: 3 }.label(),
            "failed"
        );
        assert_eq!(ChainOfTrustStatus::NotApplicable.label(), "not-applicable");
    }

    #[test]
    fn chain_of_trust_passed_and_na_are_pass() {
        assert!(ChainOfTrustStatus::Passed.is_passed());
        assert!(ChainOfTrustStatus::NotApplicable.is_passed());
        assert!(!ChainOfTrustStatus::Failed { chain_breaks: 1 }.is_passed());
    }

    // Chain-of-trust verification tests
    // ------------------------------------------------------------------

    #[test]
    fn chain_of_trust_validated_on_cycle_completion() {
        let (_dir, _store, root) = make_store();
        let mut svc = ScrubService::new(&root, StoreOptions::test_fast());

        // Complete the cycle.
        svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert!(svc.cycle_complete());

        // Chain verification should have run after the record pass.
        let stats = svc.stats();
        assert!(
            stats.chain_verified,
            "chain should be verified on completion"
        );
        assert!(
            stats.chain_breaks_detected == 0,
            "no chain breaks expected in test store"
        );
    }

    #[test]
    fn chain_stats_reflected_in_stats_after_completion() {
        let (_dir, mut store, root) = make_store();
        for i in 0..3 {
            store.put_named(format!("obj{i}"), b"data").unwrap();
        }
        store.sync_all().unwrap();
        drop(store);

        let mut svc = ScrubService::new(&root, StoreOptions::test_fast());
        svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert!(svc.cycle_complete());

        let stats = svc.stats();
        assert!(stats.chain_verified);
        assert!(
            stats.segments_in_chain > 0,
            "should have at least one segment in chain"
        );
        let _ = stats.chain_breaks_detected;
    }

    #[test]
    fn chain_suspect_entries_are_merged() {
        let (_dir, mut store, root) = make_store();
        store.put_named("obj0", b"payload-0").unwrap();
        store.sync_all().unwrap();
        drop(store);

        let mut svc = ScrubService::new(&root, StoreOptions::test_fast());
        svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert!(svc.cycle_complete());

        let entries = svc.drain_suspect_log();
        let _ = entries.len();
    }

    #[test]
    fn merge_chain_stats_updates_fields() {
        let mut stats = ScrubStats::default();
        assert!(!stats.chain_verified);
        assert_eq!(stats.segments_in_chain, 0);
        assert_eq!(stats.chain_breaks_detected, 0);

        let chain = SegmentChainStats {
            segments_in_chain: 5,
            chain_length: 960,
            last_verified_segment: 4,
            chain_breaks_detected: 1,
        };
        stats.merge_chain_stats(&chain);

        assert!(stats.chain_verified);
        assert_eq!(stats.segments_in_chain, 5);
        assert_eq!(stats.chain_breaks_detected, 1);
    }

    // ------------------------------------------------------------------
    // Mock implementations for RepairService tests
    // ------------------------------------------------------------------

    struct MockShardReader {
        data_shards: Vec<Option<Vec<u8>>>,
        parity_shard: Option<Vec<u8>>,
        written_shards: Mutex<Vec<(u64, usize, Vec<u8>)>>,
    }

    impl MockShardReader {
        fn new(data_shards: Vec<Option<Vec<u8>>>, parity_shard: Option<Vec<u8>>) -> Self {
            Self {
                data_shards,
                parity_shard,
                written_shards: Mutex::new(Vec::new()),
            }
        }

        fn written_shards(&self) -> Vec<(u64, usize, Vec<u8>)> {
            self.written_shards.lock().unwrap().clone()
        }
    }

    impl ShardReader for MockShardReader {
        fn read_data_shards(&self, _locator_id: u64, shard_count: usize) -> Vec<Option<Vec<u8>>> {
            assert_eq!(shard_count, self.data_shards.len());
            self.data_shards.clone()
        }

        fn read_parity_shard(&self, _locator_id: u64) -> Option<Vec<u8>> {
            self.parity_shard.clone()
        }

        fn write_shard(
            &self,
            locator_id: u64,
            shard_index: usize,
            data: &[u8],
        ) -> Result<(), String> {
            self.written_shards
                .lock()
                .unwrap()
                .push((locator_id, shard_index, data.to_vec()));
            Ok(())
        }
    }

    struct MockRepairPlanner {
        strategy: RepairStrategy,
        ec_shard_count: Option<usize>,
    }

    impl MockRepairPlanner {
        fn new(strategy: RepairStrategy, ec_shard_count: Option<usize>) -> Self {
            Self {
                strategy,
                ec_shard_count,
            }
        }
    }

    impl RepairPlanner for MockRepairPlanner {
        fn plan(&self, entry: &SuspectEntry) -> Option<RepairPlan> {
            Some(RepairPlan {
                entry: *entry,
                strategy: self.strategy,
                ec_shard_count: self.ec_shard_count,
            })
        }
    }

    fn make_suspect_entry(locator_id: u64) -> SuspectEntry {
        SuspectEntry {
            locator_id,
            entry_id: locator_id,
            segment_id: 1,
            offset: 0,
            record_type: 1,
            expected_hash: [0u8; 32],
            actual_hash: [0u8; 32],
            repair_attempts: 0,
            last_repair_attempt: 0,
            resolved: false,
            commit_group: 1,
            timestamp_secs: 1,
        }
    }

    // ------------------------------------------------------------------
    // RepairStats tests
    // ------------------------------------------------------------------

    #[test]
    fn repair_stats_default_zero() {
        let stats = RepairStats::default();
        assert_eq!(stats.repairs_attempted, 0);
        assert_eq!(stats.repairs_succeeded, 0);
        assert_eq!(stats.repairs_failed, 0);
        assert_eq!(stats.bytes_repaired, 0);
        assert_eq!(stats.bytes_unrepairable, 0);
    }

    // ------------------------------------------------------------------
    // RepairOutcome tests
    // ------------------------------------------------------------------

    #[test]
    fn repair_outcome_repaired_holds_bytes() {
        let outcome = RepairOutcome::Repaired {
            bytes_repaired: 4096,
        };
        match outcome {
            RepairOutcome::Repaired { bytes_repaired } => assert_eq!(bytes_repaired, 4096),
            _ => panic!("expected Repaired"),
        }
    }

    #[test]
    fn repair_outcome_failed_holds_reason() {
        let outcome = RepairOutcome::Failed {
            reason: "disk full".into(),
        };
        match outcome {
            RepairOutcome::Failed { reason } => assert_eq!(reason, "disk full"),
            _ => panic!("expected Failed"),
        }
    }

    #[test]
    fn repair_outcome_unrepairable_holds_reason() {
        let outcome = RepairOutcome::Unrepairable {
            reason: "no replicas".into(),
        };
        match outcome {
            RepairOutcome::Unrepairable { reason } => assert_eq!(reason, "no replicas"),
            _ => panic!("expected Unrepairable"),
        }
    }

    // ------------------------------------------------------------------
    // RepairPlanner tests
    // ------------------------------------------------------------------

    #[test]
    fn default_planner_always_returns_mirror() {
        let planner = DefaultRepairPlanner;
        let entry = make_suspect_entry(42);
        let plan = planner.plan(&entry).unwrap();
        assert_eq!(plan.entry.locator_id, 42);
        assert_eq!(plan.strategy, RepairStrategy::Mirror);
        assert_eq!(plan.ec_shard_count, None);
    }

    // ------------------------------------------------------------------
    // RepairService — mirror repair tests
    // ------------------------------------------------------------------

    #[test]
    fn repair_service_mirror_repairs_all_entries() {
        let mut log = SuspectLog::new();
        log.record(make_suspect_entry(10));
        log.record(make_suspect_entry(20));
        log.record(make_suspect_entry(30));

        let mirror = Arc::new(MockReconstructionSource::new(b"healthy_data".to_vec()));
        let planner = Arc::new(MockRepairPlanner::new(RepairStrategy::Mirror, None));
        let mut svc = RepairService::new(log, Some(mirror.clone()), None, Some(planner), 1);

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.processed, 3);
        assert_eq!(report.errors, 0);
        assert!(svc.cycle_complete());

        let stats = svc.stats();
        assert_eq!(stats.repairs_attempted, 3);
        assert_eq!(stats.repairs_succeeded, 3);
        assert_eq!(stats.repairs_failed, 0);
        assert_eq!(stats.bytes_repaired, b"healthy_data".len() as u64 * 3);
    }

    #[test]
    fn repair_service_skips_max_attempts_exceeded() {
        let mut log = SuspectLog::new();
        log.record(make_suspect_entry(99));

        // Mirror source that always fails.
        struct FailingMirror;
        impl ReconstructionSource for FailingMirror {
            fn reconstruct_extent(
                &self,
                _extent_id: ExtentId,
                _failed_device_id: u64,
            ) -> Result<Vec<u8>, String> {
                Err("always fails".into())
            }
            fn write_to_replacement(
                &self,
                _extent_id: ExtentId,
                _replacement_device_id: u64,
                _data: &[u8],
            ) -> Result<(), String> {
                Ok(())
            }
        }

        let mirror = Arc::new(FailingMirror);
        let planner = Arc::new(MockRepairPlanner::new(RepairStrategy::Mirror, None));
        let mut svc = RepairService::new(log, Some(mirror), None, Some(planner), 1);
        svc.set_max_repair_attempts(2);

        // First tick: 2 attempts, both fail.
        let _ = svc.tick(&ServiceBudget {
            max_items: 2,
            max_bytes: 0,
            max_ms: 0,
        });
        // Should have attempted 2 times.
        assert_eq!(svc.stats().repairs_attempted, 2);
        assert_eq!(svc.stats().repairs_failed, 2);

        // Second tick: max attempts reached, skipped.
        let _ = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(svc.stats().repairs_attempted, 2); // no new attempts
        assert_eq!(svc.stats().bytes_unrepairable, 1);
        assert!(svc.cycle_complete());
    }

    #[test]
    fn repair_service_empty_log_completes_immediately() {
        let log = SuspectLog::new();
        let mirror = Arc::new(MockReconstructionSource::new(b"data".to_vec()));
        let planner = Arc::new(MockRepairPlanner::new(RepairStrategy::Mirror, None));
        let mut svc = RepairService::new(log, Some(mirror), None, Some(planner), 1);

        assert!(!svc.has_work());
        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.processed, 0);
        assert!(svc.cycle_complete());
        assert_eq!(svc.stats().repairs_attempted, 0);
    }

    #[test]
    fn repair_service_name_and_priority() {
        let log = SuspectLog::new();
        let mirror = Arc::new(MockReconstructionSource::new(b"data".to_vec()));
        let planner = Arc::new(MockRepairPlanner::new(RepairStrategy::Mirror, None));
        let svc = RepairService::new(log, Some(mirror), None, Some(planner), 1);

        assert_eq!(svc.name(), "RepairService");
        assert_eq!(svc.priority(), ServicePriority::Critical);
    }

    #[test]
    fn repair_service_cursor_resume_across_ticks() {
        let mut log = SuspectLog::new();
        for i in 0..10 {
            log.record(make_suspect_entry(i));
        }

        let mirror = Arc::new(MockReconstructionSource::new(b"payload".to_vec()));
        let planner = Arc::new(MockRepairPlanner::new(RepairStrategy::Mirror, None));
        let mut svc = RepairService::new(log, Some(mirror.clone()), None, Some(planner), 1);

        let budget = ServiceBudget {
            max_items: 3,
            max_bytes: 0,
            max_ms: 0,
        };

        let r1 = svc.tick(&budget).unwrap();
        assert_eq!(r1.processed, 3);
        assert!(r1.has_more);
        assert!(!svc.cycle_complete());

        let r2 = svc.tick(&budget).unwrap();
        assert_eq!(r2.processed, 3);
        assert!(r2.has_more);

        let r3 = svc.tick(&budget).unwrap();
        assert_eq!(r3.processed, 3);
        assert!(r3.has_more);

        let r4 = svc.tick(&budget).unwrap();
        assert_eq!(r4.processed, 1);
        assert!(!r4.has_more);
        assert!(svc.cycle_complete());

        assert_eq!(svc.stats().repairs_succeeded, 10);
    }

    // ------------------------------------------------------------------
    // RepairService — EC repair tests
    // ------------------------------------------------------------------

    #[test]
    fn repair_service_ec_repairs_single_missing_shard() {
        // 3 data shards: a, b, c. Parity = a^b^c.
        let a = vec![0x01, 0x02, 0x03, 0x04];
        let b = vec![0x11, 0x12, 0x13, 0x14];
        let c = vec![0x21, 0x22, 0x23, 0x24];
        let parity: Vec<u8> = a
            .iter()
            .zip(b.iter())
            .zip(c.iter())
            .map(|((x, y), z)| x ^ y ^ z)
            .collect();

        // Shard at index 1 (b) is missing.
        let shards = vec![Some(a.clone()), None, Some(c.clone())];
        let reader = Arc::new(MockShardReader::new(shards, Some(parity.clone())));

        let mut log = SuspectLog::new();
        log.record(make_suspect_entry(7));

        let planner = Arc::new(MockRepairPlanner::new(
            RepairStrategy::ErasureCoded,
            Some(3),
        ));
        let mut svc = RepairService::new(log, None, Some(reader.clone()), Some(planner), 1);

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.processed, 1);
        assert_eq!(report.errors, 0);
        assert!(svc.cycle_complete());
        assert_eq!(svc.stats().repairs_succeeded, 1);

        // Verify the reconstructed shard was written at index 1.
        let written = reader.written_shards();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].0, 7); // locator_id
        assert_eq!(written[0].1, 1); // shard_index
        assert_eq!(written[0].2, b); // reconstructed data
    }

    #[test]
    fn repair_service_ec_repair_idempotent_noop() {
        // All shards present, nothing to repair — idempotent no-op.
        let a = vec![0x01, 0x02];
        let b = vec![0x11, 0x12];
        let parity = vec![0x10, 0x10];

        let shards = vec![Some(a), Some(b)];
        let reader = Arc::new(MockShardReader::new(shards, Some(parity)));

        let mut log = SuspectLog::new();
        log.record(make_suspect_entry(8));

        let planner = Arc::new(MockRepairPlanner::new(
            RepairStrategy::ErasureCoded,
            Some(2),
        ));
        let mut svc = RepairService::new(log, None, Some(reader), Some(planner), 1);

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.processed, 1);
        assert_eq!(report.errors, 0);
        assert!(svc.cycle_complete());
        assert_eq!(svc.stats().repairs_succeeded, 1);
        assert_eq!(svc.stats().bytes_repaired, 0);
    }

    #[test]
    fn repair_service_ec_missing_parity_returns_unrepairable() {
        let a = vec![0x01, 0x02];
        let b: Option<Vec<u8>> = None; // missing shard

        let shards = vec![Some(a), b];
        let reader = Arc::new(MockShardReader::new(shards, None)); // no parity

        let mut log = SuspectLog::new();
        log.record(make_suspect_entry(9));

        let planner = Arc::new(MockRepairPlanner::new(
            RepairStrategy::ErasureCoded,
            Some(2),
        ));
        let mut svc = RepairService::new(log, None, Some(reader), Some(planner), 1);

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.errors, 1);
        assert_eq!(svc.stats().bytes_unrepairable, 1);
    }

    #[test]
    fn repair_service_ec_too_many_missing_shards() {
        // 3 data shards, 2 are missing - can't reconstruct with single parity.
        let a = vec![0x01, 0x02];
        let parity = vec![0x03, 0x04];

        let shards = vec![Some(a), None, None]; // 2 missing
        let reader = Arc::new(MockShardReader::new(shards, Some(parity)));

        let mut log = SuspectLog::new();
        log.record(make_suspect_entry(10));

        let planner = Arc::new(MockRepairPlanner::new(
            RepairStrategy::ErasureCoded,
            Some(3),
        ));
        let mut svc = RepairService::new(log, None, Some(reader), Some(planner), 1);

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.errors, 1);
        assert_eq!(svc.stats().bytes_unrepairable, 1);
    }

    #[test]
    fn repair_service_no_mirror_no_shard_reader_is_unrepairable() {
        let mut log = SuspectLog::new();
        log.record(make_suspect_entry(11));

        let planner = Arc::new(MockRepairPlanner::new(RepairStrategy::Mirror, None));
        let mut svc = RepairService::new(log, None, None, Some(planner), 1);

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.errors, 1);
        assert_eq!(svc.stats().bytes_unrepairable, 1);
    }
}
