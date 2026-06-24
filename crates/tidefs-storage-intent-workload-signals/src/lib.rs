// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Bounded local workload-signal producers for storage intent.
//!
//! This crate is the first #845 producer slice. It observes local request,
//! subject/range, dataset, pool, device, path, and tenant-budget signal input
//! into fixed-size sketches, then publishes read-only
//! [`WorkloadSignalRecord`] snapshots from `tidefs-storage-intent-core`.
//!
//! The producer is deliberately non-authoritative: it does not choose
//! placement, admit scheduling work, execute prefetch, relocate data, publish
//! receipts, retire old receipts, or close payback. Missing cost, memory-only
//! evidence, sampled-away input, dropped observations, one-pass scans, phase
//! changes, noisy tenants, and hint-only signals lower the exported action
//! class and candidate.

use core::mem;

use tidefs_storage_intent_core::{
    workload_signal_can_train_upward, workload_signal_lowered_candidate, AccessPatternClass,
    ContradictionState, HintProvenance, PredictionConfidence, PrefetchResidencyCandidateClass,
    SignalMaterializationMode, StorageIntentActionClass, StorageIntentDomainId,
    StorageIntentEvidenceId, StorageIntentEvidenceKind, StorageIntentEvidenceRef,
    StorageIntentObjectScope, StorageIntentPolicyId, StorageIntentPolicyRevision,
    StorageIntentRefusalReason, StorageMediaClass, WorkloadSignalFlags, WorkloadSignalRecord,
    WorkloadSignalScopeClass,
};

/// Version of the workload-signal producer record shape.
pub const WORKLOAD_SIGNAL_PRODUCER_VERSION: u16 = 1;

/// Stable producer identifier for explanations and fixture tests.
pub const WORKLOAD_SIGNAL_PRODUCER_SPEC: &str =
    "tidefs-storage-intent-workload-signals-v1-issue-845";

/// Power-of-two byte histogram buckets carried by the local sketch.
pub const WORKLOAD_SIGNAL_HISTOGRAM_BUCKETS: usize = 16;

/// Bounded top-K slots for subject/range and path hotness sketches.
pub const WORKLOAD_SIGNAL_TOP_K: usize = 8;

/// Number of scope records exported by every read-only snapshot.
pub const WORKLOAD_SIGNAL_SNAPSHOT_RECORDS: usize = 7;

const PPM: u64 = 1_000_000;
const DEFAULT_MIN_SAMPLE_MASS: u32 = 8;
const DEFAULT_HIGH_SAMPLE_MASS: u32 = 64;
const DEFAULT_MIN_WINDOW_MS: u64 = 1_000;
const DEFAULT_MAX_DECAY_AGE_MS: u64 = 60_000;
const DEFAULT_MAX_WINDOW_MS: u64 = 60_000;
const DEFAULT_ONE_PASS_SCAN_BYTES: u64 = 8 * 1024 * 1024;
const DEFAULT_MAX_MEMORY_BYTES: u64 = 64 * 1024;
const DEFAULT_MAX_DURABLE_METADATA_WRITES: u64 = 4;
const DEFAULT_MAX_NETWORK_EMISSION_BYTES: u64 = 64 * 1024;
const DEFAULT_MAX_EVIDENCE_RETENTION_BYTES: u64 = 128 * 1024;
const DEFAULT_PHASE_CHANGE_THRESHOLD: u32 = 3;
const DEFAULT_NOISY_DROP_THRESHOLD: u32 = 4;

const EMPTY_EVIDENCE_REF: StorageIntentEvidenceRef = StorageIntentEvidenceRef {
    kind: StorageIntentEvidenceKind::Unknown,
    id: StorageIntentEvidenceId::ZERO,
    generation: 0,
    version: 0,
};

/// Local producer bounds and confidence thresholds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkloadSignalProducerConfig {
    /// Minimum retained observations before any signal can exceed low
    /// confidence.
    pub min_sample_mass: u32,
    /// Minimum retained observations for high confidence, assuming evidence
    /// and contradiction gates are also clean.
    pub high_confidence_sample_mass: u32,
    /// Minimum monotonic observation window for high confidence.
    pub min_observation_window_ms: u64,
    /// Maximum age of the newest observation before confidence decays.
    pub max_decay_age_ms: u64,
    /// Maximum retained window. Older sketches must be compacted or reset by
    /// callers before they can prove high-confidence decisions.
    pub max_observation_window_ms: u64,
    /// Histogram decay in per-mille per producer tick.
    pub decay_per_mille: u16,
    /// Retain one out of N observations. Values greater than one mark
    /// sampled-away input in snapshots.
    pub sample_every: u32,
    /// Local RAM budget for this producer's sketch and retained evidence.
    pub max_memory_bytes: u64,
    /// Durable metadata write budget for signal persistence during the window.
    pub max_durable_metadata_writes: u64,
    /// Network emission budget for signal publication during the window.
    pub max_network_emission_bytes: u64,
    /// Evidence-retention byte budget during the window.
    pub max_evidence_retention_bytes: u64,
    /// Sequential read bytes above this threshold, without reuse support,
    /// become one-pass scan evidence.
    pub one_pass_scan_bytes: u64,
    /// Alternating dominant phases above this threshold suppress confidence.
    pub phase_change_threshold: u32,
    /// Dropped/top-K-evicted observations above this threshold suppress noisy
    /// tenant confidence.
    pub noisy_drop_threshold: u32,
}

impl Default for WorkloadSignalProducerConfig {
    fn default() -> Self {
        Self {
            min_sample_mass: DEFAULT_MIN_SAMPLE_MASS,
            high_confidence_sample_mass: DEFAULT_HIGH_SAMPLE_MASS,
            min_observation_window_ms: DEFAULT_MIN_WINDOW_MS,
            max_decay_age_ms: DEFAULT_MAX_DECAY_AGE_MS,
            max_observation_window_ms: DEFAULT_MAX_WINDOW_MS,
            decay_per_mille: 50,
            sample_every: 1,
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
            max_durable_metadata_writes: DEFAULT_MAX_DURABLE_METADATA_WRITES,
            max_network_emission_bytes: DEFAULT_MAX_NETWORK_EMISSION_BYTES,
            max_evidence_retention_bytes: DEFAULT_MAX_EVIDENCE_RETENTION_BYTES,
            one_pass_scan_bytes: DEFAULT_ONE_PASS_SCAN_BYTES,
            phase_change_threshold: DEFAULT_PHASE_CHANGE_THRESHOLD,
            noisy_drop_threshold: DEFAULT_NOISY_DROP_THRESHOLD,
        }
    }
}

/// Refs and scope metadata copied into produced workload-signal records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkloadSignalProducerContext {
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub scope: StorageIntentObjectScope,
    pub pool_id: StorageIntentDomainId,
    pub budget_owner: StorageIntentDomainId,
    pub source_media: StorageMediaClass,
    pub target_media: StorageMediaClass,
    pub source_media_ref: StorageIntentEvidenceRef,
    pub target_media_ref: StorageIntentEvidenceRef,
    pub service_objective_ref: StorageIntentEvidenceRef,
    pub topology_ref: StorageIntentEvidenceRef,
    pub signal_materialization_ref: StorageIntentEvidenceRef,
    pub signal_collection_cost_ref: StorageIntentEvidenceRef,
    pub materialization_mode: SignalMaterializationMode,
    pub requested_candidate: PrefetchResidencyCandidateClass,
    pub requested_action_class: StorageIntentActionClass,
}

impl Default for WorkloadSignalProducerContext {
    fn default() -> Self {
        Self::empty()
    }
}

impl WorkloadSignalProducerContext {
    /// Build a dataset-scoped context for callers that only have current
    /// policy and ownership identity.
    #[must_use]
    pub const fn dataset(
        dataset_id: StorageIntentDomainId,
        budget_owner: StorageIntentDomainId,
    ) -> Self {
        let mut context = Self::empty();
        context.scope.dataset_id = dataset_id;
        context.budget_owner = budget_owner;
        context
    }

    /// Const-friendly default constructor.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            scope: StorageIntentObjectScope {
                dataset_id: StorageIntentDomainId::ZERO,
                object_id: StorageIntentEvidenceId::ZERO,
                range_start: 0,
                range_len: 0,
                generation: 0,
            },
            pool_id: StorageIntentDomainId::ZERO,
            budget_owner: StorageIntentDomainId::ZERO,
            source_media: StorageMediaClass::SystemRam,
            target_media: StorageMediaClass::SystemRam,
            source_media_ref: EMPTY_EVIDENCE_REF,
            target_media_ref: EMPTY_EVIDENCE_REF,
            service_objective_ref: EMPTY_EVIDENCE_REF,
            topology_ref: EMPTY_EVIDENCE_REF,
            signal_materialization_ref: EMPTY_EVIDENCE_REF,
            signal_collection_cost_ref: EMPTY_EVIDENCE_REF,
            materialization_mode: SignalMaterializationMode::MemoryOnlySketch,
            requested_candidate: PrefetchResidencyCandidateClass::NeedMoreEvidence,
            requested_action_class: StorageIntentActionClass::QueuePrefetchTuning,
        }
    }

    /// Attach producer evidence refs and materialization mode.
    #[must_use]
    pub const fn with_signal_evidence(
        mut self,
        materialization_mode: SignalMaterializationMode,
        materialization_ref: StorageIntentEvidenceRef,
        collection_cost_ref: StorageIntentEvidenceRef,
    ) -> Self {
        self.materialization_mode = materialization_mode;
        self.signal_materialization_ref = materialization_ref;
        self.signal_collection_cost_ref = collection_cost_ref;
        self
    }

    /// Attach source and target media evidence.
    #[must_use]
    pub const fn with_media(
        mut self,
        source_media: StorageMediaClass,
        target_media: StorageMediaClass,
        source_media_ref: StorageIntentEvidenceRef,
        target_media_ref: StorageIntentEvidenceRef,
    ) -> Self {
        self.source_media = source_media;
        self.target_media = target_media;
        self.source_media_ref = source_media_ref;
        self.target_media_ref = target_media_ref;
        self
    }

    /// Request the highest candidate/action class downstream consumers should
    /// consider from this producer. Snapshot logic still lowers it when signal
    /// quality is insufficient.
    #[must_use]
    pub const fn with_requested_action(
        mut self,
        candidate: PrefetchResidencyCandidateClass,
        action_class: StorageIntentActionClass,
    ) -> Self {
        self.requested_candidate = candidate;
        self.requested_action_class = action_class;
        self
    }
}

/// Per-window collection cost charged to the signal producer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkloadSignalCollectionCost {
    pub cpu_nanos: u64,
    pub memory_bytes: u64,
    pub durable_metadata_writes: u64,
    pub flash_wear_bytes: u64,
    pub network_emission_bytes: u64,
    pub evidence_retention_bytes: u64,
}

impl WorkloadSignalCollectionCost {
    /// Add one cost estimate using saturating arithmetic.
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self {
            cpu_nanos: self.cpu_nanos.saturating_add(other.cpu_nanos),
            memory_bytes: self.memory_bytes.saturating_add(other.memory_bytes),
            durable_metadata_writes: self
                .durable_metadata_writes
                .saturating_add(other.durable_metadata_writes),
            flash_wear_bytes: self.flash_wear_bytes.saturating_add(other.flash_wear_bytes),
            network_emission_bytes: self
                .network_emission_bytes
                .saturating_add(other.network_emission_bytes),
            evidence_retention_bytes: self
                .evidence_retention_bytes
                .saturating_add(other.evidence_retention_bytes),
        }
    }

    /// Returns true when this cost is above the local producer budget.
    #[must_use]
    pub const fn exceeds(self, config: WorkloadSignalProducerConfig) -> bool {
        self.memory_bytes > config.max_memory_bytes
            || self.durable_metadata_writes > config.max_durable_metadata_writes
            || self.network_emission_bytes > config.max_network_emission_bytes
            || self.evidence_retention_bytes > config.max_evidence_retention_bytes
    }
}

/// Local observation kind accepted by the bounded producer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(u8)]
pub enum WorkloadSignalOperation {
    #[default]
    Read = 0,
    Write = 1,
    Fsync = 2,
    Delete = 3,
    Metadata = 4,
    SnapshotPin = 5,
    CompressionSample = 6,
    DedupSample = 7,
    ForegroundTail = 8,
    Hint = 9,
}

/// One local producer observation. Callers provide already-authorized facts;
/// this crate only bounds and projects them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkloadSignalObservation {
    pub operation: WorkloadSignalOperation,
    pub signal_scope: WorkloadSignalScopeClass,
    pub scope: StorageIntentObjectScope,
    pub offset: u64,
    pub len: u64,
    pub now_ms: u64,
    pub subject_tag: u64,
    pub path_tag: u64,
    pub logical_bytes: u64,
    pub physical_bytes: u64,
    pub snapshot_pin_horizon_ms: u64,
    pub foreground_latency_us: u64,
    pub foreground_latency_objective_us: u64,
    pub provenance: HintProvenance,
    pub flags: WorkloadSignalFlags,
    pub collection_cost: WorkloadSignalCollectionCost,
    pub hint_access_pattern: AccessPatternClass,
    pub hint_candidate: PrefetchResidencyCandidateClass,
}

impl Default for WorkloadSignalObservation {
    fn default() -> Self {
        Self::empty()
    }
}

impl WorkloadSignalObservation {
    /// Build a read observation.
    #[must_use]
    pub const fn read(now_ms: u64, offset: u64, len: u64, subject_tag: u64) -> Self {
        let mut observation = Self::empty();
        observation.operation = WorkloadSignalOperation::Read;
        observation.now_ms = now_ms;
        observation.offset = offset;
        observation.len = len;
        observation.subject_tag = subject_tag;
        observation.logical_bytes = len;
        observation.physical_bytes = len;
        observation
    }

    /// Build a write observation.
    #[must_use]
    pub const fn write(now_ms: u64, offset: u64, len: u64, subject_tag: u64) -> Self {
        let mut observation = Self::empty();
        observation.operation = WorkloadSignalOperation::Write;
        observation.now_ms = now_ms;
        observation.offset = offset;
        observation.len = len;
        observation.subject_tag = subject_tag;
        observation.logical_bytes = len;
        observation.physical_bytes = len;
        observation
    }

    /// Build an fsync observation.
    #[must_use]
    pub const fn fsync(now_ms: u64) -> Self {
        let mut observation = Self::empty();
        observation.operation = WorkloadSignalOperation::Fsync;
        observation.now_ms = now_ms;
        observation
    }

    /// Build a metadata observation.
    #[must_use]
    pub const fn metadata(now_ms: u64, subject_tag: u64, path_tag: u64) -> Self {
        let mut observation = Self::empty();
        observation.operation = WorkloadSignalOperation::Metadata;
        observation.now_ms = now_ms;
        observation.subject_tag = subject_tag;
        observation.path_tag = path_tag;
        observation
    }

    /// Build a caller/operator hint. Hints do not add observed sample mass.
    #[must_use]
    pub const fn hint(
        now_ms: u64,
        provenance: HintProvenance,
        access_pattern: AccessPatternClass,
        candidate: PrefetchResidencyCandidateClass,
    ) -> Self {
        let mut observation = Self::empty();
        observation.operation = WorkloadSignalOperation::Hint;
        observation.now_ms = now_ms;
        observation.provenance = provenance;
        observation.flags = WorkloadSignalFlags::HINT_ONLY;
        observation.hint_access_pattern = access_pattern;
        observation.hint_candidate = candidate;
        observation
    }

    /// Const-friendly empty observation.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            operation: WorkloadSignalOperation::Read,
            signal_scope: WorkloadSignalScopeClass::Dataset,
            scope: StorageIntentObjectScope {
                dataset_id: StorageIntentDomainId::ZERO,
                object_id: StorageIntentEvidenceId::ZERO,
                range_start: 0,
                range_len: 0,
                generation: 0,
            },
            offset: 0,
            len: 0,
            now_ms: 0,
            subject_tag: 0,
            path_tag: 0,
            logical_bytes: 0,
            physical_bytes: 0,
            snapshot_pin_horizon_ms: 0,
            foreground_latency_us: 0,
            foreground_latency_objective_us: 0,
            provenance: HintProvenance::RuntimeObserved,
            flags: WorkloadSignalFlags::EMPTY,
            collection_cost: WorkloadSignalCollectionCost {
                cpu_nanos: 0,
                memory_bytes: 0,
                durable_metadata_writes: 0,
                flash_wear_bytes: 0,
                network_emission_bytes: 0,
                evidence_retention_bytes: 0,
            },
            hint_access_pattern: AccessPatternClass::Unknown,
            hint_candidate: PrefetchResidencyCandidateClass::NeedMoreEvidence,
        }
    }

    /// Attach local collection cost to an observation.
    #[must_use]
    pub const fn with_collection_cost(mut self, cost: WorkloadSignalCollectionCost) -> Self {
        self.collection_cost = cost;
        self
    }

    /// Attach observation flags.
    #[must_use]
    pub const fn with_flags(mut self, flags: WorkloadSignalFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Attach path and scope tags used by bounded top-K sketches.
    #[must_use]
    pub const fn with_path_tag(mut self, path_tag: u64) -> Self {
        self.path_tag = path_tag;
        self
    }
}

/// Fixed-point signal vector exported alongside storage-intent records.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkloadSignalVector {
    pub sample_mass: u32,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_size_top_bucket: u8,
    pub write_size_top_bucket: u8,
    pub sequential_read_ppm: u32,
    pub sequential_write_ppm: u32,
    pub write_ratio_ppm: u32,
    pub sync_density_ppm: u32,
    pub overwrite_rate_ppm: u32,
    pub reuse_hotness_ppm: u32,
    pub metadata_ratio_ppm: u32,
    pub delete_ratio_ppm: u32,
    pub compression_savings_ppm: u32,
    pub dedup_savings_ppm: u32,
    pub foreground_tail_ppm: u32,
    pub snapshot_pin_horizon_ms: u64,
    pub phase_changes: u32,
    pub dropped_observations: u32,
    pub sampled_away_observations: u32,
}

/// Action-class projection paired with each snapshot record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkloadActionCandidate {
    pub action_class: StorageIntentActionClass,
    pub prefetch_candidate: PrefetchResidencyCandidateClass,
    pub confidence: PredictionConfidence,
    pub may_change_authority: bool,
}

/// Read-only bounded snapshot for downstream storage-intent consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkloadSignalSnapshot {
    len: u8,
    records: [WorkloadSignalRecord; WORKLOAD_SIGNAL_SNAPSHOT_RECORDS],
    actions: [WorkloadActionCandidate; WORKLOAD_SIGNAL_SNAPSHOT_RECORDS],
    pub vector: WorkloadSignalVector,
    pub collection_cost: WorkloadSignalCollectionCost,
    pub hot_subject_slots: u8,
    pub hot_path_slots: u8,
}

impl WorkloadSignalSnapshot {
    /// Records in request, subject/range, dataset, pool, device, path, and
    /// tenant-budget order.
    #[must_use]
    pub fn records(&self) -> &[WorkloadSignalRecord] {
        &self.records[..self.len as usize]
    }

    /// Action-class projections in the same order as [`Self::records`].
    #[must_use]
    pub fn actions(&self) -> &[WorkloadActionCandidate] {
        &self.actions[..self.len as usize]
    }

    /// Return the first record for a scope class.
    #[must_use]
    pub fn record_for_scope(
        &self,
        signal_scope: WorkloadSignalScopeClass,
    ) -> Option<WorkloadSignalRecord> {
        let mut index = 0;
        while index < self.len as usize {
            if self.records[index].signal_scope as u8 == signal_scope as u8 {
                return Some(self.records[index]);
            }
            index += 1;
        }
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TopKEntry {
    tag: u64,
    score: u64,
}

impl TopKEntry {
    const EMPTY: Self = Self { tag: 0, score: 0 };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TopKSketch {
    entries: [TopKEntry; WORKLOAD_SIGNAL_TOP_K],
    len: u8,
    evictions: u32,
}

impl Default for TopKSketch {
    fn default() -> Self {
        Self {
            entries: [TopKEntry::EMPTY; WORKLOAD_SIGNAL_TOP_K],
            len: 0,
            evictions: 0,
        }
    }
}

impl TopKSketch {
    fn observe(&mut self, tag: u64, weight: u64) -> bool {
        if tag == 0 {
            return false;
        }

        let mut index = 0;
        while index < self.len as usize {
            if self.entries[index].tag == tag {
                self.entries[index].score = self.entries[index].score.saturating_add(weight);
                return true;
            }
            index += 1;
        }

        if (self.len as usize) < WORKLOAD_SIGNAL_TOP_K {
            self.entries[self.len as usize] = TopKEntry { tag, score: weight };
            self.len += 1;
            return false;
        }

        let mut min_index = 0;
        let mut min_score = self.entries[0].score;
        index = 1;
        while index < WORKLOAD_SIGNAL_TOP_K {
            if self.entries[index].score < min_score {
                min_score = self.entries[index].score;
                min_index = index;
            }
            index += 1;
        }

        if weight > min_score {
            self.entries[min_index] = TopKEntry { tag, score: weight };
        } else {
            self.evictions = self.evictions.saturating_add(1);
        }
        false
    }

    fn decay(&mut self) {
        let mut index = 0;
        while index < self.len as usize {
            self.entries[index].score /= 2;
            index += 1;
        }
        self.compact();
    }

    fn compact(&mut self) {
        let mut write = 0;
        let mut read = 0;
        while read < self.len as usize {
            if self.entries[read].score != 0 {
                self.entries[write] = self.entries[read];
                write += 1;
            }
            read += 1;
        }
        while write < WORKLOAD_SIGNAL_TOP_K {
            self.entries[write] = TopKEntry::EMPTY;
            write += 1;
        }
        self.len = write_entries_len(&self.entries);
    }
}

fn write_entries_len(entries: &[TopKEntry; WORKLOAD_SIGNAL_TOP_K]) -> u8 {
    let mut len = 0_u8;
    while (len as usize) < WORKLOAD_SIGNAL_TOP_K && entries[len as usize].score != 0 {
        len += 1;
    }
    len
}

/// Fixed-size decayed byte histogram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecayedByteHistogram {
    buckets: [u64; WORKLOAD_SIGNAL_HISTOGRAM_BUCKETS],
}

impl Default for DecayedByteHistogram {
    fn default() -> Self {
        Self {
            buckets: [0; WORKLOAD_SIGNAL_HISTOGRAM_BUCKETS],
        }
    }
}

impl DecayedByteHistogram {
    /// Observe a byte length into a power-of-two bucket.
    pub fn observe(&mut self, bytes: u64) {
        let bucket = bucket_for_len(bytes);
        self.buckets[bucket] = self.buckets[bucket].saturating_add(1);
    }

    /// Apply decay to every bucket.
    pub fn decay(&mut self, decay_per_mille: u16) {
        let keep = 1_000_u64.saturating_sub(decay_per_mille as u64);
        let mut index = 0;
        while index < WORKLOAD_SIGNAL_HISTOGRAM_BUCKETS {
            self.buckets[index] = self.buckets[index].saturating_mul(keep) / 1_000;
            index += 1;
        }
    }

    /// Return a bounded view of bucket counters.
    #[must_use]
    pub const fn buckets(&self) -> &[u64; WORKLOAD_SIGNAL_HISTOGRAM_BUCKETS] {
        &self.buckets
    }

    fn top_bucket(&self) -> u8 {
        let mut best = 0;
        let mut best_count = 0;
        let mut index = 0;
        while index < WORKLOAD_SIGNAL_HISTOGRAM_BUCKETS {
            if self.buckets[index] > best_count {
                best_count = self.buckets[index];
                best = index;
            }
            index += 1;
        }
        best as u8
    }
}

fn bucket_for_len(bytes: u64) -> usize {
    let mut bucket = 0;
    let mut threshold = 512_u64;
    let normalized = if bytes == 0 { 1 } else { bytes };
    while bucket + 1 < WORKLOAD_SIGNAL_HISTOGRAM_BUCKETS && normalized > threshold {
        threshold = threshold.saturating_mul(2);
        bucket += 1;
    }
    bucket
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkloadSignalSketch {
    read_histogram: DecayedByteHistogram,
    write_histogram: DecayedByteHistogram,
    hot_subjects: TopKSketch,
    hot_paths: TopKSketch,
    window_start_ms: u64,
    window_end_ms: u64,
    last_observation_ms: u64,
    sample_counter: u32,
    sample_mass: u32,
    observed_samples: u32,
    hint_samples: u32,
    sampled_away: u32,
    dropped: u32,
    reads: u32,
    writes: u32,
    fsyncs: u32,
    deletes: u32,
    metadata_ops: u32,
    read_bytes: u64,
    write_bytes: u64,
    sequential_read_bytes: u64,
    sequential_write_bytes: u64,
    overwrite_ops: u32,
    repeated_subject_hits: u32,
    snapshot_pin_events: u32,
    snapshot_pin_horizon_ms: u64,
    compression_logical_bytes: u64,
    compression_saved_bytes: u64,
    dedup_logical_bytes: u64,
    dedup_saved_bytes: u64,
    foreground_tail_events: u32,
    phase_changes: u32,
    noisy_events: u32,
    last_offset: u64,
    last_len: u64,
    last_delta: u64,
    stride_repeats: u32,
    have_last_io: bool,
    last_write_offset: u64,
    last_write_len: u64,
    have_last_write: bool,
    last_phase: AccessPatternClass,
    last_hint_access_pattern: AccessPatternClass,
    last_hint_candidate: PrefetchResidencyCandidateClass,
    provenance: HintProvenance,
    flags: WorkloadSignalFlags,
    collection_cost: WorkloadSignalCollectionCost,
}

impl Default for WorkloadSignalSketch {
    fn default() -> Self {
        Self {
            read_histogram: DecayedByteHistogram::default(),
            write_histogram: DecayedByteHistogram::default(),
            hot_subjects: TopKSketch::default(),
            hot_paths: TopKSketch::default(),
            window_start_ms: 0,
            window_end_ms: 0,
            last_observation_ms: 0,
            sample_counter: 0,
            sample_mass: 0,
            observed_samples: 0,
            hint_samples: 0,
            sampled_away: 0,
            dropped: 0,
            reads: 0,
            writes: 0,
            fsyncs: 0,
            deletes: 0,
            metadata_ops: 0,
            read_bytes: 0,
            write_bytes: 0,
            sequential_read_bytes: 0,
            sequential_write_bytes: 0,
            overwrite_ops: 0,
            repeated_subject_hits: 0,
            snapshot_pin_events: 0,
            snapshot_pin_horizon_ms: 0,
            compression_logical_bytes: 0,
            compression_saved_bytes: 0,
            dedup_logical_bytes: 0,
            dedup_saved_bytes: 0,
            foreground_tail_events: 0,
            phase_changes: 0,
            noisy_events: 0,
            last_offset: 0,
            last_len: 0,
            last_delta: 0,
            stride_repeats: 0,
            have_last_io: false,
            last_write_offset: 0,
            last_write_len: 0,
            have_last_write: false,
            last_phase: AccessPatternClass::Unknown,
            last_hint_access_pattern: AccessPatternClass::Unknown,
            last_hint_candidate: PrefetchResidencyCandidateClass::NeedMoreEvidence,
            provenance: HintProvenance::None,
            flags: WorkloadSignalFlags::EMPTY,
            collection_cost: WorkloadSignalCollectionCost::default(),
        }
    }
}

/// Bounded local workload-signal producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadSignalProducer {
    config: WorkloadSignalProducerConfig,
    context: WorkloadSignalProducerContext,
    sketch: WorkloadSignalSketch,
}

impl WorkloadSignalProducer {
    /// Create a producer with fixed local bounds.
    #[must_use]
    pub fn new(
        context: WorkloadSignalProducerContext,
        config: WorkloadSignalProducerConfig,
    ) -> Self {
        Self {
            config,
            context,
            sketch: WorkloadSignalSketch::default(),
        }
    }

    /// Create a producer with default local bounds.
    #[must_use]
    pub fn with_defaults(context: WorkloadSignalProducerContext) -> Self {
        Self::new(context, WorkloadSignalProducerConfig::default())
    }

    /// Return the fixed local memory footprint of the producer.
    #[must_use]
    pub const fn bounded_state_bytes() -> usize {
        mem::size_of::<Self>()
    }

    /// Return the producer configuration.
    #[must_use]
    pub const fn config(&self) -> WorkloadSignalProducerConfig {
        self.config
    }

    /// Observe one local workload fact.
    pub fn observe(&mut self, observation: WorkloadSignalObservation) {
        self.sketch.observe(observation, self.config);
    }

    /// Apply sketch decay while preserving bounded cardinality.
    pub fn decay(&mut self) {
        self.sketch
            .read_histogram
            .decay(self.config.decay_per_mille);
        self.sketch
            .write_histogram
            .decay(self.config.decay_per_mille);
        self.sketch.hot_subjects.decay();
        self.sketch.hot_paths.decay();
    }

    /// Reset collected local signal state.
    pub fn reset(&mut self) {
        self.sketch = WorkloadSignalSketch::default();
    }

    /// Create a read-only snapshot using the newest observed local monotonic
    /// timestamp as the age anchor.
    #[must_use]
    pub fn snapshot(&self) -> WorkloadSignalSnapshot {
        self.snapshot_at(self.sketch.window_end_ms)
    }

    /// Create a read-only snapshot at a caller-supplied local monotonic time.
    #[must_use]
    pub fn snapshot_at(&self, now_ms: u64) -> WorkloadSignalSnapshot {
        let vector = self.vector();
        let scopes = [
            WorkloadSignalScopeClass::Request,
            WorkloadSignalScopeClass::SubjectRange,
            WorkloadSignalScopeClass::Dataset,
            WorkloadSignalScopeClass::Pool,
            WorkloadSignalScopeClass::Device,
            WorkloadSignalScopeClass::Path,
            WorkloadSignalScopeClass::TenantBudget,
        ];
        let mut records = [WorkloadSignalRecord::default(); WORKLOAD_SIGNAL_SNAPSHOT_RECORDS];
        let mut actions = [WorkloadActionCandidate::default(); WORKLOAD_SIGNAL_SNAPSHOT_RECORDS];

        let mut index = 0;
        while index < WORKLOAD_SIGNAL_SNAPSHOT_RECORDS {
            let record = self.record_for_scope(scopes[index], now_ms, vector);
            records[index] = record;
            actions[index] = self.action_for_record(record);
            index += 1;
        }

        WorkloadSignalSnapshot {
            len: WORKLOAD_SIGNAL_SNAPSHOT_RECORDS as u8,
            records,
            actions,
            vector,
            collection_cost: self.sketch.collection_cost,
            hot_subject_slots: self.sketch.hot_subjects.len,
            hot_path_slots: self.sketch.hot_paths.len,
        }
    }

    fn vector(&self) -> WorkloadSignalVector {
        let data_ops = self.sketch.reads.saturating_add(self.sketch.writes);
        WorkloadSignalVector {
            sample_mass: self.sketch.sample_mass,
            read_bytes: self.sketch.read_bytes,
            write_bytes: self.sketch.write_bytes,
            read_size_top_bucket: self.sketch.read_histogram.top_bucket(),
            write_size_top_bucket: self.sketch.write_histogram.top_bucket(),
            sequential_read_ppm: ratio_ppm(
                self.sketch.sequential_read_bytes,
                self.sketch.read_bytes,
            ),
            sequential_write_ppm: ratio_ppm(
                self.sketch.sequential_write_bytes,
                self.sketch.write_bytes,
            ),
            write_ratio_ppm: ratio_ppm(self.sketch.writes as u64, data_ops as u64),
            sync_density_ppm: ratio_ppm(self.sketch.fsyncs as u64, self.sketch.writes as u64),
            overwrite_rate_ppm: ratio_ppm(
                self.sketch.overwrite_ops as u64,
                self.sketch.writes as u64,
            ),
            reuse_hotness_ppm: ratio_ppm(self.sketch.repeated_subject_hits as u64, data_ops as u64),
            metadata_ratio_ppm: ratio_ppm(
                self.sketch.metadata_ops as u64,
                self.sketch.sample_mass as u64,
            ),
            delete_ratio_ppm: ratio_ppm(self.sketch.deletes as u64, self.sketch.sample_mass as u64),
            compression_savings_ppm: ratio_ppm(
                self.sketch.compression_saved_bytes,
                self.sketch.compression_logical_bytes,
            ),
            dedup_savings_ppm: ratio_ppm(
                self.sketch.dedup_saved_bytes,
                self.sketch.dedup_logical_bytes,
            ),
            foreground_tail_ppm: ratio_ppm(
                self.sketch.foreground_tail_events as u64,
                self.sketch.sample_mass as u64,
            ),
            snapshot_pin_horizon_ms: self.sketch.snapshot_pin_horizon_ms,
            phase_changes: self.sketch.phase_changes,
            dropped_observations: self.sketch.dropped,
            sampled_away_observations: self.sketch.sampled_away,
        }
    }

    fn record_for_scope(
        &self,
        signal_scope: WorkloadSignalScopeClass,
        now_ms: u64,
        vector: WorkloadSignalVector,
    ) -> WorkloadSignalRecord {
        let flags = self.flags();
        let access_pattern = self.access_pattern(vector, flags);
        let mut record = WorkloadSignalRecord {
            policy_id: self.context.policy_id,
            policy_revision: self.context.policy_revision,
            scope: self.context.scope,
            pool_id: self.context.pool_id,
            signal_scope,
            access_pattern,
            confidence: self.confidence(signal_scope, now_ms, flags),
            observation_window_ms: self.observation_window_ms(),
            sample_mass: self.sketch.sample_mass,
            decay_age_ms: now_ms.saturating_sub(self.sketch.last_observation_ms),
            contradiction: self.contradiction(flags),
            provenance: self.provenance(flags),
            materialization_mode: self.context.materialization_mode,
            flags,
            budget_owner: self.context.budget_owner,
            source_media: self.context.source_media,
            target_media: self.context.target_media,
            source_media_ref: self.context.source_media_ref,
            target_media_ref: self.context.target_media_ref,
            service_objective_ref: self.context.service_objective_ref,
            topology_ref: self.context.topology_ref,
            signal_materialization_ref: self.context.signal_materialization_ref,
            signal_collection_cost_ref: self.context.signal_collection_cost_ref,
            candidate: self.candidate_for_access(access_pattern),
            refusal: self.refusal(flags),
        };
        record.candidate = workload_signal_lowered_candidate(record);
        record
    }

    fn observation_window_ms(&self) -> u64 {
        self.sketch
            .window_end_ms
            .saturating_sub(self.sketch.window_start_ms)
            .min(self.config.max_observation_window_ms)
    }

    fn flags(&self) -> WorkloadSignalFlags {
        let mut flags = self.sketch.flags;

        if self.sketch.hint_samples > 0 && self.sketch.observed_samples == 0 {
            flags = flags.union(WorkloadSignalFlags::HINT_ONLY);
        }
        if self.sketch.sample_mass < self.config.min_sample_mass {
            flags = flags.union(WorkloadSignalFlags::LOW_SAMPLE_MASS);
        }
        if self.sketch.sampled_away > 0 {
            flags = flags.union(WorkloadSignalFlags::SAMPLED_AWAY);
        }
        if self.sketch.dropped > 0 {
            flags = flags.union(WorkloadSignalFlags::DROPPED_OBSERVATIONS);
        }
        if matches!(
            self.context.materialization_mode,
            SignalMaterializationMode::Unknown | SignalMaterializationMode::MemoryOnlySketch
        ) {
            flags = flags.union(WorkloadSignalFlags::MEMORY_ONLY);
        }
        if !self.context.signal_collection_cost_ref.is_bound() {
            flags = flags.union(WorkloadSignalFlags::UNKNOWN_COLLECTION_COST);
        }
        if self.context.target_media.charges_rewrite_wear()
            && !self.context.signal_collection_cost_ref.is_bound()
        {
            flags = flags.union(WorkloadSignalFlags::UNKNOWN_WAF);
        }
        if (self.context.target_media.is_object_like()
            || self.context.target_media.is_archive()
            || matches!(self.context.target_media, StorageMediaClass::RemoteRam))
            && !self.context.signal_collection_cost_ref.is_bound()
        {
            flags = flags.union(WorkloadSignalFlags::UNKNOWN_EGRESS_OR_RESTORE_COST);
        }
        if self.sketch.snapshot_pin_events > 0 {
            flags = flags.union(WorkloadSignalFlags::SNAPSHOT_PINNED);
        }
        if self.sketch.collection_cost.durable_metadata_writes > 0 {
            flags = flags.union(WorkloadSignalFlags::DURABLE_METADATA_WRITES);
        }
        if self.sketch.foreground_tail_events > 0 {
            flags = flags.union(WorkloadSignalFlags::FOREGROUND_TAIL_PRESSURE);
        }
        if self.is_one_pass_scan() {
            flags = flags.union(WorkloadSignalFlags::ONE_PASS_SCAN);
        }
        if self.sketch.phase_changes >= self.config.phase_change_threshold {
            flags = flags.union(WorkloadSignalFlags::PHASE_CHANGE);
        }
        if self.sketch.noisy_events > 0
            || self.sketch.dropped >= self.config.noisy_drop_threshold
            || self.sketch.hot_subjects.evictions >= self.config.noisy_drop_threshold
            || self.sketch.hot_paths.evictions >= self.config.noisy_drop_threshold
        {
            flags = flags.union(WorkloadSignalFlags::NOISY_NEIGHBOR);
        }
        if self.sketch.collection_cost.exceeds(self.config) {
            flags = flags.union(WorkloadSignalFlags::DROPPED_OBSERVATIONS);
        }

        flags
    }

    fn is_one_pass_scan(&self) -> bool {
        self.sketch.sequential_read_bytes >= self.config.one_pass_scan_bytes
            && self.sketch.repeated_subject_hits == 0
            && self.sketch.reads >= self.config.min_sample_mass
    }

    fn access_pattern(
        &self,
        vector: WorkloadSignalVector,
        flags: WorkloadSignalFlags,
    ) -> AccessPatternClass {
        if flags.contains_all(WorkloadSignalFlags::NOISY_NEIGHBOR) {
            return AccessPatternClass::NoisyAdversarial;
        }
        if flags.contains_all(WorkloadSignalFlags::PHASE_CHANGE) {
            return AccessPatternClass::PhaseChangingSparse;
        }
        if flags.contains_all(WorkloadSignalFlags::ONE_PASS_SCAN) {
            return AccessPatternClass::OnePassScan;
        }
        if self.sketch.observed_samples == 0 && self.sketch.hint_samples > 0 {
            return self.sketch.last_hint_access_pattern;
        }
        if self.sketch.snapshot_pin_events > 0 && self.sketch.reads > 0 {
            return AccessPatternClass::SnapshotCloneRepeat;
        }
        if vector.metadata_ratio_ppm > 500_000 {
            return AccessPatternClass::MetadataNamespace;
        }
        if vector.sync_density_ppm > 500_000 && self.sketch.writes > 0 {
            return AccessPatternClass::DatabaseWalFsync;
        }
        if vector.overwrite_rate_ppm > 250_000 {
            return AccessPatternClass::OverwriteChurn;
        }
        if self.sketch.writes > self.sketch.reads.saturating_mul(2)
            && vector.sequential_write_ppm > 700_000
        {
            return AccessPatternClass::AppendLog;
        }
        if self.sketch.writes > self.sketch.reads.saturating_mul(2) {
            return AccessPatternClass::AsyncBulkWrite;
        }
        if vector.sequential_read_ppm > 700_000 && self.sketch.reads > 0 {
            return AccessPatternClass::SequentialRead;
        }
        if self.sketch.stride_repeats >= 3 {
            return AccessPatternClass::StridedRead;
        }
        if vector.reuse_hotness_ppm > 250_000 {
            return AccessPatternClass::SmallRandomHotset;
        }
        if self.sketch.reads > 0 {
            return AccessPatternClass::SmallRandomHotset;
        }
        AccessPatternClass::Unknown
    }

    fn confidence(
        &self,
        signal_scope: WorkloadSignalScopeClass,
        now_ms: u64,
        flags: WorkloadSignalFlags,
    ) -> PredictionConfidence {
        if self.sketch.sample_mass == 0 {
            return PredictionConfidence::Unknown;
        }
        if matches!(
            signal_scope,
            WorkloadSignalScopeClass::Unknown | WorkloadSignalScopeClass::Pool
        ) || self.sketch.sample_mass < self.config.min_sample_mass
        {
            return PredictionConfidence::Low;
        }
        if now_ms.saturating_sub(self.sketch.last_observation_ms) > self.config.max_decay_age_ms {
            return PredictionConfidence::Low;
        }
        if flags.intersects(
            WorkloadSignalFlags::HINT_ONLY
                .union(WorkloadSignalFlags::SAMPLED_AWAY)
                .union(WorkloadSignalFlags::DROPPED_OBSERVATIONS)
                .union(WorkloadSignalFlags::ONE_PASS_SCAN)
                .union(WorkloadSignalFlags::PHASE_CHANGE)
                .union(WorkloadSignalFlags::NOISY_NEIGHBOR)
                .union(WorkloadSignalFlags::CONTRADICTED)
                .union(WorkloadSignalFlags::UNKNOWN_COLLECTION_COST)
                .union(WorkloadSignalFlags::UNKNOWN_WAF)
                .union(WorkloadSignalFlags::UNKNOWN_EGRESS_OR_RESTORE_COST)
                .union(WorkloadSignalFlags::FOREGROUND_TAIL_PRESSURE),
        ) {
            return PredictionConfidence::Low;
        }
        if flags.contains_all(WorkloadSignalFlags::MEMORY_ONLY) {
            return PredictionConfidence::Medium;
        }
        if self.sketch.sample_mass >= self.config.high_confidence_sample_mass
            && self.observation_window_ms() >= self.config.min_observation_window_ms
            && self.context.signal_materialization_ref.is_bound()
            && self.context.signal_collection_cost_ref.is_bound()
        {
            return PredictionConfidence::High;
        }
        PredictionConfidence::Medium
    }

    fn contradiction(&self, flags: WorkloadSignalFlags) -> ContradictionState {
        if flags.contains_all(WorkloadSignalFlags::CONTRADICTED) {
            return ContradictionState::StrongContradiction;
        }
        if flags.intersects(
            WorkloadSignalFlags::PHASE_CHANGE
                .union(WorkloadSignalFlags::NOISY_NEIGHBOR)
                .union(WorkloadSignalFlags::FOREGROUND_TAIL_PRESSURE),
        ) {
            return ContradictionState::WeakContradiction;
        }
        ContradictionState::None
    }

    fn provenance(&self, flags: WorkloadSignalFlags) -> HintProvenance {
        if flags.contains_all(WorkloadSignalFlags::HINT_ONLY) {
            return if matches!(self.sketch.provenance, HintProvenance::None) {
                HintProvenance::Caller
            } else {
                self.sketch.provenance
            };
        }
        if self.sketch.observed_samples > 0 {
            HintProvenance::RuntimeObserved
        } else {
            self.sketch.provenance
        }
    }

    fn refusal(&self, flags: WorkloadSignalFlags) -> StorageIntentRefusalReason {
        if flags.contains_all(WorkloadSignalFlags::CONTRADICTED)
            || self.sketch.collection_cost.exceeds(self.config)
        {
            return StorageIntentRefusalReason::EvidenceNotUsable;
        }
        StorageIntentRefusalReason::None
    }

    fn candidate_for_access(
        &self,
        access_pattern: AccessPatternClass,
    ) -> PrefetchResidencyCandidateClass {
        if !matches!(
            self.context.requested_candidate,
            PrefetchResidencyCandidateClass::NeedMoreEvidence
                | PrefetchResidencyCandidateClass::NoPrefetch
        ) {
            return self.context.requested_candidate;
        }
        if self.sketch.observed_samples == 0 && self.sketch.hint_samples > 0 {
            return self.sketch.last_hint_candidate;
        }
        match access_pattern {
            AccessPatternClass::SequentialRead | AccessPatternClass::OnePassScan => {
                PrefetchResidencyCandidateClass::BoundedReadahead
            }
            AccessPatternClass::StridedRead | AccessPatternClass::VectorRead => {
                PrefetchResidencyCandidateClass::StridedVectorPrefetch
            }
            AccessPatternClass::MetadataNamespace => {
                PrefetchResidencyCandidateClass::MetadataNamespacePrefetch
            }
            AccessPatternClass::ManifestIndexFanout => {
                PrefetchResidencyCandidateClass::ManifestIndexPrefetch
            }
            AccessPatternClass::SnapshotCloneRepeat => {
                PrefetchResidencyCandidateClass::SnapshotClonePrefetch
            }
            AccessPatternClass::DegradedReconstruction => {
                PrefetchResidencyCandidateClass::DegradedReadPrefetch
            }
            AccessPatternClass::WanGeoDelta => PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch,
            AccessPatternClass::ObjectArchiveRestore => {
                PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage
            }
            AccessPatternClass::SmallRandomHotset => {
                if self.context.target_media.charges_rewrite_wear() {
                    PrefetchResidencyCandidateClass::FlashHotServing
                } else {
                    PrefetchResidencyCandidateClass::CacheOnlyTrial
                }
            }
            AccessPatternClass::PhaseChangingSparse | AccessPatternClass::NoisyAdversarial => {
                PrefetchResidencyCandidateClass::Cooldown
            }
            _ => PrefetchResidencyCandidateClass::NoPrefetch,
        }
    }

    fn action_for_record(&self, record: WorkloadSignalRecord) -> WorkloadActionCandidate {
        let candidate = record.candidate;
        let may_change_authority = workload_signal_can_train_upward(record)
            && matches!(
                candidate,
                PrefetchResidencyCandidateClass::AuthorityPromotionCandidate
                    | PrefetchResidencyCandidateClass::PmemDurable
                    | PrefetchResidencyCandidateClass::DemotionCandidate
            );
        let mut action_class = if may_change_authority {
            match candidate {
                PrefetchResidencyCandidateClass::AuthorityPromotionCandidate
                | PrefetchResidencyCandidateClass::PmemDurable => {
                    StorageIntentActionClass::AuthorityPromotion
                }
                PrefetchResidencyCandidateClass::DemotionCandidate => {
                    StorageIntentActionClass::DurablePlacementMovement
                }
                _ => self.context.requested_action_class,
            }
        } else {
            conservative_action_class(record.access_pattern, candidate)
        };

        if matches!(
            self.context.requested_action_class,
            StorageIntentActionClass::NewWriteShaping
                | StorageIntentActionClass::FlashServingPromotion
        ) && record.confidence == PredictionConfidence::High
            && workload_signal_can_train_upward(record)
            && !may_change_authority
        {
            action_class = self.context.requested_action_class;
        }

        WorkloadActionCandidate {
            action_class,
            prefetch_candidate: candidate,
            confidence: record.confidence,
            may_change_authority,
        }
    }
}

impl WorkloadSignalSketch {
    fn observe(
        &mut self,
        observation: WorkloadSignalObservation,
        config: WorkloadSignalProducerConfig,
    ) {
        self.sample_counter = self.sample_counter.saturating_add(1);
        if config.sample_every > 1 && self.sample_counter % config.sample_every != 0 {
            self.sampled_away = self.sampled_away.saturating_add(1);
            self.flags = self.flags.union(WorkloadSignalFlags::SAMPLED_AWAY);
            return;
        }

        if self.sample_mass == 0 && self.hint_samples == 0 {
            self.window_start_ms = observation.now_ms;
        }
        self.window_end_ms = observation.now_ms;
        self.last_observation_ms = observation.now_ms;
        self.collection_cost = self
            .collection_cost
            .saturating_add(observation.collection_cost);
        self.flags = self.flags.union(observation.flags);
        if observation
            .flags
            .contains_all(WorkloadSignalFlags::NOISY_NEIGHBOR)
        {
            self.noisy_events = self.noisy_events.saturating_add(1);
        }

        if self.collection_cost.exceeds(config) {
            self.dropped = self.dropped.saturating_add(1);
            self.flags = self.flags.union(WorkloadSignalFlags::DROPPED_OBSERVATIONS);
            return;
        }

        if observation.path_tag != 0 {
            self.hot_paths.observe(observation.path_tag, 1);
        }
        if self.hot_subjects.observe(observation.subject_tag, 1) {
            self.repeated_subject_hits = self.repeated_subject_hits.saturating_add(1);
        }

        match observation.operation {
            WorkloadSignalOperation::Hint => self.observe_hint(observation),
            WorkloadSignalOperation::Read => self.observe_read(observation),
            WorkloadSignalOperation::Write => self.observe_write(observation),
            WorkloadSignalOperation::Fsync => {
                self.count_observed(observation, AccessPatternClass::DatabaseWalFsync);
                self.fsyncs = self.fsyncs.saturating_add(1);
            }
            WorkloadSignalOperation::Delete => {
                self.count_observed(observation, AccessPatternClass::OverwriteChurn);
                self.deletes = self.deletes.saturating_add(1);
            }
            WorkloadSignalOperation::Metadata => {
                self.count_observed(observation, AccessPatternClass::MetadataNamespace);
                self.metadata_ops = self.metadata_ops.saturating_add(1);
            }
            WorkloadSignalOperation::SnapshotPin => {
                self.count_observed(observation, AccessPatternClass::SnapshotCloneRepeat);
                self.snapshot_pin_events = self.snapshot_pin_events.saturating_add(1);
                self.snapshot_pin_horizon_ms = self
                    .snapshot_pin_horizon_ms
                    .max(observation.snapshot_pin_horizon_ms);
            }
            WorkloadSignalOperation::CompressionSample => {
                self.count_observed(observation, AccessPatternClass::AsyncBulkWrite);
                self.compression_logical_bytes = self
                    .compression_logical_bytes
                    .saturating_add(observation.logical_bytes);
                self.compression_saved_bytes = self.compression_saved_bytes.saturating_add(
                    observation
                        .logical_bytes
                        .saturating_sub(observation.physical_bytes),
                );
            }
            WorkloadSignalOperation::DedupSample => {
                self.count_observed(observation, AccessPatternClass::SmallRandomHotset);
                self.dedup_logical_bytes = self
                    .dedup_logical_bytes
                    .saturating_add(observation.logical_bytes);
                self.dedup_saved_bytes = self.dedup_saved_bytes.saturating_add(
                    observation
                        .logical_bytes
                        .saturating_sub(observation.physical_bytes),
                );
            }
            WorkloadSignalOperation::ForegroundTail => {
                self.count_observed(observation, AccessPatternClass::Unknown);
                if observation.foreground_latency_objective_us == 0
                    || observation.foreground_latency_us
                        > observation.foreground_latency_objective_us
                {
                    self.foreground_tail_events = self.foreground_tail_events.saturating_add(1);
                }
            }
        }
    }

    fn observe_hint(&mut self, observation: WorkloadSignalObservation) {
        self.hint_samples = self.hint_samples.saturating_add(1);
        self.provenance = observation.provenance;
        self.last_hint_access_pattern = observation.hint_access_pattern;
        self.last_hint_candidate = observation.hint_candidate;
        self.flags = self.flags.union(WorkloadSignalFlags::HINT_ONLY);
    }

    fn observe_read(&mut self, observation: WorkloadSignalObservation) {
        self.count_observed(observation, AccessPatternClass::SequentialRead);
        self.reads = self.reads.saturating_add(1);
        self.read_bytes = self.read_bytes.saturating_add(observation.len);
        self.read_histogram.observe(observation.len);
        if self.track_io_sequentiality(observation) {
            self.sequential_read_bytes = self.sequential_read_bytes.saturating_add(observation.len);
        }
    }

    fn observe_write(&mut self, observation: WorkloadSignalObservation) {
        self.count_observed(observation, AccessPatternClass::AsyncBulkWrite);
        self.writes = self.writes.saturating_add(1);
        self.write_bytes = self.write_bytes.saturating_add(observation.len);
        self.write_histogram.observe(observation.len);
        if self.track_io_sequentiality(observation) {
            self.sequential_write_bytes =
                self.sequential_write_bytes.saturating_add(observation.len);
        }
        if self.have_last_write
            && ranges_overlap(
                self.last_write_offset,
                self.last_write_len,
                observation.offset,
                observation.len,
            )
        {
            self.overwrite_ops = self.overwrite_ops.saturating_add(1);
        }
        self.last_write_offset = observation.offset;
        self.last_write_len = observation.len;
        self.have_last_write = true;
    }

    fn count_observed(
        &mut self,
        observation: WorkloadSignalObservation,
        phase: AccessPatternClass,
    ) {
        self.sample_mass = self.sample_mass.saturating_add(1);
        self.observed_samples = self.observed_samples.saturating_add(1);
        self.provenance = HintProvenance::RuntimeObserved;
        self.track_phase(phase);
        if observation
            .flags
            .contains_all(WorkloadSignalFlags::CONTRADICTED)
        {
            self.flags = self.flags.union(WorkloadSignalFlags::CONTRADICTED);
        }
    }

    fn track_phase(&mut self, phase: AccessPatternClass) {
        if matches!(phase, AccessPatternClass::Unknown) {
            return;
        }
        if !matches!(self.last_phase, AccessPatternClass::Unknown)
            && self.last_phase as u8 != phase as u8
        {
            self.phase_changes = self.phase_changes.saturating_add(1);
        }
        self.last_phase = phase;
    }

    fn track_io_sequentiality(&mut self, observation: WorkloadSignalObservation) -> bool {
        let mut sequential = false;
        let mut delta = 0;
        if self.have_last_io {
            let expected = self.last_offset.saturating_add(self.last_len);
            sequential = observation.offset == expected;
            delta = if observation.offset >= self.last_offset {
                observation.offset.saturating_sub(self.last_offset)
            } else {
                self.last_offset.saturating_sub(observation.offset)
            };
            if delta == self.last_delta && delta != 0 {
                self.stride_repeats = self.stride_repeats.saturating_add(1);
            }
        }
        self.last_delta = delta;
        self.last_offset = observation.offset;
        self.last_len = observation.len;
        self.have_last_io = true;
        sequential
    }
}

fn ratio_ppm(numerator: u64, denominator: u64) -> u32 {
    if denominator == 0 {
        return 0;
    }
    ((numerator.saturating_mul(PPM) / denominator).min(PPM)) as u32
}

fn ranges_overlap(left_offset: u64, left_len: u64, right_offset: u64, right_len: u64) -> bool {
    let left_end = left_offset.saturating_add(left_len);
    let right_end = right_offset.saturating_add(right_len);
    left_offset < right_end && right_offset < left_end
}

fn conservative_action_class(
    access_pattern: AccessPatternClass,
    candidate: PrefetchResidencyCandidateClass,
) -> StorageIntentActionClass {
    match access_pattern {
        AccessPatternClass::SyncSmallWrite
        | AccessPatternClass::AsyncBulkWrite
        | AccessPatternClass::OverwriteChurn
        | AccessPatternClass::AppendLog
        | AccessPatternClass::DatabaseWalFsync => StorageIntentActionClass::NewWriteShaping,
        AccessPatternClass::DegradedReconstruction => {
            StorageIntentActionClass::DegradedReadReconstruction
        }
        AccessPatternClass::SmallRandomHotset
        | AccessPatternClass::VmImageMixedRead
        | AccessPatternClass::MmapPageCacheReuse => StorageIntentActionClass::CacheOnlyServingTrial,
        AccessPatternClass::PhaseChangingSparse | AccessPatternClass::NoisyAdversarial => {
            StorageIntentActionClass::QueuePrefetchTuning
        }
        _ => match candidate {
            PrefetchResidencyCandidateClass::CacheOnlyTrial
            | PrefetchResidencyCandidateClass::VolatileRamTrial => {
                StorageIntentActionClass::CacheOnlyServingTrial
            }
            PrefetchResidencyCandidateClass::FlashHotServing => {
                StorageIntentActionClass::FlashServingPromotion
            }
            _ => StorageIntentActionClass::QueuePrefetchTuning,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN_A: StorageIntentDomainId = StorageIntentDomainId([7_u8; 16]);
    const DOMAIN_B: StorageIntentDomainId = StorageIntentDomainId([9_u8; 16]);

    fn evidence_ref(kind: StorageIntentEvidenceKind, byte: u8) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(kind, StorageIntentEvidenceId([byte; 32]), 1, 1)
    }

    fn proven_context() -> WorkloadSignalProducerContext {
        WorkloadSignalProducerContext::dataset(DOMAIN_A, DOMAIN_B)
            .with_signal_evidence(
                SignalMaterializationMode::DurableSummary,
                evidence_ref(StorageIntentEvidenceKind::WorkloadEvidence, 1),
                evidence_ref(StorageIntentEvidenceKind::MediaCostWearLedger, 2),
            )
            .with_media(
                StorageMediaClass::HddRotational,
                StorageMediaClass::NvmeFlash,
                evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 3),
                evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 4),
            )
    }

    fn medium_config() -> WorkloadSignalProducerConfig {
        WorkloadSignalProducerConfig {
            min_sample_mass: 4,
            high_confidence_sample_mass: 8,
            min_observation_window_ms: 7,
            one_pass_scan_bytes: 16 * 1024,
            ..WorkloadSignalProducerConfig::default()
        }
    }

    #[test]
    fn snapshot_covers_expected_signal_scopes() {
        let mut producer = WorkloadSignalProducer::with_defaults(proven_context());
        producer.observe(WorkloadSignalObservation::read(0, 0, 4096, 1));

        let snapshot = producer.snapshot();
        assert_eq!(snapshot.records().len(), WORKLOAD_SIGNAL_SNAPSHOT_RECORDS);
        assert!(snapshot
            .record_for_scope(WorkloadSignalScopeClass::Request)
            .is_some());
        assert!(snapshot
            .record_for_scope(WorkloadSignalScopeClass::SubjectRange)
            .is_some());
        assert!(snapshot
            .record_for_scope(WorkloadSignalScopeClass::Dataset)
            .is_some());
        assert!(snapshot
            .record_for_scope(WorkloadSignalScopeClass::Pool)
            .is_some());
        assert!(snapshot
            .record_for_scope(WorkloadSignalScopeClass::Device)
            .is_some());
        assert!(snapshot
            .record_for_scope(WorkloadSignalScopeClass::Path)
            .is_some());
        assert!(snapshot
            .record_for_scope(WorkloadSignalScopeClass::TenantBudget)
            .is_some());
    }

    #[test]
    fn top_k_and_histograms_stay_bounded() {
        let mut producer = WorkloadSignalProducer::with_defaults(proven_context());
        let mut index = 0;
        while index < 128 {
            producer.observe(WorkloadSignalObservation::read(
                index as u64,
                (index as u64) * 4096,
                4096,
                index as u64 + 1,
            ));
            index += 1;
        }

        let snapshot = producer.snapshot();
        assert_eq!(snapshot.hot_subject_slots as usize, WORKLOAD_SIGNAL_TOP_K);
        assert!(WorkloadSignalProducer::bounded_state_bytes() < 4096);
        assert_eq!(
            producer.sketch.read_histogram.buckets().len(),
            WORKLOAD_SIGNAL_HISTOGRAM_BUCKETS
        );
    }

    #[test]
    fn collection_cost_budget_marks_dropped_and_refused() {
        let config = WorkloadSignalProducerConfig {
            max_memory_bytes: 64,
            ..medium_config()
        };
        let mut producer = WorkloadSignalProducer::new(proven_context(), config);
        let expensive = WorkloadSignalObservation::read(0, 0, 4096, 1).with_collection_cost(
            WorkloadSignalCollectionCost {
                memory_bytes: 1024,
                ..WorkloadSignalCollectionCost::default()
            },
        );

        producer.observe(expensive);
        let record = producer
            .snapshot()
            .record_for_scope(WorkloadSignalScopeClass::Dataset)
            .unwrap();

        assert!(record
            .flags
            .contains_all(WorkloadSignalFlags::DROPPED_OBSERVATIONS));
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(!workload_signal_can_train_upward(record));
    }

    #[test]
    fn unknown_cost_is_not_zero_cost() {
        let mut context = proven_context();
        context.signal_collection_cost_ref = StorageIntentEvidenceRef::default();
        let mut producer = WorkloadSignalProducer::new(context, medium_config());
        for index in 0..8 {
            producer.observe(WorkloadSignalObservation::read(
                index,
                index * 4096,
                4096,
                1,
            ));
        }

        let record = producer
            .snapshot()
            .record_for_scope(WorkloadSignalScopeClass::Dataset)
            .unwrap();

        assert!(record
            .flags
            .contains_all(WorkloadSignalFlags::UNKNOWN_COLLECTION_COST));
        assert!(record.flags.contains_all(WorkloadSignalFlags::UNKNOWN_WAF));
        assert_eq!(
            record.candidate,
            PrefetchResidencyCandidateClass::BoundedReadahead
        );
        assert!(!workload_signal_can_train_upward(record));
    }

    #[test]
    fn one_pass_scan_lowers_flash_promotion() {
        let context = proven_context().with_requested_action(
            PrefetchResidencyCandidateClass::FlashHotServing,
            StorageIntentActionClass::FlashServingPromotion,
        );
        let mut producer = WorkloadSignalProducer::new(context, medium_config());
        for index in 0..8 {
            producer.observe(WorkloadSignalObservation::read(
                index,
                index * 4096,
                4096,
                index + 100,
            ));
        }

        let snapshot = producer.snapshot();
        let record = snapshot
            .record_for_scope(WorkloadSignalScopeClass::Dataset)
            .unwrap();

        assert_eq!(record.access_pattern, AccessPatternClass::OnePassScan);
        assert!(record
            .flags
            .contains_all(WorkloadSignalFlags::ONE_PASS_SCAN));
        assert_eq!(
            record.candidate,
            PrefetchResidencyCandidateClass::BoundedReadahead
        );
        assert_eq!(
            snapshot.actions()[2].action_class,
            StorageIntentActionClass::QueuePrefetchTuning
        );
    }

    #[test]
    fn phase_change_sparse_workload_enters_cooldown() {
        let context = proven_context().with_requested_action(
            PrefetchResidencyCandidateClass::FlashHotServing,
            StorageIntentActionClass::FlashServingPromotion,
        );
        let mut producer = WorkloadSignalProducer::new(context, medium_config());
        producer.observe(WorkloadSignalObservation::read(0, 0, 4096, 1));
        producer.observe(WorkloadSignalObservation::write(1, 0, 4096, 1));
        producer.observe(WorkloadSignalObservation::read(2, 128 * 1024, 4096, 2));
        producer.observe(WorkloadSignalObservation::write(3, 64 * 1024, 4096, 3));

        let record = producer
            .snapshot()
            .record_for_scope(WorkloadSignalScopeClass::Dataset)
            .unwrap();

        assert_eq!(
            record.access_pattern,
            AccessPatternClass::PhaseChangingSparse
        );
        assert!(record.flags.contains_all(WorkloadSignalFlags::PHASE_CHANGE));
        assert_eq!(record.candidate, PrefetchResidencyCandidateClass::Cooldown);
    }

    #[test]
    fn hint_only_cannot_become_authority() {
        let context = proven_context().with_requested_action(
            PrefetchResidencyCandidateClass::AuthorityPromotionCandidate,
            StorageIntentActionClass::AuthorityPromotion,
        );
        let mut producer = WorkloadSignalProducer::new(context, medium_config());
        producer.observe(WorkloadSignalObservation::hint(
            0,
            HintProvenance::Caller,
            AccessPatternClass::SmallRandomHotset,
            PrefetchResidencyCandidateClass::AuthorityPromotionCandidate,
        ));

        let snapshot = producer.snapshot();
        let record = snapshot
            .record_for_scope(WorkloadSignalScopeClass::Dataset)
            .unwrap();

        assert_eq!(record.sample_mass, 0);
        assert!(record.flags.contains_all(WorkloadSignalFlags::HINT_ONLY));
        assert_eq!(
            record.candidate,
            PrefetchResidencyCandidateClass::CacheOnlyTrial
        );
        assert!(!snapshot.actions()[2].may_change_authority);
    }

    #[test]
    fn memory_only_evidence_demotes_hotset_to_cache_trial() {
        let context = WorkloadSignalProducerContext::dataset(DOMAIN_A, DOMAIN_B)
            .with_requested_action(
                PrefetchResidencyCandidateClass::PmemDurable,
                StorageIntentActionClass::AuthorityPromotion,
            );
        let mut producer = WorkloadSignalProducer::new(context, medium_config());
        for index in 0..8 {
            producer.observe(WorkloadSignalObservation::read(
                index,
                index * index * 4096,
                4096,
                42,
            ));
        }

        let record = producer
            .snapshot()
            .record_for_scope(WorkloadSignalScopeClass::Dataset)
            .unwrap();

        assert!(record.flags.contains_all(WorkloadSignalFlags::MEMORY_ONLY));
        assert_eq!(
            record.candidate,
            PrefetchResidencyCandidateClass::CacheOnlyTrial
        );
        assert!(!workload_signal_can_train_upward(record));
    }

    #[test]
    fn sampled_away_observations_demote_candidate() {
        let config = WorkloadSignalProducerConfig {
            sample_every: 2,
            min_sample_mass: 2,
            high_confidence_sample_mass: 4,
            min_observation_window_ms: 2,
            ..medium_config()
        };
        let context = proven_context().with_requested_action(
            PrefetchResidencyCandidateClass::FlashHotServing,
            StorageIntentActionClass::FlashServingPromotion,
        );
        let mut producer = WorkloadSignalProducer::new(context, config);
        for index in 0..8 {
            producer.observe(WorkloadSignalObservation::read(
                index,
                index * 4096,
                4096,
                1,
            ));
        }

        let record = producer
            .snapshot()
            .record_for_scope(WorkloadSignalScopeClass::Dataset)
            .unwrap();

        assert!(record.flags.contains_all(WorkloadSignalFlags::SAMPLED_AWAY));
        assert!(!workload_signal_can_train_upward(record));
        assert_eq!(
            record.candidate,
            PrefetchResidencyCandidateClass::CacheOnlyTrial
        );
    }

    #[test]
    fn noisy_tenant_cannot_manufacture_authority_movement() {
        let context = proven_context().with_requested_action(
            PrefetchResidencyCandidateClass::AuthorityPromotionCandidate,
            StorageIntentActionClass::AuthorityPromotion,
        );
        let mut producer = WorkloadSignalProducer::new(context, medium_config());
        for index in 0..8 {
            producer.observe(
                WorkloadSignalObservation::read(index, index * 8192, 4096, 42)
                    .with_flags(WorkloadSignalFlags::NOISY_NEIGHBOR),
            );
        }

        let snapshot = producer.snapshot();
        let record = snapshot
            .record_for_scope(WorkloadSignalScopeClass::TenantBudget)
            .unwrap();

        assert_eq!(record.access_pattern, AccessPatternClass::NoisyAdversarial);
        assert!(record
            .flags
            .contains_all(WorkloadSignalFlags::NOISY_NEIGHBOR));
        assert_eq!(record.candidate, PrefetchResidencyCandidateClass::Cooldown);
        assert!(!snapshot.actions()[6].may_change_authority);
    }

    #[test]
    fn writes_emit_new_write_shaping_not_durable_movement() {
        let context = proven_context().with_requested_action(
            PrefetchResidencyCandidateClass::DemotionCandidate,
            StorageIntentActionClass::DurablePlacementMovement,
        );
        let mut producer = WorkloadSignalProducer::new(context, medium_config());
        for index in 0..8 {
            producer.observe(WorkloadSignalObservation::write(
                index,
                index * 4096,
                4096,
                11,
            ));
        }

        let snapshot = producer.snapshot();
        let record = snapshot
            .record_for_scope(WorkloadSignalScopeClass::Dataset)
            .unwrap();

        assert_eq!(record.access_pattern, AccessPatternClass::AppendLog);
        assert_eq!(
            record.candidate,
            PrefetchResidencyCandidateClass::NoPrefetch
        );
        assert_eq!(
            snapshot.actions()[2].action_class,
            StorageIntentActionClass::NewWriteShaping
        );
    }
}
