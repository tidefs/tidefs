// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Unified resource governor: single budget authority for daemon-side memory.
//!
//! Every byte allocated by the daemon is tagged with exactly one
//! [`BudgetCategory`].  Every cache admission is a budget allocation; every
//! eviction is a budget reclaim.  Backpressure is the unified overflow valve.
//!
//! This is the first integration slice: admission/release with per-category
//! watermarks, backpressure signals, and one wired cache admission path.
//! Full 6-level migration and cluster backpressure are deferred to follow-up
//! slices (see `docs/UNIFIED_RESOURCE_GOVERNOR_DESIGN.md`).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use tidefs_background_scheduler::{
    BackgroundService, ServiceBudget, ServiceError, ServicePriority, TickReport,
};
use tidefs_incremental_job_core::IncrementalJob;
use tidefs_types_cache_lattice_core::{CacheClass, CacheEntryHeader};

// ── Budget categories ────────────────────────────────────────────────────

/// Budget categories for the unified resource governor.
///
/// Every byte in the daemon is allocated against exactly one category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BudgetCategory {
    /// Hot read cache (L1: extent payloads), prefetch cache (L2: read-ahead).
    DataCache,
    /// Decoded B+tree nodes (L3), xattrs/dirs (L4).
    MetaCache,
    /// Write-combining buffers not yet flushed (L5).
    DirtyBytes,
    /// Per-inode state: locks, handles, dirty metadata, decode state.
    InodeState,
    /// Inflight cluster RPC frames, dedup windows, bulk tokens (L6).
    ClusterQueues,
    /// Unallocated safety buffer (FUSE reply buffers, temp crypto state).
    Misc,
}

impl fmt::Display for BudgetCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataCache => write!(f, "data_cache"),
            Self::MetaCache => write!(f, "meta_cache"),
            Self::DirtyBytes => write!(f, "dirty_bytes"),
            Self::InodeState => write!(f, "inode_state"),
            Self::ClusterQueues => write!(f, "cluster_queues"),
            Self::Misc => write!(f, "misc"),
        }
    }
}

// ── Cache-level mapping ─────────────────────────────────────────────────

/// Concrete cache level whose allocations must be charged to the governor.
///
/// This is the centralized cache-level-to-budget-category mapping from
/// `docs/UNIFIED_RESOURCE_GOVERNOR_DESIGN.md`.  Concrete cache callers use
/// these variants instead of selecting budget categories from local strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CacheBudgetLevel {
    /// L1 hot read cache: frequently-read payload bytes.
    L1HotRead,
    /// L2 speculative prefetch or read-ahead bytes.
    L2PrefetchReadAhead,
    /// L2ARC-like secondary read cache metadata and resident payload handles.
    L2Arc,
    /// L3 decoded metadata nodes and authority read mirrors.
    L3DecodedMetadata,
    /// L4 directory listing cache.
    L4DirectoryListing,
    /// L4 path/dentry lookup cache.
    L4PathLookup,
    /// L4 decoded namespace/view cache.
    L4DecodedView,
    /// L5 dirty/writeback page buffers.
    L5DirtyWriteback,
    /// Per-inode runtime state and inode-record cache.
    InodeState,
    /// Cluster/session/transport queue state.
    ClusterQueue,
    /// Miscellaneous bounded runtime cache or scratch state.
    Misc,
}

/// Return the governor category for a concrete cache level.
#[must_use]
pub const fn budget_category_for_cache_level(level: CacheBudgetLevel) -> BudgetCategory {
    match level {
        CacheBudgetLevel::L1HotRead
        | CacheBudgetLevel::L2PrefetchReadAhead
        | CacheBudgetLevel::L2Arc => BudgetCategory::DataCache,
        CacheBudgetLevel::L3DecodedMetadata
        | CacheBudgetLevel::L4DirectoryListing
        | CacheBudgetLevel::L4PathLookup
        | CacheBudgetLevel::L4DecodedView => BudgetCategory::MetaCache,
        CacheBudgetLevel::L5DirtyWriteback => BudgetCategory::DirtyBytes,
        CacheBudgetLevel::InodeState => BudgetCategory::InodeState,
        CacheBudgetLevel::ClusterQueue => BudgetCategory::ClusterQueues,
        CacheBudgetLevel::Misc => BudgetCategory::Misc,
    }
}

/// Return the governor category for cache-lattice classes that flow through
/// [`crate::CacheLatticeRegistry`].
#[must_use]
pub const fn budget_category_for_cache_class(class: CacheClass) -> BudgetCategory {
    match class {
        CacheClass::AuthorityReadMirror | CacheClass::AllocatorHotSummary => {
            BudgetCategory::MetaCache
        }
        CacheClass::PosixNamespaceMirror => BudgetCategory::MetaCache,
        CacheClass::PublicationStaging => BudgetCategory::DirtyBytes,
        CacheClass::PosixPageWriteback => BudgetCategory::DataCache,
        CacheClass::BlockVolumeMappingQueue => BudgetCategory::DirtyBytes,
        CacheClass::ProductRuntime | CacheClass::ValidationObserve => BudgetCategory::Misc,
        CacheClass::SessionFence => BudgetCategory::ClusterQueues,
    }
}

/// Return the governor category for a concrete cache-lattice entry.
///
/// Dirty entries are charged to [`BudgetCategory::DirtyBytes`] regardless of
/// cache class, because L5 dirty/writeback bytes must drain through writeback
/// and must not be treated as clean evictable cache.
#[must_use]
pub fn budget_category_for_entry(header: &CacheEntryHeader) -> BudgetCategory {
    if header.dirty_state.is_dirty() {
        BudgetCategory::DirtyBytes
    } else {
        budget_category_for_cache_class(header.cache_class)
    }
}

// ── Backpressure signal ──────────────────────────────────────────────────

/// Backpressure signal emitted by the governor per category or globally.
///
/// Callers (FUSE admission throttle, cluster transport admission) consume
/// this signal to reduce or block incoming work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackpressureSignal {
    /// Normal operation, no backpressure.
    None,
    /// Category is above the soft watermark — throttle non-critical
    /// admission, trigger background eviction.
    SoftPressure,
    /// Category is at or above the hard limit — reject new admission
    /// until pressure subsides.
    HardPressure,
}

impl fmt::Display for BackpressureSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::SoftPressure => write!(f, "soft"),
            Self::HardPressure => write!(f, "hard"),
        }
    }
}

// ── Budget partitions ────────────────────────────────────────────────────

/// Stable governor budget partition key.
///
/// This is intentionally a small opaque key instead of a direct dependency on a
/// dataset crate: mounted filesystems, prefetch, and future budget-owner
/// evidence can all project their owner identity into this governor key without
/// making the governor redefine those authorities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BudgetPartitionKey([u8; 16]);

impl BudgetPartitionKey {
    /// Create a partition key from a stable 128-bit owner/dataset identifier.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Return the raw stable key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for BudgetPartitionKey {
    fn from(value: [u8; 16]) -> Self {
        Self::from_bytes(value)
    }
}

impl fmt::Display for BudgetPartitionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Policy for budget left unused by other partitions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BudgetPartitionPolicy {
    /// A partition cannot exceed its protected per-category cap.
    #[default]
    Strict,
    /// A partition may borrow currently unused category capacity.
    ShareUnused,
}

/// Per-partition budget policy layered below category and global hard limits.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GovernorPartitionConfig {
    /// Whether unused category budget can be borrowed by another partition.
    pub policy: BudgetPartitionPolicy,
    /// Protected fraction of each category cap available to one partition.
    pub category_fraction: f64,
    /// Soft-pressure fraction of the current partition limit.
    pub soft_fraction: f64,
}

impl Default for GovernorPartitionConfig {
    fn default() -> Self {
        Self {
            policy: BudgetPartitionPolicy::Strict,
            category_fraction: 0.50,
            soft_fraction: 0.70,
        }
    }
}

impl GovernorPartitionConfig {
    /// Validate partition policy fractions.
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.category_fraction) {
            let category_fraction = self.category_fraction;
            return Err(format!(
                "partition category fraction {category_fraction} out of range [0, 1]"
            ));
        }
        if !(0.0..=1.0).contains(&self.soft_fraction) {
            let soft_fraction = self.soft_fraction;
            return Err(format!(
                "partition soft fraction {soft_fraction} out of range [0, 1]"
            ));
        }
        Ok(())
    }
}

/// Read-only pressure state for one budget partition within one category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovernorPartitionPressureState {
    /// Partition whose pressure was sampled.
    pub partition: BudgetPartitionKey,
    /// Budget category whose partition usage was sampled.
    pub category: BudgetCategory,
    /// Current per-partition pressure signal.
    pub signal: BackpressureSignal,
    /// Current partition usage in bytes for this category.
    pub used: u64,
    /// Effective current partition limit.
    pub limit: u64,
    /// Protected cap before optional unused-budget sharing.
    pub protected_limit: u64,
    /// Soft watermark derived from the effective partition limit.
    pub soft_watermark: u64,
    /// Extra limit currently available from unused category budget sharing.
    pub shared_unused_bytes: u64,
}

/// Read-only usage and pressure snapshot for one budget partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernorPartitionUsageState {
    /// Partition whose usage was sampled.
    pub partition: BudgetPartitionKey,
    /// Total bytes charged to this partition across all categories.
    pub total_used: u64,
    /// Per-category usage and pressure rows.
    pub categories: [GovernorPartitionPressureState; 6],
}

impl GovernorPartitionUsageState {
    /// Return this partition's pressure row for one category.
    #[must_use]
    pub fn pressure_for_category(
        &self,
        category: BudgetCategory,
    ) -> GovernorPartitionPressureState {
        self.categories[Governor::category_index(category)]
    }
}

// ── Reclaim ladder state ─────────────────────────────────────────────────

/// Governor reclaim ladder stage selected for a pressure snapshot.
///
/// Stages 1 through 4 can become bounded background work. Stage 5 is an
/// admission/backpressure signal only; it is intentionally not converted into
/// a background service tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReclaimStage {
    /// Stage 1: evict cold read/prefetch/cache entries.
    EvictColdCache,
    /// Stage 2: shrink metadata-facing cache state after soft pressure persists.
    ShrinkMetadataCaches,
    /// Stage 3: flush dirty/writeback bytes through an existing flush surface.
    FlushDirtyData,
    /// Stage 4: request the existing commit/sync boundary for hard dirty pressure.
    ForceCommitGroupSync,
    /// Stage 5: terminal admission/backpressure signal, not background work.
    AdmissionBackpressure,
}

impl ReclaimStage {
    /// Numeric stage in the design ladder.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::EvictColdCache => 1,
            Self::ShrinkMetadataCaches => 2,
            Self::FlushDirtyData => 3,
            Self::ForceCommitGroupSync => 4,
            Self::AdmissionBackpressure => 5,
        }
    }

    /// Returns `true` if this stage can be claimed by a background service.
    #[must_use]
    pub const fn is_background_work(self) -> bool {
        !matches!(self, Self::AdmissionBackpressure)
    }
}

impl fmt::Display for ReclaimStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EvictColdCache => write!(f, "stage1_evict_cold_cache"),
            Self::ShrinkMetadataCaches => write!(f, "stage2_shrink_metadata_caches"),
            Self::FlushDirtyData => write!(f, "stage3_flush_dirty_data"),
            Self::ForceCommitGroupSync => write!(f, "stage4_force_commit_group_sync"),
            Self::AdmissionBackpressure => write!(f, "stage5_admission_backpressure"),
        }
    }
}

/// Class of scheduler service that may claim a reclaim request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReclaimWorkKind {
    /// Stage 1/2 cache maintenance at latency-sensitive priority.
    CacheMaintenance,
    /// Stage 3 dirty-byte flush at throughput priority.
    DirtyFlush,
    /// Stage 4 existing commit/sync boundary request at critical priority.
    CommitBoundary,
}

/// Read-only pressure state for one governor category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovernorPressureState {
    /// Budget category whose pressure was sampled.
    pub category: BudgetCategory,
    /// Current backpressure signal for the category.
    pub signal: BackpressureSignal,
    /// Current category usage in bytes.
    pub used: u64,
    /// Category cap in bytes.
    pub cap: u64,
    /// Soft watermark in bytes.
    pub soft_watermark: u64,
    /// Number of completed pressure claims while this pressure instance persists.
    pub pressure_ticks: u64,
    /// Current reclaim ladder stage, if any.
    pub stage: Option<ReclaimStage>,
    /// Whether a background reclaim request is already claimed for this pressure.
    pub reclaim_inflight: bool,
}

/// Bounded reclaim work claimed from a governor pressure snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReclaimRequest {
    /// Budget category requiring reclaim or sync-boundary attention.
    pub category: BudgetCategory,
    /// Ladder stage to execute.
    pub stage: ReclaimStage,
    /// Pressure signal observed when the work was claimed.
    pub signal: BackpressureSignal,
    /// Usage observed when the work was claimed.
    pub used: u64,
    /// Category cap observed when the work was claimed.
    pub cap: u64,
    /// Soft watermark observed when the work was claimed.
    pub soft_watermark: u64,
    /// Target bytes to reclaim or flush for this bounded tick.
    pub target_bytes: u64,
    /// Pressure ticks already claimed for this pressure instance.
    pub pressure_ticks: u64,
    /// Generation token invalidated when pressure clears or a newer claim supersedes it.
    pub generation: u64,
}

impl ReclaimRequest {
    /// Return the service class that may execute this request, if any.
    #[must_use]
    pub const fn work_kind(self) -> Option<ReclaimWorkKind> {
        match self.stage {
            ReclaimStage::EvictColdCache | ReclaimStage::ShrinkMetadataCaches => {
                Some(ReclaimWorkKind::CacheMaintenance)
            }
            ReclaimStage::FlushDirtyData => Some(ReclaimWorkKind::DirtyFlush),
            ReclaimStage::ForceCommitGroupSync => Some(ReclaimWorkKind::CommitBoundary),
            ReclaimStage::AdmissionBackpressure => None,
        }
    }
}

/// Result of one bounded reclaim worker invocation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReclaimOutcome {
    /// Items processed by the worker.
    pub items_processed: u64,
    /// Bytes scanned, flushed, or otherwise consumed by the worker.
    pub bytes_processed: u64,
    /// Bytes that should be released from the request category in the governor.
    pub bytes_released: u64,
}

impl ReclaimOutcome {
    /// Zero-work outcome.
    pub const ZERO: Self = Self {
        items_processed: 0,
        bytes_processed: 0,
        bytes_released: 0,
    };
}

// ── Budget error ─────────────────────────────────────────────────────────

/// Errors returned by governor admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BudgetError {
    /// Requested allocation exceeds the category hard limit.
    OverBudget {
        category: BudgetCategory,
        requested: u64,
        available: u64,
    },
    /// Requested allocation exceeds the global hard limit.
    GlobalOverBudget { requested: u64, available: u64 },
    /// Category is not recognised (defensive).
    UnknownCategory,
}

impl fmt::Display for BudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverBudget {
                category,
                requested,
                available,
            } => write!(
                f,
                "category {category} over budget: requested {requested}, available {available}"
            ),
            Self::GlobalOverBudget {
                requested,
                available,
            } => write!(
                f,
                "global over budget: requested {requested}, available {available}"
            ),
            Self::UnknownCategory => write!(f, "unknown budget category"),
        }
    }
}

// ── Admission ticket ─────────────────────────────────────────────────────

/// A granted admission ticket.
///
/// Obtained from [`Governor::admit`].  The ticket must be held for the
/// lifetime of the allocation; dropping it does **not** automatically
/// release the budget (use [`Governor::release`] for that).
#[derive(Debug)]
pub struct AdmissionTicket {
    pub category: BudgetCategory,
    pub size: u64,
    pub partition: Option<BudgetPartitionKey>,
}

// ── Auto-tune evidence ─────────────────────────────────────────────────────

/// Maximum per-category soft-watermark shift applied by auto-tune.
pub const AUTO_TUNE_MAX_FRACTION_SHIFT: f64 = 0.20;

/// Maximum evidence age accepted by [`Governor::apply_auto_tune`].
pub const AUTO_TUNE_MAX_FRESHNESS_MS: u64 = 30_000;

/// Owner of a bounded auto-tune evidence record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernorAutoTuneOwner {
    /// Direct utilization and backpressure observed by the governor.
    GovernorUtilization,
    /// Admission/rejection pressure from cache-core callers.
    CacheAdmission,
    /// Cache hit/miss pressure.
    HitMissPressure,
    /// Dirty-byte pressure from local writeback accounting.
    DirtyBytePressure,
    /// Cache churn pressure from eviction/reinsertion behavior.
    CacheChurn,
    /// Explicit workload signal record with an external policy owner.
    WorkloadSignalRecord,
}

/// Unit attached to a bounded auto-tune evidence record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernorAutoTuneUnit {
    /// Pressure score in the inclusive range 0..=100.
    Ratio0To100,
    /// Byte count for the named category.
    Bytes,
    /// Event rate for churn, hit/miss, or admission pressure.
    EventsPerSecond,
}

/// Effect of an auto-tune input on a protected safety limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernorAutoTuneSafetyEffect {
    /// The input preserves the existing safety limit.
    PreservesExistingLimit,
    /// The input would weaken the existing safety limit.
    WeakensLimit,
}

/// Safety-effect declaration required for every auto-tune input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovernorAutoTuneSafety {
    pub durability: GovernorAutoTuneSafetyEffect,
    pub dirty_bytes: GovernorAutoTuneSafetyEffect,
    pub cluster_queues: GovernorAutoTuneSafetyEffect,
}

impl GovernorAutoTuneSafety {
    /// Declare that the input does not weaken protected safety limits.
    #[must_use]
    pub const fn preserves_existing_limits() -> Self {
        Self {
            durability: GovernorAutoTuneSafetyEffect::PreservesExistingLimit,
            dirty_bytes: GovernorAutoTuneSafetyEffect::PreservesExistingLimit,
            cluster_queues: GovernorAutoTuneSafetyEffect::PreservesExistingLimit,
        }
    }

    fn preserves_all_limits(self) -> bool {
        self.durability == GovernorAutoTuneSafetyEffect::PreservesExistingLimit
            && self.dirty_bytes == GovernorAutoTuneSafetyEffect::PreservesExistingLimit
            && self.cluster_queues == GovernorAutoTuneSafetyEffect::PreservesExistingLimit
    }
}

/// Explicit bounded pressure evidence for auto-tuning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernorAutoTuneEvidence {
    /// Category to tune. Missing categories are rejected as ambiguous input.
    pub category: Option<BudgetCategory>,
    /// Owner/source of the evidence. Missing owners are rejected.
    pub owner: Option<GovernorAutoTuneOwner>,
    /// Unit for the evidence record. Missing units are rejected.
    pub unit: Option<GovernorAutoTuneUnit>,
    /// Age of the evidence in milliseconds. Missing or stale freshness is rejected.
    pub freshness_ms: Option<u64>,
    /// Bounded pressure score, interpreted as 0 = clear and 100 = maximum pressure.
    pub pressure_score: u16,
    /// Declared effect on protected safety limits.
    pub safety: Option<GovernorAutoTuneSafety>,
}

impl GovernorAutoTuneEvidence {
    /// Create a fully-specified local pressure record.
    #[must_use]
    pub const fn pressure(
        category: BudgetCategory,
        owner: GovernorAutoTuneOwner,
        unit: GovernorAutoTuneUnit,
        freshness_ms: u64,
        pressure_score: u16,
    ) -> Self {
        Self {
            category: Some(category),
            owner: Some(owner),
            unit: Some(unit),
            freshness_ms: Some(freshness_ms),
            pressure_score,
            safety: Some(GovernorAutoTuneSafety::preserves_existing_limits()),
        }
    }
}

/// Result of an auto-tune application attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernorAutoTuneDecision {
    /// Auto-tune is disabled, so inputs were ignored and no state changed.
    Disabled,
    /// Auto-tune updated the listed number of distinct category watermarks.
    Applied { updated_categories: usize },
}

/// Error returned when an auto-tune input is unsafe or ambiguous.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernorAutoTuneError {
    /// Required explicit evidence metadata was missing.
    AmbiguousInput(&'static str),
    /// Evidence was older than the supported freshness window.
    StaleInput {
        freshness_ms: u64,
        max_freshness_ms: u64,
    },
    /// Pressure score was outside 0..=100.
    PressureOutOfRange { pressure_score: u16 },
    /// The input would weaken a protected safety limit.
    UnsafeInput {
        category: BudgetCategory,
        reason: &'static str,
    },
}

impl fmt::Display for GovernorAutoTuneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousInput(reason) => write!(f, "ambiguous auto-tune input: {reason}"),
            Self::StaleInput {
                freshness_ms,
                max_freshness_ms,
            } => write!(
                f,
                "stale auto-tune input: age {freshness_ms}ms exceeds {max_freshness_ms}ms"
            ),
            Self::PressureOutOfRange { pressure_score } => {
                write!(
                    f,
                    "auto-tune pressure score {pressure_score} out of range 0..=100"
                )
            }
            Self::UnsafeInput { category, reason } => {
                write!(f, "unsafe auto-tune input for {category}: {reason}")
            }
        }
    }
}

// ── Per-category configuration ───────────────────────────────────────────

/// Per-category budget configuration.
#[derive(Clone, Debug)]
struct CategoryConfig {
    /// Total bytes allocated to this category.
    cap: u64,
    /// Soft watermark: above this, backpressure is [`SoftPressure`].
    soft_watermark: u64,
    /// Default soft-watermark fraction from the static design spec.
    base_soft_fraction: f64,
    /// Current soft-watermark fraction after optional auto-tune.
    soft_fraction: f64,
    /// Hard limit: equal to cap for simplicity in the first slice.
    hard_limit: u64,
}

impl CategoryConfig {
    fn new(cap: u64, soft_fraction: f64) -> Self {
        Self {
            cap,
            soft_watermark: Self::soft_watermark(cap, soft_fraction),
            base_soft_fraction: soft_fraction,
            soft_fraction,
            hard_limit: cap,
        }
    }

    fn soft_watermark(cap: u64, soft_fraction: f64) -> u64 {
        (cap as f64 * soft_fraction).round().min(cap as f64) as u64
    }

    fn set_soft_fraction(&mut self, soft_fraction: f64) {
        self.soft_fraction = soft_fraction;
        self.soft_watermark = Self::soft_watermark(self.cap, soft_fraction).min(self.cap);
    }
}

// ── Per-category runtime state ───────────────────────────────────────────

#[derive(Clone, Debug)]
struct CategoryState {
    /// Bytes currently allocated against this category.
    used: u64,
    /// Whether the soft-pressure signal is currently raised.
    soft_pressure: bool,
    /// Whether the hard-pressure signal is currently raised.
    hard_pressure: bool,
    /// Number of bounded reclaim claims made while this pressure instance persists.
    pressure_ticks: u64,
    /// Currently claimed reclaim work, if any.
    reclaim_inflight: Option<InflightReclaim>,
    /// Generation token bumped when pressure starts, clears, or a claim is made.
    reclaim_generation: u64,
}

impl CategoryState {
    fn new() -> Self {
        Self {
            used: 0,
            soft_pressure: false,
            hard_pressure: false,
            pressure_ticks: 0,
            reclaim_inflight: None,
            reclaim_generation: 0,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct PartitionState {
    categories: [PartitionCategoryState; 6],
}

impl PartitionState {
    fn is_empty(&self) -> bool {
        self.categories.iter().all(|category| category.used == 0)
    }
}

#[derive(Clone, Debug, Default)]
struct PartitionCategoryState {
    used: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PartitionLimit {
    limit: u64,
    protected_limit: u64,
    shared_unused_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InflightReclaim {
    stage: ReclaimStage,
    generation: u64,
}

// ── Governor configuration ───────────────────────────────────────────────

/// Configuration for the unified resource governor.
#[derive(Clone, Debug)]
pub struct GovernorConfig {
    /// Total daemon memory budget in bytes.
    /// Default: 60% of host physical RAM, clamped to [256 MiB, 256 GiB].
    pub total_budget_bytes: u64,

    /// Per-category fractions (must sum to 1.0).
    pub data_cache_fraction: f64, // default 0.40
    pub meta_cache_fraction: f64,     // default 0.20
    pub dirty_bytes_fraction: f64,    // default 0.25
    pub inode_state_fraction: f64,    // default 0.08
    pub cluster_queues_fraction: f64, // default 0.05
    pub misc_fraction: f64,           // default 0.02

    /// Whether to auto-tune soft watermarks from explicit bounded evidence.
    pub auto_tune: bool, // default false
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            total_budget_bytes: 256 * 1024 * 1024, // 256 MiB floor
            data_cache_fraction: 0.40,
            meta_cache_fraction: 0.20,
            dirty_bytes_fraction: 0.25,
            inode_state_fraction: 0.08,
            cluster_queues_fraction: 0.05,
            misc_fraction: 0.02,
            auto_tune: false,
        }
    }
}

impl GovernorConfig {
    /// Validate that fractions sum to 1.0 within a small epsilon and each
    /// fraction is non-negative.
    pub fn validate(&self) -> Result<(), String> {
        let sum = self.data_cache_fraction
            + self.meta_cache_fraction
            + self.dirty_bytes_fraction
            + self.inode_state_fraction
            + self.cluster_queues_fraction
            + self.misc_fraction;
        if (sum - 1.0).abs() > 1e-9 {
            return Err(format!("category fractions sum to {sum}, must be 1.0"));
        }
        for (name, f) in [
            ("data_cache", self.data_cache_fraction),
            ("meta_cache", self.meta_cache_fraction),
            ("dirty_bytes", self.dirty_bytes_fraction),
            ("inode_state", self.inode_state_fraction),
            ("cluster_queues", self.cluster_queues_fraction),
            ("misc", self.misc_fraction),
        ] {
            if !(0.0..=1.0).contains(&f) {
                return Err(format!("{name} fraction {f} out of range [0, 1]"));
            }
        }
        Ok(())
    }

    fn category_fractions(&self) -> [f64; 6] {
        [
            self.data_cache_fraction,
            self.meta_cache_fraction,
            self.dirty_bytes_fraction,
            self.inode_state_fraction,
            self.cluster_queues_fraction,
            self.misc_fraction,
        ]
    }
}

// ── Governor ─────────────────────────────────────────────────────────────

/// Unified resource governor: single budget authority for all daemon-side
/// memory.
///
/// ## Thread safety
///
/// `Governor` is `Send + Sync` and uses interior mutability via
/// `Arc<Mutex<…>>`.  It is safe to share across concurrent FUSE worker
/// threads and background job tasks.
#[derive(Clone)]
pub struct Governor {
    inner: Arc<Mutex<GovernorInner>>,
}

struct GovernorInner {
    config: GovernorConfig,
    partition_config: GovernorPartitionConfig,
    categories: [CategoryState; 6],
    category_configs: [CategoryConfig; 6],
    partitions: HashMap<BudgetPartitionKey, PartitionState>,
    /// Total bytes currently allocated across all categories.
    total_used: u64,
}

impl Governor {
    /// Categories in index order matching [`BudgetCategory`] discriminant
    /// order (DataCache=0 … Misc=5).
    const CATEGORIES: [BudgetCategory; 6] = [
        BudgetCategory::DataCache,
        BudgetCategory::MetaCache,
        BudgetCategory::DirtyBytes,
        BudgetCategory::InodeState,
        BudgetCategory::ClusterQueues,
        BudgetCategory::Misc,
    ];

    const DEFAULT_SOFT_FRACTIONS: [f64; 6] = [0.70, 0.70, 0.50, 0.70, 0.70, 0.70];

    /// Create a new governor from a validated configuration.
    ///
    /// Returns an error if the configuration fails validation.
    pub fn new(config: GovernorConfig) -> Result<Self, String> {
        Self::new_with_partition_config(config, GovernorPartitionConfig::default())
    }

    /// Create a new governor with an explicit partition policy.
    ///
    /// Category/global caps remain the hard outer boundary. Partitioned
    /// admission must also pass the configured per-partition limit.
    pub fn new_with_partition_config(
        config: GovernorConfig,
        partition_config: GovernorPartitionConfig,
    ) -> Result<Self, String> {
        config.validate()?;
        partition_config.validate()?;
        let total = config.total_budget_bytes;
        let caps = Self::caps_from_fractions(total, config.category_fractions());
        // Soft watermarks per the design spec.
        let mut category_configs: [CategoryConfig; 6] =
            std::array::from_fn(|_| CategoryConfig::new(0, 0.0));
        for (i, &cap) in caps.iter().enumerate() {
            category_configs[i] = CategoryConfig::new(cap, Self::DEFAULT_SOFT_FRACTIONS[i]);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(GovernorInner {
                config,
                partition_config,
                categories: std::array::from_fn(|_| CategoryState::new()),
                category_configs,
                partitions: HashMap::new(),
                total_used: 0,
            })),
        })
    }

    /// Request admission of `size` bytes into `category`.
    ///
    /// Returns an [`AdmissionTicket`] if the allocation is within budget,
    /// or a [`BudgetError`] if the category or global hard limit would be
    /// exceeded.
    pub fn admit(
        &self,
        category: BudgetCategory,
        size: u64,
    ) -> Result<AdmissionTicket, BudgetError> {
        self.admit_partitioned(category, size, None)
    }

    /// Request admission of `size` bytes into `category` for one partition.
    ///
    /// The request must pass the global hard limit, the category hard limit,
    /// and the configured partition limit before any usage is charged.
    pub fn admit_for_partition(
        &self,
        partition: BudgetPartitionKey,
        category: BudgetCategory,
        size: u64,
    ) -> Result<AdmissionTicket, BudgetError> {
        self.admit_partitioned(category, size, Some(partition))
    }

    fn admit_partitioned(
        &self,
        category: BudgetCategory,
        size: u64,
        partition: Option<BudgetPartitionKey>,
    ) -> Result<AdmissionTicket, BudgetError> {
        let mut inner = self.inner.lock().unwrap();

        let idx = Self::category_index(category);
        let hard_limit = inner.category_configs[idx].hard_limit;
        let used = inner.categories[idx].used;
        let total_budget = inner.config.total_budget_bytes;

        // Check global hard limit first.
        let new_total = inner.total_used.saturating_add(size);
        if new_total > total_budget {
            return Err(BudgetError::GlobalOverBudget {
                requested: size,
                available: total_budget.saturating_sub(inner.total_used),
            });
        }

        // Check category hard limit.
        let new_used = used.saturating_add(size);
        if new_used > hard_limit {
            return Err(BudgetError::OverBudget {
                category,
                requested: size,
                available: hard_limit.saturating_sub(used),
            });
        }

        if let Some(partition) = partition {
            let partition_used = Self::partition_used_locked(&inner, partition, idx);
            let partition_limit = Self::partition_limit_locked(&inner, partition, idx).limit;
            let new_partition_used = partition_used.saturating_add(size);
            if new_partition_used > partition_limit {
                return Err(BudgetError::OverBudget {
                    category,
                    requested: size,
                    available: partition_limit.saturating_sub(partition_used),
                });
            }
        }

        // Update state.
        inner.total_used = new_total;
        inner.categories[idx].used = new_used;
        if let Some(partition) = partition.filter(|_| size > 0) {
            let state = inner.partitions.entry(partition).or_default();
            state.categories[idx].used = state.categories[idx].used.saturating_add(size);
        }

        Self::refresh_pressure_locked(&mut inner, idx);

        Ok(AdmissionTicket {
            category,
            size,
            partition,
        })
    }

    /// Release `size` bytes back to `category` and the global budget.
    ///
    /// If the category was previously over its soft watermark and the
    /// release brings it back under, the soft-pressure signal is cleared.
    pub fn release(&self, category: BudgetCategory, size: u64) {
        self.release_partitioned(category, size, None);
    }

    /// Release `size` bytes from a partition and the enclosing category/global
    /// budget.
    ///
    /// Over-release is scoped to the named partition, so it cannot reclaim
    /// bytes charged to another partition or to unpartitioned category usage.
    pub fn release_for_partition(
        &self,
        partition: BudgetPartitionKey,
        category: BudgetCategory,
        size: u64,
    ) {
        self.release_partitioned(category, size, Some(partition));
    }

    fn release_partitioned(
        &self,
        category: BudgetCategory,
        size: u64,
        partition: Option<BudgetPartitionKey>,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let idx = Self::category_index(category);

        let released = if let Some(partition) = partition {
            let (released, remove_partition) =
                if let Some(state) = inner.partitions.get_mut(&partition) {
                    let released = state.categories[idx].used.min(size);
                    state.categories[idx].used -= released;
                    (released, state.is_empty())
                } else {
                    (0, false)
                };
            if remove_partition {
                inner.partitions.remove(&partition);
            }
            released
        } else {
            inner.categories[idx].used.min(size)
        };

        inner.categories[idx].used = inner.categories[idx].used.saturating_sub(released);
        inner.total_used = inner.total_used.saturating_sub(released);

        Self::refresh_pressure_locked(&mut inner, idx);
    }

    /// Move an already-admitted allocation between categories without changing
    /// total daemon memory usage.
    ///
    /// This keeps page-cache clean/dirty transitions atomic from the governor's
    /// perspective: a clean page can become dirty by transferring bytes from
    /// `DataCache` to `DirtyBytes`, and a successful writeback can transfer
    /// them back to clean cache.
    pub fn transfer(
        &self,
        from: BudgetCategory,
        to: BudgetCategory,
        size: u64,
    ) -> Result<(), BudgetError> {
        if from == to || size == 0 {
            return Ok(());
        }

        let mut inner = self.inner.lock().unwrap();
        let from_idx = Self::category_index(from);
        let to_idx = Self::category_index(to);
        let used_from = inner.categories[from_idx].used;
        if used_from < size {
            return Err(BudgetError::OverBudget {
                category: from,
                requested: size,
                available: used_from,
            });
        }
        let total_after_release = inner.total_used.saturating_sub(size);
        let total_after_transfer = total_after_release.saturating_add(size);
        let total_budget = inner.config.total_budget_bytes;

        if total_after_transfer > total_budget {
            return Err(BudgetError::GlobalOverBudget {
                requested: size,
                available: total_budget.saturating_sub(total_after_release),
            });
        }

        let hard_limit = inner.category_configs[to_idx].hard_limit;
        let used_to = inner.categories[to_idx].used;
        let new_used_to = used_to.saturating_add(size);
        if new_used_to > hard_limit {
            return Err(BudgetError::OverBudget {
                category: to,
                requested: size,
                available: hard_limit.saturating_sub(used_to),
            });
        }

        inner.categories[from_idx].used = used_from - size;
        inner.categories[to_idx].used = new_used_to;
        inner.total_used = total_after_transfer;
        Self::refresh_pressure_locked(&mut inner, from_idx);
        Self::refresh_pressure_locked(&mut inner, to_idx);
        Ok(())
    }

    /// Move an already-admitted allocation between categories while preserving
    /// the partition identity attached to the allocation.
    pub fn transfer_for_partition(
        &self,
        partition: BudgetPartitionKey,
        from: BudgetCategory,
        to: BudgetCategory,
        size: u64,
    ) -> Result<(), BudgetError> {
        if from == to || size == 0 {
            return Ok(());
        }

        let mut inner = self.inner.lock().unwrap();
        let from_idx = Self::category_index(from);
        let to_idx = Self::category_index(to);
        let partition_from_used = Self::partition_used_locked(&inner, partition, from_idx);
        if partition_from_used < size {
            return Err(BudgetError::OverBudget {
                category: from,
                requested: size,
                available: partition_from_used,
            });
        }

        let used_from = inner.categories[from_idx].used;
        if used_from < size {
            return Err(BudgetError::OverBudget {
                category: from,
                requested: size,
                available: used_from,
            });
        }

        let hard_limit = inner.category_configs[to_idx].hard_limit;
        let used_to = inner.categories[to_idx].used;
        let new_used_to = used_to.saturating_add(size);
        if new_used_to > hard_limit {
            return Err(BudgetError::OverBudget {
                category: to,
                requested: size,
                available: hard_limit.saturating_sub(used_to),
            });
        }

        let partition_to_used = Self::partition_used_locked(&inner, partition, to_idx);
        let partition_limit = Self::partition_limit_locked(&inner, partition, to_idx).limit;
        let new_partition_to_used = partition_to_used.saturating_add(size);
        if new_partition_to_used > partition_limit {
            return Err(BudgetError::OverBudget {
                category: to,
                requested: size,
                available: partition_limit.saturating_sub(partition_to_used),
            });
        }

        inner.categories[from_idx].used = used_from - size;
        inner.categories[to_idx].used = new_used_to;

        let remove_partition = {
            let state = inner.partitions.entry(partition).or_default();
            state.categories[from_idx].used -= size;
            state.categories[to_idx].used = state.categories[to_idx].used.saturating_add(size);
            state.is_empty()
        };
        if remove_partition {
            inner.partitions.remove(&partition);
        }

        Self::refresh_pressure_locked(&mut inner, from_idx);
        Self::refresh_pressure_locked(&mut inner, to_idx);
        Ok(())
    }

    /// Apply explicit bounded local pressure evidence to soft watermarks.
    ///
    /// Auto-tune is disabled by default.  When enabled, this first governor-only
    /// slice adjusts soft watermarks only; hard category caps and the global hard
    /// budget remain unchanged.
    pub fn apply_auto_tune(
        &self,
        evidence: &[GovernorAutoTuneEvidence],
    ) -> Result<GovernorAutoTuneDecision, GovernorAutoTuneError> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.config.auto_tune {
            return Ok(GovernorAutoTuneDecision::Disabled);
        }

        for record in evidence {
            Self::validate_auto_tune_record(record)?;
        }

        let mut updated = [false; 6];
        for record in evidence {
            let category = record
                .category
                .expect("auto-tune evidence category was validated");
            let idx = Self::category_index(category);
            let base = inner.category_configs[idx].base_soft_fraction;
            let tuned = Self::tuned_soft_fraction(category, base, record.pressure_score);
            inner.category_configs[idx].set_soft_fraction(tuned);
            Self::refresh_pressure_locked(&mut inner, idx);
            updated[idx] = true;
        }

        Ok(GovernorAutoTuneDecision::Applied {
            updated_categories: updated.iter().filter(|&&was_updated| was_updated).count(),
        })
    }

    /// Return the backpressure signal for a specific category.
    #[must_use]
    pub fn backpressure(&self, category: BudgetCategory) -> BackpressureSignal {
        let inner = self.inner.lock().unwrap();
        let idx = Self::category_index(category);
        let state = &inner.categories[idx];
        if state.hard_pressure {
            BackpressureSignal::HardPressure
        } else if state.soft_pressure {
            BackpressureSignal::SoftPressure
        } else {
            BackpressureSignal::None
        }
    }

    /// Return the global backpressure signal (worst-case across all
    /// categories).
    #[must_use]
    pub fn global_backpressure(&self) -> BackpressureSignal {
        let inner = self.inner.lock().unwrap();
        let mut worst = BackpressureSignal::None;
        for state in &inner.categories {
            if state.hard_pressure {
                return BackpressureSignal::HardPressure;
            }
            if state.soft_pressure {
                worst = BackpressureSignal::SoftPressure;
            }
        }
        worst
    }

    /// Return current bytes used in a category.
    #[must_use]
    pub fn category_used(&self, category: BudgetCategory) -> u64 {
        let inner = self.inner.lock().unwrap();
        let idx = Self::category_index(category);
        inner.categories[idx].used
    }

    /// Return the category cap (hard limit) in bytes.
    #[must_use]
    pub fn category_cap(&self, category: BudgetCategory) -> u64 {
        let inner = self.inner.lock().unwrap();
        let idx = Self::category_index(category);
        inner.category_configs[idx].cap
    }

    /// Return the current soft watermark for a category.
    #[must_use]
    pub fn category_soft_watermark(&self, category: BudgetCategory) -> u64 {
        let inner = self.inner.lock().unwrap();
        let idx = Self::category_index(category);
        inner.category_configs[idx].soft_watermark
    }

    /// Return the active partition accounting policy.
    #[must_use]
    pub fn partition_config(&self) -> GovernorPartitionConfig {
        self.inner.lock().unwrap().partition_config
    }

    /// Return the active unused-budget sharing policy.
    #[must_use]
    pub fn partition_policy(&self) -> BudgetPartitionPolicy {
        self.inner.lock().unwrap().partition_config.policy
    }

    /// Return bytes currently charged to a partition in one category.
    #[must_use]
    pub fn partition_used(&self, partition: BudgetPartitionKey, category: BudgetCategory) -> u64 {
        let inner = self.inner.lock().unwrap();
        let idx = Self::category_index(category);
        Self::partition_used_locked(&inner, partition, idx)
    }

    /// Return the protected per-partition cap before unused-budget sharing.
    #[must_use]
    pub fn partition_protected_limit(&self, category: BudgetCategory) -> u64 {
        let inner = self.inner.lock().unwrap();
        let idx = Self::category_index(category);
        Self::partition_protected_limit_locked(&inner, idx)
    }

    /// Return the effective current limit for a partition in one category.
    #[must_use]
    pub fn partition_limit(&self, partition: BudgetPartitionKey, category: BudgetCategory) -> u64 {
        let inner = self.inner.lock().unwrap();
        let idx = Self::category_index(category);
        Self::partition_limit_locked(&inner, partition, idx).limit
    }

    /// Return the backpressure signal for a partition in one category.
    #[must_use]
    pub fn partition_backpressure(
        &self,
        partition: BudgetPartitionKey,
        category: BudgetCategory,
    ) -> BackpressureSignal {
        self.partition_pressure_state(partition, category).signal
    }

    /// Return a read-only pressure snapshot for a partition in one category.
    #[must_use]
    pub fn partition_pressure_state(
        &self,
        partition: BudgetPartitionKey,
        category: BudgetCategory,
    ) -> GovernorPartitionPressureState {
        let inner = self.inner.lock().unwrap();
        let idx = Self::category_index(category);
        Self::partition_pressure_state_for_locked(&inner, partition, idx, category)
    }

    /// Return pressure snapshots for every active partition in one category.
    ///
    /// The returned list is sorted by partition key so operator-visible
    /// reports and tests do not depend on hash-map iteration order.
    #[must_use]
    pub fn partition_pressure_states(
        &self,
        category: BudgetCategory,
    ) -> Vec<GovernorPartitionPressureState> {
        let inner = self.inner.lock().unwrap();
        let idx = Self::category_index(category);
        let mut states = inner
            .partitions
            .iter()
            .filter(|(_, state)| state.categories[idx].used > 0)
            .map(|(&partition, _)| {
                Self::partition_pressure_state_for_locked(&inner, partition, idx, category)
            })
            .collect::<Vec<_>>();
        states.sort_by(|left, right| left.partition.as_bytes().cmp(right.partition.as_bytes()));
        states
    }

    /// Return a read-only usage and pressure snapshot for one partition.
    #[must_use]
    pub fn partition_usage_state(
        &self,
        partition: BudgetPartitionKey,
    ) -> GovernorPartitionUsageState {
        let inner = self.inner.lock().unwrap();
        Self::partition_usage_state_for_locked(&inner, partition)
    }

    /// Return usage snapshots for every active partition.
    ///
    /// The returned list is sorted by partition key so operator-visible
    /// reports and tests do not depend on hash-map iteration order.
    #[must_use]
    pub fn partition_usage_states(&self) -> Vec<GovernorPartitionUsageState> {
        let inner = self.inner.lock().unwrap();
        let mut partitions = inner
            .partitions
            .iter()
            .filter(|(_, state)| !state.is_empty())
            .map(|(&partition, _)| partition)
            .collect::<Vec<_>>();
        partitions.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        partitions
            .into_iter()
            .map(|partition| Self::partition_usage_state_for_locked(&inner, partition))
            .collect()
    }

    /// Return whether auto-tune is enabled.
    #[must_use]
    pub fn auto_tune_enabled(&self) -> bool {
        self.inner.lock().unwrap().config.auto_tune
    }

    /// Return total bytes used across all categories.
    #[must_use]
    pub fn total_used(&self) -> u64 {
        self.inner.lock().unwrap().total_used
    }

    /// Return the total budget cap.
    #[must_use]
    pub fn total_budget_bytes(&self) -> u64 {
        self.inner.lock().unwrap().config.total_budget_bytes
    }

    /// Return a read-only pressure snapshot for every budget category.
    ///
    /// This records which category and reclaim stage need attention without
    /// executing reclaim while the governor lock is held.
    #[must_use]
    pub fn pressure_state(&self) -> Vec<GovernorPressureState> {
        let inner = self.inner.lock().unwrap();
        Self::CATEGORIES
            .iter()
            .enumerate()
            .map(|(idx, &category)| Self::pressure_state_for_locked(&inner, idx, category))
            .collect()
    }

    /// Return pending admission/backpressure signals for stage 5.
    ///
    /// Stage 5 remains an admission signal for FUSE/transport follow-up
    /// consumers and is not returned by [`claim_reclaim_work`](Self::claim_reclaim_work).
    #[must_use]
    pub fn admission_backpressure_requests(&self) -> Vec<GovernorPressureState> {
        self.pressure_state()
            .into_iter()
            .filter(|state| state.stage == Some(ReclaimStage::AdmissionBackpressure))
            .collect()
    }

    /// Return `true` when the requested scheduler service can claim work.
    #[must_use]
    pub fn has_reclaim_work(&self, kind: ReclaimWorkKind) -> bool {
        let inner = self.inner.lock().unwrap();
        Self::CATEGORIES.iter().enumerate().any(|(idx, &category)| {
            let state = Self::pressure_state_for_locked(&inner, idx, category);
            state.stage.and_then(Self::work_kind_for_stage) == Some(kind) && !state.reclaim_inflight
        })
    }

    /// Claim one bounded reclaim request for the requested scheduler service.
    ///
    /// The returned request is a small data record.  Callers execute reclaim
    /// outside the governor lock, then call
    /// [`finish_reclaim_work`](Self::finish_reclaim_work).
    pub fn claim_reclaim_work(&self, kind: ReclaimWorkKind) -> Option<ReclaimRequest> {
        let mut inner = self.inner.lock().unwrap();
        for (idx, &category) in Self::CATEGORIES.iter().enumerate() {
            let signal = Self::backpressure_signal_locked(&inner.categories[idx]);
            let Some(stage) =
                Self::stage_for_pressure(category, signal, inner.categories[idx].pressure_ticks)
            else {
                continue;
            };
            if Self::work_kind_for_stage(stage) != Some(kind) {
                continue;
            }
            if inner.categories[idx].reclaim_inflight.is_some() {
                continue;
            }

            inner.categories[idx].pressure_ticks =
                inner.categories[idx].pressure_ticks.saturating_add(1);
            inner.categories[idx].reclaim_generation =
                inner.categories[idx].reclaim_generation.saturating_add(1);
            let generation = inner.categories[idx].reclaim_generation;
            inner.categories[idx].reclaim_inflight = Some(InflightReclaim { stage, generation });

            let cfg = &inner.category_configs[idx];
            let used = inner.categories[idx].used;
            return Some(ReclaimRequest {
                category,
                stage,
                signal,
                used,
                cap: cfg.cap,
                soft_watermark: cfg.soft_watermark,
                target_bytes: Self::target_bytes_for_stage(stage, used, cfg.soft_watermark),
                pressure_ticks: inner.categories[idx].pressure_ticks,
                generation,
            });
        }
        None
    }

    /// Return `true` if a previously claimed request still matches live pressure.
    #[must_use]
    pub fn reclaim_request_active(&self, request: ReclaimRequest) -> bool {
        let inner = self.inner.lock().unwrap();
        let idx = Self::category_index(request.category);
        let state = &inner.categories[idx];
        matches!(
            state.reclaim_inflight,
            Some(inflight)
                if inflight.stage == request.stage
                    && inflight.generation == request.generation
                    && Self::backpressure_signal_locked(state) != BackpressureSignal::None
        )
    }

    /// Mark a claimed reclaim request as finished.
    pub fn finish_reclaim_work(&self, request: ReclaimRequest) {
        let mut inner = self.inner.lock().unwrap();
        let idx = Self::category_index(request.category);
        if matches!(
            inner.categories[idx].reclaim_inflight,
            Some(inflight)
                if inflight.stage == request.stage
                    && inflight.generation == request.generation
        ) {
            inner.categories[idx].reclaim_inflight = None;
        }
        Self::refresh_pressure_locked(&mut inner, idx);
    }

    // ── internal helpers ──────────────────────────────────────────────

    fn category_index(category: BudgetCategory) -> usize {
        match category {
            BudgetCategory::DataCache => 0,
            BudgetCategory::MetaCache => 1,
            BudgetCategory::DirtyBytes => 2,
            BudgetCategory::InodeState => 3,
            BudgetCategory::ClusterQueues => 4,
            BudgetCategory::Misc => 5,
        }
    }

    fn partition_used_locked(
        inner: &GovernorInner,
        partition: BudgetPartitionKey,
        idx: usize,
    ) -> u64 {
        inner
            .partitions
            .get(&partition)
            .map_or(0, |state| state.categories[idx].used)
    }

    fn partition_protected_limit_locked(inner: &GovernorInner, idx: usize) -> u64 {
        let hard_limit = inner.category_configs[idx].hard_limit;
        (hard_limit as f64 * inner.partition_config.category_fraction)
            .round()
            .min(hard_limit as f64) as u64
    }

    fn partition_limit_locked(
        inner: &GovernorInner,
        partition: BudgetPartitionKey,
        idx: usize,
    ) -> PartitionLimit {
        let protected_limit = Self::partition_protected_limit_locked(inner, idx);
        match inner.partition_config.policy {
            BudgetPartitionPolicy::Strict => PartitionLimit {
                limit: protected_limit,
                protected_limit,
                shared_unused_bytes: 0,
            },
            BudgetPartitionPolicy::ShareUnused => {
                let used_by_partition = Self::partition_used_locked(inner, partition, idx);
                let used_by_others = inner.categories[idx].used.saturating_sub(used_by_partition);
                let limit = inner.category_configs[idx]
                    .hard_limit
                    .saturating_sub(used_by_others);
                PartitionLimit {
                    limit,
                    protected_limit,
                    shared_unused_bytes: limit.saturating_sub(protected_limit),
                }
            }
        }
    }

    fn partition_soft_watermark_locked(inner: &GovernorInner, limit: u64) -> u64 {
        (limit as f64 * inner.partition_config.soft_fraction)
            .round()
            .min(limit as f64) as u64
    }

    fn partition_pressure_state_for_locked(
        inner: &GovernorInner,
        partition: BudgetPartitionKey,
        idx: usize,
        category: BudgetCategory,
    ) -> GovernorPartitionPressureState {
        let used = Self::partition_used_locked(inner, partition, idx);
        let limit = Self::partition_limit_locked(inner, partition, idx);
        let soft_watermark = Self::partition_soft_watermark_locked(inner, limit.limit);
        let (soft_pressure, hard_pressure) =
            Self::pressure_flags(used, limit.limit, soft_watermark);
        let signal = if hard_pressure {
            BackpressureSignal::HardPressure
        } else if soft_pressure {
            BackpressureSignal::SoftPressure
        } else {
            BackpressureSignal::None
        };
        GovernorPartitionPressureState {
            partition,
            category,
            signal,
            used,
            limit: limit.limit,
            protected_limit: limit.protected_limit,
            soft_watermark,
            shared_unused_bytes: limit.shared_unused_bytes,
        }
    }

    fn partition_usage_state_for_locked(
        inner: &GovernorInner,
        partition: BudgetPartitionKey,
    ) -> GovernorPartitionUsageState {
        let categories = std::array::from_fn(|idx| {
            let category = Self::CATEGORIES[idx];
            Self::partition_pressure_state_for_locked(inner, partition, idx, category)
        });
        let total_used = categories.iter().map(|state| state.used).sum();
        GovernorPartitionUsageState {
            partition,
            total_used,
            categories,
        }
    }

    fn caps_from_fractions(total: u64, fractions: [f64; 6]) -> [u64; 6] {
        std::array::from_fn(|idx| (total as f64 * fractions[idx]) as u64)
    }

    fn validate_auto_tune_record(
        record: &GovernorAutoTuneEvidence,
    ) -> Result<BudgetCategory, GovernorAutoTuneError> {
        let category = Self::require_auto_tune_field(record.category, "missing category")?;
        let owner = Self::require_auto_tune_field(record.owner, "missing owner")?;
        let _unit = Self::require_auto_tune_field(record.unit, "missing unit")?;
        let freshness_ms = Self::require_auto_tune_field(record.freshness_ms, "missing freshness")?;
        if freshness_ms > AUTO_TUNE_MAX_FRESHNESS_MS {
            return Err(GovernorAutoTuneError::StaleInput {
                freshness_ms,
                max_freshness_ms: AUTO_TUNE_MAX_FRESHNESS_MS,
            });
        }
        if record.pressure_score > 100 {
            return Err(GovernorAutoTuneError::PressureOutOfRange {
                pressure_score: record.pressure_score,
            });
        }
        let safety = Self::require_auto_tune_field(record.safety, "missing safety effect")?;
        if !safety.preserves_all_limits() {
            return Err(GovernorAutoTuneError::UnsafeInput {
                category,
                reason: "input would weaken a protected safety limit",
            });
        }
        if owner == GovernorAutoTuneOwner::DirtyBytePressure
            && category != BudgetCategory::DirtyBytes
        {
            return Err(GovernorAutoTuneError::AmbiguousInput(
                "dirty-byte pressure must target dirty_bytes",
            ));
        }

        Ok(category)
    }

    fn require_auto_tune_field<T>(
        field: Option<T>,
        reason: &'static str,
    ) -> Result<T, GovernorAutoTuneError> {
        field.ok_or(GovernorAutoTuneError::AmbiguousInput(reason))
    }

    fn tuned_soft_fraction(
        category: BudgetCategory,
        base_soft_fraction: f64,
        pressure_score: u16,
    ) -> f64 {
        let pressure = f64::from(pressure_score) / 100.0;
        let shift = base_soft_fraction * AUTO_TUNE_MAX_FRACTION_SHIFT * pressure;
        let min = base_soft_fraction * (1.0 - AUTO_TUNE_MAX_FRACTION_SHIFT);
        let max = base_soft_fraction * (1.0 + AUTO_TUNE_MAX_FRACTION_SHIFT);
        let tuned = match category {
            BudgetCategory::DataCache | BudgetCategory::MetaCache | BudgetCategory::InodeState => {
                base_soft_fraction + shift
            }
            BudgetCategory::DirtyBytes | BudgetCategory::ClusterQueues | BudgetCategory::Misc => {
                base_soft_fraction - shift
            }
        };
        tuned.clamp(min, max)
    }

    fn backpressure_signal_locked(state: &CategoryState) -> BackpressureSignal {
        if state.hard_pressure {
            BackpressureSignal::HardPressure
        } else if state.soft_pressure {
            BackpressureSignal::SoftPressure
        } else {
            BackpressureSignal::None
        }
    }

    fn pressure_state_for_locked(
        inner: &GovernorInner,
        idx: usize,
        category: BudgetCategory,
    ) -> GovernorPressureState {
        let state = &inner.categories[idx];
        let cfg = &inner.category_configs[idx];
        let signal = Self::backpressure_signal_locked(state);
        GovernorPressureState {
            category,
            signal,
            used: state.used,
            cap: cfg.cap,
            soft_watermark: cfg.soft_watermark,
            pressure_ticks: state.pressure_ticks,
            stage: Self::stage_for_pressure(category, signal, state.pressure_ticks),
            reclaim_inflight: state.reclaim_inflight.is_some(),
        }
    }

    fn stage_for_pressure(
        category: BudgetCategory,
        signal: BackpressureSignal,
        pressure_ticks: u64,
    ) -> Option<ReclaimStage> {
        match signal {
            BackpressureSignal::None => None,
            BackpressureSignal::HardPressure => {
                if category == BudgetCategory::DirtyBytes {
                    Some(ReclaimStage::ForceCommitGroupSync)
                } else {
                    Some(ReclaimStage::AdmissionBackpressure)
                }
            }
            BackpressureSignal::SoftPressure => match category {
                BudgetCategory::DataCache | BudgetCategory::InodeState => {
                    Some(ReclaimStage::EvictColdCache)
                }
                BudgetCategory::MetaCache => {
                    if pressure_ticks == 0 {
                        Some(ReclaimStage::EvictColdCache)
                    } else {
                        Some(ReclaimStage::ShrinkMetadataCaches)
                    }
                }
                BudgetCategory::DirtyBytes => Some(ReclaimStage::FlushDirtyData),
                BudgetCategory::ClusterQueues | BudgetCategory::Misc => {
                    Some(ReclaimStage::AdmissionBackpressure)
                }
            },
        }
    }

    const fn work_kind_for_stage(stage: ReclaimStage) -> Option<ReclaimWorkKind> {
        match stage {
            ReclaimStage::EvictColdCache | ReclaimStage::ShrinkMetadataCaches => {
                Some(ReclaimWorkKind::CacheMaintenance)
            }
            ReclaimStage::FlushDirtyData => Some(ReclaimWorkKind::DirtyFlush),
            ReclaimStage::ForceCommitGroupSync => Some(ReclaimWorkKind::CommitBoundary),
            ReclaimStage::AdmissionBackpressure => None,
        }
    }

    fn target_bytes_for_stage(stage: ReclaimStage, used: u64, soft_watermark: u64) -> u64 {
        match stage {
            ReclaimStage::ForceCommitGroupSync => used,
            ReclaimStage::AdmissionBackpressure => 0,
            ReclaimStage::EvictColdCache
            | ReclaimStage::ShrinkMetadataCaches
            | ReclaimStage::FlushDirtyData => used.saturating_sub(soft_watermark),
        }
    }

    fn pressure_flags(used: u64, cap: u64, soft_watermark: u64) -> (bool, bool) {
        if used == 0 || cap == 0 {
            return (false, false);
        }
        let hard_pressure = (used as u128) * 100 >= (cap as u128) * 95;
        let soft_pressure = used >= soft_watermark;
        (soft_pressure, hard_pressure)
    }

    fn refresh_pressure_locked(inner: &mut GovernorInner, idx: usize) {
        let was_under_pressure =
            inner.categories[idx].soft_pressure || inner.categories[idx].hard_pressure;
        let used = inner.categories[idx].used;
        let cap = inner.category_configs[idx].cap;
        let soft_watermark = inner.category_configs[idx].soft_watermark;
        let (soft_pressure, hard_pressure) = Self::pressure_flags(used, cap, soft_watermark);
        inner.categories[idx].hard_pressure = hard_pressure;
        inner.categories[idx].soft_pressure = soft_pressure;
        let is_under_pressure = soft_pressure || hard_pressure;
        if !is_under_pressure || !was_under_pressure {
            inner.categories[idx].pressure_ticks = 0;
            inner.categories[idx].reclaim_inflight = None;
            inner.categories[idx].reclaim_generation =
                inner.categories[idx].reclaim_generation.saturating_add(1);
        }
    }
}

// ── Scheduler reclaim services ────────────────────────────────────────────

/// Worker used by [`GovernorCacheReclaimService`] to execute stage 1/2 work.
pub trait CacheReclaimWorker: Send {
    /// Execute one bounded cache-maintenance reclaim tick.
    fn reclaim_cache(
        &mut self,
        request: ReclaimRequest,
        budget: ServiceBudget,
    ) -> Result<ReclaimOutcome, ServiceError>;
}

/// Worker used by [`GovernorDirtyFlushService`] to execute stage 3 work.
pub trait DirtyReclaimWorker: Send {
    /// Execute one bounded dirty-byte flush tick.
    fn flush_dirty(
        &mut self,
        request: ReclaimRequest,
        budget: ServiceBudget,
    ) -> Result<ReclaimOutcome, ServiceError>;
}

/// Worker used by [`GovernorCommitBoundaryService`] to execute stage 4 work.
pub trait CommitBoundaryWorker: Send {
    /// Record or invoke the existing commit/sync boundary for hard dirty pressure.
    fn force_commit_boundary(
        &mut self,
        request: ReclaimRequest,
        budget: ServiceBudget,
    ) -> Result<ReclaimOutcome, ServiceError>;
}

/// Wrap an existing [`IncrementalJob`] as a dirty-byte reclaim worker.
///
/// This is the generic bridge for cleaner/writeback jobs that already honor
/// the shared `WorkBudget` contract.  It does not introduce a second dirty
/// data authority; the wrapped job remains responsible for the actual flush or
/// cleaner action.
pub struct GovernorIncrementalReclaimWorker<J: IncrementalJob> {
    job: J,
    last_items_processed: u64,
    last_bytes_processed: u64,
    complete: bool,
}

impl<J: IncrementalJob> GovernorIncrementalReclaimWorker<J> {
    /// Create a dirty reclaim worker from an existing incremental job.
    #[must_use]
    pub fn new(job: J) -> Self {
        Self {
            job,
            last_items_processed: 0,
            last_bytes_processed: 0,
            complete: false,
        }
    }

    /// Borrow the wrapped job.
    #[must_use]
    pub fn inner(&self) -> &J {
        &self.job
    }

    /// Borrow the wrapped job mutably.
    #[must_use]
    pub fn inner_mut(&mut self) -> &mut J {
        &mut self.job
    }
}

impl<J: IncrementalJob> DirtyReclaimWorker for GovernorIncrementalReclaimWorker<J> {
    fn flush_dirty(
        &mut self,
        _request: ReclaimRequest,
        budget: ServiceBudget,
    ) -> Result<ReclaimOutcome, ServiceError> {
        if self.complete {
            return Ok(ReclaimOutcome::ZERO);
        }
        let step =
            self.job
                .step(budget.to_work_budget())
                .map_err(|error| ServiceError::JobError {
                    service: GovernorDirtyFlushService::<Self>::NAME,
                    error,
                })?;
        let items = step
            .checkpoint
            .progress
            .items_processed
            .saturating_sub(self.last_items_processed);
        let bytes = step
            .checkpoint
            .progress
            .bytes_processed
            .saturating_sub(self.last_bytes_processed);
        self.last_items_processed = step.checkpoint.progress.items_processed;
        self.last_bytes_processed = step.checkpoint.progress.bytes_processed;
        self.complete = step.is_complete;
        Ok(ReclaimOutcome {
            items_processed: items,
            bytes_processed: bytes,
            bytes_released: bytes,
        })
    }
}

/// Scheduler service for stage 1/2 cache maintenance.
pub struct GovernorCacheReclaimService<W: CacheReclaimWorker> {
    governor: Governor,
    worker: W,
}

impl<W: CacheReclaimWorker> GovernorCacheReclaimService<W> {
    /// Stable service name used in scheduler reports.
    pub const NAME: &'static str = "governor-cache-reclaim";
    /// Hard per-tick budget for latency-sensitive cache reclaim.
    pub const TICK_BUDGET: ServiceBudget = ServiceBudget {
        max_items: 64,
        max_bytes: 4 * 1024 * 1024,
        max_ms: 10,
    };

    /// Create a cache reclaim service.
    #[must_use]
    pub fn new(governor: Governor, worker: W) -> Self {
        Self { governor, worker }
    }
}

impl<W: CacheReclaimWorker> BackgroundService for GovernorCacheReclaimService<W> {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn priority(&self) -> ServicePriority {
        ServicePriority::LatencySensitive
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        let Some(request) = self
            .governor
            .claim_reclaim_work(ReclaimWorkKind::CacheMaintenance)
        else {
            return Ok(TickReport::default());
        };
        if !self.governor.reclaim_request_active(request) {
            self.governor.finish_reclaim_work(request);
            return Ok(TickReport {
                skipped: 1,
                has_more: self.has_work(),
                ..TickReport::default()
            });
        }

        let bounded = bounded_service_budget(*budget, Self::TICK_BUDGET);
        match self.worker.reclaim_cache(request, bounded) {
            Ok(outcome) => {
                finish_reclaim_tick(Self::NAME, &self.governor, request, bounded, outcome)
            }
            Err(error) => {
                self.governor.finish_reclaim_work(request);
                Err(error)
            }
        }
    }

    fn has_work(&self) -> bool {
        self.governor
            .has_reclaim_work(ReclaimWorkKind::CacheMaintenance)
    }
}

/// Scheduler service for stage 3 dirty-byte flush work.
pub struct GovernorDirtyFlushService<W: DirtyReclaimWorker> {
    governor: Governor,
    worker: W,
}

impl<W: DirtyReclaimWorker> GovernorDirtyFlushService<W> {
    /// Stable service name used in scheduler reports.
    pub const NAME: &'static str = "governor-dirty-flush";
    /// Hard per-tick budget for throughput dirty-byte flush work.
    pub const TICK_BUDGET: ServiceBudget = ServiceBudget {
        max_items: 128,
        max_bytes: 16 * 1024 * 1024,
        max_ms: 50,
    };

    /// Create a dirty flush service.
    #[must_use]
    pub fn new(governor: Governor, worker: W) -> Self {
        Self { governor, worker }
    }
}

impl<W: DirtyReclaimWorker> BackgroundService for GovernorDirtyFlushService<W> {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn priority(&self) -> ServicePriority {
        ServicePriority::Throughput
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        let Some(request) = self
            .governor
            .claim_reclaim_work(ReclaimWorkKind::DirtyFlush)
        else {
            return Ok(TickReport::default());
        };
        if !self.governor.reclaim_request_active(request) {
            self.governor.finish_reclaim_work(request);
            return Ok(TickReport {
                skipped: 1,
                has_more: self.has_work(),
                ..TickReport::default()
            });
        }

        let bounded = bounded_service_budget(*budget, Self::TICK_BUDGET);
        match self.worker.flush_dirty(request, bounded) {
            Ok(outcome) => {
                finish_reclaim_tick(Self::NAME, &self.governor, request, bounded, outcome)
            }
            Err(error) => {
                self.governor.finish_reclaim_work(request);
                Err(error)
            }
        }
    }

    fn has_work(&self) -> bool {
        self.governor.has_reclaim_work(ReclaimWorkKind::DirtyFlush)
    }
}

/// Scheduler service for stage 4 hard dirty pressure.
pub struct GovernorCommitBoundaryService<W: CommitBoundaryWorker> {
    governor: Governor,
    worker: W,
}

impl<W: CommitBoundaryWorker> GovernorCommitBoundaryService<W> {
    /// Stable service name used in scheduler reports.
    pub const NAME: &'static str = "governor-commit-boundary";
    /// Hard per-tick budget for one commit/sync boundary request.
    pub const TICK_BUDGET: ServiceBudget = ServiceBudget {
        max_items: 1,
        max_bytes: 0,
        max_ms: 10,
    };

    /// Create a commit-boundary service.
    #[must_use]
    pub fn new(governor: Governor, worker: W) -> Self {
        Self { governor, worker }
    }
}

impl<W: CommitBoundaryWorker> BackgroundService for GovernorCommitBoundaryService<W> {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn priority(&self) -> ServicePriority {
        ServicePriority::Critical
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        let Some(request) = self
            .governor
            .claim_reclaim_work(ReclaimWorkKind::CommitBoundary)
        else {
            return Ok(TickReport::default());
        };
        if !self.governor.reclaim_request_active(request) {
            self.governor.finish_reclaim_work(request);
            return Ok(TickReport {
                skipped: 1,
                has_more: self.has_work(),
                ..TickReport::default()
            });
        }

        let bounded = bounded_service_budget(*budget, Self::TICK_BUDGET);
        match self.worker.force_commit_boundary(request, bounded) {
            Ok(outcome) => {
                finish_reclaim_tick(Self::NAME, &self.governor, request, bounded, outcome)
            }
            Err(error) => {
                self.governor.finish_reclaim_work(request);
                Err(error)
            }
        }
    }

    fn has_work(&self) -> bool {
        self.governor
            .has_reclaim_work(ReclaimWorkKind::CommitBoundary)
    }
}

fn bounded_service_budget(outer: ServiceBudget, cap: ServiceBudget) -> ServiceBudget {
    ServiceBudget {
        max_items: bounded_limit(outer.max_items, cap.max_items),
        max_bytes: bounded_limit(outer.max_bytes, cap.max_bytes),
        max_ms: bounded_limit(outer.max_ms, cap.max_ms),
    }
}

fn bounded_limit(outer: u64, cap: u64) -> u64 {
    match (outer, cap) {
        (0, value) | (value, 0) => value,
        (outer, cap) => outer.min(cap),
    }
}

fn finish_reclaim_tick(
    service: &'static str,
    governor: &Governor,
    request: ReclaimRequest,
    budget: ServiceBudget,
    outcome: ReclaimOutcome,
) -> Result<TickReport, ServiceError> {
    if budget.max_items > 0 && outcome.items_processed > budget.max_items {
        governor.finish_reclaim_work(request);
        return Err(ServiceError::BudgetExceeded {
            service,
            limit: budget.max_items,
            actual: outcome.items_processed,
        });
    }
    if budget.max_bytes > 0 && outcome.bytes_processed > budget.max_bytes {
        governor.finish_reclaim_work(request);
        return Err(ServiceError::BudgetExceeded {
            service,
            limit: budget.max_bytes,
            actual: outcome.bytes_processed,
        });
    }

    let released = outcome.bytes_released.min(request.used);
    if released > 0 {
        governor.release(request.category, released);
    }
    governor.finish_reclaim_work(request);
    Ok(TickReport {
        processed: outcome.items_processed,
        skipped: 0,
        errors: 0,
        items_consumed: outcome.items_processed,
        bytes_consumed: outcome.bytes_processed,
        has_more: request
            .work_kind()
            .map(|kind| governor.has_reclaim_work(kind))
            .unwrap_or(false),
    })
}

impl fmt::Debug for Governor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock().unwrap();
        f.debug_struct("Governor")
            .field("total_budget_bytes", &inner.config.total_budget_bytes)
            .field("total_used", &inner.total_used)
            .field(
                "categories",
                &Governor::CATEGORIES
                    .iter()
                    .enumerate()
                    .map(|(i, cat)| {
                        let state = &inner.categories[i];
                        let cfg = &inner.category_configs[i];
                        (cat.to_string(), state.used, cfg.cap)
                    })
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tidefs_background_scheduler::{BackgroundScheduler, ServiceBudget, ServicePriority};
    use tidefs_types_cache_lattice_core::{
        DirtyStateClass, MemoryDomain, PosixWritebackState, RebuildCostClass,
    };
    use tidefs_types_incremental_job_core::{
        Checkpoint, CursorState, JobError, JobId, JobKind, JobProgress, StepResult, WorkBudget,
    };

    fn test_config() -> GovernorConfig {
        GovernorConfig::default()
    }

    fn single_category_config(category: BudgetCategory, auto_tune: bool) -> GovernorConfig {
        let fraction = |candidate| {
            if category == candidate {
                1.0
            } else {
                0.0
            }
        };
        GovernorConfig {
            total_budget_bytes: 1000,
            data_cache_fraction: fraction(BudgetCategory::DataCache),
            meta_cache_fraction: fraction(BudgetCategory::MetaCache),
            dirty_bytes_fraction: fraction(BudgetCategory::DirtyBytes),
            inode_state_fraction: fraction(BudgetCategory::InodeState),
            cluster_queues_fraction: fraction(BudgetCategory::ClusterQueues),
            misc_fraction: fraction(BudgetCategory::Misc),
            auto_tune,
        }
    }

    fn single_category_budget_config(
        category: BudgetCategory,
        total_budget_bytes: u64,
    ) -> GovernorConfig {
        let fraction = |candidate| {
            if candidate == category {
                1.0
            } else {
                0.0
            }
        };
        GovernorConfig {
            total_budget_bytes,
            data_cache_fraction: fraction(BudgetCategory::DataCache),
            meta_cache_fraction: fraction(BudgetCategory::MetaCache),
            dirty_bytes_fraction: fraction(BudgetCategory::DirtyBytes),
            inode_state_fraction: fraction(BudgetCategory::InodeState),
            cluster_queues_fraction: fraction(BudgetCategory::ClusterQueues),
            misc_fraction: fraction(BudgetCategory::Misc),
            auto_tune: false,
        }
    }

    fn data_pressure(score: u16) -> GovernorAutoTuneEvidence {
        GovernorAutoTuneEvidence::pressure(
            BudgetCategory::DataCache,
            GovernorAutoTuneOwner::HitMissPressure,
            GovernorAutoTuneUnit::Ratio0To100,
            1_000,
            score,
        )
    }

    fn dirty_pressure(score: u16) -> GovernorAutoTuneEvidence {
        GovernorAutoTuneEvidence::pressure(
            BudgetCategory::DirtyBytes,
            GovernorAutoTuneOwner::DirtyBytePressure,
            GovernorAutoTuneUnit::Ratio0To100,
            1_000,
            score,
        )
    }

    fn pressure_state_for(g: &Governor, category: BudgetCategory) -> GovernorPressureState {
        g.pressure_state()
            .into_iter()
            .find(|state| state.category == category)
            .unwrap()
    }

    fn partition_key(byte: u8) -> BudgetPartitionKey {
        BudgetPartitionKey::from_bytes([byte; 16])
    }

    #[derive(Clone, Default)]
    struct ReclaimCallLog {
        calls: Arc<Mutex<Vec<(ReclaimRequest, ServiceBudget)>>>,
    }

    impl ReclaimCallLog {
        fn record(&self, request: ReclaimRequest, budget: ServiceBudget) {
            self.calls.lock().unwrap().push((request, budget));
        }

        fn calls(&self) -> Vec<(ReclaimRequest, ServiceBudget)> {
            self.calls.lock().unwrap().clone()
        }
    }

    struct ReleasingCacheWorker {
        log: ReclaimCallLog,
        release_bytes: u64,
    }

    impl CacheReclaimWorker for ReleasingCacheWorker {
        fn reclaim_cache(
            &mut self,
            request: ReclaimRequest,
            budget: ServiceBudget,
        ) -> Result<ReclaimOutcome, ServiceError> {
            self.log.record(request, budget);
            Ok(ReclaimOutcome {
                items_processed: 1,
                bytes_processed: self.release_bytes,
                bytes_released: self.release_bytes,
            })
        }
    }

    struct FailingCacheWorker;

    impl CacheReclaimWorker for FailingCacheWorker {
        fn reclaim_cache(
            &mut self,
            _request: ReclaimRequest,
            _budget: ServiceBudget,
        ) -> Result<ReclaimOutcome, ServiceError> {
            Err(ServiceError::Internal {
                service: "test-cache-reclaim",
                message: "boom",
            })
        }
    }

    struct ReleasingDirtyWorker {
        log: ReclaimCallLog,
        release_bytes: u64,
    }

    impl DirtyReclaimWorker for ReleasingDirtyWorker {
        fn flush_dirty(
            &mut self,
            request: ReclaimRequest,
            budget: ServiceBudget,
        ) -> Result<ReclaimOutcome, ServiceError> {
            self.log.record(request, budget);
            Ok(ReclaimOutcome {
                items_processed: 1,
                bytes_processed: self.release_bytes,
                bytes_released: self.release_bytes,
            })
        }
    }

    struct RecordingCommitWorker {
        log: ReclaimCallLog,
    }

    impl CommitBoundaryWorker for RecordingCommitWorker {
        fn force_commit_boundary(
            &mut self,
            request: ReclaimRequest,
            budget: ServiceBudget,
        ) -> Result<ReclaimOutcome, ServiceError> {
            self.log.record(request, budget);
            Ok(ReclaimOutcome {
                items_processed: 1,
                bytes_processed: 0,
                bytes_released: 0,
            })
        }
    }

    struct FakeIncrementalDirtyJob {
        steps: Vec<(u64, u64, bool)>,
        calls: Arc<Mutex<Vec<WorkBudget>>>,
        total_items: u64,
        total_bytes: u64,
    }

    impl FakeIncrementalDirtyJob {
        fn new(steps: Vec<(u64, u64, bool)>) -> (Self, Arc<Mutex<Vec<WorkBudget>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    steps,
                    calls: calls.clone(),
                    total_items: 0,
                    total_bytes: 0,
                },
                calls,
            )
        }

        fn checkpoint(&self, is_complete: bool) -> StepResult {
            let checkpoint = Checkpoint {
                job_id: JobId::NONE,
                job_kind: JobKind::DataCleaner,
                epoch: 1,
                cursor_state: CursorState::empty(),
                progress: JobProgress {
                    items_processed: self.total_items,
                    items_total_estimate: 0,
                    bytes_processed: self.total_bytes,
                    bytes_total_estimate: 0,
                    elapsed_ms: 0,
                },
            };
            if is_complete {
                StepResult::complete(checkpoint)
            } else {
                StepResult::in_progress(checkpoint)
            }
        }
    }

    impl IncrementalJob for FakeIncrementalDirtyJob {
        fn resume(_state: Option<Checkpoint>) -> Result<Self, JobError>
        where
            Self: Sized,
        {
            Ok(Self {
                steps: Vec::new(),
                calls: Arc::new(Mutex::new(Vec::new())),
                total_items: 0,
                total_bytes: 0,
            })
        }

        fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
            self.calls.lock().unwrap().push(budget);
            let (items, bytes, is_complete) = self.steps.remove(0);
            self.total_items = self.total_items.saturating_add(items);
            self.total_bytes = self.total_bytes.saturating_add(bytes);
            Ok(self.checkpoint(is_complete))
        }

        fn persist_checkpoint(&self, _checkpoint: &Checkpoint) -> Result<(), JobError> {
            Ok(())
        }

        fn complete(self) -> Result<(), JobError> {
            Ok(())
        }

        fn job_id(&self) -> JobId {
            JobId::NONE
        }

        fn job_kind(&self) -> JobKind {
            JobKind::DataCleaner
        }
    }

    #[test]
    fn new_governor_starts_empty() {
        let g = Governor::new(test_config()).unwrap();
        assert_eq!(g.total_used(), 0);
        for cat in Governor::CATEGORIES {
            assert_eq!(g.category_used(cat), 0);
            assert_eq!(g.backpressure(cat), BackpressureSignal::None);
        }
        assert_eq!(g.global_backpressure(), BackpressureSignal::None);
    }

    #[test]
    fn admit_within_budget_succeeds() {
        let g = Governor::new(test_config()).unwrap();
        let cap = g.category_cap(BudgetCategory::DataCache);
        let result = g.admit(BudgetCategory::DataCache, cap / 2);
        assert!(result.is_ok());
        let ticket = result.unwrap();
        assert_eq!(ticket.category, BudgetCategory::DataCache);
        assert_eq!(ticket.size, cap / 2);
        assert_eq!(g.category_used(BudgetCategory::DataCache), cap / 2);
    }

    #[test]
    fn admit_past_category_hard_limit_fails() {
        let g = Governor::new(test_config()).unwrap();
        let cap = g.category_cap(BudgetCategory::DataCache);
        let result = g.admit(BudgetCategory::DataCache, cap + 1);
        assert!(matches!(result, Err(BudgetError::OverBudget { .. })));
        assert_eq!(g.category_used(BudgetCategory::DataCache), 0);
    }

    #[test]
    fn admit_past_global_hard_limit_fails() {
        // Two categories with separate caps — fill one, then try the other
        // when global total is exhausted.
        let config = GovernorConfig {
            total_budget_bytes: 1000,
            data_cache_fraction: 0.5, // cap 500
            meta_cache_fraction: 0.5, // cap 500
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
            auto_tune: false,
        };
        let g = Governor::new(config).unwrap();
        // Fill data_cache to 500.
        assert!(g.admit(BudgetCategory::DataCache, 500).is_ok());
        // Fill meta_cache to 500 — global exhausted.
        assert!(g.admit(BudgetCategory::MetaCache, 500).is_ok());
        // Now any further admission fails globally.
        let result = g.admit(BudgetCategory::DataCache, 1);
        assert!(matches!(result, Err(BudgetError::GlobalOverBudget { .. })));
    }

    #[test]
    fn release_returns_budget() {
        let g = Governor::new(test_config()).unwrap();
        let alloc = 1024;
        g.admit(BudgetCategory::DataCache, alloc).unwrap();
        assert_eq!(g.category_used(BudgetCategory::DataCache), alloc);
        g.release(BudgetCategory::DataCache, alloc);
        assert_eq!(g.category_used(BudgetCategory::DataCache), 0);
        assert_eq!(g.total_used(), 0);
    }

    #[test]
    fn release_partial_returns_partial_budget() {
        let g = Governor::new(test_config()).unwrap();
        g.admit(BudgetCategory::MetaCache, 1024).unwrap();
        g.admit(BudgetCategory::MetaCache, 512).unwrap();
        assert_eq!(g.category_used(BudgetCategory::MetaCache), 1536);
        g.release(BudgetCategory::MetaCache, 512);
        assert_eq!(g.category_used(BudgetCategory::MetaCache), 1024);
    }

    #[test]
    fn backpressure_soft_threshold() {
        let config = GovernorConfig {
            total_budget_bytes: 1000,
            data_cache_fraction: 1.0,
            meta_cache_fraction: 0.0,
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
            auto_tune: false,
        };
        let g = Governor::new(config).unwrap();
        // Cap is 1000, soft watermark at 70% = 700.
        // Allocate 699: should still be None.
        g.admit(BudgetCategory::DataCache, 699).unwrap();
        assert_eq!(
            g.backpressure(BudgetCategory::DataCache),
            BackpressureSignal::None
        );
        // Allocate 2 more → 701: should trigger soft pressure.
        g.admit(BudgetCategory::DataCache, 2).unwrap();
        assert_eq!(
            g.backpressure(BudgetCategory::DataCache),
            BackpressureSignal::SoftPressure
        );
    }

    #[test]
    fn backpressure_hard_threshold() {
        let config = GovernorConfig {
            total_budget_bytes: 1000,
            data_cache_fraction: 1.0,
            meta_cache_fraction: 0.0,
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
            auto_tune: false,
        };
        let g = Governor::new(config).unwrap();
        // Cap is 1000, hard at 95% = 950.
        g.admit(BudgetCategory::DataCache, 949).unwrap();
        assert_eq!(
            g.backpressure(BudgetCategory::DataCache),
            BackpressureSignal::SoftPressure
        );
        g.admit(BudgetCategory::DataCache, 1).unwrap();
        assert_eq!(
            g.backpressure(BudgetCategory::DataCache),
            BackpressureSignal::HardPressure
        );
    }

    #[test]
    fn release_clears_soft_pressure() {
        let config = GovernorConfig {
            total_budget_bytes: 1000,
            data_cache_fraction: 1.0,
            meta_cache_fraction: 0.0,
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
            auto_tune: false,
        };
        let g = Governor::new(config).unwrap();
        // Allocate to 750 (above 700 soft).
        g.admit(BudgetCategory::DataCache, 750).unwrap();
        assert_eq!(
            g.backpressure(BudgetCategory::DataCache),
            BackpressureSignal::SoftPressure
        );
        // Release 100 → 650 (below 700 soft).
        g.release(BudgetCategory::DataCache, 100);
        assert_eq!(
            g.backpressure(BudgetCategory::DataCache),
            BackpressureSignal::None
        );
    }

    #[test]
    fn global_backpressure_reports_worst_category() {
        let config = GovernorConfig {
            total_budget_bytes: 2000,
            data_cache_fraction: 0.5, // 1000
            meta_cache_fraction: 0.5, // 1000
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
            auto_tune: false,
        };
        let g = Governor::new(config).unwrap();
        // DataCache at 750 = soft.
        g.admit(BudgetCategory::DataCache, 750).unwrap();
        assert_eq!(g.global_backpressure(), BackpressureSignal::SoftPressure);
        // MetaCache still None, but global reflects worst.
        g.admit(BudgetCategory::MetaCache, 960).unwrap(); // 960/1000 = 96% = hard
        assert_eq!(g.global_backpressure(), BackpressureSignal::HardPressure);
        // Release MetaCache below soft.
        g.release(BudgetCategory::MetaCache, 500);
        assert_eq!(g.global_backpressure(), BackpressureSignal::SoftPressure);
        // Release DataCache below soft.
        g.release(BudgetCategory::DataCache, 100);
        assert_eq!(g.global_backpressure(), BackpressureSignal::None);
    }

    #[test]
    fn concurrent_admit_release_across_categories() {
        let g = Governor::new(test_config()).unwrap();
        // Allocate into two categories.
        g.admit(BudgetCategory::DataCache, 1024).unwrap();
        g.admit(BudgetCategory::MetaCache, 512).unwrap();
        assert_eq!(g.category_used(BudgetCategory::DataCache), 1024);
        assert_eq!(g.category_used(BudgetCategory::MetaCache), 512);
        assert_eq!(g.total_used(), 1536);
        // Release from one.
        g.release(BudgetCategory::DataCache, 1024);
        assert_eq!(g.category_used(BudgetCategory::DataCache), 0);
        assert_eq!(g.total_used(), 512);
    }

    #[test]
    fn saturating_release_does_not_underflow() {
        let g = Governor::new(test_config()).unwrap();
        // Release more than allocated — saturates at zero.
        g.release(BudgetCategory::DataCache, 1024);
        assert_eq!(g.category_used(BudgetCategory::DataCache), 0);
        assert_eq!(g.total_used(), 0);
    }

    #[test]
    fn over_release_does_not_reclaim_other_category_usage() {
        let g = Governor::new(test_config()).unwrap();
        g.admit(BudgetCategory::DataCache, 1024).unwrap();
        g.admit(BudgetCategory::MetaCache, 512).unwrap();

        g.release(BudgetCategory::DataCache, 4096);

        assert_eq!(g.category_used(BudgetCategory::DataCache), 0);
        assert_eq!(g.category_used(BudgetCategory::MetaCache), 512);
        assert_eq!(g.total_used(), 512);
    }

    #[test]
    fn zero_cap_category_zero_usage_has_no_pressure() {
        let config = GovernorConfig {
            total_budget_bytes: 1000,
            data_cache_fraction: 1.0,
            meta_cache_fraction: 0.0,
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
            auto_tune: false,
        };
        let g = Governor::new(config).unwrap();

        g.release(BudgetCategory::MetaCache, 0);
        assert_eq!(
            g.backpressure(BudgetCategory::MetaCache),
            BackpressureSignal::None
        );

        g.admit(BudgetCategory::MetaCache, 0).unwrap();
        assert_eq!(g.category_used(BudgetCategory::MetaCache), 0);
        assert_eq!(
            g.backpressure(BudgetCategory::MetaCache),
            BackpressureSignal::None
        );
    }

    #[test]
    fn config_validation_rejects_bad_fractions() {
        let cfg = GovernorConfig {
            data_cache_fraction: 1.0,
            ..GovernorConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validation_accepts_default() {
        assert!(GovernorConfig::default().validate().is_ok());
    }

    #[test]
    fn auto_tune_defaults_disabled_and_ignores_evidence() {
        let g = Governor::new(single_category_config(BudgetCategory::DataCache, false)).unwrap();
        let before = g.category_soft_watermark(BudgetCategory::DataCache);

        let decision = g.apply_auto_tune(&[data_pressure(100)]).unwrap();

        assert_eq!(decision, GovernorAutoTuneDecision::Disabled);
        assert!(!g.auto_tune_enabled());
        assert_eq!(g.category_soft_watermark(BudgetCategory::DataCache), before);
    }

    #[test]
    fn auto_tune_uses_deterministic_hit_miss_pressure() {
        let g = Governor::new(single_category_config(BudgetCategory::DataCache, true)).unwrap();

        let decision = g.apply_auto_tune(&[data_pressure(50)]).unwrap();

        assert_eq!(
            decision,
            GovernorAutoTuneDecision::Applied {
                updated_categories: 1
            }
        );
        assert_eq!(g.category_cap(BudgetCategory::DataCache), 1000);
        assert_eq!(g.category_soft_watermark(BudgetCategory::DataCache), 770);
    }

    #[test]
    fn auto_tune_enforces_watermark_bounds_without_raising_hard_caps() {
        let data = Governor::new(single_category_config(BudgetCategory::DataCache, true)).unwrap();
        data.apply_auto_tune(&[data_pressure(100)]).unwrap();

        assert_eq!(data.category_soft_watermark(BudgetCategory::DataCache), 840);
        assert_eq!(data.category_cap(BudgetCategory::DataCache), 1000);
        assert!(matches!(
            data.admit(BudgetCategory::DataCache, 1001),
            Err(BudgetError::GlobalOverBudget { .. })
        ));

        let dirty =
            Governor::new(single_category_config(BudgetCategory::DirtyBytes, true)).unwrap();
        dirty.apply_auto_tune(&[dirty_pressure(100)]).unwrap();

        assert_eq!(
            dirty.category_soft_watermark(BudgetCategory::DirtyBytes),
            400
        );
        assert_eq!(dirty.category_cap(BudgetCategory::DirtyBytes), 1000);
    }

    #[test]
    fn auto_tune_clears_pressure_back_to_static_watermark() {
        let g = Governor::new(single_category_config(BudgetCategory::DataCache, true)).unwrap();
        g.admit(BudgetCategory::DataCache, 750).unwrap();
        assert_eq!(
            g.backpressure(BudgetCategory::DataCache),
            BackpressureSignal::SoftPressure
        );

        g.apply_auto_tune(&[data_pressure(100)]).unwrap();
        assert_eq!(g.category_soft_watermark(BudgetCategory::DataCache), 840);
        assert_eq!(
            g.backpressure(BudgetCategory::DataCache),
            BackpressureSignal::None
        );

        g.apply_auto_tune(&[data_pressure(0)]).unwrap();
        assert_eq!(g.category_soft_watermark(BudgetCategory::DataCache), 700);
        assert_eq!(
            g.backpressure(BudgetCategory::DataCache),
            BackpressureSignal::SoftPressure
        );
    }

    #[test]
    fn auto_tune_refuses_missing_required_evidence_fields() {
        let g = Governor::new(single_category_config(BudgetCategory::DataCache, true)).unwrap();

        let missing_fields = [
            ({
                let mut record = data_pressure(10);
                record.category = None;
                (record, "missing category")
            }),
            ({
                let mut record = data_pressure(10);
                record.owner = None;
                (record, "missing owner")
            }),
            ({
                let mut record = data_pressure(10);
                record.unit = None;
                (record, "missing unit")
            }),
            ({
                let mut record = data_pressure(10);
                record.freshness_ms = None;
                (record, "missing freshness")
            }),
            ({
                let mut record = data_pressure(10);
                record.safety = None;
                (record, "missing safety effect")
            }),
        ];

        for (record, reason) in missing_fields {
            assert_eq!(
                g.apply_auto_tune(&[record]),
                Err(GovernorAutoTuneError::AmbiguousInput(reason))
            );
        }

        assert_eq!(g.category_soft_watermark(BudgetCategory::DataCache), 700);
    }

    #[test]
    fn auto_tune_refuses_stale_out_of_range_or_mistargeted_input() {
        let g = Governor::new(single_category_config(BudgetCategory::DataCache, true)).unwrap();

        let mut stale = data_pressure(10);
        stale.freshness_ms = Some(AUTO_TUNE_MAX_FRESHNESS_MS + 1);
        assert_eq!(
            g.apply_auto_tune(&[stale]),
            Err(GovernorAutoTuneError::StaleInput {
                freshness_ms: AUTO_TUNE_MAX_FRESHNESS_MS + 1,
                max_freshness_ms: AUTO_TUNE_MAX_FRESHNESS_MS,
            })
        );

        let out_of_range = data_pressure(101);
        assert_eq!(
            g.apply_auto_tune(&[out_of_range]),
            Err(GovernorAutoTuneError::PressureOutOfRange {
                pressure_score: 101
            })
        );

        let mistargeted_dirty_pressure = GovernorAutoTuneEvidence::pressure(
            BudgetCategory::DataCache,
            GovernorAutoTuneOwner::DirtyBytePressure,
            GovernorAutoTuneUnit::Ratio0To100,
            1_000,
            10,
        );
        assert_eq!(
            g.apply_auto_tune(&[mistargeted_dirty_pressure]),
            Err(GovernorAutoTuneError::AmbiguousInput(
                "dirty-byte pressure must target dirty_bytes"
            ))
        );

        assert_eq!(g.category_soft_watermark(BudgetCategory::DataCache), 700);
    }

    #[test]
    fn auto_tune_refuses_any_unsafe_limit_effect() {
        let g = Governor::new(single_category_config(BudgetCategory::DataCache, true)).unwrap();

        let unsafe_safety_inputs = [
            GovernorAutoTuneSafety {
                durability: GovernorAutoTuneSafetyEffect::WeakensLimit,
                dirty_bytes: GovernorAutoTuneSafetyEffect::PreservesExistingLimit,
                cluster_queues: GovernorAutoTuneSafetyEffect::PreservesExistingLimit,
            },
            GovernorAutoTuneSafety {
                durability: GovernorAutoTuneSafetyEffect::PreservesExistingLimit,
                dirty_bytes: GovernorAutoTuneSafetyEffect::WeakensLimit,
                cluster_queues: GovernorAutoTuneSafetyEffect::PreservesExistingLimit,
            },
            GovernorAutoTuneSafety {
                durability: GovernorAutoTuneSafetyEffect::PreservesExistingLimit,
                dirty_bytes: GovernorAutoTuneSafetyEffect::PreservesExistingLimit,
                cluster_queues: GovernorAutoTuneSafetyEffect::WeakensLimit,
            },
        ];

        for safety in unsafe_safety_inputs {
            let mut unsafe_input = data_pressure(10);
            unsafe_input.safety = Some(safety);
            assert_eq!(
                g.apply_auto_tune(&[unsafe_input]),
                Err(GovernorAutoTuneError::UnsafeInput {
                    category: BudgetCategory::DataCache,
                    reason: "input would weaken a protected safety limit",
                })
            );
        }

        assert_eq!(g.category_soft_watermark(BudgetCategory::DataCache), 700);
    }

    #[test]
    fn auto_tune_rejects_invalid_batch_without_partial_watermark_changes() {
        let config = GovernorConfig {
            total_budget_bytes: 1000,
            data_cache_fraction: 0.5,
            meta_cache_fraction: 0.5,
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
            auto_tune: true,
        };
        let g = Governor::new(config).unwrap();
        let data_before = g.category_soft_watermark(BudgetCategory::DataCache);
        let meta_before = g.category_soft_watermark(BudgetCategory::MetaCache);
        let stale_meta = GovernorAutoTuneEvidence::pressure(
            BudgetCategory::MetaCache,
            GovernorAutoTuneOwner::CacheAdmission,
            GovernorAutoTuneUnit::Ratio0To100,
            AUTO_TUNE_MAX_FRESHNESS_MS + 1,
            80,
        );

        assert_eq!(
            g.apply_auto_tune(&[data_pressure(100), stale_meta]),
            Err(GovernorAutoTuneError::StaleInput {
                freshness_ms: AUTO_TUNE_MAX_FRESHNESS_MS + 1,
                max_freshness_ms: AUTO_TUNE_MAX_FRESHNESS_MS,
            })
        );

        assert_eq!(
            g.category_soft_watermark(BudgetCategory::DataCache),
            data_before
        );
        assert_eq!(
            g.category_soft_watermark(BudgetCategory::MetaCache),
            meta_before
        );
    }

    #[test]
    fn governor_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Governor>();
    }

    #[test]
    fn budget_error_display() {
        let e = BudgetError::OverBudget {
            category: BudgetCategory::DataCache,
            requested: 100,
            available: 50,
        };
        let s = format!("{e}");
        assert!(s.contains("data_cache"));
        assert!(s.contains("100"));
        assert!(s.contains("50"));
    }

    #[test]
    fn backpressure_signal_display() {
        assert_eq!(format!("{}", BackpressureSignal::None), "none");
        assert_eq!(format!("{}", BackpressureSignal::SoftPressure), "soft");
        assert_eq!(format!("{}", BackpressureSignal::HardPressure), "hard");
    }

    #[test]
    fn pressure_state_records_stage_without_claiming_work() {
        let g = Governor::new(single_category_budget_config(
            BudgetCategory::DataCache,
            1000,
        ))
        .unwrap();
        g.admit(BudgetCategory::DataCache, 701).unwrap();

        let state = pressure_state_for(&g, BudgetCategory::DataCache);
        assert_eq!(state.signal, BackpressureSignal::SoftPressure);
        assert_eq!(state.stage, Some(ReclaimStage::EvictColdCache));
        assert_eq!(state.pressure_ticks, 0);
        assert!(!state.reclaim_inflight);
        assert!(g.has_reclaim_work(ReclaimWorkKind::CacheMaintenance));
    }

    #[test]
    fn metadata_pressure_escalates_to_stage_two_after_one_claimed_tick() {
        let g = Governor::new(single_category_budget_config(
            BudgetCategory::MetaCache,
            1000,
        ))
        .unwrap();
        g.admit(BudgetCategory::MetaCache, 701).unwrap();

        let first = g
            .claim_reclaim_work(ReclaimWorkKind::CacheMaintenance)
            .unwrap();
        assert_eq!(first.stage, ReclaimStage::EvictColdCache);
        assert_eq!(
            g.claim_reclaim_work(ReclaimWorkKind::CacheMaintenance),
            None
        );

        g.finish_reclaim_work(first);
        let second = g
            .claim_reclaim_work(ReclaimWorkKind::CacheMaintenance)
            .unwrap();
        assert_eq!(second.stage, ReclaimStage::ShrinkMetadataCaches);
        assert_eq!(second.pressure_ticks, 2);
    }

    #[test]
    fn stale_reclaim_request_is_invalidated_when_pressure_clears() {
        let g = Governor::new(single_category_budget_config(
            BudgetCategory::DataCache,
            1000,
        ))
        .unwrap();
        g.admit(BudgetCategory::DataCache, 800).unwrap();
        let request = g
            .claim_reclaim_work(ReclaimWorkKind::CacheMaintenance)
            .unwrap();

        g.release(BudgetCategory::DataCache, 200);

        assert!(!g.reclaim_request_active(request));
        g.finish_reclaim_work(request);
        assert_eq!(
            g.claim_reclaim_work(ReclaimWorkKind::CacheMaintenance),
            None
        );
        assert_eq!(
            g.backpressure(BudgetCategory::DataCache),
            BackpressureSignal::None
        );
    }

    #[test]
    fn stage_five_is_admission_signal_not_background_work() {
        let g = Governor::new(single_category_budget_config(
            BudgetCategory::DataCache,
            1000,
        ))
        .unwrap();
        g.admit(BudgetCategory::DataCache, 950).unwrap();

        let state = pressure_state_for(&g, BudgetCategory::DataCache);
        assert_eq!(state.signal, BackpressureSignal::HardPressure);
        assert_eq!(state.stage, Some(ReclaimStage::AdmissionBackpressure));
        assert!(!g.has_reclaim_work(ReclaimWorkKind::CacheMaintenance));
        assert_eq!(g.admission_backpressure_requests(), vec![state]);
    }

    #[test]
    fn cache_reclaim_service_runs_bounded_latency_sensitive_tick() {
        let g = Governor::new(single_category_budget_config(
            BudgetCategory::DataCache,
            1000,
        ))
        .unwrap();
        g.admit(BudgetCategory::DataCache, 800).unwrap();
        let log = ReclaimCallLog::default();
        let worker = ReleasingCacheWorker {
            log: log.clone(),
            release_bytes: 200,
        };
        let mut scheduler = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
        scheduler.register(Box::new(GovernorCacheReclaimService::new(
            g.clone(),
            worker,
        )));

        let registered = scheduler.registered_services();
        assert_eq!(registered[0].priority, ServicePriority::LatencySensitive);

        let report = scheduler.run_cycle();
        assert_eq!(report.services_ran, 1);
        assert_eq!(report.total_processed, 1);
        let calls = log.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0.stage, ReclaimStage::EvictColdCache);
        assert_eq!(
            calls[0].1.max_items,
            GovernorCacheReclaimService::<ReleasingCacheWorker>::TICK_BUDGET.max_items
        );
        assert_eq!(
            calls[0].1.max_bytes,
            GovernorCacheReclaimService::<ReleasingCacheWorker>::TICK_BUDGET.max_bytes
        );
        assert_eq!(
            calls[0].1.max_ms,
            GovernorCacheReclaimService::<ReleasingCacheWorker>::TICK_BUDGET.max_ms
        );
        assert_eq!(g.category_used(BudgetCategory::DataCache), 600);
        assert_eq!(
            g.backpressure(BudgetCategory::DataCache),
            BackpressureSignal::None
        );

        let idle = scheduler.run_cycle();
        assert_eq!(idle.services_ran, 0);
    }

    #[test]
    fn failed_reclaim_tick_clears_inflight_request_for_retry() {
        let g = Governor::new(single_category_budget_config(
            BudgetCategory::DataCache,
            1000,
        ))
        .unwrap();
        g.admit(BudgetCategory::DataCache, 800).unwrap();
        let mut service = GovernorCacheReclaimService::new(g.clone(), FailingCacheWorker);

        let err = service.tick(&ServiceBudget::UNBOUNDED).unwrap_err();

        assert!(matches!(err, ServiceError::Internal { .. }));
        let state = pressure_state_for(&g, BudgetCategory::DataCache);
        assert_eq!(state.stage, Some(ReclaimStage::EvictColdCache));
        assert!(!state.reclaim_inflight);
        assert!(g.has_reclaim_work(ReclaimWorkKind::CacheMaintenance));
    }

    #[test]
    fn dirty_flush_service_runs_bounded_throughput_tick() {
        let g = Governor::new(single_category_budget_config(
            BudgetCategory::DirtyBytes,
            1000,
        ))
        .unwrap();
        g.admit(BudgetCategory::DirtyBytes, 600).unwrap();
        let log = ReclaimCallLog::default();
        let worker = ReleasingDirtyWorker {
            log: log.clone(),
            release_bytes: 150,
        };
        let mut scheduler = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
        scheduler.register(Box::new(GovernorDirtyFlushService::new(g.clone(), worker)));

        let registered = scheduler.registered_services();
        assert_eq!(registered[0].priority, ServicePriority::Throughput);

        let report = scheduler.run_cycle();
        assert_eq!(report.services_ran, 1);
        let calls = log.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0.stage, ReclaimStage::FlushDirtyData);
        assert_eq!(
            calls[0].1.max_items,
            GovernorDirtyFlushService::<ReleasingDirtyWorker>::TICK_BUDGET.max_items
        );
        assert_eq!(
            calls[0].1.max_bytes,
            GovernorDirtyFlushService::<ReleasingDirtyWorker>::TICK_BUDGET.max_bytes
        );
        assert_eq!(
            calls[0].1.max_ms,
            GovernorDirtyFlushService::<ReleasingDirtyWorker>::TICK_BUDGET.max_ms
        );
        assert_eq!(g.category_used(BudgetCategory::DirtyBytes), 450);
        assert_eq!(
            g.backpressure(BudgetCategory::DirtyBytes),
            BackpressureSignal::None
        );
    }

    #[test]
    fn dirty_flush_service_drives_existing_incremental_job_surface() {
        let g = Governor::new(single_category_budget_config(
            BudgetCategory::DirtyBytes,
            1000,
        ))
        .unwrap();
        g.admit(BudgetCategory::DirtyBytes, 600).unwrap();
        let (job, calls) = FakeIncrementalDirtyJob::new(vec![(2, 150, false)]);
        let worker = GovernorIncrementalReclaimWorker::new(job);
        let mut scheduler = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
        scheduler.register(Box::new(GovernorDirtyFlushService::new(g.clone(), worker)));

        let report = scheduler.run_cycle();

        assert_eq!(report.services_ran, 1);
        assert_eq!(report.total_processed, 2);
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        type FakeDirtyFlushService =
            GovernorDirtyFlushService<GovernorIncrementalReclaimWorker<FakeIncrementalDirtyJob>>;
        assert_eq!(
            calls[0].max_items,
            FakeDirtyFlushService::TICK_BUDGET.max_items
        );
        assert_eq!(
            calls[0].max_bytes,
            FakeDirtyFlushService::TICK_BUDGET.max_bytes
        );
        assert_eq!(g.category_used(BudgetCategory::DirtyBytes), 450);
    }

    #[test]
    fn hard_dirty_pressure_records_commit_boundary_without_new_authority() {
        let g = Governor::new(single_category_budget_config(
            BudgetCategory::DirtyBytes,
            1000,
        ))
        .unwrap();
        g.admit(BudgetCategory::DirtyBytes, 950).unwrap();
        let log = ReclaimCallLog::default();
        let worker = RecordingCommitWorker { log: log.clone() };
        let mut scheduler = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
        scheduler.register(Box::new(GovernorCommitBoundaryService::new(
            g.clone(),
            worker,
        )));

        let registered = scheduler.registered_services();
        assert_eq!(registered[0].priority, ServicePriority::Critical);

        let report = scheduler.run_cycle();
        assert_eq!(report.services_ran, 1);
        let calls = log.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0.stage, ReclaimStage::ForceCommitGroupSync);
        assert_eq!(
            calls[0].1.max_items,
            GovernorCommitBoundaryService::<RecordingCommitWorker>::TICK_BUDGET.max_items
        );
        assert_eq!(
            calls[0].1.max_bytes,
            GovernorCommitBoundaryService::<RecordingCommitWorker>::TICK_BUDGET.max_bytes
        );
        assert_eq!(
            calls[0].1.max_ms,
            GovernorCommitBoundaryService::<RecordingCommitWorker>::TICK_BUDGET.max_ms
        );
        assert_eq!(g.category_used(BudgetCategory::DirtyBytes), 950);
        assert!(g.has_reclaim_work(ReclaimWorkKind::CommitBoundary));
    }

    #[test]
    fn budget_category_display() {
        assert_eq!(format!("{}", BudgetCategory::DataCache), "data_cache");
        assert_eq!(format!("{}", BudgetCategory::MetaCache), "meta_cache");
    }

    #[test]
    fn cache_level_mapping_matches_governor_categories() {
        assert_eq!(
            budget_category_for_cache_level(CacheBudgetLevel::L1HotRead),
            BudgetCategory::DataCache
        );
        assert_eq!(
            budget_category_for_cache_level(CacheBudgetLevel::L2PrefetchReadAhead),
            BudgetCategory::DataCache
        );
        assert_eq!(
            budget_category_for_cache_level(CacheBudgetLevel::L4DirectoryListing),
            BudgetCategory::MetaCache
        );
        assert_eq!(
            budget_category_for_cache_level(CacheBudgetLevel::L5DirtyWriteback),
            BudgetCategory::DirtyBytes
        );
        assert_eq!(
            budget_category_for_cache_level(CacheBudgetLevel::InodeState),
            BudgetCategory::InodeState
        );
    }

    #[test]
    fn cache_entry_mapping_uses_class_and_dirty_override() {
        let mut header = CacheEntryHeader::new(
            CacheClass::PosixNamespaceMirror,
            MemoryDomain::AdapterServingHot,
            1,
            "path_lookup",
            RebuildCostClass::Cheap,
            1,
        );
        assert_eq!(
            budget_category_for_entry(&header),
            BudgetCategory::MetaCache
        );

        header.cache_class = CacheClass::PosixPageWriteback;
        assert_eq!(
            budget_category_for_entry(&header),
            BudgetCategory::DataCache
        );

        header.dirty_state = DirtyStateClass::PosixWriteback(PosixWritebackState::DirtyOpen);
        assert_eq!(
            budget_category_for_entry(&header),
            BudgetCategory::DirtyBytes
        );
    }

    #[test]
    fn transfer_moves_usage_between_categories_without_changing_total() {
        let config = GovernorConfig {
            total_budget_bytes: 1000,
            data_cache_fraction: 0.5,
            meta_cache_fraction: 0.0,
            dirty_bytes_fraction: 0.5,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
            auto_tune: false,
        };
        let g = Governor::new(config).unwrap();
        g.admit(BudgetCategory::DataCache, 256).unwrap();

        g.transfer(BudgetCategory::DataCache, BudgetCategory::DirtyBytes, 256)
            .unwrap();

        assert_eq!(g.category_used(BudgetCategory::DataCache), 0);
        assert_eq!(g.category_used(BudgetCategory::DirtyBytes), 256);
        assert_eq!(g.total_used(), 256);
    }

    #[test]
    fn transfer_rejects_missing_source_bytes_without_changing_usage() {
        let config = GovernorConfig {
            total_budget_bytes: 1000,
            data_cache_fraction: 0.5,
            meta_cache_fraction: 0.0,
            dirty_bytes_fraction: 0.5,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
            auto_tune: false,
        };
        let g = Governor::new(config).unwrap();
        g.admit(BudgetCategory::DataCache, 128).unwrap();

        let err = g
            .transfer(BudgetCategory::DataCache, BudgetCategory::DirtyBytes, 256)
            .unwrap_err();
        assert_eq!(
            err,
            BudgetError::OverBudget {
                category: BudgetCategory::DataCache,
                requested: 256,
                available: 128,
            }
        );
        assert_eq!(g.category_used(BudgetCategory::DataCache), 128);
        assert_eq!(g.category_used(BudgetCategory::DirtyBytes), 0);
        assert_eq!(g.total_used(), 128);
    }

    #[test]
    fn partitioned_admit_tracks_partition_and_category_usage() {
        let g = Governor::new(single_category_budget_config(
            BudgetCategory::DataCache,
            1000,
        ))
        .unwrap();
        let dataset = partition_key(0x11);

        let ticket = g
            .admit_for_partition(dataset, BudgetCategory::DataCache, 400)
            .unwrap();

        assert_eq!(ticket.category, BudgetCategory::DataCache);
        assert_eq!(ticket.size, 400);
        assert_eq!(ticket.partition, Some(dataset));
        assert_eq!(g.category_used(BudgetCategory::DataCache), 400);
        assert_eq!(g.total_used(), 400);
        assert_eq!(g.partition_used(dataset, BudgetCategory::DataCache), 400);
        assert_eq!(g.partition_protected_limit(BudgetCategory::DataCache), 500);
        assert_eq!(g.partition_limit(dataset, BudgetCategory::DataCache), 500);
    }

    #[test]
    fn partitioned_admit_rejects_over_partition_without_changing_usage() {
        let g = Governor::new(single_category_budget_config(
            BudgetCategory::DataCache,
            1000,
        ))
        .unwrap();
        let dataset = partition_key(0x22);

        g.admit_for_partition(dataset, BudgetCategory::DataCache, 500)
            .unwrap();
        let err = g
            .admit_for_partition(dataset, BudgetCategory::DataCache, 1)
            .unwrap_err();

        assert_eq!(
            err,
            BudgetError::OverBudget {
                category: BudgetCategory::DataCache,
                requested: 1,
                available: 0,
            }
        );
        assert_eq!(g.category_used(BudgetCategory::DataCache), 500);
        assert_eq!(g.partition_used(dataset, BudgetCategory::DataCache), 500);
    }

    #[test]
    fn partitioned_admit_still_rejects_global_over_budget_across_datasets() {
        let g = Governor::new_with_partition_config(
            single_category_budget_config(BudgetCategory::DataCache, 1000),
            GovernorPartitionConfig {
                policy: BudgetPartitionPolicy::Strict,
                category_fraction: 1.0,
                soft_fraction: 0.70,
            },
        )
        .unwrap();
        let first = partition_key(0x31);
        let second = partition_key(0x32);

        g.admit_for_partition(first, BudgetCategory::DataCache, 600)
            .unwrap();
        g.admit_for_partition(second, BudgetCategory::DataCache, 400)
            .unwrap();
        let err = g
            .admit_for_partition(second, BudgetCategory::DataCache, 1)
            .unwrap_err();

        assert_eq!(
            err,
            BudgetError::GlobalOverBudget {
                requested: 1,
                available: 0,
            }
        );
        assert_eq!(g.total_used(), 1000);
        assert_eq!(g.partition_used(first, BudgetCategory::DataCache), 600);
        assert_eq!(g.partition_used(second, BudgetCategory::DataCache), 400);
    }

    #[test]
    fn partition_release_allows_retry_without_reclaiming_other_partition_usage() {
        let g = Governor::new(single_category_budget_config(
            BudgetCategory::DataCache,
            1000,
        ))
        .unwrap();
        let first = partition_key(0x41);
        let second = partition_key(0x42);

        g.admit_for_partition(first, BudgetCategory::DataCache, 500)
            .unwrap();
        g.admit_for_partition(second, BudgetCategory::DataCache, 250)
            .unwrap();
        assert!(matches!(
            g.admit_for_partition(first, BudgetCategory::DataCache, 1),
            Err(BudgetError::OverBudget { .. })
        ));

        g.release_for_partition(first, BudgetCategory::DataCache, 200);
        g.admit_for_partition(first, BudgetCategory::DataCache, 200)
            .unwrap();

        assert_eq!(g.partition_used(first, BudgetCategory::DataCache), 500);
        assert_eq!(g.partition_used(second, BudgetCategory::DataCache), 250);
        assert_eq!(g.category_used(BudgetCategory::DataCache), 750);
        assert_eq!(g.total_used(), 750);
    }

    #[test]
    fn partition_pressure_reports_dataset_local_signal() {
        let g = Governor::new(single_category_budget_config(
            BudgetCategory::DataCache,
            1000,
        ))
        .unwrap();
        let dataset = partition_key(0x55);

        g.admit_for_partition(dataset, BudgetCategory::DataCache, 350)
            .unwrap();
        let soft = g.partition_pressure_state(dataset, BudgetCategory::DataCache);

        assert_eq!(soft.partition, dataset);
        assert_eq!(soft.category, BudgetCategory::DataCache);
        assert_eq!(soft.used, 350);
        assert_eq!(soft.limit, 500);
        assert_eq!(soft.protected_limit, 500);
        assert_eq!(soft.soft_watermark, 350);
        assert_eq!(soft.signal, BackpressureSignal::SoftPressure);
        assert_eq!(
            g.backpressure(BudgetCategory::DataCache),
            BackpressureSignal::None
        );

        g.admit_for_partition(dataset, BudgetCategory::DataCache, 125)
            .unwrap();
        assert_eq!(
            g.partition_backpressure(dataset, BudgetCategory::DataCache),
            BackpressureSignal::HardPressure
        );
    }

    #[test]
    fn partition_pressure_snapshot_lists_active_category_partitions() {
        let g = Governor::new(GovernorConfig {
            total_budget_bytes: 2000,
            data_cache_fraction: 0.5,
            meta_cache_fraction: 0.5,
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
            auto_tune: false,
        })
        .unwrap();
        let first = partition_key(0x10);
        let second = partition_key(0x30);

        g.admit_for_partition(second, BudgetCategory::DataCache, 125)
            .unwrap();
        g.admit_for_partition(first, BudgetCategory::MetaCache, 200)
            .unwrap();
        g.admit_for_partition(first, BudgetCategory::DataCache, 350)
            .unwrap();

        let data_states = g.partition_pressure_states(BudgetCategory::DataCache);
        assert_eq!(data_states.len(), 2);
        assert_eq!(data_states[0].partition, first);
        assert_eq!(data_states[0].used, 350);
        assert_eq!(data_states[0].limit, 500);
        assert_eq!(data_states[0].signal, BackpressureSignal::SoftPressure);
        assert_eq!(data_states[1].partition, second);
        assert_eq!(data_states[1].used, 125);
        assert_eq!(data_states[1].limit, 500);
        assert_eq!(data_states[1].signal, BackpressureSignal::None);

        let meta_states = g.partition_pressure_states(BudgetCategory::MetaCache);
        assert_eq!(meta_states.len(), 1);
        assert_eq!(meta_states[0].partition, first);
        assert_eq!(meta_states[0].used, 200);

        g.release_for_partition(first, BudgetCategory::DataCache, 350);
        let data_states = g.partition_pressure_states(BudgetCategory::DataCache);
        assert_eq!(data_states.len(), 1);
        assert_eq!(data_states[0].partition, second);
        assert_eq!(data_states[0].used, 125);
        assert_eq!(g.partition_used(first, BudgetCategory::MetaCache), 200);
    }

    #[test]
    fn partition_usage_snapshot_groups_all_categories_for_dataset() {
        let g = Governor::new(GovernorConfig {
            total_budget_bytes: 1000,
            data_cache_fraction: 0.4,
            meta_cache_fraction: 0.2,
            dirty_bytes_fraction: 0.3,
            inode_state_fraction: 0.05,
            cluster_queues_fraction: 0.03,
            misc_fraction: 0.02,
            auto_tune: false,
        })
        .unwrap();
        let first = partition_key(0x10);
        let second = partition_key(0x30);

        g.admit_for_partition(second, BudgetCategory::DataCache, 100)
            .unwrap();
        g.admit_for_partition(first, BudgetCategory::DataCache, 180)
            .unwrap();
        g.admit_for_partition(first, BudgetCategory::MetaCache, 60)
            .unwrap();
        g.transfer_for_partition(
            first,
            BudgetCategory::DataCache,
            BudgetCategory::DirtyBytes,
            80,
        )
        .unwrap();

        let snapshot = g.partition_usage_state(first);
        assert_eq!(snapshot.partition, first);
        assert_eq!(snapshot.total_used, 240);
        assert_eq!(
            snapshot
                .pressure_for_category(BudgetCategory::DataCache)
                .used,
            100
        );
        assert_eq!(
            snapshot
                .pressure_for_category(BudgetCategory::MetaCache)
                .used,
            60
        );
        assert_eq!(
            snapshot
                .pressure_for_category(BudgetCategory::DirtyBytes)
                .used,
            80
        );
        assert_eq!(
            snapshot
                .pressure_for_category(BudgetCategory::ClusterQueues)
                .used,
            0
        );
        assert_eq!(
            snapshot
                .categories
                .iter()
                .map(|category| category.used)
                .sum::<u64>(),
            snapshot.total_used
        );

        let active = g.partition_usage_states();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].partition, first);
        assert_eq!(active[0].total_used, 240);
        assert_eq!(active[1].partition, second);
        assert_eq!(active[1].total_used, 100);

        g.release_for_partition(first, BudgetCategory::DataCache, 100);
        g.release_for_partition(first, BudgetCategory::MetaCache, 60);
        g.release_for_partition(first, BudgetCategory::DirtyBytes, 80);
        let active = g.partition_usage_states();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].partition, second);
        assert_eq!(active[0].total_used, 100);
        assert_eq!(g.partition_usage_state(first).total_used, 0);
    }

    #[test]
    fn share_unused_partition_policy_is_explicit_and_observable() {
        let g = Governor::new_with_partition_config(
            single_category_budget_config(BudgetCategory::DataCache, 1000),
            GovernorPartitionConfig {
                policy: BudgetPartitionPolicy::ShareUnused,
                category_fraction: 0.25,
                soft_fraction: 0.70,
            },
        )
        .unwrap();
        let dataset = partition_key(0x66);

        assert_eq!(g.partition_policy(), BudgetPartitionPolicy::ShareUnused);
        assert_eq!(
            g.partition_config(),
            GovernorPartitionConfig {
                policy: BudgetPartitionPolicy::ShareUnused,
                category_fraction: 0.25,
                soft_fraction: 0.70,
            }
        );
        assert_eq!(g.partition_protected_limit(BudgetCategory::DataCache), 250);
        assert_eq!(g.partition_limit(dataset, BudgetCategory::DataCache), 1000);

        g.admit_for_partition(dataset, BudgetCategory::DataCache, 600)
            .unwrap();
        let state = g.partition_pressure_state(dataset, BudgetCategory::DataCache);

        assert_eq!(state.used, 600);
        assert_eq!(state.limit, 1000);
        assert_eq!(state.protected_limit, 250);
        assert_eq!(state.shared_unused_bytes, 750);
        assert_eq!(state.signal, BackpressureSignal::None);
    }

    #[test]
    fn share_unused_partition_snapshot_reports_live_borrow_headroom() {
        let g = Governor::new_with_partition_config(
            single_category_budget_config(BudgetCategory::DataCache, 1000),
            GovernorPartitionConfig {
                policy: BudgetPartitionPolicy::ShareUnused,
                category_fraction: 0.25,
                soft_fraction: 0.70,
            },
        )
        .unwrap();
        let first = partition_key(0x61);
        let second = partition_key(0x62);

        g.admit_for_partition(first, BudgetCategory::DataCache, 600)
            .unwrap();
        g.admit_for_partition(second, BudgetCategory::DataCache, 100)
            .unwrap();

        let states = g.partition_pressure_states(BudgetCategory::DataCache);
        assert_eq!(states.len(), 2);
        assert_eq!(states[0].partition, first);
        assert_eq!(states[0].used, 600);
        assert_eq!(states[0].protected_limit, 250);
        assert_eq!(states[0].limit, 900);
        assert_eq!(states[0].shared_unused_bytes, 650);
        assert_eq!(states[0].soft_watermark, 630);
        assert_eq!(states[0].signal, BackpressureSignal::None);
        assert_eq!(states[1].partition, second);
        assert_eq!(states[1].used, 100);
        assert_eq!(states[1].protected_limit, 250);
        assert_eq!(states[1].limit, 400);
        assert_eq!(states[1].shared_unused_bytes, 150);
        assert_eq!(states[1].soft_watermark, 280);
        assert_eq!(states[1].signal, BackpressureSignal::None);
    }

    #[test]
    fn share_unused_partition_usage_snapshot_reports_live_borrow_headroom() {
        let g = Governor::new_with_partition_config(
            single_category_budget_config(BudgetCategory::DataCache, 1000),
            GovernorPartitionConfig {
                policy: BudgetPartitionPolicy::ShareUnused,
                category_fraction: 0.25,
                soft_fraction: 0.70,
            },
        )
        .unwrap();
        let first = partition_key(0x61);
        let second = partition_key(0x62);

        g.admit_for_partition(first, BudgetCategory::DataCache, 600)
            .unwrap();
        g.admit_for_partition(second, BudgetCategory::DataCache, 100)
            .unwrap();

        let snapshot = g.partition_usage_state(first);
        let data = snapshot.pressure_for_category(BudgetCategory::DataCache);
        assert_eq!(snapshot.total_used, 600);
        assert_eq!(data.used, 600);
        assert_eq!(data.protected_limit, 250);
        assert_eq!(data.limit, 900);
        assert_eq!(data.shared_unused_bytes, 650);
        assert_eq!(data.soft_watermark, 630);
        assert_eq!(data.signal, BackpressureSignal::None);
    }

    #[test]
    fn partitioned_transfer_preserves_partition_identity() {
        let config = GovernorConfig {
            total_budget_bytes: 1000,
            data_cache_fraction: 0.5,
            meta_cache_fraction: 0.0,
            dirty_bytes_fraction: 0.5,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
            auto_tune: false,
        };
        let g = Governor::new(config).unwrap();
        let dataset = partition_key(0x77);

        g.admit_for_partition(dataset, BudgetCategory::DataCache, 200)
            .unwrap();
        g.transfer_for_partition(
            dataset,
            BudgetCategory::DataCache,
            BudgetCategory::DirtyBytes,
            200,
        )
        .unwrap();

        assert_eq!(g.partition_used(dataset, BudgetCategory::DataCache), 0);
        assert_eq!(g.partition_used(dataset, BudgetCategory::DirtyBytes), 200);
        assert_eq!(g.category_used(BudgetCategory::DataCache), 0);
        assert_eq!(g.category_used(BudgetCategory::DirtyBytes), 200);
        assert_eq!(g.total_used(), 200);
    }
}
