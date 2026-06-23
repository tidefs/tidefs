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

use std::fmt;
use std::sync::{Arc, Mutex};
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
    GlobalOverBudget {
        requested: u64,
        available: u64,
    },
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
}

// ── Per-category configuration ───────────────────────────────────────────

/// Per-category budget configuration.
#[derive(Clone, Debug)]
struct CategoryConfig {
    /// Total bytes allocated to this category.
    cap: u64,
    /// Soft watermark: above this, backpressure is [`SoftPressure`].
    soft_watermark: u64,
    /// Hard limit: equal to cap for simplicity in the first slice.
    hard_limit: u64,
}

impl CategoryConfig {
    fn new(cap: u64, soft_fraction: f64) -> Self {
        let soft = (cap as f64 * soft_fraction) as u64;
        Self {
            cap,
            soft_watermark: soft.min(cap),
            hard_limit: cap,
        }
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
}

impl CategoryState {
    fn new() -> Self {
        Self {
            used: 0,
            soft_pressure: false,
            hard_pressure: false,
        }
    }
}

// ── Governor configuration ───────────────────────────────────────────────

/// Configuration for the unified resource governor.
#[derive(Clone, Debug)]
pub struct GovernorConfig {
    /// Total daemon memory budget in bytes.
    /// Default: 60% of host physical RAM, clamped to [256 MiB, 256 GiB].
    pub total_budget_bytes: u64,

    /// Per-category fractions (must sum to 1.0).
    pub data_cache_fraction: f64,       // default 0.40
    pub meta_cache_fraction: f64,       // default 0.20
    pub dirty_bytes_fraction: f64,      // default 0.25
    pub inode_state_fraction: f64,      // default 0.08
    pub cluster_queues_fraction: f64,   // default 0.05
    pub misc_fraction: f64,             // default 0.02
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
        }
    }
}

impl GovernorConfig {
    /// Validate that fractions sum to 1.0 within a small epsilon and each
    /// fraction is non-negative.
    #[must_use]
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
            if f < 0.0 || f > 1.0 {
                return Err(format!("{name} fraction {f} out of range [0, 1]"));
            }
        }
        Ok(())
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
    categories: [CategoryState; 6],
    category_configs: [CategoryConfig; 6],
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

    /// Create a new governor from a validated configuration.
    ///
    /// Returns an error if the configuration fails validation.
    pub fn new(config: GovernorConfig) -> Result<Self, String> {
        config.validate()?;
        let total = config.total_budget_bytes;
        let caps: [u64; 6] = [
            (total as f64 * config.data_cache_fraction) as u64,
            (total as f64 * config.meta_cache_fraction) as u64,
            (total as f64 * config.dirty_bytes_fraction) as u64,
            (total as f64 * config.inode_state_fraction) as u64,
            (total as f64 * config.cluster_queues_fraction) as u64,
            (total as f64 * config.misc_fraction) as u64,
        ];
        // Soft watermarks per the design spec.
        let soft_fractions: [f64; 6] = [0.70, 0.70, 0.50, 0.70, 0.70, 0.70];
        let mut category_configs: [CategoryConfig; 6] =
            std::array::from_fn(|_| CategoryConfig::new(0, 0.0));
        for (i, &cap) in caps.iter().enumerate() {
            category_configs[i] = CategoryConfig::new(cap, soft_fractions[i]);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(GovernorInner {
                config,
                categories: std::array::from_fn(|_| CategoryState::new()),
                category_configs,
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
        let mut inner = self.inner.lock().unwrap();

        let idx = Self::category_index(category);
        let hard_limit = inner.category_configs[idx].hard_limit;
        let soft_watermark = inner.category_configs[idx].soft_watermark;
        let cap = inner.category_configs[idx].cap;
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

        // Update state.
        inner.total_used = new_total;
        inner.categories[idx].used = new_used;

        // Recompute pressure signals.
        let (soft_pressure, hard_pressure) =
            Self::pressure_flags(new_used, cap, soft_watermark);
        inner.categories[idx].hard_pressure = hard_pressure;
        inner.categories[idx].soft_pressure = soft_pressure;

        Ok(AdmissionTicket { category, size })
    }

    /// Release `size` bytes back to `category` and the global budget.
    ///
    /// If the category was previously over its soft watermark and the
    /// release brings it back under, the soft-pressure signal is cleared.
    pub fn release(&self, category: BudgetCategory, size: u64) {
        let mut inner = self.inner.lock().unwrap();
        let idx = Self::category_index(category);

        let released = inner.categories[idx].used.min(size);
        inner.categories[idx].used -= released;
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

    fn pressure_flags(used: u64, cap: u64, soft_watermark: u64) -> (bool, bool) {
        if used == 0 || cap == 0 {
            return (false, false);
        }
        let hard_pressure = (used as u128) * 100 >= (cap as u128) * 95;
        let soft_pressure = used >= soft_watermark;
        (soft_pressure, hard_pressure)
    }

    fn refresh_pressure_locked(inner: &mut GovernorInner, idx: usize) {
        let used = inner.categories[idx].used;
        let cap = inner.category_configs[idx].cap;
        let soft_watermark = inner.category_configs[idx].soft_watermark;
        let (soft_pressure, hard_pressure) =
            Self::pressure_flags(used, cap, soft_watermark);
        inner.categories[idx].hard_pressure = hard_pressure;
        inner.categories[idx].soft_pressure = soft_pressure;
    }
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
    use tidefs_types_cache_lattice_core::{
        DirtyStateClass, MemoryDomain, PosixWritebackState, RebuildCostClass,
    };

    fn test_config() -> GovernorConfig {
        GovernorConfig::default()
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
            data_cache_fraction: 0.5,   // cap 500
            meta_cache_fraction: 0.5,   // cap 500
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
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
            data_cache_fraction: 0.5,  // 1000
            meta_cache_fraction: 0.5,  // 1000
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
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
        let mut cfg = GovernorConfig::default();
        cfg.data_cache_fraction = 1.0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validation_accepts_default() {
        assert!(GovernorConfig::default().validate().is_ok());
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
        assert_eq!(budget_category_for_entry(&header), BudgetCategory::MetaCache);

        header.cache_class = CacheClass::PosixPageWriteback;
        assert_eq!(budget_category_for_entry(&header), BudgetCategory::DataCache);

        header.dirty_state = DirtyStateClass::PosixWriteback(PosixWritebackState::DirtyOpen);
        assert_eq!(budget_category_for_entry(&header), BudgetCategory::DirtyBytes);
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
}
