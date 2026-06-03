#![no_std]
#![forbid(unsafe_code)]

//! Cache lattice types for Design rule P4-02.
//!
//! Defines the type-level foundation for the tidefs cache lattice:
//! 8 memory domains, 9 cache classes, 18 mandatory entry-header fields,
//! 3 dirty/writeback state machines, and admission/validation/eviction/
//! poison law types.
//!
//! This is the `no_std` authority copy. Runtime implementations in
//! `tidefs-local-filesystem` use these types to build design rule-compliant
//! caches with explicit memory-domain, budget-domain, and freshness-contract
//! tracking.

use blake3::Hasher;
use core::convert::TryFrom;
use core::fmt;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SPEC identifier
// ---------------------------------------------------------------------------

/// Canonical spec identifier for the cache lattice.
pub const CACHE_LATTICE_SPEC: &str = "tidefs-cache-lattice-p4-02-v1";

// ---------------------------------------------------------------------------
// Memory domains (8)
// ---------------------------------------------------------------------------

/// Named memory domain — the accounting/reclaim boundary for runtime caches.
///
/// Each domain has a reclaim priority class and reserve-interaction rules.
/// Higher reclaim priority = protect longer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum MemoryDomain {
    /// Sealed canonical requests, receipts, authority anchors, witness summaries.
    /// Reclaim: last resort, reference-counted retirement only.
    /// Reserve: protected reserve eligible.
    AuthorityImmutable = 0,
    /// Hot mutable authority-adjacent state: head/root mirrors, domain/lease/epoch mirrors.
    /// Reclaim: tightly bounded, shrink only after checkpointed.
    /// Reserve: protected reserve eligible.
    AuthorityMutableHot = 1,
    /// Mutable dirty windows and publication/writeback staging.
    /// Reclaim: cannot evict blindly; must flush, abort, or compact via state machines.
    /// Reserve: protected reserve eligible up to declared floors.
    StagingDirty = 2,
    /// Hot charter-serving mirrors: path/dentry/inode, handle/dir-stream, queue mirrors.
    /// Reclaim: high-pressure reclaimable.
    /// Reserve: no protected reserve borrowing.
    AdapterServingHot = 3,
    /// Explanation/query and other product-serving caches: answer fragments, summaries.
    /// Reclaim: reclaimable after adapter-serving.
    /// Reserve: no protected reserve borrowing.
    ProductServing = 4,
    /// Hot validation bundle fragments, trace mirrors, dashboard renders.
    /// Reclaim: very reclaimable, low priority.
    /// Reserve: no protected reserve borrowing.
    ObserveHot = 5,
    /// Rebuild/relocation temporary scratch buffers.
    /// Reclaim: eagerly reclaimed when idle.
    /// Reserve: no protected reserve borrowing.
    RebuildRelocationTemp = 6,
    /// Kernel-pinned DMA pages, bio vectors, pinned folios.
    /// Reclaim: NOT evicted; drained by pin/loan release.
    /// Reserve: protected reserve eligible through pinned-byte budgets.
    KernelPinnedDma = 7,
}

impl MemoryDomain {
    /// Number of memory domains.
    pub const COUNT: usize = 8;

    /// Human-readable domain name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            MemoryDomain::AuthorityImmutable => "authority_immutable",
            MemoryDomain::AuthorityMutableHot => "authority_mutable_hot",
            MemoryDomain::StagingDirty => "staging_dirty",
            MemoryDomain::AdapterServingHot => "adapter_serving_hot",
            MemoryDomain::ProductServing => "product_serving",
            MemoryDomain::ObserveHot => "observe_hot",
            MemoryDomain::RebuildRelocationTemp => "rebuild_relocation_temp",
            MemoryDomain::KernelPinnedDma => "kernel_pinned_dma",
        }
    }

    /// Whether this domain is protected-reserve eligible.
    #[must_use]
    pub const fn is_reserve_eligible(self) -> bool {
        matches!(
            self,
            MemoryDomain::AuthorityImmutable
                | MemoryDomain::AuthorityMutableHot
                | MemoryDomain::StagingDirty
                | MemoryDomain::KernelPinnedDma
        )
    }

    /// Reclaim priority (higher = protect longer).
    #[must_use]
    pub const fn reclaim_priority(self) -> u8 {
        match self {
            MemoryDomain::AuthorityImmutable => 10,
            MemoryDomain::AuthorityMutableHot => 9,
            MemoryDomain::StagingDirty => 8,
            MemoryDomain::KernelPinnedDma => 7,
            MemoryDomain::AdapterServingHot => 5,
            MemoryDomain::ProductServing => 3,
            MemoryDomain::ObserveHot => 2,
            MemoryDomain::RebuildRelocationTemp => 1,
        }
    }
}

impl fmt::Display for MemoryDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<u8> for MemoryDomain {
    type Error = CacheLatticeError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(MemoryDomain::AuthorityImmutable),
            1 => Ok(MemoryDomain::AuthorityMutableHot),
            2 => Ok(MemoryDomain::StagingDirty),
            3 => Ok(MemoryDomain::AdapterServingHot),
            4 => Ok(MemoryDomain::ProductServing),
            5 => Ok(MemoryDomain::ObserveHot),
            6 => Ok(MemoryDomain::RebuildRelocationTemp),
            7 => Ok(MemoryDomain::KernelPinnedDma),
            _ => Err(CacheLatticeError::InvalidMemoryDomain),
        }
    }
}

// ---------------------------------------------------------------------------
// Cache classes (9)
// ---------------------------------------------------------------------------

/// Named cache class — a fixed design rule role within the lattice.
///
/// Each class maps to a specific memory domain and carries a reclaim
/// priority ordinal. Higher = protect longer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum CacheClass {
    /// Immutable revision/facet/head/policy read acceleration.
    /// Domain: AuthorityImmutable/AuthorityMutableHot. Reclaim priority: 6.
    AuthorityReadMirror = 0,
    /// Prepared successor and receipt staging.
    /// Domain: StagingDirty. Reclaim priority: 9.
    PublicationStaging = 1,
    /// Free-run heaps, shard summaries, reclaim victim queues.
    /// Domain: AuthorityMutableHot/RebuildRelocationTemp. Reclaim priority: 7.
    AllocatorHotSummary = 2,
    /// Path/dentry/inode/xattr/dir-cookie mirrors.
    /// Domain: AdapterServingHot. Reclaim priority: 5.
    PosixNamespaceMirror = 3,
    /// Buffered file data, mmap/writeback windows.
    /// Domain: StagingDirty/AdapterServingHot. Reclaim priority: 8.
    PosixPageWriteback = 4,
    /// LBA->extent mirrors, request windows, completion mirrors.
    /// Domain: StagingDirty/AdapterServingHot/KernelPinnedDma. Reclaim priority: 8.
    BlockVolumeMappingQueue = 5,
    /// Explanation/query answer fragments, locality/planning assists.
    /// Domain: ProductServing. Reclaim priority: 3.
    ProductRuntime = 6,
    /// Hot validation bundle fragments, trace mirrors, dashboards.
    /// Domain: ObserveHot. Reclaim priority: 2.
    ValidationObserve = 7,
    /// Transport/session/cohort/fence mirrors.
    /// Domain: AuthorityMutableHot/ObserveHot. Reclaim priority: 4.
    SessionFence = 8,
}

impl CacheClass {
    pub const COUNT: usize = 9;

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            CacheClass::AuthorityReadMirror => "authority_read_mirror",
            CacheClass::PublicationStaging => "publication_staging",
            CacheClass::AllocatorHotSummary => "allocator_hot_summary",
            CacheClass::PosixNamespaceMirror => "posix_namespace_mirror",
            CacheClass::PosixPageWriteback => "posix_page_writeback",
            CacheClass::BlockVolumeMappingQueue => "block_volume_mapping_queue",
            CacheClass::ProductRuntime => "product_runtime",
            CacheClass::ValidationObserve => "validation_observe",
            CacheClass::SessionFence => "session_fence",
        }
    }

    /// Primary memory domain for this cache class.
    #[must_use]
    pub const fn primary_domain(self) -> MemoryDomain {
        match self {
            CacheClass::AuthorityReadMirror => MemoryDomain::AuthorityImmutable,
            CacheClass::PublicationStaging => MemoryDomain::StagingDirty,
            CacheClass::AllocatorHotSummary => MemoryDomain::AuthorityMutableHot,
            CacheClass::PosixNamespaceMirror => MemoryDomain::AdapterServingHot,
            CacheClass::PosixPageWriteback => MemoryDomain::StagingDirty,
            CacheClass::BlockVolumeMappingQueue => MemoryDomain::StagingDirty,
            CacheClass::ProductRuntime => MemoryDomain::ProductServing,
            CacheClass::ValidationObserve => MemoryDomain::ObserveHot,
            CacheClass::SessionFence => MemoryDomain::AuthorityMutableHot,
        }
    }

    /// Reclaim priority (higher = protect longer).
    #[must_use]
    pub const fn reclaim_priority(self) -> u8 {
        match self {
            CacheClass::PublicationStaging => 9,
            CacheClass::PosixPageWriteback => 8,
            CacheClass::BlockVolumeMappingQueue => 8,
            CacheClass::AllocatorHotSummary => 7,
            CacheClass::AuthorityReadMirror => 6,
            CacheClass::PosixNamespaceMirror => 5,
            CacheClass::SessionFence => 4,
            CacheClass::ProductRuntime => 3,
            CacheClass::ValidationObserve => 2,
        }
    }

    /// Whether this class carries dirty state (must drain, not hard-evict).
    #[must_use]
    pub const fn is_dirty_class(self) -> bool {
        matches!(
            self,
            CacheClass::PublicationStaging
                | CacheClass::PosixPageWriteback
                | CacheClass::BlockVolumeMappingQueue
        )
    }
}

impl fmt::Display for CacheClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<u8> for CacheClass {
    type Error = CacheLatticeError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(CacheClass::AuthorityReadMirror),
            1 => Ok(CacheClass::PublicationStaging),
            2 => Ok(CacheClass::AllocatorHotSummary),
            3 => Ok(CacheClass::PosixNamespaceMirror),
            4 => Ok(CacheClass::PosixPageWriteback),
            5 => Ok(CacheClass::BlockVolumeMappingQueue),
            6 => Ok(CacheClass::ProductRuntime),
            7 => Ok(CacheClass::ValidationObserve),
            8 => Ok(CacheClass::SessionFence),
            _ => Err(CacheLatticeError::InvalidCacheClass),
        }
    }
}

// ---------------------------------------------------------------------------
// Dirty state — 3 writeback state machines
// ---------------------------------------------------------------------------

/// POSIX filesystem adapter page writeback state machine.
///
/// `dirty_writeback_0.posix_filesystem_adapter.writeback`
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PosixWritebackState {
    Clean,
    DirtyOpen,
    DirtySealed,
    WritebackInflight,
    PublicationWait,
    CleanPublished,
    ErrorPoisoned,
}

impl PosixWritebackState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            PosixWritebackState::Clean => "clean",
            PosixWritebackState::DirtyOpen => "dirty_open",
            PosixWritebackState::DirtySealed => "dirty_sealed",
            PosixWritebackState::WritebackInflight => "writeback_inflight",
            PosixWritebackState::PublicationWait => "publication_wait",
            PosixWritebackState::CleanPublished => "clean_published",
            PosixWritebackState::ErrorPoisoned => "error_poisoned",
        }
    }
}

/// Block volume adapter range flush state machine.
///
/// `dirty_writeback_1.block_volume_adapter.range_flush`
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockFlushState {
    Clean,
    DirtyRange,
    FlushPending,
    FuaPending,
    DurableClean,
    ErrorPoisoned,
}

impl BlockFlushState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            BlockFlushState::Clean => "clean",
            BlockFlushState::DirtyRange => "dirty_range",
            BlockFlushState::FlushPending => "flush_pending",
            BlockFlushState::FuaPending => "fua_pending",
            BlockFlushState::DurableClean => "durable_clean",
            BlockFlushState::ErrorPoisoned => "error_poisoned",
        }
    }
}

/// Publication payload writeback state machine.
///
/// `dirty_writeback_2.publication_payload`
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationPayloadState {
    PreparedUnsealed,
    SealedReady,
    PublicationInflight,
    ReceiptIssued,
    Retired,
    ErrorPoisoned,
}

impl PublicationPayloadState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            PublicationPayloadState::PreparedUnsealed => "prepared_unsealed",
            PublicationPayloadState::SealedReady => "sealed_ready",
            PublicationPayloadState::PublicationInflight => "publication_inflight",
            PublicationPayloadState::ReceiptIssued => "receipt_issued",
            PublicationPayloadState::Retired => "retired",
            PublicationPayloadState::ErrorPoisoned => "error_poisoned",
        }
    }
}

/// Unified dirty state class — discriminates which writeback machine applies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirtyStateClass {
    /// Not dirty — clean serving cache.
    Clean,
    /// POSIX page writeback state machine.
    PosixWriteback(PosixWritebackState),
    /// Block volume range flush state machine.
    BlockFlush(BlockFlushState),
    /// Publication payload state machine.
    PublicationPayload(PublicationPayloadState),
}

impl DirtyStateClass {
    #[must_use]
    pub const fn is_clean(self) -> bool {
        matches!(self, DirtyStateClass::Clean)
    }

    #[must_use]
    pub const fn is_dirty(self) -> bool {
        !self.is_clean()
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            DirtyStateClass::Clean => "clean",
            DirtyStateClass::PosixWriteback(s) => s.as_str(),
            DirtyStateClass::BlockFlush(s) => s.as_str(),
            DirtyStateClass::PublicationPayload(s) => s.as_str(),
        }
    }
}

impl fmt::Display for DirtyStateClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Poison state
// ---------------------------------------------------------------------------

/// Poison state for cache entries that have been invalidated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoisonState {
    /// Entry is valid and servable.
    Clean,
    /// Anchor mismatch cannot be reconciled.
    AnchorMismatch,
    /// Publication receipt contradicts staged payload.
    ReceiptContradiction,
    /// Dirty window lost required writeback witnesses.
    LostWitness,
    /// Transport/session state violates fence progression.
    FenceViolation,
    /// Unknown corruption detected.
    Corrupted,
}

impl PoisonState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            PoisonState::Clean => "clean",
            PoisonState::AnchorMismatch => "anchor_mismatch",
            PoisonState::ReceiptContradiction => "receipt_contradiction",
            PoisonState::LostWitness => "lost_witness",
            PoisonState::FenceViolation => "fence_violation",
            PoisonState::Corrupted => "corrupted",
        }
    }

    #[must_use]
    pub const fn is_clean(self) -> bool {
        matches!(self, PoisonState::Clean)
    }
}

impl fmt::Display for PoisonState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Reserve guard class
// ---------------------------------------------------------------------------

/// Reserve guard classification for cache entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReserveGuardClass {
    /// No reserve protection — evictable under pressure.
    None,
    /// Soft reserve: evict only after non-reserve entries.
    Soft,
    /// Hard reserve: evict only on domain-level pressure emergency.
    Hard,
    /// Pinned: non-evictable, must be drained via loan/pin release.
    Pinned,
}

impl ReserveGuardClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ReserveGuardClass::None => "none",
            ReserveGuardClass::Soft => "soft",
            ReserveGuardClass::Hard => "hard",
            ReserveGuardClass::Pinned => "pinned",
        }
    }
}

// ---------------------------------------------------------------------------
// Evictability class
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum EvictabilityClass {
    /// Immediately evictable — no constraints.
    Immediate = 0,
    /// Evictable after LRU tail.
    LruTail = 1,
    /// Evictable only after dirty drain.
    AfterDirtyDrain = 2,
    /// Evictable only under pressure emergency.
    EmergencyOnly = 3,
    /// Non-evictable: must be drained by external mechanism.
    Pinned = 4,
}

// ---------------------------------------------------------------------------
// Rebuild cost class
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RebuildCostClass {
    /// Trivially rebuildable: re-read from store.
    Trivial = 0,
    /// Cheap rebuild: indexed lookup.
    Cheap = 1,
    /// Moderate rebuild: computation or scan required.
    Moderate = 2,
    /// Expensive rebuild: significant I/O or computation.
    Expensive = 3,
    /// Prohibitively expensive: full scan or rebuild.
    Prohibitive = 4,
}

// ---------------------------------------------------------------------------
// Cache entry header — 18 mandatory fields
// ---------------------------------------------------------------------------

/// The common header for every cache entry in the lattice.
///
/// Per P4-02 §4, every cache entry carries these 18 fields regardless of
/// class. They provide the anchor/fence/budget/dirty/poison tracking
/// required by the design rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheEntryHeader {
    /// Which cache class this entry belongs to (1 of 9).
    pub cache_class: CacheClass,
    /// Which memory domain this entry lives in (1 of 8).
    pub memory_domain: MemoryDomain,
    /// Digest of the entry's lookup key (for hash-table sharding).
    pub entry_key_digest: u64,
    /// Reference to the authority-anchor vector this entry is bound to.
    /// Zero means "no anchor" (best-effort only).
    pub anchor_vector_ref: u64,
    /// Reference to the freshness-fence vector this entry satisfies.
    /// Zero means "no fence" (eventual only).
    pub freshness_fence_vector_ref: u64,
    /// Policy revision this entry was admitted under.
    pub policy_revision_ref: u64,
    /// Budget domain that paid for this entry's allocation.
    /// Byte buffer (max 64 bytes), inline.
    pub budget_domain_buf: [u8; 64],
    /// Length of budget_domain name.
    pub budget_domain_len: u8,
    /// Reserve guard class for this entry.
    pub reserve_guard: ReserveGuardClass,
    /// Dirty state class (clean or which writeback machine).
    pub dirty_state: DirtyStateClass,
    /// Byte size of the entry payload (excluding header).
    pub entry_size_bytes: u64,
    /// Monotonic birth counter for admission ordering.
    pub birth_counter: u64,
    /// Monotonic counter of last access (hit or admit).
    pub last_hit_counter: u64,
    /// Cost class for rebuilding this entry if evicted.
    pub rebuild_cost: RebuildCostClass,
    /// How evictable this entry is.
    pub evictability: EvictabilityClass,
    /// Whether this entry is poisoned and why.
    pub poison_state: PoisonState,
    /// Reference to validation/preservation link (zero = none).
    pub validation_link_ref: u64,
    /// Exactness class: what accuracy this entry promises.
    /// Stored as u8: 0=Exact, 1=BoundedStaleness, 2=BestEffort, 3=SnapshotExact.
    pub exactness_class: u8,
    /// Freshness class: what staleness contract this entry promises.
    /// Stored as u8: 0=ReadYourWrites, 1=BoundedFence, 2=Eventual, 3=Snapshot.
    pub freshness_class: u8,
    /// Validity token for epoch/lease-bound freshness tracking.
    /// When an epoch advances or a lease is revoked, the token is
    /// recomputed; entries with a mismatch are stale.
    pub validity_token: ValidityToken,
}

impl CacheEntryHeader {
    /// Maximum length for budget domain names.
    pub const BUDGET_DOMAIN_MAX_LEN: usize = 64;

    /// Create a new header for a cache entry with required fields.
    ///
    /// Panics if budget_domain exceeds 64 bytes.
    #[must_use]
    pub fn new(
        cache_class: CacheClass,
        memory_domain: MemoryDomain,
        entry_key_digest: u64,
        budget_domain: &str,
        rebuild_cost: RebuildCostClass,
        birth_counter: u64,
    ) -> Self {
        let b = budget_domain.as_bytes();
        assert!(
            b.len() <= Self::BUDGET_DOMAIN_MAX_LEN,
            "budget domain too long"
        );
        let mut buf = [0_u8; 64];
        buf[..b.len()].copy_from_slice(b);
        Self {
            cache_class,
            memory_domain,
            entry_key_digest,
            anchor_vector_ref: 0,
            freshness_fence_vector_ref: 0,
            policy_revision_ref: 0,
            budget_domain_buf: buf,
            budget_domain_len: b.len() as u8,
            reserve_guard: ReserveGuardClass::Soft,
            dirty_state: DirtyStateClass::Clean,
            entry_size_bytes: 0,
            birth_counter,
            last_hit_counter: birth_counter,
            rebuild_cost,
            evictability: EvictabilityClass::LruTail,
            poison_state: PoisonState::Clean,
            validation_link_ref: 0,
            exactness_class: 0, // Exact by default
            freshness_class: 0, // ReadYourWrites by default
            validity_token: ValidityToken::default(),
        }
    }

    /// Set the budget domain from a string.
    pub fn set_budget_domain(&mut self, domain: &str) {
        let b = domain.as_bytes();
        assert!(b.len() <= Self::BUDGET_DOMAIN_MAX_LEN);
        self.budget_domain_buf = [0_u8; 64];
        self.budget_domain_buf[..b.len()].copy_from_slice(b);
        self.budget_domain_len = b.len() as u8;
    }

    /// Get the budget domain as a string.
    #[must_use]
    pub fn budget_domain_str(&self) -> &str {
        core::str::from_utf8(&self.budget_domain_buf[..self.budget_domain_len as usize])
            .unwrap_or("invalid_utf8")
    }

    /// Set the entry size and mark as dirty if staging_dirty domain.
    pub fn set_size(&mut self, bytes: u64) {
        self.entry_size_bytes = bytes;
    }

    /// Mark this entry as hit.
    pub fn mark_hit(&mut self, counter: u64) {
        self.last_hit_counter = counter;
    }

    /// Poison this entry with the given reason.
    pub fn poison(&mut self, reason: PoisonState) {
        self.poison_state = reason;
    }

    // ── Header invariants (P4-02 §4.2) ──────────────────────────────────

    /// Check invariant 1: entries without an anchor vector may not claim
    /// exact or freshness-bounded answers.
    #[must_use = "invariant checks must not be silently ignored"]
    pub fn check_invariant_anchor(&self) -> Result<(), CacheLatticeError> {
        if self.anchor_vector_ref == 0 {
            if self.exactness_class == 0 {
                // ExactnessClass::Exact
                return Err(CacheLatticeError::AnchorRequiredForExact);
            }
            if self.freshness_class <= 1 {
                // ReadYourWrites or BoundedFence
                return Err(CacheLatticeError::AnchorRequiredForFreshness);
            }
        }
        Ok(())
    }

    /// Check invariant 2: entries in staging_dirty must have non-clean dirty state.
    #[must_use = "invariant checks must not be silently ignored"]
    pub fn check_invariant_dirty_domain(&self) -> Result<(), CacheLatticeError> {
        if self.memory_domain == MemoryDomain::StagingDirty && self.dirty_state.is_clean() {
            return Err(CacheLatticeError::DirtyDomainRequiresDirtyState);
        }
        Ok(())
    }

    /// Check invariant 4: entries lacking a budget domain are invalid.
    #[must_use = "invariant checks must not be silently ignored"]
    pub fn check_invariant_budget_domain(&self) -> Result<(), CacheLatticeError> {
        if self.budget_domain_len == 0 {
            return Err(CacheLatticeError::BudgetDomainRequired);
        }
        Ok(())
    }

    /// Check invariant 5: poisoned entries may only be served if charter allows
    /// degraded-but-valid behavior.
    #[must_use = "invariant checks must not be silently ignored"]
    pub fn check_invariant_poison(&self) -> Result<(), CacheLatticeError> {
        if !self.poison_state.is_clean() {
            return Err(CacheLatticeError::PoisonedEntryNotServable);
        }
        Ok(())
    }

    /// Run all header invariants.
    #[must_use = "invariant checks must not be silently ignored"]
    pub fn validate(&self) -> Result<(), CacheLatticeError> {
        self.check_invariant_anchor()?;
        self.check_invariant_dirty_domain()?;
        self.check_invariant_budget_domain()?;
        self.check_invariant_poison()?;
        Ok(())
    }

    /// Validate the entry is servable (clean, not poisoned, invariants pass).
    #[must_use]
    pub fn is_servable(&self) -> bool {
        self.poison_state.is_clean() && self.validate().is_ok()
    }
}

// ---------------------------------------------------------------------------
// Admission result
// ---------------------------------------------------------------------------

/// Result of an admission check for a cache entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionResult {
    /// Entry was admitted.
    Admitted,
    /// Rejected: budget domain debit unavailable.
    BudgetExhausted,
    /// Rejected: reserve floor would be breached.
    ReserveBreach,
    /// Rejected: entry exceeds max entry size.
    OversizedEntry,
    /// Rejected: dirty state not legal for this class.
    DirtyStateIllegal,
    /// Rejected: anchor/fence requirements not met.
    AnchorFenceIncomplete,
}

impl AdmissionResult {
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        matches!(self, AdmissionResult::Admitted)
    }
}

// ---------------------------------------------------------------------------
// Cache lattice report
// ---------------------------------------------------------------------------

/// Summary report for the cache lattice state.
#[derive(Clone, Debug, Default)]
pub struct CacheLatticeReport {
    pub spec: &'static str,
    pub total_entries: usize,
    pub total_bytes: u64,
    pub entries_by_domain: [usize; MemoryDomain::COUNT],
    pub entries_by_class: [usize; CacheClass::COUNT],
    pub poisoned_entries: usize,
    pub dirty_entries: usize,
    pub reserve_soft: usize,
    pub reserve_hard: usize,
    pub reserve_pinned: usize,
}

impl CacheLatticeReport {
    #[must_use]
    pub fn new() -> Self {
        Self {
            spec: CACHE_LATTICE_SPEC,
            ..Default::default()
        }
    }
}
// ---------------------------------------------------------------------------
// Cache-lattice view types (5 canonical view classes)
// ---------------------------------------------------------------------------

/// View class discriminator for typed dispatch.
///
/// Five canonical view types as specified in the unified cache-lattice
/// views design. Each view class has its own key space, completeness
/// condition, and invalidation token scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ViewClass {
    /// Full directory listing view keyed by `(dir_inode_id, dir_rev)`.
    /// Complete when all entries are enumerated.
    DirectoryListing = 0,
    /// Hierarchy manifest view keyed by `(subtree_root_id, subtree_rev)`.
    /// Complete when the full subtree has been walked.
    HierarchyManifest = 1,
    /// Path lookup view keyed by `(parent_inode_id, name_bytes)`.
    /// Complete when the target inode has been verified.
    PathLookup = 2,
    /// Negative lookup cache keyed by `(parent_inode_id, name_bytes)`.
    /// Complete when the name has been confirmed absent.
    MissingPath = 3,
    /// Bulk negative cache keyed by `(dir_inode_id)`.
    /// Complete when all known-missing names within the directory are listed.
    MissingNames = 4,
}

impl ViewClass {
    /// Number of canonical view classes.
    pub const COUNT: usize = 5;

    /// Human-readable view class name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ViewClass::DirectoryListing => "directory_listing",
            ViewClass::HierarchyManifest => "hierarchy_manifest",
            ViewClass::PathLookup => "path_lookup",
            ViewClass::MissingPath => "missing_path",
            ViewClass::MissingNames => "missing_names",
        }
    }
}

impl fmt::Display for ViewClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<u8> for ViewClass {
    type Error = CacheLatticeError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(ViewClass::DirectoryListing),
            1 => Ok(ViewClass::HierarchyManifest),
            2 => Ok(ViewClass::PathLookup),
            3 => Ok(ViewClass::MissingPath),
            4 => Ok(ViewClass::MissingNames),
            _ => Err(CacheLatticeError::InvalidCacheClass),
        }
    }
}

// ---------------------------------------------------------------------------
// ValidityToken — 32-byte opaque BLAKE3-based invalidation token
// ---------------------------------------------------------------------------

/// An opaque 32-byte validity token: BLAKE3-256 hash of
/// (monotonic_generation || authoritative_state).
///
/// Views are invalidated by computing a new token when a dirty operation
/// (create, unlink, rename, write) affects the view's key space. The
/// stored token is opaque; equality comparison determines validity.
/// The 32-byte token embeds a generation counter inside the hash input
/// to guarantee monotonic advancement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ValidityToken([u8; 32]);

impl ValidityToken {
    /// Compute a new token from the generation counter and authoritative state.
    ///
    /// The token is `BLAKE3(generation.to_le_bytes() || authoritative_state)`.
    #[must_use]
    pub fn compute(generation: u64, authoritative_state: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(&generation.to_le_bytes());
        hasher.update(authoritative_state);
        let hash = hasher.finalize();
        let mut token = [0u8; 32];
        token.copy_from_slice(hash.as_bytes());
        Self(token)
    }

    /// Create a token from raw 32 bytes (e.g., deserialized from disk).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the raw 32-byte token value.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Check whether a stored token matches this one.
    #[must_use]
    pub fn matches(&self, stored: ValidityToken) -> bool {
        self.0 == stored.0
    }
}

impl Default for ValidityToken {
    /// Returns a zero token. This is only useful as a sentinel;
    /// real tokens should be computed via `compute()`.
    fn default() -> Self {
        Self([0u8; 32])
    }
}

impl fmt::Display for ValidityToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ViewBuildCost — cost classification for view construction
// ---------------------------------------------------------------------------

/// High-level cost classification for view construction.
///
/// Used by eviction policy: cheaper views are evicted first under pressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum ViewBuildCost {
    Cheap = 0,
    Moderate = 1,
    Expensive = 2,
    Prohibitive = 3,
}

/// Accumulated build cost detail for a cache-lattice view.
///
/// Tracks the operations consumed during view construction so that
/// expensive-to-rebuild views can be retained longer under pressure.
/// Use `ViewBuildCost` (the enum) for policy decisions;
/// use `ViewBuildCostDetail` for observability.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ViewBuildCostDetail {
    /// Authoritative reads: btree scans, inode reads, change-stream iteration.
    pub authoritative_reads: u64,
    /// Derived writes: writing view pages to cache.
    pub derived_writes: u64,
    /// Bookkeeping: compaction, tombstone cleanup, index maintenance.
    pub bookkeeping: u64,
}

impl ViewBuildCostDetail {
    /// Total operations consumed during the build.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.authoritative_reads
            .saturating_add(self.derived_writes)
            .saturating_add(self.bookkeeping)
    }

    /// Map the total to a ViewBuildCost classification.
    #[must_use]
    pub fn to_view_build_cost(&self) -> ViewBuildCost {
        match self.total() {
            0..=9 => ViewBuildCost::Cheap,
            10..=99 => ViewBuildCost::Cheap,
            100..=999 => ViewBuildCost::Moderate,
            _ => ViewBuildCost::Expensive,
        }
    }
}

// ---------------------------------------------------------------------------
// ViewMeta — the completeness contract for a cached view
// ---------------------------------------------------------------------------

/// Completeness contract for a cached view entry.
///
/// Carries identity, freshness, cost, and completeness metadata
/// for cache-lattice view entries per the unified cache-lattice
/// views design spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ViewMeta {
    /// Unique identifier for this view instance.
    pub view_id: u64,
    /// High-level cost classification for eviction policy.
    pub build_cost: ViewBuildCost,
    /// Wall-clock timestamp of view creation (milliseconds since epoch).
    pub created_at_ms: i64,
    /// Wall-clock timestamp of last cache hit (milliseconds since epoch).
    pub last_hit_ms: i64,
    /// Cumulative hit count since creation.
    pub hit_count: u64,
    /// Payload size in bytes.
    pub size_bytes: u64,
    /// Whether this view is complete (can prove negatives).
    pub complete: bool,
    /// Whether the view is stale (token mismatch or superseded generation).
    pub stale: bool,
    /// Generation of the authoritative data at view build time.
    /// Compared against current generation to detect staleness.
    pub seen_generation: u64,
    /// Cost consumed during build. Drives eviction decisions.
    pub cost: ViewBuildCostDetail,
    /// View class discriminator for typed dispatch.
    pub view_class: ViewClass,
    /// Validity token for cross-invalidation.
    /// Mismatch with current token -> view is invalid.
    pub stored_token: ValidityToken,
}

impl ViewMeta {
    /// Create a new view metadata record.
    ///
    /// `created_at_ms` and `last_hit_ms` are set to the same initial timestamp.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        view_id: u64,
        build_cost: ViewBuildCost,
        created_at_ms: i64,
        size_bytes: u64,
        complete: bool,
        seen_generation: u64,
        cost: ViewBuildCostDetail,
        view_class: ViewClass,
        stored_token: ValidityToken,
    ) -> Self {
        Self {
            view_id,
            build_cost,
            created_at_ms,
            last_hit_ms: created_at_ms,
            hit_count: 0,
            size_bytes,
            complete,
            stale: false,
            seen_generation,
            cost,
            view_class,
            stored_token,
        }
    }

    /// Record a cache hit, updating stats.
    pub fn record_hit(&mut self, now_ms: i64) {
        self.last_hit_ms = now_ms;
        self.hit_count = self.hit_count.saturating_add(1);
    }

    /// Mark this view as stale (superseded by a newer token).
    pub fn mark_stale(&mut self) {
        self.stale = true;
    }

    /// Check whether this view is currently valid (not stale, token matches).
    #[must_use]
    pub fn is_valid(&self, current_token: ValidityToken) -> bool {
        !self.stale && current_token.matches(self.stored_token)
    }
}

// ---------------------------------------------------------------------------
// ViewStats — per-view-class observability counters
// ---------------------------------------------------------------------------

/// Per-class view statistics for the CacheLatticeReport.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct ViewStats {
    pub directory_listing_hits: u64,
    pub directory_listing_misses: u64,
    pub path_lookup_hits: u64,
    pub path_lookup_misses: u64,
    pub missing_path_negative_proofs: u64,
    pub hierarchy_manifest_hits: u64,
    pub view_builds_total: u64,
    pub view_evictions_total: u64,
    pub derived_catalog_bytes: u64,
}

// ---------------------------------------------------------------------------
// Cache lattice error
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheLatticeError {
    InvalidMemoryDomain,
    InvalidCacheClass,
    AnchorRequiredForExact,
    AnchorRequiredForFreshness,
    DirtyDomainRequiresDirtyState,
    BudgetDomainRequired,
    PoisonedEntryNotServable,
    BudgetDomainTooLong,
}

impl fmt::Display for CacheLatticeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheLatticeError::InvalidMemoryDomain => f.write_str("invalid memory domain"),
            CacheLatticeError::InvalidCacheClass => f.write_str("invalid cache class"),
            CacheLatticeError::AnchorRequiredForExact => {
                f.write_str("anchor vector required for exact answers")
            }
            CacheLatticeError::AnchorRequiredForFreshness => {
                f.write_str("anchor vector required for bounded freshness")
            }
            CacheLatticeError::DirtyDomainRequiresDirtyState => {
                f.write_str("staging_dirty domain requires non-clean dirty state")
            }
            CacheLatticeError::BudgetDomainRequired => {
                f.write_str("budget domain required for cache entry")
            }
            CacheLatticeError::PoisonedEntryNotServable => {
                f.write_str("poisoned entry not servable")
            }
            CacheLatticeError::BudgetDomainTooLong => f.write_str("budget domain name too long"),
        }
    }
}

// ---------------------------------------------------------------------------

// View cache report — cache-lattice view statistics
// ---------------------------------------------------------------------------

/// Aggregate statistics for cache-lattice views, as specified
/// by the unified cache-lattice views design.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CacheLatticeViewReport {
    /// Total number of cached views across all classes.
    pub total_views: u64,
    /// Total byte size of all cached view payloads.
    pub total_size: u64,
    /// Hit rate as a fraction (0.0–1.0). Computed from hits / (hits + misses).
    pub hit_rate: f64,
    /// Miss rate as a fraction (1.0 - hit_rate).
    pub miss_rate: f64,
    /// Total number of evictions since last reset.
    pub eviction_count: u64,
    /// Per-class hit/miss/eviction breakdown.
    pub by_class: ViewStats,
}

impl CacheLatticeViewReport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_domain_count_matches() {
        assert_eq!(MemoryDomain::COUNT, 8);
    }

    #[test]
    fn memory_domain_reserve_eligibility() {
        assert!(MemoryDomain::AuthorityImmutable.is_reserve_eligible());
        assert!(MemoryDomain::StagingDirty.is_reserve_eligible());
        assert!(!MemoryDomain::AdapterServingHot.is_reserve_eligible());
    }

    #[test]
    fn cache_class_primary_domains() {
        assert_eq!(
            CacheClass::PosixPageWriteback.primary_domain(),
            MemoryDomain::StagingDirty,
        );
        assert_eq!(
            CacheClass::PosixNamespaceMirror.primary_domain(),
            MemoryDomain::AdapterServingHot,
        );
    }

    #[test]
    fn dirty_classes_identified() {
        assert!(CacheClass::PublicationStaging.is_dirty_class());
        assert!(CacheClass::PosixPageWriteback.is_dirty_class());
        assert!(!CacheClass::PosixNamespaceMirror.is_dirty_class());
    }

    #[test]
    fn header_invariant_anchor_required_for_exact() {
        let mut h = CacheEntryHeader::new(
            CacheClass::PosixNamespaceMirror,
            MemoryDomain::AdapterServingHot,
            1,
            "adapter_serving",
            RebuildCostClass::Cheap,
            1,
        );
        h.anchor_vector_ref = 0;
        h.exactness_class = 0; // Exact
        assert_eq!(
            h.check_invariant_anchor(),
            Err(CacheLatticeError::AnchorRequiredForExact),
        );
    }

    #[test]
    fn header_invariant_dirty_domain() {
        let h = CacheEntryHeader::new(
            CacheClass::PosixPageWriteback,
            MemoryDomain::StagingDirty,
            2,
            "staging_dirty",
            RebuildCostClass::Moderate,
            1,
        );
        assert_eq!(
            h.check_invariant_dirty_domain(),
            Err(CacheLatticeError::DirtyDomainRequiresDirtyState),
        );
    }

    #[test]
    fn header_invariant_budget_domain() {
        let mut h = CacheEntryHeader::new(
            CacheClass::AuthorityReadMirror,
            MemoryDomain::AuthorityImmutable,
            3,
            "authority_immutable",
            RebuildCostClass::Trivial,
            1,
        );
        h.budget_domain_len = 0;
        assert_eq!(
            h.check_invariant_budget_domain(),
            Err(CacheLatticeError::BudgetDomainRequired),
        );
    }

    #[test]
    fn header_invariant_poison() {
        let mut h = CacheEntryHeader::new(
            CacheClass::PosixNamespaceMirror,
            MemoryDomain::AdapterServingHot,
            4,
            "adapter_serving",
            RebuildCostClass::Cheap,
            1,
        );
        h.poison_state = PoisonState::Corrupted;
        assert_eq!(
            h.check_invariant_poison(),
            Err(CacheLatticeError::PoisonedEntryNotServable),
        );
        assert!(!h.is_servable());
    }

    #[test]
    fn header_validate_all_invariants_pass() {
        let mut h = CacheEntryHeader::new(
            CacheClass::PosixNamespaceMirror,
            MemoryDomain::AdapterServingHot,
            5,
            "adapter_serving",
            RebuildCostClass::Cheap,
            1,
        );
        h.anchor_vector_ref = 1; // Has anchor -> exact OK
        h.exactness_class = 0;
        assert!(h.validate().is_ok());
        assert!(h.is_servable());
    }

    #[test]
    fn budget_domain_roundtrips() {
        let h = CacheEntryHeader::new(
            CacheClass::ProductRuntime,
            MemoryDomain::ProductServing,
            6,
            "product_serving",
            RebuildCostClass::Expensive,
            1,
        );
        assert_eq!(h.budget_domain_str(), "product_serving");
    }

    #[test]
    fn poison_state_display() {
        assert_eq!(PoisonState::Clean.as_str(), "clean");
        assert_eq!(PoisonState::AnchorMismatch.as_str(), "anchor_mismatch");
    }

    #[test]
    fn reclaim_priority_ordinality() {
        // Higher priority means protect longer.
        assert!(
            CacheClass::PublicationStaging.reclaim_priority()
                > CacheClass::ValidationObserve.reclaim_priority()
        );
        assert!(
            MemoryDomain::AuthorityImmutable.reclaim_priority()
                > MemoryDomain::RebuildRelocationTemp.reclaim_priority()
        );
    }

    #[test]
    fn cache_class_try_from_u8() {
        assert_eq!(
            CacheClass::try_from(0).unwrap(),
            CacheClass::AuthorityReadMirror,
        );
        assert_eq!(CacheClass::try_from(8).unwrap(), CacheClass::SessionFence,);
        assert!(CacheClass::try_from(9).is_err());
    }

    // ── ValidityToken tests ────────────────────────────────────────

    #[test]
    fn validity_token_compute_is_deterministic() {
        let t1 = ValidityToken::compute(42, b"hello");
        let t2 = ValidityToken::compute(42, b"hello");
        assert_eq!(t1, t2);
    }

    #[test]
    fn validity_token_different_generation_differs() {
        let t1 = ValidityToken::compute(1, b"state");
        let t2 = ValidityToken::compute(2, b"state");
        assert_ne!(t1, t2);
    }

    #[test]
    fn validity_token_different_state_differs() {
        let t1 = ValidityToken::compute(1, b"state_a");
        let t2 = ValidityToken::compute(1, b"state_b");
        assert_ne!(t1, t2);
    }

    #[test]
    fn validity_token_matches() {
        let t1 = ValidityToken::compute(7, b"data");
        let t2 = ValidityToken::compute(7, b"data");
        assert!(t1.matches(t2));
    }

    #[test]
    fn validity_token_default_is_zero() {
        let dt = ValidityToken::default();
        assert_eq!(dt.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn validity_token_from_bytes_roundtrips() {
        let orig = ValidityToken::compute(99, b"roundtrip");
        let bytes = *orig.as_bytes();
        let restored = ValidityToken::from_bytes(bytes);
        assert_eq!(orig, restored);
    }

    // ── ViewBuildCost enum tests ───────────────────────────────────

    #[test]
    fn view_build_cost_ordering() {
        assert!(ViewBuildCost::Cheap < ViewBuildCost::Moderate);
        assert!(ViewBuildCost::Moderate < ViewBuildCost::Expensive);
        assert!(ViewBuildCost::Expensive < ViewBuildCost::Prohibitive);
    }

    #[test]
    fn view_build_cost_detail_to_classification() {
        let cheap = ViewBuildCostDetail {
            authoritative_reads: 5,
            ..Default::default()
        };
        assert_eq!(cheap.to_view_build_cost(), ViewBuildCost::Cheap);

        let moderate = ViewBuildCostDetail {
            authoritative_reads: 50,
            bookkeeping: 55,
            ..Default::default()
        };
        assert_eq!(moderate.to_view_build_cost(), ViewBuildCost::Moderate);

        let expensive = ViewBuildCostDetail {
            authoritative_reads: 500,
            derived_writes: 700,
            ..Default::default()
        };
        assert_eq!(expensive.to_view_build_cost(), ViewBuildCost::Expensive);
    }

    // ── ViewMeta extended tests ────────────────────────────────────

    #[test]
    fn view_meta_record_hit_updates_stats() {
        let token = ValidityToken::compute(1, b"test");
        let mut meta = ViewMeta::new(
            100,
            ViewBuildCost::Cheap,
            1000,
            4096,
            true,
            1,
            ViewBuildCostDetail::default(),
            ViewClass::PathLookup,
            token,
        );
        assert_eq!(meta.hit_count, 0);
        assert_eq!(meta.last_hit_ms, 1000);
        meta.record_hit(2000);
        assert_eq!(meta.hit_count, 1);
        assert_eq!(meta.last_hit_ms, 2000);
    }

    #[test]
    fn view_meta_stale_and_valid() {
        let token_v1 = ValidityToken::compute(1, b"state_v1");
        let token_v2 = ValidityToken::compute(2, b"state_v2");
        let mut meta = ViewMeta::new(
            200,
            ViewBuildCost::Moderate,
            5000,
            8192,
            true,
            1,
            ViewBuildCostDetail::default(),
            ViewClass::DirectoryListing,
            token_v1,
        );
        assert!(meta.is_valid(token_v1));
        assert!(!meta.is_valid(token_v2));
        meta.mark_stale();
        assert!(!meta.is_valid(token_v1));
    }

    #[test]
    fn cache_lattice_view_report_defaults() {
        let report = CacheLatticeViewReport::default();
        assert_eq!(report.total_views, 0);
        assert_eq!(report.total_size, 0);
        assert_eq!(report.eviction_count, 0);
    }
}
