// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Atomic coordination strategy switching protocol with epoch fencing.
//!
//! Implements the 5-level contention-adaptive coordination strategy lifecycle:
//!
//!   1. **Uncontended** — direct local access, no coordination overhead
//!   2. **Optimistic** — optimistic concurrency with conflict detection
//!   3. **Lease** — distributed lease-based coordination
//!   4. **TDMA** — time-division multiple access scheduling
//!   5. **LeaderSerialized** — leader-serialized single-writer
//!
//! Every strategy transition follows the quiesce→drain→verify→switch→publish
//! lifecycle.  Epoch fencing rejects late-arriving operations that were
//! admitted under a superseded strategy epoch, preventing split-brain writes.
//! The former strategy-selection dispatch pipeline (select_strategy,
//! WorkloadProfile, DispatchDecision, HysteresisConfig) and the
//! tidefs-contention-detector crate have been removed; their role is
//! superseded by the claim-ledger and placement-planner pipelines.

use std::fmt;
use std::num::NonZeroU32;
use tidefs_membership_epoch::EpochId;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Coordination strategy levels
// ---------------------------------------------------------------------------

/// The five coordination strategies ordered by increasing contention.
///
/// Strategies are ordered such that later variants handle higher contention
/// levels. The system may transition through adjacent levels via
/// [`StrategyTransition`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CoordinationStrategy {
    /// No contention: direct local access without coordination overhead.
    /// Suitable for single-writer workloads or read-only replicas.
    Uncontended = 0,
    /// Low contention: optimistic concurrency with conflict detection on
    /// commit. Writers proceed without blocking; conflicts are resolved
    /// by abort-and-retry.
    Optimistic = 1,
    /// Moderate contention: distributed lease-based coordination.
    /// Writers acquire time-bounded leases before mutation; leases are
    /// quorum-acknowledged and automatically revoked on node failure.
    Lease = 2,
    /// High contention: time-division multiple access scheduling.
    /// A fair round-robin scheduler assigns per-object time slots to
    /// contending nodes, bounding worst-case latency.
    TDMA = 3,
    /// Extreme contention: leader-serialized single-writer.
    /// All mutations for the object flow through a designated leader node
    /// that serialises writes and replicates results.
    LeaderSerialized = 4,
}

impl Default for CoordinationStrategy {
    /// Uncontended is the default strategy — no coordination overhead.
    fn default() -> Self {
        Self::Uncontended
    }
}

impl CoordinationStrategy {
    /// Return the number of strategy levels.
    #[must_use]
    pub const fn level_count() -> usize {
        5
    }

    /// Return the capability matrix for this strategy level.
    ///
    /// Each strategy level provides different guarantees about concurrency,
    /// ordering, and fencing. Callers use [`StrategyCapabilities::satisfies`]
    /// to check whether a specific POSIX operation class is safe under this
    /// strategy.
    #[must_use]
    pub const fn capabilities(self) -> StrategyCapabilities {
        match self {
            Self::Uncontended => StrategyCapabilities {
                max_concurrent_writers: None, // unbounded
                ordering_guarantee: OrderingGuarantee::None,
                requires_quorum: false,
                supports_fencing: false,
            },
            Self::Optimistic => StrategyCapabilities {
                max_concurrent_writers: None,
                ordering_guarantee: OrderingGuarantee::None,
                requires_quorum: false,
                supports_fencing: false,
            },
            Self::Lease => StrategyCapabilities {
                max_concurrent_writers: None,
                ordering_guarantee: OrderingGuarantee::CausalOrder,
                requires_quorum: true,
                supports_fencing: true,
            },
            Self::TDMA => StrategyCapabilities {
                max_concurrent_writers: Some(match NonZeroU32::new(1) {
                    Some(v) => v,
                    None => unreachable!(),
                }),
                ordering_guarantee: OrderingGuarantee::CausalOrder,
                requires_quorum: false, // TDMA is schedule-based, not quorum
                supports_fencing: true,
            },
            Self::LeaderSerialized => StrategyCapabilities {
                max_concurrent_writers: Some(match NonZeroU32::new(1) {
                    Some(v) => v,
                    None => unreachable!(),
                }),
                ordering_guarantee: OrderingGuarantee::TotalOrder,
                requires_quorum: false,
                supports_fencing: true,
            },
        }
    }

    /// Return the strategy at a given numeric level (0-4).
    ///
    /// Returns `None` if `level` is out of range.
    #[must_use]
    pub const fn from_level(level: u8) -> Option<Self> {
        match level {
            0 => Some(Self::Uncontended),
            1 => Some(Self::Optimistic),
            2 => Some(Self::Lease),
            3 => Some(Self::TDMA),
            4 => Some(Self::LeaderSerialized),
            _ => None,
        }
    }

    /// Return the numeric level (0-4).
    pub const fn to_level(self) -> u8 {
        self as u8
    }

    /// Whether this strategy requires distributed coordination.
    pub const fn requires_coordination(self) -> bool {
        matches!(self, Self::Lease | Self::TDMA | Self::LeaderSerialized)
    }

    /// Whether this strategy uses leases.
    pub const fn uses_leases(self) -> bool {
        matches!(self, Self::Lease)
    }

    /// Whether this strategy supports concurrent writes from multiple nodes.
    pub const fn allows_concurrent_writers(self) -> bool {
        match self {
            Self::Uncontended | Self::Optimistic | Self::Lease | Self::TDMA => true,
            Self::LeaderSerialized => false,
        }
    }
}

impl fmt::Display for CoordinationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Uncontended => "Uncontended",
            Self::Optimistic => "Optimistic",
            Self::Lease => "Lease",
            Self::TDMA => "TDMA",
            Self::LeaderSerialized => "LeaderSerialized",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Transition phases
// ---------------------------------------------------------------------------

/// The five phases of a strategy transition.
///
/// Transitions proceed in strict forward order.  At any point before
/// `Publish`, the transition may be rolled back to the original strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TransitionPhase {
    /// In-flight operations under the old strategy are quiesced — no new
    /// operations are admitted under the old strategy epoch.
    Quiesce,
    /// Pending writes under the old strategy are drained to completion
    /// (or cancelled if they cannot complete within the drain timeout).
    Drain,
    /// The drain state is verified: no lost writes, all dirty state is
    /// accounted for, and the new strategy's preconditions are satisfied.
    Verify,
    /// The active strategy is atomically swapped to the new strategy.
    /// The epoch fence is advanced so incoming operations are routed to
    /// the new strategy.
    Switch,
    /// The transition is published to observers (contention detector,
    /// lease manager, TDMA scheduler). The old strategy state is
    /// released. The transition is now irreversible.
    Publish,
}

impl TransitionPhase {
    /// Return the next phase in the lifecycle, or `None` if already at
    /// the terminal phase.
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Quiesce => Some(Self::Drain),
            Self::Drain => Some(Self::Verify),
            Self::Verify => Some(Self::Switch),
            Self::Switch => Some(Self::Publish),
            Self::Publish => None,
        }
    }

    /// Whether this phase precedes `Publish` (the transition is still
    /// reversible).
    pub const fn is_reversible(self) -> bool {
        !matches!(self, Self::Publish)
    }
}

impl fmt::Display for TransitionPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Quiesce => "Quiesce",
            Self::Drain => "Drain",
            Self::Verify => "Verify",
            Self::Switch => "Switch",
            Self::Publish => "Publish",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Strategy epoch
// ---------------------------------------------------------------------------

/// A monotonically-increasing strategy epoch used for fencing.
///
/// Every coordination strategy assignment carries an epoch.  When a
/// transition completes, the epoch is incremented.  Operations admitted
/// under a stale epoch are rejected by the [`EpochFence`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StrategyEpoch(pub u64);

impl StrategyEpoch {
    /// The initial epoch (zero).
    pub const ZERO: Self = Self(0);

    /// Create a new epoch from the given value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the next epoch.
    pub const fn next(self) -> Self {
        Self(self.0.checked_add(1).expect("epoch overflow"))
    }

    /// Convert from a membership [`EpochId`].
    pub fn from_membership_epoch(epoch: EpochId) -> Self {
        Self(epoch.0)
    }

    /// Return the inner value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl From<EpochId> for StrategyEpoch {
    fn from(epoch: EpochId) -> Self {
        Self(epoch.0)
    }
}

impl fmt::Display for StrategyEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during a strategy transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TransitionError {
    /// The transition cannot proceed: the phase progression is invalid
    /// (e.g. advancing from `Publish`).
    InvalidPhaseProgression,
    /// The drain phase timed out before all in-flight operations completed.
    DrainTimeout,
    /// The verify phase failed — lost writes or unmet preconditions were
    /// detected.
    VerificationFailed,
    /// The switch was attempted but the new strategy epoch was stale
    /// (a concurrent transition beat us).
    StaleEpoch,
    /// The transition was rolled back.
    RolledBack,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPhaseProgression => write!(f, "invalid phase progression"),
            Self::DrainTimeout => write!(f, "drain timeout"),
            Self::VerificationFailed => write!(f, "verification failed"),
            Self::StaleEpoch => write!(f, "stale epoch"),
            Self::RolledBack => write!(f, "rolled back"),
        }
    }
}

/// Error returned when an operation is rejected by an epoch fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum FenceError {
    /// The operation's epoch is behind the current fence.
    StaleEpoch {
        fence_epoch: u64,
        operation_epoch: u64,
    },
}

impl fmt::Display for FenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleEpoch {
                fence_epoch,
                operation_epoch,
            } => {
                write!(f, "stale epoch: operation epoch {operation_epoch} is behind fence epoch {fence_epoch}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// StrategyTransition — the active transition
// ---------------------------------------------------------------------------

/// A state machine that drives an atomic strategy switch.
///
/// Created by [`StrategyTransition::begin`], the transition progresses
/// through [`TransitionPhase`] in strict order via [`advance`](Self::advance).
/// At any phase before `Publish`, [`rollback`](Self::rollback) can revert
/// to the original strategy.
///
/// # Example
///
/// ```rust
/// use tidefs_coordination_strategy::{
///     CoordinationStrategy, StrategyEpoch, StrategyTransition,
///     TransitionError, TransitionPhase,
/// };
/// let mut t = StrategyTransition::begin(
///     CoordinationStrategy::Optimistic,
///     CoordinationStrategy::Lease,
///     StrategyEpoch::new(5),
/// );
/// assert_eq!(t.advance(), Ok(TransitionPhase::Drain));
/// assert_eq!(t.advance(), Ok(TransitionPhase::Verify));
/// assert_eq!(t.advance(), Ok(TransitionPhase::Switch));
/// assert_eq!(t.advance(), Ok(TransitionPhase::Publish));
/// // After Publish, further advance returns an error.
/// assert_eq!(t.advance(), Err(TransitionError::InvalidPhaseProgression));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrategyTransition {
    /// The strategy being left.
    pub from: CoordinationStrategy,
    /// The strategy being adopted.
    pub to: CoordinationStrategy,
    /// The new epoch for the target strategy.
    pub new_epoch: StrategyEpoch,
    /// Current phase of the transition.
    pub phase: TransitionPhase,
}

impl StrategyTransition {
    /// Begin a new strategy transition.
    ///
    /// The transition starts in [`TransitionPhase::Quiesce`].
    /// `from` and `to` must be different strategies, and the new epoch
    /// must be greater than the current epoch (guarded by the caller).
    ///
    /// # Panics
    ///
    /// Panics if `from == to` — a no-op transition is not allowed.
    pub fn begin(
        from: CoordinationStrategy,
        to: CoordinationStrategy,
        new_epoch: StrategyEpoch,
    ) -> Self {
        assert_ne!(from, to, "transition must change strategy");
        Self {
            from,
            to,
            new_epoch,
            phase: TransitionPhase::Quiesce,
        }
    }

    /// Advance the transition to the next phase.
    ///
    /// Returns the new phase on success, or a [`TransitionError`] if the
    /// advance cannot proceed (e.g. already at `Publish`).
    ///
    /// When the phase advances to `Publish`, the transition is committed
    /// and can no longer be rolled back.
    pub fn advance(&mut self) -> Result<TransitionPhase, TransitionError> {
        let next = self
            .phase
            .next()
            .ok_or(TransitionError::InvalidPhaseProgression)?;
        self.phase = next;
        Ok(self.phase)
    }

    /// Roll back the transition, returning to the original strategy.
    ///
    /// After rollback, the transition is consumed and must not be used
    /// again. A new transition must be initiated if the strategy switch
    /// is re-attempted.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::InvalidPhaseProgression`] if the
    /// transition has already been published (irreversible).
    pub fn rollback(mut self) -> Result<(), TransitionError> {
        if !self.phase.is_reversible() {
            return Err(TransitionError::InvalidPhaseProgression);
        }
        self.phase = TransitionPhase::Quiesce;
        // The transition is consumed; the caller drops it.
        Ok(())
    }

    /// Whether this transition is still in progress (not yet published
    /// or rolled back).
    pub fn is_active(&self) -> bool {
        self.phase != TransitionPhase::Publish
    }

    /// Whether the transition has been published (irreversible).
    pub fn is_published(&self) -> bool {
        self.phase == TransitionPhase::Publish
    }

    /// The current phase.
    pub fn phase(&self) -> TransitionPhase {
        self.phase
    }
}

// ---------------------------------------------------------------------------
// EpochFence — rejects stale operations
// ---------------------------------------------------------------------------

/// A monotonic epoch fence that rejects operations admitted under a
/// superseded strategy epoch.
///
/// The fence is advanced when a strategy transition publishes.  Operations
/// that carry an epoch behind the fence are rejected with
/// [`FenceError::StaleEpoch`].
#[derive(Clone, Debug, PartialEq, Eq)]
/// # Examples
///
/// ```rust
/// use tidefs_coordination_strategy::{EpochFence, FenceError, StrategyEpoch};
///
/// let fence = EpochFence::new(StrategyEpoch::new(10));
///
/// // Current-epoch operations are admitted.
/// assert!(fence.admit(StrategyEpoch::new(10)).is_ok());
///
/// // Future-epoch operations are admitted.
/// assert!(fence.admit(StrategyEpoch::new(15)).is_ok());
///
/// // Stale operations are rejected.
/// assert!(matches!(
///     fence.admit(StrategyEpoch::new(5)),
///     Err(FenceError::StaleEpoch { .. })
/// ));
/// ```
pub struct EpochFence {
    current: StrategyEpoch,
}

impl EpochFence {
    /// Create a new fence at the given epoch.
    #[must_use]
    pub fn new(epoch: StrategyEpoch) -> Self {
        Self { current: epoch }
    }

    /// Admit an operation if its epoch is not behind the fence.
    ///
    /// Returns `Ok(())` when the operation's epoch matches or exceeds the
    /// fence, or [`FenceError::StaleEpoch`] otherwise.
    pub fn admit(&self, operation_epoch: StrategyEpoch) -> Result<(), FenceError> {
        if operation_epoch >= self.current {
            Ok(())
        } else {
            Err(FenceError::StaleEpoch {
                fence_epoch: self.current.value(),
                operation_epoch: operation_epoch.value(),
            })
        }
    }

    /// Return the current fence epoch.
    pub fn current_epoch(&self) -> StrategyEpoch {
        self.current
    }

    /// Advance the fence to a new epoch.
    ///
    /// # Panics
    ///
    /// Panics if the new epoch is not strictly greater than the current
    /// epoch (fence must be monotonic).
    pub fn advance(&mut self, new_epoch: StrategyEpoch) {
        assert!(
            new_epoch > self.current,
            "fence epoch must be monotonic: {new_epoch:?} <= {:?}",
            self.current
        );
        self.current = new_epoch;
    }
}

// ---------------------------------------------------------------------------
// Ordering guarantee
// ---------------------------------------------------------------------------

/// The ordering guarantee provided by a coordination strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OrderingGuarantee {
    /// No ordering guarantee: writes may appear in any order across nodes.
    None = 0,
    /// Causal ordering: writes that are causally related are observed in
    /// the same order by all nodes. Independent writes may appear out of
    /// order.
    CausalOrder = 1,
    /// Total ordering: all writes are observed in the same total order by
    /// every node. The strongest guarantee.
    TotalOrder = 2,
}

impl fmt::Display for OrderingGuarantee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None => "None",
            Self::CausalOrder => "CausalOrder",
            Self::TotalOrder => "TotalOrder",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Strategy capabilities
// ---------------------------------------------------------------------------

/// The runtime capabilities provided by a coordination strategy level.
///
/// Callers use [`StrategyCapabilities::satisfies`] to gate operations:
/// if the active strategy for an inode/block does not provide the
/// ordering or concurrency guarantees required by the POSIX operation
/// class, the operation is rejected or deferred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StrategyCapabilities {
    /// Maximum concurrent writers permitted. `None` means unbounded.
    pub max_concurrent_writers: Option<NonZeroU32>,
    /// The ordering guarantee for writes under this strategy.
    pub ordering_guarantee: OrderingGuarantee,
    /// Whether this strategy requires a quorum of replicas to acknowledge
    /// each mutation before it is considered durable.
    pub requires_quorum: bool,
    /// Whether this strategy supports epoch-based fencing to reject stale
    /// operations from nodes that missed a strategy transition.
    pub supports_fencing: bool,
}

impl StrategyCapabilities {
    /// Check whether this strategy satisfies the POSIX requirements for
    /// the given operation class.
    ///
    /// Returns `true` if the operation can be safely dispatched under
    /// this strategy's guarantees.
    #[must_use]
    pub const fn satisfies(self, op: PosixOperationClass) -> bool {
        let required = op.required_guarantee();
        self.ordering_guarantee as u8 >= required as u8
    }
}

// ---------------------------------------------------------------------------
// POSIX operation class
// ---------------------------------------------------------------------------
/// POSIX operation classes that have ordering and concurrency requirements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PosixOperationClass {
    /// Data writes (pwrite, write, mmap write).
    Write,
    /// Truncate (ftruncate, truncate).
    Truncate,
    /// Rename (atomic exchange of two directory entries).
    Rename,
    /// Hard link creation.
    Link,
    /// Unlink (directory entry removal).
    Unlink,
    /// Advisory or mandatory lock operations (fcntl F_SETLK, flock).
    Lock,
}

impl PosixOperationClass {
    /// Return the minimum ordering guarantee required for this operation
    /// class to be POSIX-correct.
    ///
    /// - `Write` and `Truncate` require at least causal ordering so that
    ///   a read following a write on any node sees the write.
    /// - `Rename` requires total ordering: the atomic exchange must be
    ///   visible consistently across all nodes.
    /// - `Link` and `Unlink` require causal ordering.
    /// - `Lock` requires no ordering guarantee (locks are advisory and
    ///   handled by the lease manager independently of write ordering).
    pub const fn required_guarantee(self) -> OrderingGuarantee {
        match self {
            Self::Write | Self::Truncate | Self::Link | Self::Unlink => {
                OrderingGuarantee::CausalOrder
            }
            Self::Rename => OrderingGuarantee::TotalOrder,
            Self::Lock => OrderingGuarantee::None,
        }
    }
}
impl fmt::Display for PosixOperationClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Write => "Write",
            Self::Truncate => "Truncate",
            Self::Rename => "Rename",
            Self::Link => "Link",
            Self::Unlink => "Unlink",
            Self::Lock => "Lock",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------

// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── CoordinationStrategy ──────────────────────────────────────────

    #[test]
    fn strategy_level_count() {
        assert_eq!(CoordinationStrategy::level_count(), 5);
    }

    #[test]
    fn strategy_from_to_level_roundtrip() {
        for level in 0..5u8 {
            let s = CoordinationStrategy::from_level(level).unwrap();
            assert_eq!(s.to_level(), level);
        }
    }

    #[test]
    fn strategy_from_level_out_of_range() {
        assert_eq!(CoordinationStrategy::from_level(5), None);
        assert_eq!(CoordinationStrategy::from_level(255), None);
    }

    #[test]
    fn strategy_ordering_matches_contention() {
        // Higher contention = higher ordinal.
        assert!(CoordinationStrategy::Uncontended < CoordinationStrategy::Optimistic);
        assert!(CoordinationStrategy::Optimistic < CoordinationStrategy::Lease);
        assert!(CoordinationStrategy::Lease < CoordinationStrategy::TDMA);
        assert!(CoordinationStrategy::TDMA < CoordinationStrategy::LeaderSerialized);
    }

    #[test]
    fn strategy_requires_coordination() {
        assert!(!CoordinationStrategy::Uncontended.requires_coordination());
        assert!(!CoordinationStrategy::Optimistic.requires_coordination());
        assert!(CoordinationStrategy::Lease.requires_coordination());
        assert!(CoordinationStrategy::TDMA.requires_coordination());
        assert!(CoordinationStrategy::LeaderSerialized.requires_coordination());
    }

    #[test]
    fn strategy_uses_leases() {
        assert!(!CoordinationStrategy::Uncontended.uses_leases());
        assert!(!CoordinationStrategy::Optimistic.uses_leases());
        assert!(CoordinationStrategy::Lease.uses_leases());
        assert!(!CoordinationStrategy::TDMA.uses_leases());
        assert!(!CoordinationStrategy::LeaderSerialized.uses_leases());
    }

    #[test]
    fn strategy_allows_concurrent_writers() {
        assert!(CoordinationStrategy::Uncontended.allows_concurrent_writers());
        assert!(CoordinationStrategy::Optimistic.allows_concurrent_writers());
        assert!(CoordinationStrategy::Lease.allows_concurrent_writers());
        assert!(CoordinationStrategy::TDMA.allows_concurrent_writers());
        assert!(!CoordinationStrategy::LeaderSerialized.allows_concurrent_writers());
    }

    // ── TransitionPhase ──────────────────────────────────────────────

    #[test]
    fn phase_progression_quiesce_to_publish() {
        assert_eq!(
            TransitionPhase::Quiesce.next(),
            Some(TransitionPhase::Drain)
        );
        assert_eq!(TransitionPhase::Drain.next(), Some(TransitionPhase::Verify));
        assert_eq!(
            TransitionPhase::Verify.next(),
            Some(TransitionPhase::Switch)
        );
        assert_eq!(
            TransitionPhase::Switch.next(),
            Some(TransitionPhase::Publish)
        );
        assert_eq!(TransitionPhase::Publish.next(), None);
    }

    #[test]
    fn phase_reversibility() {
        assert!(TransitionPhase::Quiesce.is_reversible());
        assert!(TransitionPhase::Drain.is_reversible());
        assert!(TransitionPhase::Verify.is_reversible());
        assert!(TransitionPhase::Switch.is_reversible());
        assert!(!TransitionPhase::Publish.is_reversible());
    }

    // ── StrategyEpoch ────────────────────────────────────────────────

    #[test]
    fn epoch_next_increments() {
        let e = StrategyEpoch::new(3);
        assert_eq!(e.next(), StrategyEpoch::new(4));
    }

    #[test]
    fn epoch_zero_is_initial() {
        assert_eq!(StrategyEpoch::ZERO.value(), 0);
    }

    #[test]
    fn epoch_ordering() {
        assert!(StrategyEpoch::new(1) > StrategyEpoch::new(0));
        assert!(StrategyEpoch::new(5) == StrategyEpoch::new(5));
    }

    #[test]
    fn epoch_from_membership() {
        let membership = EpochId::new(42);
        let se = StrategyEpoch::from_membership_epoch(membership);
        assert_eq!(se.value(), 42);
        // Also test From impl
        let se2: StrategyEpoch = membership.into();
        assert_eq!(se2.value(), 42);
    }

    // ── StrategyTransition ───────────────────────────────────────────

    #[test]
    fn transition_full_lifecycle() {
        let mut t = StrategyTransition::begin(
            CoordinationStrategy::Optimistic,
            CoordinationStrategy::Lease,
            StrategyEpoch::new(1),
        );
        assert_eq!(t.phase(), TransitionPhase::Quiesce);
        assert!(t.is_active());

        assert_eq!(t.advance(), Ok(TransitionPhase::Drain));
        assert_eq!(t.advance(), Ok(TransitionPhase::Verify));
        assert_eq!(t.advance(), Ok(TransitionPhase::Switch));
        assert_eq!(t.advance(), Ok(TransitionPhase::Publish));

        assert!(t.is_published());
        assert!(!t.is_active());
    }

    #[test]
    #[should_panic(expected = "transition must change strategy")]
    fn transition_rejects_noop() {
        StrategyTransition::begin(
            CoordinationStrategy::Uncontended,
            CoordinationStrategy::Uncontended,
            StrategyEpoch::new(1),
        );
    }

    #[test]
    fn transition_advance_past_publish_is_error() {
        let mut t = StrategyTransition::begin(
            CoordinationStrategy::Uncontended,
            CoordinationStrategy::Optimistic,
            StrategyEpoch::new(1),
        );
        // Advance through all 4 steps to Publish.
        t.advance().unwrap(); // Quiesce -> Drain
        t.advance().unwrap(); // Drain -> Verify
        t.advance().unwrap(); // Verify -> Switch
        t.advance().unwrap(); // Switch -> Publish
                              // Already at Publish; next advance is an error.
        assert_eq!(t.advance(), Err(TransitionError::InvalidPhaseProgression));
    }

    #[test]
    fn transition_rollback_before_publish_succeeds() {
        let mut t = StrategyTransition::begin(
            CoordinationStrategy::Optimistic,
            CoordinationStrategy::Lease,
            StrategyEpoch::new(1),
        );
        t.advance().unwrap(); // Quiesce -> Drain
        t.advance().unwrap(); // Drain -> Verify
                              // Rollback at Verify should succeed.
        assert_eq!(t.rollback(), Ok(()));
    }

    #[test]
    fn transition_rollback_after_publish_fails() {
        let mut t = StrategyTransition::begin(
            CoordinationStrategy::Optimistic,
            CoordinationStrategy::Lease,
            StrategyEpoch::new(1),
        );
        t.advance().unwrap(); // -> Drain
        t.advance().unwrap(); // -> Verify
        t.advance().unwrap(); // -> Switch
        t.advance().unwrap(); // -> Publish
                              // Rollback after Publish is an error.
        assert_eq!(t.rollback(), Err(TransitionError::InvalidPhaseProgression));
    }

    #[test]
    fn transition_cross_all_levels() {
        // Verify every adjacent level pair transitions cleanly.
        let pairs = [
            (
                CoordinationStrategy::Uncontended,
                CoordinationStrategy::Optimistic,
            ),
            (
                CoordinationStrategy::Optimistic,
                CoordinationStrategy::Lease,
            ),
            (CoordinationStrategy::Lease, CoordinationStrategy::TDMA),
            (
                CoordinationStrategy::TDMA,
                CoordinationStrategy::LeaderSerialized,
            ),
        ];
        for (from, to) in &pairs {
            let mut t = StrategyTransition::begin(*from, *to, StrategyEpoch::new(1));
            t.advance().unwrap();
            t.advance().unwrap();
            t.advance().unwrap();
            t.advance().unwrap();
            assert!(t.is_published());
        }
    }

    // ── EpochFence ───────────────────────────────────────────────────

    #[test]
    fn fence_admits_current_epoch() {
        let fence = EpochFence::new(StrategyEpoch::new(5));
        assert_eq!(fence.admit(StrategyEpoch::new(5)), Ok(()));
    }

    #[test]
    fn fence_admits_future_epoch() {
        let fence = EpochFence::new(StrategyEpoch::new(5));
        assert_eq!(fence.admit(StrategyEpoch::new(7)), Ok(()));
    }

    #[test]
    fn fence_rejects_stale_epoch() {
        let fence = EpochFence::new(StrategyEpoch::new(5));
        let err = fence.admit(StrategyEpoch::new(3)).unwrap_err();
        assert_eq!(
            err,
            FenceError::StaleEpoch {
                fence_epoch: 5,
                operation_epoch: 3,
            }
        );
    }

    #[test]
    fn fence_advance_is_monotonic() {
        let mut fence = EpochFence::new(StrategyEpoch::new(1));
        fence.advance(StrategyEpoch::new(3));
        assert_eq!(fence.current_epoch(), StrategyEpoch::new(3));
        // Old epoch is now rejected.
        assert!(fence.admit(StrategyEpoch::new(1)).is_err());
    }

    #[test]
    #[should_panic(expected = "fence epoch must be monotonic")]
    fn fence_advance_rejects_regression() {
        let mut fence = EpochFence::new(StrategyEpoch::new(5));
        fence.advance(StrategyEpoch::new(3)); // must panic
    }

    #[test]
    fn fence_current_epoch_accessor() {
        let fence = EpochFence::new(StrategyEpoch::new(42));
        assert_eq!(fence.current_epoch(), StrategyEpoch::new(42));
    }

    // ── Transition + Fence integration ──────────────────────────────

    #[test]
    fn post_transition_fence_rejects_old_epoch() {
        let old_epoch = StrategyEpoch::new(5);
        let new_epoch = old_epoch.next(); // 6

        let mut fence = EpochFence::new(old_epoch);

        // Begin and complete a transition.
        let mut t = StrategyTransition::begin(
            CoordinationStrategy::Optimistic,
            CoordinationStrategy::Lease,
            new_epoch,
        );
        t.advance().unwrap();
        t.advance().unwrap();
        t.advance().unwrap();
        t.advance().unwrap(); // Publish
        assert!(t.is_published());

        // Advance the fence to the new epoch.
        fence.advance(new_epoch);

        // Old-epoch operations are now rejected.
        assert!(fence.admit(old_epoch).is_err());
        // New-epoch operations are admitted.
        assert_eq!(fence.admit(new_epoch), Ok(()));
    }

    // ── StrategyCapabilities ─────────────────────────────────────────────────

    #[test]
    fn capabilities_matrix_is_internally_consistent() {
        // Uncontended and Optimistic: no ordering, no fencing.
        for s in &[
            CoordinationStrategy::Uncontended,
            CoordinationStrategy::Optimistic,
        ] {
            let c = s.capabilities();
            assert_eq!(c.ordering_guarantee, OrderingGuarantee::None);
            assert!(!c.requires_quorum);
            assert!(!c.supports_fencing);
        }

        // Lease: causal ordering, quorum, fencing.
        let lc = CoordinationStrategy::Lease.capabilities();
        assert_eq!(lc.ordering_guarantee, OrderingGuarantee::CausalOrder);
        assert!(lc.requires_quorum);
        assert!(lc.supports_fencing);

        // TDMA: causal ordering, single writer, fencing, no quorum.
        let tc = CoordinationStrategy::TDMA.capabilities();
        assert_eq!(tc.ordering_guarantee, OrderingGuarantee::CausalOrder);
        assert_eq!(tc.max_concurrent_writers.unwrap().get(), 1);
        assert!(!tc.requires_quorum);
        assert!(tc.supports_fencing);

        // LeaderSerialized: total ordering, single writer, fencing.
        let lsc = CoordinationStrategy::LeaderSerialized.capabilities();
        assert_eq!(lsc.ordering_guarantee, OrderingGuarantee::TotalOrder);
        assert_eq!(lsc.max_concurrent_writers.unwrap().get(), 1);
        assert!(!lsc.requires_quorum);
        assert!(lsc.supports_fencing);
    }

    #[test]
    fn capabilities_ordering_guarantee_increases_with_strategy() {
        let strategies = [
            CoordinationStrategy::Uncontended,
            CoordinationStrategy::Optimistic,
            CoordinationStrategy::Lease,
            CoordinationStrategy::TDMA,
            CoordinationStrategy::LeaderSerialized,
        ];
        for i in 0..(strategies.len() - 1) {
            let lower = strategies[i].capabilities();
            let higher = strategies[i + 1].capabilities();
            assert!(
                lower.ordering_guarantee <= higher.ordering_guarantee,
                "strategy {i} lower={:?} must be <= higher={:?}",
                lower.ordering_guarantee,
                higher.ordering_guarantee,
            );
        }
    }

    // ── PosixOperationClass ─────────────────────────────────────────────────

    #[test]
    fn posix_operation_required_guarantees() {
        // Rename needs total ordering.
        assert_eq!(
            PosixOperationClass::Rename.required_guarantee(),
            OrderingGuarantee::TotalOrder,
        );
        // Write, Truncate, Link, Unlink need causal.
        for op in &[
            PosixOperationClass::Write,
            PosixOperationClass::Truncate,
            PosixOperationClass::Link,
            PosixOperationClass::Unlink,
        ] {
            assert_eq!(
                op.required_guarantee(),
                OrderingGuarantee::CausalOrder,
                "op {op:?} requires CausalOrder",
            );
        }
        // Lock needs no ordering guarantee.
        assert_eq!(
            PosixOperationClass::Lock.required_guarantee(),
            OrderingGuarantee::None,
        );
    }

    #[test]
    fn satisfies_per_strategy_per_op_matrix() {
        /// Helper: check which operation classes a strategy satisfies.
        fn check(
            strategy: CoordinationStrategy,
            expected_write: bool,
            expected_truncate: bool,
            expected_rename: bool,
            expected_link: bool,
            expected_unlink: bool,
            expected_lock: bool,
        ) {
            let caps = strategy.capabilities();
            assert_eq!(
                caps.satisfies(PosixOperationClass::Write),
                expected_write,
                "{strategy:?} satisfies Write = {expected_write}",
            );
            assert_eq!(
                caps.satisfies(PosixOperationClass::Truncate),
                expected_truncate,
                "{strategy:?} satisfies Truncate = {expected_truncate}",
            );
            assert_eq!(
                caps.satisfies(PosixOperationClass::Rename),
                expected_rename,
                "{strategy:?} satisfies Rename = {expected_rename}",
            );
            assert_eq!(
                caps.satisfies(PosixOperationClass::Link),
                expected_link,
                "{strategy:?} satisfies Link = {expected_link}",
            );
            assert_eq!(
                caps.satisfies(PosixOperationClass::Unlink),
                expected_unlink,
                "{strategy:?} satisfies Unlink = {expected_unlink}",
            );
            assert_eq!(
                caps.satisfies(PosixOperationClass::Lock),
                expected_lock,
                "{strategy:?} satisfies Lock = {expected_lock}",
            );
        }

        // Uncontended: no ordering -> Lock only.
        check(
            CoordinationStrategy::Uncontended,
            false, // Write
            false, // Truncate
            false, // Rename
            false, // Link
            false, // Unlink
            true,  // Lock
        );

        // Optimistic: no ordering -> Lock only.
        check(
            CoordinationStrategy::Optimistic,
            false,
            false,
            false,
            false,
            false,
            true,
        );

        // Lease: causal ordering -> everything except Rename.
        check(
            CoordinationStrategy::Lease,
            true,  // Write
            true,  // Truncate
            false, // Rename (needs Total)
            true,  // Link
            true,  // Unlink
            true,  // Lock
        );

        // TDMA: causal ordering -> everything except Rename.
        check(
            CoordinationStrategy::TDMA,
            true,
            true,
            false,
            true,
            true,
            true,
        );

        // LeaderSerialized: total ordering -> everything.
        check(
            CoordinationStrategy::LeaderSerialized,
            true,
            true,
            true,
            true,
            true,
            true,
        );
    }

    #[test]
    fn lock_is_satisfied_by_all_strategies() {
        for s in &[
            CoordinationStrategy::Uncontended,
            CoordinationStrategy::Optimistic,
            CoordinationStrategy::Lease,
            CoordinationStrategy::TDMA,
            CoordinationStrategy::LeaderSerialized,
        ] {
            assert!(
                s.capabilities().satisfies(PosixOperationClass::Lock),
                "{s:?} must satisfy Lock",
            );
        }
    }

    #[test]
    fn rename_only_satisfied_by_total_order() {
        // Rename requires TotalOrder -> only LeaderSerialized.
        assert!(!CoordinationStrategy::Uncontended
            .capabilities()
            .satisfies(PosixOperationClass::Rename));
        assert!(!CoordinationStrategy::Optimistic
            .capabilities()
            .satisfies(PosixOperationClass::Rename));
        assert!(!CoordinationStrategy::Lease
            .capabilities()
            .satisfies(PosixOperationClass::Rename));
        assert!(!CoordinationStrategy::TDMA
            .capabilities()
            .satisfies(PosixOperationClass::Rename));
        assert!(CoordinationStrategy::LeaderSerialized
            .capabilities()
            .satisfies(PosixOperationClass::Rename));
    }

    // ── Reverse (de-escalation) transitions ──────────────────────────

    #[test]
    fn transition_downward_all_adjacent_pairs() {
        // Verify every adjacent de-escalation transitions cleanly.
        let pairs = [
            (
                CoordinationStrategy::Optimistic,
                CoordinationStrategy::Uncontended,
            ),
            (
                CoordinationStrategy::Lease,
                CoordinationStrategy::Optimistic,
            ),
            (CoordinationStrategy::TDMA, CoordinationStrategy::Lease),
            (
                CoordinationStrategy::LeaderSerialized,
                CoordinationStrategy::TDMA,
            ),
        ];
        for (from, to) in &pairs {
            let mut t = StrategyTransition::begin(*from, *to, StrategyEpoch::new(1));
            assert_eq!(t.from, *from);
            assert_eq!(t.to, *to);
            t.advance().unwrap();
            t.advance().unwrap();
            t.advance().unwrap();
            t.advance().unwrap();
            assert!(t.is_published());
        }
    }

    #[test]
    fn transition_downward_rollback_retransition() {
        // Rollback a downward transition then retry successfully.
        let mut t = StrategyTransition::begin(
            CoordinationStrategy::TDMA,
            CoordinationStrategy::Lease,
            StrategyEpoch::new(7),
        );
        t.advance().unwrap(); // Quiesce -> Drain
        t.advance().unwrap(); // Drain -> Verify
        assert_eq!(t.rollback(), Ok(()));

        // Retry same downward transition.
        let mut t2 = StrategyTransition::begin(
            CoordinationStrategy::TDMA,
            CoordinationStrategy::Lease,
            StrategyEpoch::new(8),
        );
        t2.advance().unwrap();
        t2.advance().unwrap();
        t2.advance().unwrap();
        t2.advance().unwrap();
        assert!(t2.is_published());
    }

    // ── Non-adjacent (skip) transitions ──────────────────────────────

    #[test]
    fn transition_skip_levels_upward() {
        // Non-adjacent upward transitions are valid in the current
        // implementation (no adjacency enforcement exists).
        let skips = [
            (
                CoordinationStrategy::Uncontended,
                CoordinationStrategy::Lease,
            ),
            (CoordinationStrategy::Optimistic, CoordinationStrategy::TDMA),
            (
                CoordinationStrategy::Lease,
                CoordinationStrategy::LeaderSerialized,
            ),
            (
                CoordinationStrategy::Uncontended,
                CoordinationStrategy::TDMA,
            ),
            (
                CoordinationStrategy::Optimistic,
                CoordinationStrategy::LeaderSerialized,
            ),
            (
                CoordinationStrategy::Uncontended,
                CoordinationStrategy::LeaderSerialized,
            ),
        ];
        for (from, to) in &skips {
            let mut t = StrategyTransition::begin(*from, *to, StrategyEpoch::new(1));
            t.advance().unwrap();
            t.advance().unwrap();
            t.advance().unwrap();
            t.advance().unwrap();
            assert!(t.is_published());
        }
    }

    #[test]
    fn transition_skip_levels_downward() {
        let skips = [
            (
                CoordinationStrategy::LeaderSerialized,
                CoordinationStrategy::Lease,
            ),
            (CoordinationStrategy::TDMA, CoordinationStrategy::Optimistic),
            (
                CoordinationStrategy::Lease,
                CoordinationStrategy::Uncontended,
            ),
            (
                CoordinationStrategy::LeaderSerialized,
                CoordinationStrategy::Optimistic,
            ),
            (
                CoordinationStrategy::TDMA,
                CoordinationStrategy::Uncontended,
            ),
            (
                CoordinationStrategy::LeaderSerialized,
                CoordinationStrategy::Uncontended,
            ),
        ];
        for (from, to) in &skips {
            let mut t = StrategyTransition::begin(*from, *to, StrategyEpoch::new(1));
            t.advance().unwrap();
            t.advance().unwrap();
            t.advance().unwrap();
            t.advance().unwrap();
            assert!(t.is_published());
        }
    }

    // ── Strategy discriminant uniqueness ─────────────────────────────

    #[test]
    fn strategy_all_discriminants_unique() {
        use std::collections::HashSet;
        let strategies = [
            CoordinationStrategy::Uncontended,
            CoordinationStrategy::Optimistic,
            CoordinationStrategy::Lease,
            CoordinationStrategy::TDMA,
            CoordinationStrategy::LeaderSerialized,
        ];
        let mut seen = HashSet::new();
        for s in &strategies {
            let disc = s.to_level();
            assert!(seen.insert(disc), "duplicate discriminant {disc}");
        }
        assert_eq!(seen.len(), 5);
    }

    // ═══════════════════════════════════════════════════════════════
    // Display formatting
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn display_coordination_strategy_all_variants() {
        assert_eq!(CoordinationStrategy::Uncontended.to_string(), "Uncontended");
        assert_eq!(CoordinationStrategy::Optimistic.to_string(), "Optimistic");
        assert_eq!(CoordinationStrategy::Lease.to_string(), "Lease");
        assert_eq!(CoordinationStrategy::TDMA.to_string(), "TDMA");
        assert_eq!(
            CoordinationStrategy::LeaderSerialized.to_string(),
            "LeaderSerialized"
        );
    }

    #[test]
    fn display_transition_phase_all_variants() {
        assert_eq!(TransitionPhase::Quiesce.to_string(), "Quiesce");
        assert_eq!(TransitionPhase::Drain.to_string(), "Drain");
        assert_eq!(TransitionPhase::Verify.to_string(), "Verify");
        assert_eq!(TransitionPhase::Switch.to_string(), "Switch");
        assert_eq!(TransitionPhase::Publish.to_string(), "Publish");
    }

    #[test]
    fn display_strategy_epoch() {
        assert_eq!(StrategyEpoch::new(42).to_string(), "42");
        assert_eq!(StrategyEpoch::ZERO.to_string(), "0");
    }

    #[test]
    fn display_transition_error_all_variants() {
        assert_eq!(
            TransitionError::InvalidPhaseProgression.to_string(),
            "invalid phase progression"
        );
        assert_eq!(TransitionError::DrainTimeout.to_string(), "drain timeout");
        assert_eq!(
            TransitionError::VerificationFailed.to_string(),
            "verification failed"
        );
        assert_eq!(TransitionError::StaleEpoch.to_string(), "stale epoch");
        assert_eq!(TransitionError::RolledBack.to_string(), "rolled back");
    }

    #[test]
    fn display_fence_error() {
        let err = FenceError::StaleEpoch {
            fence_epoch: 5,
            operation_epoch: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("stale epoch"));
        assert!(msg.contains("5"));
        assert!(msg.contains("3"));
    }

    #[test]
    fn display_ordering_guarantee_all_variants() {
        assert_eq!(OrderingGuarantee::None.to_string(), "None");
        assert_eq!(OrderingGuarantee::CausalOrder.to_string(), "CausalOrder");
        assert_eq!(OrderingGuarantee::TotalOrder.to_string(), "TotalOrder");
    }

    #[test]
    fn display_posix_operation_class_all_variants() {
        assert_eq!(PosixOperationClass::Write.to_string(), "Write");
        assert_eq!(PosixOperationClass::Truncate.to_string(), "Truncate");
        assert_eq!(PosixOperationClass::Rename.to_string(), "Rename");
        assert_eq!(PosixOperationClass::Link.to_string(), "Link");
        assert_eq!(PosixOperationClass::Unlink.to_string(), "Unlink");
        assert_eq!(PosixOperationClass::Lock.to_string(), "Lock");
    }

    #[test]
    fn display_roundtrip_via_format() {
        for s in &[
            CoordinationStrategy::Uncontended,
            CoordinationStrategy::Optimistic,
            CoordinationStrategy::Lease,
            CoordinationStrategy::TDMA,
            CoordinationStrategy::LeaderSerialized,
        ] {
            let rendered = format!("{s}");
            assert!(!rendered.is_empty());
            assert!(format!("{s:?}").contains(&rendered));
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Debug formatting
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn debug_coordination_strategy_contains_variant_name() {
        let strategies = [
            CoordinationStrategy::Uncontended,
            CoordinationStrategy::Optimistic,
            CoordinationStrategy::Lease,
            CoordinationStrategy::TDMA,
            CoordinationStrategy::LeaderSerialized,
        ];
        let expected_names = [
            "Uncontended",
            "Optimistic",
            "Lease",
            "TDMA",
            "LeaderSerialized",
        ];
        for (s, name) in strategies.iter().zip(expected_names.iter()) {
            let dbg = format!("{s:?}");
            assert!(
                dbg.contains(name),
                "Debug for {name} missing variant name: {dbg}"
            );
        }
    }

    #[test]
    fn debug_transition_phase_contains_variant_name() {
        let phases = [
            TransitionPhase::Quiesce,
            TransitionPhase::Drain,
            TransitionPhase::Verify,
            TransitionPhase::Switch,
            TransitionPhase::Publish,
        ];
        let names = ["Quiesce", "Drain", "Verify", "Switch", "Publish"];
        for (p, name) in phases.iter().zip(names.iter()) {
            assert!(format!("{p:?}").contains(name));
        }
    }

    #[test]
    fn debug_fence_error_contains_field_values() {
        let err = FenceError::StaleEpoch {
            fence_epoch: 7,
            operation_epoch: 2,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("7"));
        assert!(dbg.contains("2"));
    }

    // ═══════════════════════════════════════════════════════════════
    // Default variant
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn default_strategy_is_uncontended() {
        assert_eq!(
            CoordinationStrategy::default(),
            CoordinationStrategy::Uncontended
        );
    }

    #[test]
    fn default_strategy_has_lowest_ordinal() {
        let default = CoordinationStrategy::default();
        let all = [
            CoordinationStrategy::Uncontended,
            CoordinationStrategy::Optimistic,
            CoordinationStrategy::Lease,
            CoordinationStrategy::TDMA,
            CoordinationStrategy::LeaderSerialized,
        ];
        for s in &all {
            assert!(default as u8 <= s.to_level());
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Serialization round-trip (serde feature)
    // ═══════════════════════════════════════════════════════════════

    #[cfg(feature = "serde")]
    mod serde_tests {
        use super::*;

        fn json_roundtrip<
            T: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug + PartialEq,
        >(
            val: &T,
        ) {
            let encoded = serde_json::to_string(val).expect("serialize");
            let decoded: T = serde_json::from_str(&encoded).expect("deserialize");
            assert_eq!(&decoded, val, "round-trip mismatch for {val:?}");
        }

        #[test]
        fn serde_coordination_strategy_all_variants() {
            for s in &[
                CoordinationStrategy::Uncontended,
                CoordinationStrategy::Optimistic,
                CoordinationStrategy::Lease,
                CoordinationStrategy::TDMA,
                CoordinationStrategy::LeaderSerialized,
            ] {
                json_roundtrip(s);
            }
        }

        #[test]
        fn serde_transition_phase_all_variants() {
            for p in &[
                TransitionPhase::Quiesce,
                TransitionPhase::Drain,
                TransitionPhase::Verify,
                TransitionPhase::Switch,
                TransitionPhase::Publish,
            ] {
                json_roundtrip(p);
            }
        }

        #[test]
        fn serde_strategy_epoch_roundtrip() {
            for val in [0, 1, 42, u64::MAX - 1] {
                json_roundtrip(&StrategyEpoch::new(val));
            }
        }

        #[test]
        fn serde_transition_error_all_variants() {
            for err in &[
                TransitionError::InvalidPhaseProgression,
                TransitionError::DrainTimeout,
                TransitionError::VerificationFailed,
                TransitionError::StaleEpoch,
                TransitionError::RolledBack,
            ] {
                json_roundtrip(err);
            }
        }

        #[test]
        fn serde_fence_error_roundtrip() {
            let err = FenceError::StaleEpoch {
                fence_epoch: 5,
                operation_epoch: 3,
            };
            json_roundtrip(&err);
        }

        #[test]
        fn serde_ordering_guarantee_all_variants() {
            for g in &[
                OrderingGuarantee::None,
                OrderingGuarantee::CausalOrder,
                OrderingGuarantee::TotalOrder,
            ] {
                json_roundtrip(g);
            }
        }

        #[test]
        fn serde_posix_operation_class_all_variants() {
            for op in &[
                PosixOperationClass::Write,
                PosixOperationClass::Truncate,
                PosixOperationClass::Rename,
                PosixOperationClass::Link,
                PosixOperationClass::Unlink,
                PosixOperationClass::Lock,
            ] {
                json_roundtrip(op);
            }
        }

        #[test]
        fn serde_unknown_discriminant_rejected() {
            let json = "5";
            let result: Result<CoordinationStrategy, _> = serde_json::from_str(json);
            assert!(result.is_err(), "unknown discriminant should be rejected");
        }

        #[test]
        fn serde_negative_discriminant_rejected() {
            let json = "-1";
            let result: Result<CoordinationStrategy, _> = serde_json::from_str(json);
            assert!(result.is_err(), "negative discriminant should be rejected");
        }

        #[test]
        fn serde_unknown_ordering_guarantee_rejected() {
            let json = "3";
            let result: Result<OrderingGuarantee, _> = serde_json::from_str(json);
            assert!(result.is_err(), "unknown discriminant should be rejected");
        }
    }
}
