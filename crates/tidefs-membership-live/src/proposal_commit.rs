#![forbid(unsafe_code)]

//! Coordinator proposal-to-epoch commit pipeline with monotonic sequencing
//! and atomic state advancement.
//!
//! ## Role
//!
//! The proposal commit pipeline is the central coordinator-side path that
//! accepts validated membership proposals (join, eviction, departure) and
//! commits them through an ordered, atomic pipeline:
//!
//! 1. **Sequence**: assign a monotonic proposal sequence number.
//! 2. **Validate**: check idempotency, incarnation freshness, and state
//!    preconditions.
//! 3. **Apply**: atomically advance the epoch state, producing a successor
//!    epoch.
//! 4. **Journal**: record the transition in the coordinator transition
//!    journal for crash-recovery replay.
//! 5. **Dispatch**: publish the committed epoch to subscribers (transport,
//!    epoch-gate, admission control).
//!
//! ## Thread safety
//!
//! [`ProposalSequencer`] uses an `AtomicU64` counter so multiple
//! coordinator handlers (join, eviction, departure) can allocate
//! sequence numbers without contention.

use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// ProposalSequencer
// ---------------------------------------------------------------------------

/// Monotonic u64 proposal sequence number generator.
///
/// Thread-safe via [`AtomicU64`]. Allocates strictly increasing sequence
/// numbers across all coordinator proposal sources (join, eviction,
/// departure). The sequence number is embedded in epoch proposals so
/// consumers can detect out-of-order or replayed proposals.
///
/// # Lifecycle
///
/// Construct at coordinator startup with `new()` or `starting_at(n)`.
/// Each call to `next()` returns an incrementing sequence number.
/// `current()` exposes the last allocated value without advancing.
///
/// # Example
///
/// ```ignore
/// let seq = ProposalSequencer::new();
/// assert_eq!(seq.next(), 1);
/// assert_eq!(seq.next(), 2);
/// assert_eq!(seq.next(), 3);
/// assert_eq!(seq.current(), 3);
/// ```
#[derive(Debug)]
pub struct ProposalSequencer {
    counter: AtomicU64,
}

impl ProposalSequencer {
    /// Create a new sequencer starting at sequence number 0 (first
    /// `next()` returns 1).
    #[must_use]
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }

    /// Create a sequencer resuming from a previously persisted sequence
    /// number. The next call to `next()` returns `previous + 1`.
    #[must_use]
    pub fn starting_at(previous: u64) -> Self {
        Self {
            counter: AtomicU64::new(previous),
        }
    }

    /// Allocate the next monotonic proposal sequence number.
    ///
    /// Returns the new sequence number. Thread-safe: concurrent callers
    /// each receive a distinct, monotonically increasing value.
    pub fn next(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Return the last allocated sequence number without advancing.
    ///
    /// Useful for snapshotting the current state for persistence or
    /// diagnostics.
    #[must_use]
    pub fn current(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }

    /// Reset the sequencer to a given value.
    ///
    /// Only safe during coordinator bootstrap or recovery when no
    /// concurrent callers are allocating sequence numbers.
    pub fn reset(&self, value: u64) {
        self.counter.store(value, Ordering::SeqCst);
    }
}

impl Default for ProposalSequencer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ProposalCommitError
// ---------------------------------------------------------------------------

/// Errors produced by the proposal commit pipeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalCommitError {
    /// Two proposals were submitted at the same sequence number.
    SequenceConflict { sequence: u64 },
    /// The proposal carries a stale coordinator incarnation.
    StaleIncarnation {
        msg_incarnation: u64,
        current_incarnation: u64,
    },
    /// The proposal idempotency key was already committed.
    DuplicateProposal { committed_epoch: u64 },
    /// The proposal could not be applied to the current epoch state.
    StateApplicationFailure { reason: String },
}

impl std::fmt::Display for ProposalCommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SequenceConflict { sequence } => {
                write!(f, "sequence conflict at sequence number {sequence}")
            }
            Self::StaleIncarnation {
                msg_incarnation,
                current_incarnation,
            } => {
                write!(
                    f,
                    "stale incarnation: msg={msg_incarnation} current={current_incarnation}"
                )
            }
            Self::DuplicateProposal { committed_epoch } => {
                write!(
                    f,
                    "duplicate proposal already committed at epoch {committed_epoch}"
                )
            }
            Self::StateApplicationFailure { reason } => {
                write!(f, "state application failure: {reason}")
            }
        }
    }
}

impl std::error::Error for ProposalCommitError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    // ── ProposalSequencer ──────────────────────────────────────────

    #[test]
    fn new_starts_at_zero_current() {
        let seq = ProposalSequencer::new();
        assert_eq!(seq.current(), 0);
    }

    #[test]
    fn first_next_returns_one() {
        let seq = ProposalSequencer::new();
        assert_eq!(seq.next(), 1);
        assert_eq!(seq.current(), 1);
    }

    #[test]
    fn sequential_allocation_monotonic() {
        let seq = ProposalSequencer::new();
        for expected in 1..=100u64 {
            assert_eq!(seq.next(), expected);
        }
        assert_eq!(seq.current(), 100);
    }

    #[test]
    fn starting_at_resumes_from_given_value() {
        let seq = ProposalSequencer::starting_at(42);
        assert_eq!(seq.current(), 42);
        assert_eq!(seq.next(), 43);
        assert_eq!(seq.next(), 44);
        assert_eq!(seq.current(), 44);
    }

    #[test]
    fn starting_at_zero_equivalent_to_new() {
        let seq = ProposalSequencer::starting_at(0);
        assert_eq!(seq.current(), 0);
        assert_eq!(seq.next(), 1);
        assert_eq!(seq.next(), 2);
    }

    #[test]
    fn current_does_not_advance() {
        let seq = ProposalSequencer::new();
        assert_eq!(seq.next(), 1);
        assert_eq!(seq.current(), 1);
        assert_eq!(seq.current(), 1);
        assert_eq!(seq.current(), 1);
    }

    #[test]
    fn reset_sets_counter_to_value() {
        let seq = ProposalSequencer::new();
        seq.next();
        seq.next();
        seq.next();
        assert_eq!(seq.current(), 3);
        seq.reset(100);
        assert_eq!(seq.current(), 100);
        assert_eq!(seq.next(), 101);
    }

    #[test]
    fn default_creates_new_sequencer() {
        let seq = ProposalSequencer::default();
        assert_eq!(seq.current(), 0);
        assert_eq!(seq.next(), 1);
    }

    #[test]
    fn concurrent_allocation_is_monotonic() {
        let seq = Arc::new(ProposalSequencer::new());
        let num_threads = 8;
        let per_thread = 1000;

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let seq = Arc::clone(&seq);
                thread::spawn(move || {
                    let mut values = Vec::with_capacity(per_thread);
                    for _ in 0..per_thread {
                        values.push(seq.next());
                    }
                    values
                })
            })
            .collect();

        let mut all_values: Vec<u64> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();

        all_values.sort();
        let expected: Vec<u64> = (1..=(num_threads * per_thread) as u64).collect();
        assert_eq!(all_values, expected);
        assert_eq!(seq.current(), (num_threads * per_thread) as u64);
    }

    #[test]
    fn concurrent_allocation_no_duplicates() {
        let seq = Arc::new(ProposalSequencer::new());
        let num_threads = 4;
        let per_thread = 500;

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let seq = Arc::clone(&seq);
                thread::spawn(move || {
                    let mut values = Vec::with_capacity(per_thread);
                    for _ in 0..per_thread {
                        values.push(seq.next());
                    }
                    values
                })
            })
            .collect();

        let mut all_values: Vec<u64> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();

        all_values.sort();
        let total: usize = all_values.len();
        all_values.dedup();
        assert_eq!(all_values.len(), total, "no duplicates expected");
    }

    // ── ProposalCommitError ────────────────────────────────────────

    #[test]
    fn sequence_conflict_display() {
        let err = ProposalCommitError::SequenceConflict { sequence: 42 };
        let msg = err.to_string();
        assert!(msg.contains("42"));
        assert!(msg.contains("sequence conflict"));
    }

    #[test]
    fn stale_incarnation_display() {
        let err = ProposalCommitError::StaleIncarnation {
            msg_incarnation: 2,
            current_incarnation: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains("msg=2"));
        assert!(msg.contains("current=5"));
    }

    #[test]
    fn duplicate_proposal_display() {
        let err = ProposalCommitError::DuplicateProposal { committed_epoch: 7 };
        let msg = err.to_string();
        assert!(msg.contains("epoch 7"));
    }

    #[test]
    fn state_application_failure_display() {
        let err = ProposalCommitError::StateApplicationFailure {
            reason: "roster already contains the peer".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("roster already contains the peer"));
    }

    #[test]
    fn proposal_commit_error_is_std_error() {
        fn assert_error(_: &dyn std::error::Error) {}
        let err = ProposalCommitError::SequenceConflict { sequence: 1 };
        assert_error(&err);
    }

    #[test]
    fn proposal_commit_error_equality() {
        assert_eq!(
            ProposalCommitError::SequenceConflict { sequence: 1 },
            ProposalCommitError::SequenceConflict { sequence: 1 },
        );
        assert_ne!(
            ProposalCommitError::SequenceConflict { sequence: 1 },
            ProposalCommitError::SequenceConflict { sequence: 2 },
        );
        assert_ne!(
            ProposalCommitError::SequenceConflict { sequence: 1 },
            ProposalCommitError::DuplicateProposal { committed_epoch: 1 },
        );
    }
}

// ---------------------------------------------------------------------------
// ProposalCommitPipeline
// ---------------------------------------------------------------------------

use std::sync::Arc;
use tidefs_membership_epoch::incarnation::IncarnationTracker;
use tidefs_membership_epoch::proposal_idempotency::{
    IdempotencyConfig, IdempotencyTracker, ProposalIdempotencyKey, ProposalOutcome,
};
use tidefs_membership_epoch::transition_journal::{
    apply_transition_kind, MembershipTransitionJournal, TransitionKind,
};
use tidefs_membership_epoch::{EpochId, Incarnation, LeaveReason, MemberId};

use crate::epoch_coordinator::{EpochAdvanceCoordinator, EpochView};

/// The kind of membership proposal being committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposalKind {
    /// A peer is joining the cluster.
    Join {
        member_id: MemberId,
        incarnation: Incarnation,
    },
    /// A peer is being evicted (failure detection).
    Eviction {
        member_id: MemberId,
        incarnation: Incarnation,
        reason: LeaveReason,
    },
    /// A peer is voluntarily departing.
    Departure {
        member_id: MemberId,
        incarnation: Incarnation,
        reason: LeaveReason,
    },
}

impl ProposalKind {
    /// The member id targeted by this proposal.
    #[must_use]
    pub fn member_id(&self) -> MemberId {
        match self {
            Self::Join { member_id, .. }
            | Self::Eviction { member_id, .. }
            | Self::Departure { member_id, .. } => *member_id,
        }
    }

    /// The incarnation carried by this proposal.
    #[must_use]
    pub fn incarnation(&self) -> Incarnation {
        match self {
            Self::Join { incarnation, .. }
            | Self::Eviction { incarnation, .. }
            | Self::Departure { incarnation, .. } => *incarnation,
        }
    }

    /// Compute a deterministic idempotency key for this proposal.
    /// Computed via `ProposalIdempotencyKey::from_intent` from the
    /// Computed via [] from the
    /// canonical byte representation of the proposal kind, delegating
    /// in `tidefs-membership-epoch`.
    /// in .
    #[must_use]
    pub fn idempotency_key(&self) -> ProposalIdempotencyKey {
        let mut intent = Vec::new();
        match self {
            Self::Join { member_id, .. } => {
                intent.extend_from_slice(b"join");
                intent.extend_from_slice(&member_id.0.to_le_bytes());
            }
            Self::Eviction {
                member_id, reason, ..
            } => {
                intent.extend_from_slice(b"eviction");
                intent.extend_from_slice(&member_id.0.to_le_bytes());
                intent.push(*reason as u8);
            }
            Self::Departure {
                member_id, reason, ..
            } => {
                intent.extend_from_slice(b"departure");
                intent.extend_from_slice(&member_id.0.to_le_bytes());
                intent.push(*reason as u8);
            }
        }
        ProposalIdempotencyKey::from_intent(&intent)
    }
    /// Convert this proposal kind into a [`TransitionKind`] for journaling.
    fn to_transition_kind(&self, epoch: EpochId) -> TransitionKind {
        match self {
            Self::Join { member_id, .. } => TransitionKind::Join {
                peer_id: *member_id,
                epoch,
            },
            Self::Eviction {
                member_id, reason, ..
            }
            | Self::Departure {
                member_id, reason, ..
            } => TransitionKind::Leave {
                peer_id: *member_id,
                epoch,
                reason: *reason,
            },
        }
    }
}

/// The coordinator-side proposal-to-epoch commit pipeline.
///
/// Accepts validated membership proposals (join, eviction, departure),
/// sequences them, checks idempotency and incarnation freshness, applies
/// them to the current roster, journals the transition, and dispatches
/// the committed epoch view to subscribers via the
/// [`EpochAdvanceCoordinator`].
///
/// # Lifecycle
///
/// 1. Construct with [`new`] or [`with_defaults`], providing the
///    coordinator's [`MemberId`] and [`IncarnationTracker`].
/// 2. Call [`commit`] for each validated proposal, passing the
///    [`MembershipTransitionJournal`] and [`EpochAdvanceCoordinator`].
/// 3. The coordinator's epoch counter advances, subscribers are
///    notified, and the idempotency tracker records the commit.
///
/// [`new`]: ProposalCommitPipeline::new
/// [`with_defaults`]: ProposalCommitPipeline::with_defaults
/// [`commit`]: ProposalCommitPipeline::commit
pub struct ProposalCommitPipeline {
    /// Monotonic proposal sequence number allocator.
    sequencer: Arc<ProposalSequencer>,
    /// Idempotency-key deduplication tracker.
    idempotency: IdempotencyTracker,
    /// Coordinator incarnation tracker for stale-command rejection.
    incarnation_tracker: IncarnationTracker,
    /// The coordinator's own member id.
    coordinator_id: MemberId,
}

impl ProposalCommitPipeline {
    /// Create a new commit pipeline.
    #[must_use]
    pub fn new(
        sequencer: Arc<ProposalSequencer>,
        idempotency_config: IdempotencyConfig,
        incarnation_tracker: IncarnationTracker,
        coordinator_id: MemberId,
    ) -> Self {
        Self {
            sequencer,
            idempotency: IdempotencyTracker::new(idempotency_config),
            incarnation_tracker,
            coordinator_id,
        }
    }

    /// Create a new commit pipeline with default idempotency config
    /// (8-epoch retention, 4096-key capacity).
    #[must_use]
    pub fn with_defaults(
        sequencer: Arc<ProposalSequencer>,
        incarnation_tracker: IncarnationTracker,
        coordinator_id: MemberId,
    ) -> Self {
        Self::new(
            sequencer,
            IdempotencyConfig::default(),
            incarnation_tracker,
            coordinator_id,
        )
    }

    /// Commit a validated proposal through the full pipeline.
    ///
    /// # Flow
    ///
    /// 1. Validate incarnation freshness.
    /// 2. Check idempotency — duplicate proposals return
    ///    [`ProposalCommitError::DuplicateProposal`].
    /// 3. Allocate a monotonic sequence number.
    /// 4. Compute the successor roster via
    ///    [`apply_transition_kind`].
    /// 5. Journal the transition (prepare → commit).
    /// 6. Advance the epoch via
    ///    [`EpochAdvanceCoordinator::force_advance_epoch`], which
    ///    notifies all registered subscribers.
    ///
    /// # Errors
    ///
    /// - [`ProposalCommitError::StaleIncarnation`] if the proposal
    ///   carries an incarnation lower than the tracker's current value.
    /// - [`ProposalCommitError::DuplicateProposal`] if the idempotency
    ///   key is already tracked.
    /// - [`ProposalCommitError::StateApplicationFailure`] if the
    ///   coordinator is not initialized, the epoch number doesn't
    ///   match, or the roster computation fails.
    pub fn commit(
        &mut self,
        kind: &ProposalKind,
        now_ms: u64,
        journal: &mut MembershipTransitionJournal,
        coordinator: &mut EpochAdvanceCoordinator,
    ) -> Result<EpochView, ProposalCommitError> {
        // 1. Validate incarnation freshness.
        let proposal_incarnation = kind.incarnation();
        self.incarnation_tracker
            .validate(proposal_incarnation)
            .map_err(|stale| ProposalCommitError::StaleIncarnation {
                msg_incarnation: stale.msg_incarnation.0,
                current_incarnation: stale.current_incarnation.0,
            })?;

        // 2. Check idempotency.
        let next_epoch = coordinator.epoch_counter() + 1;
        let key = kind.idempotency_key();
        match self
            .idempotency
            .check_and_insert(self.coordinator_id.0, key, next_epoch)
        {
            ProposalOutcome::PassThrough => {}
            ProposalOutcome::AlreadyCommitted { epoch } => {
                return Err(ProposalCommitError::DuplicateProposal {
                    committed_epoch: epoch,
                });
            }
        }

        // 3. Allocate sequence number.
        let _sequence = self.sequencer.next();

        // 4. Compute the successor roster.
        let current_view = coordinator.current_view().ok_or_else(|| {
            ProposalCommitError::StateApplicationFailure {
                reason: "coordinator not initialized".into(),
            }
        })?;
        let current_roster = &current_view.member_set;
        let next_epoch_id = EpochId::new(next_epoch);
        let transition_kind = kind.to_transition_kind(next_epoch_id);
        let new_roster = apply_transition_kind(current_roster, &transition_kind);

        // 5. Journal: prepare.
        let tx_id = journal.record_prepare(transition_kind, now_ms);

        // 6. Advance the epoch (notifies subscribers).
        let committed_view = coordinator
            .force_advance_epoch(next_epoch, &new_roster, now_ms)
            .ok_or_else(|| ProposalCommitError::StateApplicationFailure {
                reason: format!(
                    "force_advance_epoch failed: epoch={next_epoch} expected={} initialized={}",
                    coordinator.epoch_counter() + 1,
                    coordinator.current_view().is_some(),
                ),
            })?;

        // 7. Journal: commit.
        journal.record_commit(tx_id, now_ms);

        Ok(committed_view)
    }

    /// Return a reference to the internal sequencer.
    #[must_use]
    pub fn sequencer(&self) -> &ProposalSequencer {
        &self.sequencer
    }

    /// Return the current incarnation value.
    #[must_use]
    pub fn current_incarnation(&self) -> Incarnation {
        self.incarnation_tracker.current()
    }

    /// Return the coordinator's member id.
    #[must_use]
    pub fn coordinator_id(&self) -> MemberId {
        self.coordinator_id
    }

    /// Return the number of tracked idempotency entries.
    #[must_use]
    pub fn idempotency_entry_count(&self) -> usize {
        self.idempotency.len()
    }
}

// ---------------------------------------------------------------------------
// Tests: ProposalKind and ProposalCommitPipeline
// ---------------------------------------------------------------------------

#[cfg(test)]
mod pipeline_tests {
    use super::*;
    use crate::epoch_coordinator::EpochAdvanceCoordinator;
    use std::sync::Arc;
    use tidefs_membership_epoch::incarnation::IncarnationTracker;
    use tidefs_membership_epoch::transition_journal::MembershipTransitionJournal;
    use tidefs_membership_epoch::{Incarnation, LeaveReason, MemberId};

    fn member(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn make_sequencer() -> Arc<ProposalSequencer> {
        Arc::new(ProposalSequencer::new())
    }

    fn make_incarnation_tracker() -> IncarnationTracker {
        IncarnationTracker::genesis()
    }

    fn make_coordinator(members: &[MemberId]) -> EpochAdvanceCoordinator {
        let mut c = EpochAdvanceCoordinator::new(1);
        c.initialize(members.to_vec(), 1000);
        c
    }

    fn make_journal() -> MembershipTransitionJournal {
        MembershipTransitionJournal::new()
    }

    fn pipeline() -> ProposalCommitPipeline {
        ProposalCommitPipeline::with_defaults(
            make_sequencer(),
            make_incarnation_tracker(),
            member(1),
        )
    }

    // ── ProposalKind ──────────────────────────────────────────────

    #[test]
    fn proposal_kind_member_id() {
        let join = ProposalKind::Join {
            member_id: member(42),
            incarnation: Incarnation::ZERO,
        };
        assert_eq!(join.member_id(), member(42));

        let evict = ProposalKind::Eviction {
            member_id: member(7),
            incarnation: Incarnation(1),
            reason: LeaveReason::Voluntary,
        };
        assert_eq!(evict.member_id(), member(7));

        let depart = ProposalKind::Departure {
            member_id: member(99),
            incarnation: Incarnation(3),
            reason: LeaveReason::Voluntary,
        };
        assert_eq!(depart.member_id(), member(99));
    }

    #[test]
    fn proposal_kind_incarnation() {
        let join = ProposalKind::Join {
            member_id: member(1),
            incarnation: Incarnation(5),
        };
        assert_eq!(join.incarnation(), Incarnation(5));

        let evict = ProposalKind::Eviction {
            member_id: member(1),
            incarnation: Incarnation(3),
            reason: LeaveReason::Voluntary,
        };
        assert_eq!(evict.incarnation(), Incarnation(3));
    }

    #[test]
    fn idempotency_key_deterministic() {
        let k1 = ProposalKind::Join {
            member_id: member(10),
            incarnation: Incarnation(1),
        }
        .idempotency_key();
        let k2 = ProposalKind::Join {
            member_id: member(10),
            incarnation: Incarnation(1),
        }
        .idempotency_key();
        assert_eq!(k1, k2);
    }

    #[test]
    fn idempotency_key_differs_by_kind() {
        let join = ProposalKind::Join {
            member_id: member(10),
            incarnation: Incarnation(1),
        }
        .idempotency_key();
        let evict = ProposalKind::Eviction {
            member_id: member(10),
            incarnation: Incarnation(1),
            reason: LeaveReason::Voluntary,
        }
        .idempotency_key();
        assert_ne!(join, evict);
    }

    #[test]
    fn idempotency_key_differs_by_member() {
        let k1 = ProposalKind::Join {
            member_id: member(10),
            incarnation: Incarnation(1),
        }
        .idempotency_key();
        let k2 = ProposalKind::Join {
            member_id: member(11),
            incarnation: Incarnation(1),
        }
        .idempotency_key();
        assert_ne!(k1, k2);
    }

    #[test]
    fn idempotency_key_differs_by_reason() {
        let k1 = ProposalKind::Eviction {
            member_id: member(10),
            incarnation: Incarnation(1),
            reason: LeaveReason::Voluntary,
        }
        .idempotency_key();
        let k2 = ProposalKind::Eviction {
            member_id: member(10),
            incarnation: Incarnation(1),
            reason: LeaveReason::Maintenance,
        }
        .idempotency_key();
        assert_ne!(k1, k2);
    }

    // ── Join commit ───────────────────────────────────────────────

    #[test]
    fn commit_join_adds_member() {
        let mut pipeline = pipeline();
        let mut journal = make_journal();
        let mut coordinator = make_coordinator(&[member(1)]);

        let kind = ProposalKind::Join {
            member_id: member(2),
            incarnation: Incarnation::ZERO,
        };

        let result = pipeline.commit(&kind, 2000, &mut journal, &mut coordinator);
        assert!(result.is_ok(), "expected Ok, got {:?}", result.err());

        let view = result.unwrap();
        assert!(view.contains(member(1)));
        assert!(view.contains(member(2)));
        assert_eq!(view.member_count(), 2);
        assert!(view.epoch_number.0 > 0);
        assert!(!journal.is_empty());
    }

    #[test]
    fn commit_join_increments_epoch() {
        let mut pipeline = pipeline();
        let mut journal = make_journal();
        let mut coordinator = make_coordinator(&[member(1)]);

        let initial_epoch = coordinator.epoch_counter();

        let kind = ProposalKind::Join {
            member_id: member(2),
            incarnation: Incarnation::ZERO,
        };
        let result = pipeline.commit(&kind, 2000, &mut journal, &mut coordinator);
        assert!(result.is_ok());

        assert_eq!(coordinator.epoch_counter(), initial_epoch + 1);
    }

    #[test]
    fn commit_multiple_joins() {
        let mut pipeline = pipeline();
        let mut journal = make_journal();
        let mut coordinator = make_coordinator(&[member(1)]);

        for peer_id in 2..=5u64 {
            let kind = ProposalKind::Join {
                member_id: member(peer_id),
                incarnation: Incarnation::ZERO,
            };
            let result = pipeline.commit(&kind, 3000, &mut journal, &mut coordinator);
            assert!(
                result.is_ok(),
                "join peer {peer_id} failed: {:?}",
                result.err()
            );
        }

        let view = coordinator.current_view().unwrap();
        assert_eq!(view.member_count(), 5);
        assert_eq!(coordinator.epoch_counter(), 4);
        assert_eq!(journal.len(), 4);
    }

    // ── Eviction commit ───────────────────────────────────────────

    #[test]
    fn commit_eviction_removes_member() {
        let mut pipeline = pipeline();
        let mut journal = make_journal();
        let mut coordinator = make_coordinator(&[member(1), member(2), member(3)]);

        let kind = ProposalKind::Eviction {
            member_id: member(2),
            incarnation: Incarnation::ZERO,
            reason: LeaveReason::Maintenance,
        };

        let result = pipeline.commit(&kind, 2000, &mut journal, &mut coordinator);
        assert!(result.is_ok(), "expected Ok, got {:?}", result.err());

        let view = coordinator.current_view().unwrap();
        assert!(view.contains(member(1)));
        assert!(!view.contains(member(2)));
        assert!(view.contains(member(3)));
        assert_eq!(view.member_count(), 2);
    }

    // ── Departure commit ──────────────────────────────────────────

    #[test]
    fn commit_departure_removes_member() {
        let mut pipeline = pipeline();
        let mut journal = make_journal();
        let mut coordinator = make_coordinator(&[member(1), member(2)]);

        let kind = ProposalKind::Departure {
            member_id: member(2),
            incarnation: Incarnation::ZERO,
            reason: LeaveReason::Voluntary,
        };

        let result = pipeline.commit(&kind, 2000, &mut journal, &mut coordinator);
        assert!(result.is_ok());

        let view = coordinator.current_view().unwrap();
        assert_eq!(view.member_count(), 1);
        assert!(!view.contains(member(2)));
    }

    // ── Idempotency rejection ─────────────────────────────────────

    #[test]
    fn duplicate_join_rejected() {
        let mut pipeline = pipeline();
        let mut journal = make_journal();
        let mut coordinator = make_coordinator(&[member(1)]);

        let kind = ProposalKind::Join {
            member_id: member(2),
            incarnation: Incarnation::ZERO,
        };

        // First commit succeeds.
        let r1 = pipeline.commit(&kind, 2000, &mut journal, &mut coordinator);
        assert!(r1.is_ok());

        // Second commit with same proposal is rejected.
        let r2 = pipeline.commit(&kind, 3000, &mut journal, &mut coordinator);
        match r2 {
            Err(ProposalCommitError::DuplicateProposal { committed_epoch }) => {
                assert!(committed_epoch > 0);
            }
            other => panic!("expected DuplicateProposal, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_eviction_rejected() {
        let mut pipeline = pipeline();
        let mut journal = make_journal();
        let mut coordinator = make_coordinator(&[member(1), member(2)]);

        let kind = ProposalKind::Eviction {
            member_id: member(2),
            incarnation: Incarnation::ZERO,
            reason: LeaveReason::Maintenance,
        };

        assert!(pipeline
            .commit(&kind, 2000, &mut journal, &mut coordinator)
            .is_ok());
        assert!(matches!(
            pipeline.commit(&kind, 3000, &mut journal, &mut coordinator),
            Err(ProposalCommitError::DuplicateProposal { .. })
        ));
    }

    // ── Stale incarnation rejection ───────────────────────────────

    #[test]
    fn stale_incarnation_rejected() {
        let tracker = IncarnationTracker::new(Incarnation(5));
        let mut pipeline =
            ProposalCommitPipeline::with_defaults(make_sequencer(), tracker, member(1));
        let mut journal = make_journal();
        let mut coordinator = make_coordinator(&[member(1)]);

        let kind = ProposalKind::Join {
            member_id: member(2),
            incarnation: Incarnation(3), // lower than tracker's 5
        };

        let result = pipeline.commit(&kind, 2000, &mut journal, &mut coordinator);
        match result {
            Err(ProposalCommitError::StaleIncarnation {
                msg_incarnation,
                current_incarnation,
            }) => {
                assert_eq!(msg_incarnation, 3);
                assert_eq!(current_incarnation, 5);
            }
            other => panic!("expected StaleIncarnation, got {other:?}"),
        }
    }

    #[test]
    fn current_incarnation_accepted() {
        let tracker = IncarnationTracker::new(Incarnation(5));
        let mut pipeline =
            ProposalCommitPipeline::with_defaults(make_sequencer(), tracker, member(1));
        let mut journal = make_journal();
        let mut coordinator = make_coordinator(&[member(1)]);

        let kind = ProposalKind::Join {
            member_id: member(2),
            incarnation: Incarnation(5), // equal to tracker
        };

        assert!(pipeline
            .commit(&kind, 2000, &mut journal, &mut coordinator)
            .is_ok());
    }

    #[test]
    fn higher_incarnation_accepted() {
        let tracker = IncarnationTracker::new(Incarnation(3));
        let mut pipeline =
            ProposalCommitPipeline::with_defaults(make_sequencer(), tracker, member(1));
        let mut journal = make_journal();
        let mut coordinator = make_coordinator(&[member(1)]);

        let kind = ProposalKind::Join {
            member_id: member(2),
            incarnation: Incarnation(7), // higher than tracker
        };

        assert!(pipeline
            .commit(&kind, 2000, &mut journal, &mut coordinator)
            .is_ok());
    }

    // ── Uninitialized coordinator ──────────────────────────────────

    #[test]
    fn uninitialized_coordinator_rejected() {
        let mut pipeline = pipeline();
        let mut journal = make_journal();
        let mut coordinator = EpochAdvanceCoordinator::new(1); // NOT initialized

        let kind = ProposalKind::Join {
            member_id: member(2),
            incarnation: Incarnation::ZERO,
        };

        let result = pipeline.commit(&kind, 2000, &mut journal, &mut coordinator);
        match result {
            Err(ProposalCommitError::StateApplicationFailure { reason }) => {
                assert!(reason.contains("not initialized"));
            }
            other => panic!("expected StateApplicationFailure, got {other:?}"),
        }
    }

    // ── Accessor tests ─────────────────────────────────────────────

    #[test]
    fn pipeline_accessors() {
        let pipeline = pipeline();
        assert_eq!(pipeline.coordinator_id(), member(1));
        assert_eq!(pipeline.current_incarnation(), Incarnation::ZERO);
        assert_eq!(pipeline.idempotency_entry_count(), 0);
    }

    #[test]
    fn idempotency_entry_count_grows() {
        let mut pipeline = pipeline();
        let mut journal = make_journal();
        let mut coordinator = make_coordinator(&[member(1)]);

        assert_eq!(pipeline.idempotency_entry_count(), 0);

        let _ = pipeline.commit(
            &ProposalKind::Join {
                member_id: member(2),
                incarnation: Incarnation::ZERO,
            },
            2000,
            &mut journal,
            &mut coordinator,
        );
        assert_eq!(pipeline.idempotency_entry_count(), 1);

        let _ = pipeline.commit(
            &ProposalKind::Join {
                member_id: member(3),
                incarnation: Incarnation::ZERO,
            },
            3000,
            &mut journal,
            &mut coordinator,
        );
        assert_eq!(pipeline.idempotency_entry_count(), 2);
    }

    #[test]
    fn sequencer_is_shared() {
        let seq = make_sequencer();
        let mut pipeline1 = ProposalCommitPipeline::with_defaults(
            Arc::clone(&seq),
            make_incarnation_tracker(),
            member(1),
        );
        let pipeline2 = ProposalCommitPipeline::with_defaults(
            Arc::clone(&seq),
            make_incarnation_tracker(),
            member(2),
        );

        // Both pipelines share the same sequencer; sequence numbers
        // are allocated globally across pipelines.
        assert_eq!(pipeline1.sequencer().current(), 0);
        assert_eq!(pipeline2.sequencer().current(), 0);

        let mut journal = make_journal();
        let mut coord1 = make_coordinator(&[member(1)]);
        let result1 = pipeline1.commit(
            &ProposalKind::Join {
                member_id: member(10),
                incarnation: Incarnation::ZERO,
            },
            2000,
            &mut journal,
            &mut coord1,
        );
        assert!(result1.is_ok());

        // The shared sequencer advanced.
        assert!(pipeline1.sequencer().current() > 0);
        assert_eq!(
            pipeline1.sequencer().current(),
            pipeline2.sequencer().current()
        );
    }

    // ── TransitionKind conversion ──────────────────────────────────

    #[test]
    fn proposal_kind_to_transition_kind_join() {
        let kind = ProposalKind::Join {
            member_id: member(42),
            incarnation: Incarnation::ZERO,
        };
        let tk = kind.to_transition_kind(EpochId::new(5));
        match tk {
            TransitionKind::Join { peer_id, epoch } => {
                assert_eq!(peer_id, member(42));
                assert_eq!(epoch, EpochId::new(5));
            }
            other => panic!("expected Join, got {other:?}"),
        }
    }

    #[test]
    fn proposal_kind_to_transition_kind_leave() {
        let kind = ProposalKind::Eviction {
            member_id: member(7),
            incarnation: Incarnation::ZERO,
            reason: LeaveReason::Maintenance,
        };
        let tk = kind.to_transition_kind(EpochId::new(3));
        match tk {
            TransitionKind::Leave {
                peer_id,
                epoch,
                reason,
            } => {
                assert_eq!(peer_id, member(7));
                assert_eq!(epoch, EpochId::new(3));
                assert_eq!(reason, LeaveReason::Maintenance);
            }
            other => panic!("expected Leave, got {other:?}"),
        }
    }

    // ── Existing roster unchanged on no-op ─────────────────────────

    #[test]
    fn commit_join_of_existing_member_still_adds() {
        // apply_transition_kind just adds; it doesn't check for duplicates,
        // but the caller (JoinHandler) already validates before submitting.
        // The pipeline mechanically applies the transition.
        let mut pipeline = pipeline();
        let mut journal = make_journal();
        let mut coordinator = make_coordinator(&[member(1), member(2)]);

        let kind = ProposalKind::Join {
            member_id: member(2),
            incarnation: Incarnation::ZERO,
        };

        let result = pipeline.commit(&kind, 2000, &mut journal, &mut coordinator);
        assert!(result.is_ok());

        let view = coordinator.current_view().unwrap();
        // apply_transition_kind sorts + dedups, so duplicate is harmless
        assert_eq!(view.member_count(), 2);
    }
}
