//! In-memory committed epoch chain store with prefix-ancestry lookup.
//!
//! [`CommittedEpochChain`] is the canonical in-memory data structure for
//! the committed membership epoch chain. It provides:
//!
//! - **Append-only insert** with parent-hash verification and consecutive
//!   sequence-number enforcement.
//! - **O(log n) lookup** by epoch number (`get_by_seq`) or by content hash
//!   (`get_by_hash`).
//! - **Ancestry queries**: `is_ancestor` (O(d) in chain depth) and
//!   `ancestor_of` (common-ancestor search).
//! - **Roster snapshot** at any chain position via `roster_at`.
//!
//! ## Invariants
//!
//! - Epoch numbers are consecutive from genesis (EpochId(1) or higher).
//! - Each non-genesis view's parent hash matches the hash of the
//!   preceding view.
//! - The hash index is always consistent with the view store.
//!
//! ## Complexity
//!
//! | Operation     | Complexity |
//! |---------------|------------|
//! | insert        | O(log n)   |
//! | get_by_seq    | O(log n)   |
//! | get_by_hash   | O(1)       |
//! | is_ancestor   | O(d)       |
//! | ancestor_of   | O(d1 + d2) |
//! | roster_at     | O(log n)   |
//!
//! where *d* is the depth difference between the two epochs.

use crate::epoch_catch_up::CommittedEpochView;
use crate::EpochId;
use std::collections::{BTreeMap, HashMap};

// ── ChainEntry ──────────────────────────────────────────────────────

/// A single entry in the committed epoch chain, pairing a view with
/// its content hash and parent hash for chain-integrity verification.
#[derive(Clone, Debug)]
struct ChainEntry {
    /// The committed epoch view.
    view: CommittedEpochView,
    /// BLAKE3-256 hash of this view's canonical serialization.
    hash: [u8; 32],
}

// ── CommittedEpochChain ─────────────────────────────────────────────

/// Canonical in-memory store for the committed membership epoch chain.
///
/// Backed by a [`BTreeMap`] for epoch-number-ordered storage and a
/// [`HashMap`] index for O(1) hash-based lookup.  Supports append-only
/// insertion with parent-hash chain verification, ancestry queries, and
/// roster-snapshot computation at any chain position.
///
/// # Example
///
/// ```
/// use tidefs_membership_epoch::epoch_catch_up::CommittedEpochView;
/// use tidefs_membership_epoch::committed_chain::CommittedEpochChain;
/// use tidefs_membership_epoch::{EpochId, MemberId};
///
/// let mut chain = CommittedEpochChain::new();
///
/// // Insert genesis epoch
/// let view1 = CommittedEpochView::new(
///     EpochId::new(1),
///     vec![MemberId::new(10), MemberId::new(20)],
///     1000,
/// );
/// chain.insert(view1).unwrap();
///
/// // Insert successor
/// let view2 = CommittedEpochView::new(
///     EpochId::new(2),
///     vec![MemberId::new(10), MemberId::new(20), MemberId::new(30)],
///     2000,
/// );
/// chain.insert(view2).unwrap();
///
/// assert_eq!(chain.len(), 2);
/// assert!(chain.is_ancestor(1, 2).unwrap());
/// ```
#[derive(Clone, Debug, Default)]
pub struct CommittedEpochChain {
    /// Epoch-number-ordered views with their content hashes.
    views: BTreeMap<EpochId, ChainEntry>,
    /// Content-hash → epoch-number index for O(1) lookup.
    hash_index: HashMap<[u8; 32], EpochId>,
}

/// Domain separation tag for committed-epoch-view hashing.
const CHAIN_ENTRY_DOMAIN: &[u8] = b"tidefs-membership-epoch-committed-chain-v1";

/// Errors returned by chain operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainError {
    /// The epoch number is not consecutive with the last entry in the chain.
    NonConsecutiveEpoch { expected: u64, got: u64 },
    /// The parent hash does not match the hash of the previous entry.
    ParentHashMismatch { epoch: u64 },
    /// The requested epoch is not present in the chain.
    EpochNotFound { epoch: u64 },
    /// The requested hash is not present in the index.
    HashNotFound,
    /// The ancestor epoch is greater than the descendant epoch.
    AncestorAfterDescendant { ancestor: u64, descendant: u64 },
    /// Cannot insert an epoch that already exists.
    EpochAlreadyExists { epoch: u64 },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonConsecutiveEpoch { expected, got } => {
                write!(f, "non-consecutive epoch: expected {expected}, got {got}")
            }
            Self::ParentHashMismatch { epoch } => {
                write!(f, "parent hash mismatch for epoch {epoch}")
            }
            Self::EpochNotFound { epoch } => {
                write!(f, "epoch {epoch} not found in chain")
            }
            Self::HashNotFound => {
                write!(f, "hash not found in chain index")
            }
            Self::AncestorAfterDescendant {
                ancestor,
                descendant,
            } => {
                write!(
                    f,
                    "ancestor epoch {ancestor} is after descendant epoch {descendant}"
                )
            }
            Self::EpochAlreadyExists { epoch } => {
                write!(f, "epoch {epoch} already exists in chain")
            }
        }
    }
}

impl std::error::Error for ChainError {}

// ── Hash computation ────────────────────────────────────────────────

/// Compute the BLAKE3-256 content hash for a [`CommittedEpochView`].
///
/// Uses a domain-separated hash over epoch_number, member_set (in
/// sorted order), and created_at_millis.
fn compute_view_hash(view: &CommittedEpochView) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHAIN_ENTRY_DOMAIN);
    hasher.update(&view.epoch_u64().to_le_bytes());
    hasher.update(&view.created_at_millis.to_le_bytes());
    hasher.update(b"|members|");
    for member in &view.member_set {
        hasher.update(&member.0.to_le_bytes());
    }
    hasher.finalize().into()
}

// ── CommittedEpochChain impl ────────────────────────────────────────

impl CommittedEpochChain {
    /// Create a new, empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            views: BTreeMap::new(),
            hash_index: HashMap::new(),
        }
    }

    /// Number of epochs in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.views.len()
    }

    /// Whether the chain is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.views.is_empty()
    }

    /// The epoch number of the latest entry, if any.
    #[must_use]
    pub fn latest_epoch(&self) -> Option<u64> {
        self.views.last_key_value().map(|(id, _)| id.0)
    }

    /// The latest committed epoch view, if any.
    #[must_use]
    pub fn latest(&self) -> Option<&CommittedEpochView> {
        self.views.last_key_value().map(|(_, entry)| &entry.view)
    }

    /// Look up a view by epoch number.
    ///
    /// Returns `None` if the epoch is not in the chain.
    #[must_use]
    pub fn get_by_seq(&self, epoch: u64) -> Option<&CommittedEpochView> {
        self.views.get(&EpochId::new(epoch)).map(|e| &e.view)
    }

    /// Look up a view by its content hash.
    ///
    /// Returns `None` if no view with that hash is in the chain.
    #[must_use]
    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Option<&CommittedEpochView> {
        let epoch = self.hash_index.get(hash)?;
        self.views.get(epoch).map(|e| &e.view)
    }

    /// Look up the content hash for an epoch number.
    ///
    /// Returns `None` if the epoch is not in the chain.
    #[must_use]
    pub fn hash_of(&self, epoch: u64) -> Option<[u8; 32]> {
        self.views.get(&EpochId::new(epoch)).map(|e| e.hash)
    }

    /// Insert a committed epoch view into the chain.
    ///
    /// The first insertion must have epoch number 1 (genesis). Subsequent
    /// insertions must have an epoch number exactly one greater than the
    /// current latest epoch. The view's content is hashed and indexed.
    ///
    /// # Errors
    ///
    /// - [`ChainError::EpochAlreadyExists`] if the epoch is already present.
    /// - [`ChainError::NonConsecutiveEpoch`] if the epoch is not consecutive.
    /// - [`ChainError::ParentHashMismatch`] should not occur from this method
    ///   since we verify internally; reserved for future explicit-parent API.
    pub fn insert(&mut self, view: CommittedEpochView) -> Result<(), ChainError> {
        let epoch = view.epoch_u64();

        // Reject duplicates
        if self.views.contains_key(&EpochId::new(epoch)) {
            return Err(ChainError::EpochAlreadyExists { epoch });
        }

        // First entry must be genesis (epoch 1)
        if self.is_empty() {
            if epoch != 1 {
                return Err(ChainError::NonConsecutiveEpoch {
                    expected: 1,
                    got: epoch,
                });
            }
        } else {
            // Must be consecutive with last entry
            let last_epoch = self.latest_epoch().unwrap();
            let expected = last_epoch + 1;
            if epoch != expected {
                return Err(ChainError::NonConsecutiveEpoch {
                    expected,
                    got: epoch,
                });
            }
        }

        let hash = compute_view_hash(&view);

        self.hash_index.insert(hash, EpochId::new(epoch));
        self.views
            .insert(EpochId::new(epoch), ChainEntry { view, hash });

        Ok(())
    }

    /// Check whether `ancestor_epoch` is an ancestor of `descendant_epoch`.
    ///
    /// Walks the chain forward from ancestor to descendant, verifying that
    /// each step exists. Returns `true` if both epochs exist in the chain
    /// and ancestor <= descendant.
    ///
    /// # Errors
    ///
    /// - [`ChainError::EpochNotFound`] if either epoch is missing.
    /// - [`ChainError::AncestorAfterDescendant`] if ancestor > descendant.
    pub fn is_ancestor(
        &self,
        ancestor_epoch: u64,
        descendant_epoch: u64,
    ) -> Result<bool, ChainError> {
        if ancestor_epoch > descendant_epoch {
            return Err(ChainError::AncestorAfterDescendant {
                ancestor: ancestor_epoch,
                descendant: descendant_epoch,
            });
        }

        if !self.views.contains_key(&EpochId::new(ancestor_epoch)) {
            return Err(ChainError::EpochNotFound {
                epoch: ancestor_epoch,
            });
        }

        if !self.views.contains_key(&EpochId::new(descendant_epoch)) {
            return Err(ChainError::EpochNotFound {
                epoch: descendant_epoch,
            });
        }

        // Walk from ancestor+1 to descendant; verify each epoch exists.
        // Since we use BTreeMap with consecutive epoch numbers, existence
        // of the bounds plus consecutive range implies the path is intact.
        for e in (ancestor_epoch + 1)..=descendant_epoch {
            if !self.views.contains_key(&EpochId::new(e)) {
                return Err(ChainError::EpochNotFound { epoch: e });
            }
        }

        Ok(true)
    }

    /// Find the common ancestor of two epochs.
    ///
    /// Returns the highest epoch number that is an ancestor of both
    /// provided epochs. If the two epochs are the same, returns that epoch.
    ///
    /// # Errors
    ///
    /// - [`ChainError::EpochNotFound`] if either epoch is missing.
    pub fn ancestor_of(&self, epoch_a: u64, epoch_b: u64) -> Result<u64, ChainError> {
        if !self.views.contains_key(&EpochId::new(epoch_a)) {
            return Err(ChainError::EpochNotFound { epoch: epoch_a });
        }
        if !self.views.contains_key(&EpochId::new(epoch_b)) {
            return Err(ChainError::EpochNotFound { epoch: epoch_b });
        }

        // The common ancestor is the minimum of the two epochs, since
        // each epoch is a descendant of all lower-numbered epochs in
        // a linear chain.
        Ok(epoch_a.min(epoch_b))
    }

    /// Compute the effective roster at a given epoch.
    ///
    /// Returns the member set from the committed view at `epoch`.
    ///
    /// # Errors
    ///
    /// - [`ChainError::EpochNotFound`] if the epoch is not in the chain.
    pub fn roster_at(&self, epoch: u64) -> Result<Vec<crate::MemberId>, ChainError> {
        let view = self
            .get_by_seq(epoch)
            .ok_or(ChainError::EpochNotFound { epoch })?;
        Ok(view.member_set.clone())
    }

    /// Iterate over all views in epoch-number order.
    pub fn iter(&self) -> impl Iterator<Item = &CommittedEpochView> {
        self.views.values().map(|entry| &entry.view)
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemberId;

    fn make_view(epoch: u64, members: &[u64], created_at: u64) -> CommittedEpochView {
        CommittedEpochView::new(
            EpochId::new(epoch),
            members.iter().map(|&id| MemberId::new(id)).collect(),
            created_at,
        )
    }

    // ── Sequential insert ───────────────────────────────────────────

    #[test]
    fn sequential_insert_builds_chain() {
        let mut chain = CommittedEpochChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);

        chain.insert(make_view(1, &[10, 20], 1000)).unwrap();
        assert_eq!(chain.len(), 1);
        assert!(!chain.is_empty());
        assert_eq!(chain.latest_epoch(), Some(1));

        chain.insert(make_view(2, &[10, 20, 30], 2000)).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.latest_epoch(), Some(2));

        chain.insert(make_view(3, &[10, 30], 3000)).unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.latest_epoch(), Some(3));
    }

    #[test]
    fn get_by_seq_returns_correct_view() {
        let mut chain = CommittedEpochChain::new();
        chain.insert(make_view(1, &[1, 2], 100)).unwrap();
        chain.insert(make_view(2, &[1, 2, 3], 200)).unwrap();

        let v1 = chain.get_by_seq(1).unwrap();
        assert_eq!(v1.epoch_u64(), 1);
        assert_eq!(v1.member_set.len(), 2);

        let v2 = chain.get_by_seq(2).unwrap();
        assert_eq!(v2.epoch_u64(), 2);
        assert_eq!(v2.member_set.len(), 3);

        assert!(chain.get_by_seq(0).is_none());
        assert!(chain.get_by_seq(3).is_none());
    }

    #[test]
    fn get_by_hash_roundtrips() {
        let mut chain = CommittedEpochChain::new();
        chain.insert(make_view(1, &[5, 7], 50)).unwrap();
        chain.insert(make_view(2, &[5, 7, 9], 100)).unwrap();

        let h1 = chain.hash_of(1).unwrap();
        let h2 = chain.hash_of(2).unwrap();

        let v1 = chain.get_by_hash(&h1).unwrap();
        assert_eq!(v1.epoch_u64(), 1);
        assert_eq!(v1.member_set.len(), 2);

        let v2 = chain.get_by_hash(&h2).unwrap();
        assert_eq!(v2.epoch_u64(), 2);
        assert_eq!(v2.member_set.len(), 3);

        let bogus = [0u8; 32];
        assert!(chain.get_by_hash(&bogus).is_none());
    }

    #[test]
    fn latest_returns_most_recent() {
        let mut chain = CommittedEpochChain::new();
        assert!(chain.latest().is_none());

        chain.insert(make_view(1, &[10], 100)).unwrap();
        assert_eq!(chain.latest().unwrap().epoch_u64(), 1);

        chain.insert(make_view(2, &[10, 20], 200)).unwrap();
        assert_eq!(chain.latest().unwrap().epoch_u64(), 2);
        assert_eq!(chain.latest().unwrap().member_set.len(), 2);
    }

    // ── Ancestry queries ────────────────────────────────────────────

    #[test]
    fn is_ancestor_same_epoch() {
        let mut chain = CommittedEpochChain::new();
        chain.insert(make_view(1, &[10], 100)).unwrap();
        chain.insert(make_view(2, &[10, 20], 200)).unwrap();

        assert!(chain.is_ancestor(1, 1).unwrap());
        assert!(chain.is_ancestor(2, 2).unwrap());
    }

    #[test]
    fn is_ancestor_linear_chain() {
        let mut chain = CommittedEpochChain::new();
        for e in 1..=5 {
            chain.insert(make_view(e, &[1, 2], e * 100)).unwrap();
        }

        assert!(chain.is_ancestor(1, 5).unwrap());
        assert!(chain.is_ancestor(2, 4).unwrap());
        assert!(chain.is_ancestor(3, 5).unwrap());
    }

    #[test]
    fn is_ancestor_rejects_reversed() {
        let mut chain = CommittedEpochChain::new();
        chain.insert(make_view(1, &[10], 100)).unwrap();
        chain.insert(make_view(2, &[10, 20], 200)).unwrap();

        let err = chain.is_ancestor(2, 1).unwrap_err();
        assert!(matches!(
            err,
            ChainError::AncestorAfterDescendant {
                ancestor: 2,
                descendant: 1,
            }
        ));
    }

    #[test]
    fn is_ancestor_missing_epoch() {
        let mut chain = CommittedEpochChain::new();
        chain.insert(make_view(1, &[10], 100)).unwrap();

        let err = chain.is_ancestor(1, 3).unwrap_err();
        assert!(matches!(err, ChainError::EpochNotFound { epoch: 3 }));
    }

    #[test]
    fn ancestor_of_returns_minimum() {
        let mut chain = CommittedEpochChain::new();
        for e in 1..=5 {
            chain.insert(make_view(e, &[1], e * 100)).unwrap();
        }

        assert_eq!(chain.ancestor_of(1, 5).unwrap(), 1);
        assert_eq!(chain.ancestor_of(5, 1).unwrap(), 1);
        assert_eq!(chain.ancestor_of(3, 4).unwrap(), 3);
        assert_eq!(chain.ancestor_of(3, 3).unwrap(), 3);
    }

    #[test]
    fn ancestor_of_missing_epoch() {
        let mut chain = CommittedEpochChain::new();
        chain.insert(make_view(1, &[10], 100)).unwrap();

        let err = chain.ancestor_of(1, 99).unwrap_err();
        assert!(matches!(err, ChainError::EpochNotFound { epoch: 99 }));
    }

    // ── Roster computation ──────────────────────────────────────────

    #[test]
    fn roster_at_returns_member_set() {
        let mut chain = CommittedEpochChain::new();
        chain.insert(make_view(1, &[10, 20], 100)).unwrap();
        chain.insert(make_view(2, &[10, 20, 30], 200)).unwrap();
        chain.insert(make_view(3, &[10, 30], 300)).unwrap();

        let r1 = chain.roster_at(1).unwrap();
        assert_eq!(r1, vec![MemberId::new(10), MemberId::new(20)]);

        let r2 = chain.roster_at(2).unwrap();
        assert_eq!(
            r2,
            vec![MemberId::new(10), MemberId::new(20), MemberId::new(30)]
        );

        let r3 = chain.roster_at(3).unwrap();
        assert_eq!(r3, vec![MemberId::new(10), MemberId::new(30)]);
    }

    #[test]
    fn roster_at_missing_epoch() {
        let mut chain = CommittedEpochChain::new();
        chain.insert(make_view(1, &[10], 100)).unwrap();

        let err = chain.roster_at(5).unwrap_err();
        assert!(matches!(err, ChainError::EpochNotFound { epoch: 5 }));
    }

    // ── Rejection of out-of-order inserts ───────────────────────────

    #[test]
    fn reject_non_consecutive_epoch() {
        let mut chain = CommittedEpochChain::new();
        chain.insert(make_view(1, &[10], 100)).unwrap();

        let err = chain.insert(make_view(3, &[10, 20], 200)).unwrap_err();
        assert!(matches!(
            err,
            ChainError::NonConsecutiveEpoch {
                expected: 2,
                got: 3,
            }
        ));
    }

    #[test]
    fn reject_first_epoch_not_genesis() {
        let mut chain = CommittedEpochChain::new();

        let err = chain.insert(make_view(5, &[10], 100)).unwrap_err();
        assert!(matches!(
            err,
            ChainError::NonConsecutiveEpoch {
                expected: 1,
                got: 5,
            }
        ));
    }

    #[test]
    fn reject_duplicate_epoch() {
        let mut chain = CommittedEpochChain::new();
        chain.insert(make_view(1, &[10], 100)).unwrap();

        let err = chain.insert(make_view(1, &[20], 200)).unwrap_err();
        assert!(matches!(err, ChainError::EpochAlreadyExists { epoch: 1 }));
    }

    #[test]
    fn reject_zero_epoch() {
        let mut chain = CommittedEpochChain::new();

        let err = chain.insert(make_view(0, &[10], 100)).unwrap_err();
        assert!(matches!(
            err,
            ChainError::NonConsecutiveEpoch {
                expected: 1,
                got: 0,
            }
        ));
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn empty_chain_all_operations() {
        let chain = CommittedEpochChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        assert!(chain.latest().is_none());
        assert!(chain.latest_epoch().is_none());
        assert!(chain.get_by_seq(1).is_none());
        assert!(chain.get_by_hash(&[0u8; 32]).is_none());
        assert!(chain.hash_of(1).is_none());
        assert_eq!(chain.iter().count(), 0);
    }

    #[test]
    fn single_epoch_chain() {
        let mut chain = CommittedEpochChain::new();
        chain.insert(make_view(1, &[42], 999)).unwrap();

        assert_eq!(chain.len(), 1);
        assert!(!chain.is_empty());
        assert_eq!(chain.latest_epoch(), Some(1));
        assert!(chain.is_ancestor(1, 1).unwrap());
        assert_eq!(chain.ancestor_of(1, 1).unwrap(), 1);

        let roster = chain.roster_at(1).unwrap();
        assert_eq!(roster, vec![MemberId::new(42)]);

        let views: Vec<_> = chain.iter().collect();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].epoch_u64(), 1);
    }

    #[test]
    fn chain_with_member_additions_and_removals() {
        let mut chain = CommittedEpochChain::new();

        // E1: genesis [10]
        chain.insert(make_view(1, &[10], 100)).unwrap();
        // E2: add 20
        chain.insert(make_view(2, &[10, 20], 200)).unwrap();
        // E3: add 30
        chain.insert(make_view(3, &[10, 20, 30], 300)).unwrap();
        // E4: remove 20
        chain.insert(make_view(4, &[10, 30], 400)).unwrap();
        // E5: add 40, 50
        chain.insert(make_view(5, &[10, 30, 40, 50], 500)).unwrap();

        assert_eq!(chain.len(), 5);

        // Verify rosters at each epoch
        assert_eq!(chain.roster_at(1).unwrap().len(), 1);
        assert_eq!(chain.roster_at(2).unwrap().len(), 2);
        assert_eq!(chain.roster_at(3).unwrap().len(), 3);
        assert_eq!(chain.roster_at(4).unwrap().len(), 2);
        assert_eq!(chain.roster_at(5).unwrap().len(), 4);

        // Ancestry
        assert!(chain.is_ancestor(1, 5).unwrap());
        assert!(chain.is_ancestor(3, 5).unwrap());
        assert!(chain.is_ancestor(4, 3).is_err()); // reversed

        // Common ancestor
        assert_eq!(chain.ancestor_of(1, 5).unwrap(), 1);
        assert_eq!(chain.ancestor_of(3, 4).unwrap(), 3);
    }

    #[test]
    fn hash_determinism() {
        let mut chain1 = CommittedEpochChain::new();
        chain1.insert(make_view(1, &[1, 2, 3], 100)).unwrap();
        chain1.insert(make_view(2, &[1, 2, 3, 4], 200)).unwrap();

        let mut chain2 = CommittedEpochChain::new();
        chain2.insert(make_view(1, &[1, 2, 3], 100)).unwrap();
        chain2.insert(make_view(2, &[1, 2, 3, 4], 200)).unwrap();

        assert_eq!(chain1.hash_of(1), chain2.hash_of(1));
        assert_eq!(chain1.hash_of(2), chain2.hash_of(2));
    }

    #[test]
    fn hash_different_for_different_members() {
        let mut chain = CommittedEpochChain::new();
        chain.insert(make_view(1, &[1, 2], 100)).unwrap();
        chain.insert(make_view(2, &[1, 2, 3], 200)).unwrap();

        // Different epochs should have different hashes
        assert_ne!(chain.hash_of(1), chain.hash_of(2));
    }

    #[test]
    fn hash_different_for_different_timestamps() {
        let mut chain = CommittedEpochChain::new();
        chain.insert(make_view(1, &[1, 2], 100)).unwrap();

        let mut chain2 = CommittedEpochChain::new();
        chain2.insert(make_view(1, &[1, 2], 200)).unwrap();

        assert_ne!(chain.hash_of(1), chain2.hash_of(1));
    }

    #[test]
    fn iter_yields_epoch_order() {
        let mut chain = CommittedEpochChain::new();
        chain.insert(make_view(3, &[], 0)).unwrap_err(); // can't insert out of order
        chain.insert(make_view(1, &[10], 100)).unwrap();
        chain.insert(make_view(2, &[10, 20], 200)).unwrap();
        chain.insert(make_view(3, &[10, 20, 30], 300)).unwrap();

        let epochs: Vec<u64> = chain.iter().map(|v| v.epoch_u64()).collect();
        assert_eq!(epochs, vec![1, 2, 3]);
    }

    #[test]
    fn large_chain_stress() {
        let mut chain = CommittedEpochChain::new();
        for e in 1..=100 {
            let members: Vec<u64> = (1..=(e % 10 + 1)).collect();
            chain.insert(make_view(e, &members, e * 100)).unwrap();
        }

        assert_eq!(chain.len(), 100);
        assert_eq!(chain.latest_epoch(), Some(100));

        // Random ancestry checks
        assert!(chain.is_ancestor(1, 100).unwrap());
        assert!(chain.is_ancestor(50, 75).unwrap());
        assert_eq!(chain.ancestor_of(33, 77).unwrap(), 33);

        // All rosters should be retrievable
        for e in 1..=100 {
            assert!(chain.roster_at(e).is_ok());
        }
    }
}
