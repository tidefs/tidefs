//! CommitGroupCoordinator: two-phase commit coordinator managing monotonic commit_group
//! number assignment and BLAKE3 digest chaining across sequential commits.
//!
//! The coordinator bridges committed intent-log regions and the commit_group
//! pipeline. It assigns transaction group numbers, tracks the committed root
//! pointer, and chains BLAKE3 digests so each commit cryptographically
//! references its predecessor.
//!
//! # Digest chain
//!
//! Each commit produces a chain digest computed as:
//!
//! ```text
//! chain_digest = BLAKE3-keyed(last_chain_digest || commit_data)
//! ```
//!
//! This forms a hash chain where every commit-group segment footer carries
//! the digest of all prior commits, making history tamper-evident.

use crate::types::{CommitGroupId, RootPointer};

/// Domain context for commit-group chain digest derivation.
const COMMIT_GROUP_CHAIN_CONTEXT: &str = "TideFS CommitGroup Chain v1";

/// Discriminant reused from `DomainTag::SegmentIntegrityFooter` (0x0B) for
/// compatibility with the existing domain-separation scheme.
const CHAIN_DOMAIN_DISCRIMINANT: u8 = 0x0B;

// ---------------------------------------------------------------------------
// CommitGroupCoordinator
// ---------------------------------------------------------------------------

/// Two-phase commit coordinator: assigns monotonic commit_group numbers, tracks the
/// committed root, and chains BLAKE3 digests across sequential commits.
///
/// # Lifecycle
///
/// ```text
/// new() / resume()  ─►  assign_next()  ─►  chain_digest()  ─►  advance()
///                            ↑                                         │
///                            └─────────────────────────────────────────┘
/// ```
#[derive(Clone, Debug)]
pub struct CommitGroupCoordinator {
    /// The next transaction group number to assign.
    next_txg_number: CommitGroupId,
    /// BLAKE3-256 digest of the most recently committed group.
    /// Zero on a fresh coordinator; updated on every [`advance`](Self::advance).
    last_chain_digest: [u8; 32],
    /// The root pointer of the most recently committed group.
    committed_root: RootPointer,
}

impl CommitGroupCoordinator {
    /// Create a fresh coordinator starting at commit_group 1 with a zero chain digest.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_txg_number: CommitGroupId::FIRST,
            last_chain_digest: [0u8; 32],
            committed_root: RootPointer::NIL,
        }
    }

    /// Create a coordinator resuming from a previously committed root.
    ///
    /// The next assigned commit_group number will be `recovered_root.commit_group_id.next()`.
    /// The chain digest starts at zero since we do not have the prior digest
    /// on disk (recovery reconstructs state, not the full hash chain).
    #[must_use]
    pub fn resume(recovered_root: RootPointer) -> Self {
        let next = if recovered_root.is_valid() {
            recovered_root.commit_group_id.next()
        } else {
            CommitGroupId::FIRST
        };
        Self {
            next_txg_number: next,
            last_chain_digest: [0u8; 32],
            committed_root: recovered_root,
        }
    }

    /// Create a coordinator resuming from a recovered root with a known
    /// chain digest (e.g., from a previously persisted committed root).
    ///
    /// The chain is restored so subsequent commits continue the existing
    /// hash chain rather than starting a new one from zero.
    #[must_use]
    pub fn resume_with_digest(recovered_root: RootPointer, recovered_digest: [u8; 32]) -> Self {
        let next = if recovered_root.is_valid() {
            recovered_root.commit_group_id.next()
        } else {
            CommitGroupId::FIRST
        };
        Self {
            next_txg_number: next,
            last_chain_digest: recovered_digest,
            committed_root: recovered_root,
        }
    }

    /// The next commit_group number that will be assigned.
    #[must_use]
    pub fn next_txg_number(&self) -> CommitGroupId {
        self.next_txg_number
    }

    /// The most recently committed root pointer.
    #[must_use]
    pub fn committed_root(&self) -> RootPointer {
        self.committed_root
    }

    /// The BLAKE3-256 digest of the most recent commit in the chain.
    #[must_use]
    pub fn last_chain_digest(&self) -> [u8; 32] {
        self.last_chain_digest
    }

    /// Assign and return the next monotonic commit_group number.
    ///
    /// After this call, `next_txg_number` advances by one. The caller
    /// must eventually call [`advance`](Self::advance) when the commit
    /// succeeds, or the assigned number is lost.
    pub fn assign_next(&mut self) -> CommitGroupId {
        let assigned = self.next_txg_number;
        self.next_txg_number = assigned.next();
        assigned
    }

    /// Compute a BLAKE3-256 chain digest for `commit_data`.
    ///
    /// The digest is domain-separated via BLAKE3 key derivation:
    /// `BLAKE3-KDF(context, discriminant) → key`, then
    /// `BLAKE3-keyed(key, last_chain_digest || commit_data)`.
    ///
    /// This chains each commit to its predecessor, making the entire
    /// commit history tamper-evident.
    ///
    /// Does not mutate the coordinator — call [`advance`](Self::advance)
    /// to persist the new digest.
    #[must_use]
    pub fn chain_digest(&self, commit_data: &[u8]) -> [u8; 32] {
        let key = blake3::derive_key(COMMIT_GROUP_CHAIN_CONTEXT, &[CHAIN_DOMAIN_DISCRIMINANT]);
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(&self.last_chain_digest);
        hasher.update(commit_data);
        *hasher.finalize().as_bytes()
    }

    /// Advance the coordinator after a successful commit.
    ///
    /// Records `new_root` as the committed root and `new_digest` as the
    /// chain digest for the next commit. Typically `new_digest` is the
    /// result of a prior [`chain_digest`](Self::chain_digest) call.
    pub fn advance(&mut self, new_root: RootPointer, new_digest: [u8; 32]) {
        self.committed_root = new_root;
        self.last_chain_digest = new_digest;
    }
}

impl Default for CommitGroupCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Basic lifecycle ────────────────────────────────────────────

    #[test]
    fn new_coordinator_starts_at_txg_1() {
        let c = CommitGroupCoordinator::new();
        assert_eq!(c.next_txg_number(), CommitGroupId::FIRST);
        assert_eq!(c.committed_root(), RootPointer::NIL);
        assert_eq!(c.last_chain_digest(), [0u8; 32]);
    }

    #[test]
    fn assign_next_produces_monotonic_sequence() {
        let mut c = CommitGroupCoordinator::new();
        let t1 = c.assign_next();
        assert_eq!(t1, CommitGroupId(1));
        assert_eq!(c.next_txg_number(), CommitGroupId(2));

        let t2 = c.assign_next();
        assert_eq!(t2, CommitGroupId(2));
        assert_eq!(c.next_txg_number(), CommitGroupId(3));

        let t3 = c.assign_next();
        assert_eq!(t3, CommitGroupId(3));
        assert_eq!(c.next_txg_number(), CommitGroupId(4));
    }

    #[test]
    fn advance_updates_root_and_digest() {
        let mut c = CommitGroupCoordinator::new();
        let _commit_group = c.assign_next();

        let new_root = RootPointer::new(CommitGroupId(1), 42);
        let new_digest = [0xAAu8; 32];
        c.advance(new_root, new_digest);

        assert_eq!(c.committed_root(), new_root);
        assert_eq!(c.last_chain_digest(), new_digest);
        assert_eq!(c.next_txg_number(), CommitGroupId(2));
    }

    // ── Resume ─────────────────────────────────────────────────────

    #[test]
    fn resume_from_valid_root() {
        let recovered = RootPointer::new(CommitGroupId(5), 99);
        let c = CommitGroupCoordinator::resume(recovered);

        assert_eq!(c.committed_root(), recovered);
        assert_eq!(c.next_txg_number(), CommitGroupId(6));
        assert_eq!(c.last_chain_digest(), [0u8; 32]);
    }

    #[test]
    fn resume_from_nil_root_starts_at_1() {
        let c = CommitGroupCoordinator::resume(RootPointer::NIL);
        assert_eq!(c.next_txg_number(), CommitGroupId::FIRST);
        assert_eq!(c.committed_root(), RootPointer::NIL);
    }

    #[test]
    fn resume_with_digest_preserves_digest() {
        let recovered = RootPointer::new(CommitGroupId(5), 99);
        let digest = [0xABu8; 32];
        let c = CommitGroupCoordinator::resume_with_digest(recovered, digest);

        assert_eq!(c.committed_root(), recovered);
        assert_eq!(c.last_chain_digest(), digest);
        assert_eq!(c.next_txg_number(), CommitGroupId(6));
    }

    #[test]
    fn resume_with_digest_chains_from_recovered_digest() {
        let recovered = RootPointer::new(CommitGroupId(1), 42);
        let prev_digest = [0x11u8; 32];
        let c = CommitGroupCoordinator::resume_with_digest(recovered, prev_digest);

        // The first commit after recovery should chain from prev_digest
        let d1 = c.chain_digest(b"post-recovery commit");

        // Same starting state (new + advance) should produce same result
        let mut verify = CommitGroupCoordinator::new();
        verify.advance(recovered, prev_digest);
        let v1 = verify.chain_digest(b"post-recovery commit");
        assert_eq!(d1, v1);
    }

    // ── Digest chaining ────────────────────────────────────────────

    #[test]
    fn chain_digest_is_deterministic() {
        let c = CommitGroupCoordinator::new();
        let d1 = c.chain_digest(b"hello");
        let d2 = c.chain_digest(b"hello");
        assert_eq!(d1, d2);
    }

    #[test]
    fn chain_digest_changes_with_data() {
        let c = CommitGroupCoordinator::new();
        let d1 = c.chain_digest(b"data A");
        let d2 = c.chain_digest(b"data B");
        assert_ne!(d1, d2);
    }

    #[test]
    fn chain_digest_depends_on_prior_digest() {
        let mut c = CommitGroupCoordinator::new();

        let d1 = c.chain_digest(b"commit 1");
        c.advance(RootPointer::new(CommitGroupId(1), 0), d1);

        let d2 = c.chain_digest(b"commit 2");

        // Recompute with same prior digest.
        let mut c2 = CommitGroupCoordinator::new();
        c2.advance(RootPointer::new(CommitGroupId(1), 0), d1);
        let d2_recomputed = c2.chain_digest(b"commit 2");
        assert_eq!(d2, d2_recomputed);

        // Different prior digest → different chain digest.
        let d2_different = CommitGroupCoordinator::new().chain_digest(b"commit 2");
        assert_ne!(d2, d2_different);
    }

    #[test]
    fn chain_digest_forms_verifiable_sequence() {
        let mut c = CommitGroupCoordinator::new();

        let d1 = c.chain_digest(b"commit_group 1 data");
        c.advance(RootPointer::new(CommitGroupId(1), 100), d1);

        let d2 = c.chain_digest(b"commit_group 2 data");
        c.advance(RootPointer::new(CommitGroupId(2), 200), d2);

        let d3 = c.chain_digest(b"commit_group 3 data");
        c.advance(RootPointer::new(CommitGroupId(3), 300), d3);

        // All non-zero and distinct.
        assert_ne!(d1, [0u8; 32]);
        assert_ne!(d2, [0u8; 32]);
        assert_ne!(d3, [0u8; 32]);
        assert_ne!(d1, d2);
        assert_ne!(d2, d3);
        assert_ne!(d1, d3);

        // Replay verification.
        let mut verify = CommitGroupCoordinator::new();
        let v1 = verify.chain_digest(b"commit_group 1 data");
        assert_eq!(v1, d1);
        verify.advance(RootPointer::new(CommitGroupId(1), 100), v1);

        let v2 = verify.chain_digest(b"commit_group 2 data");
        assert_eq!(v2, d2);
        verify.advance(RootPointer::new(CommitGroupId(2), 200), v2);

        let v3 = verify.chain_digest(b"commit_group 3 data");
        assert_eq!(v3, d3);
    }

    #[test]
    fn chain_digest_domain_separated_from_raw_blake3() {
        let c = CommitGroupCoordinator::new();
        let chain_d = c.chain_digest(b"test");

        // Raw BLAKE3 without domain separation should differ.
        let mut raw_hasher = blake3::Hasher::new();
        raw_hasher.update(&[0u8; 32]);
        raw_hasher.update(b"test");
        let raw_d: [u8; 32] = *raw_hasher.finalize().as_bytes();

        assert_ne!(chain_d, raw_d);
    }

    // ── Default ────────────────────────────────────────────────────

    #[test]
    fn default_equals_new() {
        let c1 = CommitGroupCoordinator::new();
        let c2 = CommitGroupCoordinator::default();
        assert_eq!(c1.next_txg_number(), c2.next_txg_number());
        assert_eq!(c1.committed_root(), c2.committed_root());
        assert_eq!(c1.last_chain_digest(), c2.last_chain_digest());
    }
}
