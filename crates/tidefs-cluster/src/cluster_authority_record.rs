// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Persisted cluster authority record: on-disk quorum and cluster-map
//! authority state that nodes discover and validate during boot.
//!
//! The [`ClusterAuthorityRecord`] is the persisted truth source for
//! multi-node cluster operation. It is stored in the pool device system
//! area and carries enough state for a node to determine current
//! membership, voting/quorum configuration, import ownership, and
//! placement-map freshness without an external monitor daemon.
//!
//! ## Design
//!
//! - Each record forms a hash chain: `prev_digest` links to the previous
//!   record, and `self_digest` is a BLAKE3-256 hash over all other fields.
//! - Records are identified on disk by a 4-byte magic prefix
//!   (`CLUSTER_AUTHORITY_MAGIC`).
//! - Fail-closed semantics: any record that fails validation (bad magic,
//!   checksum mismatch, broken chain, zero epoch, empty voter set when
//!   epoch > 0) returns a [`ClusterAuthorityVerdict::Refused`] with a
//!   structured reason.
//! - After all nodes lose power, a fresh node scans pool device system
//!   areas, discovers the latest valid authority record, and uses it to
//!   determine whether it can import the pool, which nodes are voters,
//!   and whether the placement map is current.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tidefs_membership_epoch::EpochId;

// ── On-disk constants ─────────────────────────────────────────────

/// Magic bytes identifying a cluster authority record on disk.
pub const CLUSTER_AUTHORITY_MAGIC: [u8; 4] = *b"VBCA";

/// Current authority record format version.
pub const CLUSTER_AUTHORITY_VERSION: u32 = 1;

/// BLAKE3 domain separation string for authority record self-hashing.
const AUTHORITY_RECORD_DOMAIN: &[u8] = b"tidefs-cluster-authority-record-v1";

// ── ClusterAuthorityRecord ────────────────────────────────────────

/// Persisted cluster authority state stored on pool devices.
///
/// This is the durable truth for: which epoch the cluster is in,
/// which nodes are voting members, which nodes are fenced, who holds
/// the import lease, and what placement map is current.
///
/// On boot, nodes scan pool device system areas for the newest valid
/// record and use it to reconstruct cluster state without an external
/// monitor daemon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterAuthorityRecord {
    /// Magic bytes: must equal [`CLUSTER_AUTHORITY_MAGIC`].
    pub magic: [u8; 4],
    /// Format version: must equal [`CLUSTER_AUTHORITY_VERSION`].
    pub version: u32,
    /// Pool GUID this authority governs.
    pub pool_guid: [u8; 16],
    /// Current membership epoch (monotonically increasing).
    pub membership_epoch: EpochId,
    /// Set of voting member node IDs.
    pub voter_set: BTreeSet<u64>,
    /// Set of learner member node IDs.
    pub learner_set: BTreeSet<u64>,
    /// Set of fenced node IDs (excluded from I/O and voting).
    pub fenced_nodes: BTreeSet<u64>,
    /// Node ID of the current import owner (zero if none).
    pub import_owner: u64,
    /// Current placement-map epoch (monotonically increasing).
    pub placement_map_epoch: u64,
    /// BLAKE3-256 digest of the current placement map.
    pub placement_map_digest: [u8; 32],
    /// Last committed authority transition receipt ID.
    pub last_authority_receipt: u64,
    /// Pool topology generation this record was written at.
    pub topology_generation: u64,
    /// Transaction group at which this record was committed.
    pub committed_txg: u64,
    /// Monotonic authority record sequence number.
    pub sequence: u64,
    /// BLAKE3-256 digest of the previous authority record
    /// (all zeros for the genesis record).
    pub prev_digest: [u8; 32],
    /// BLAKE3-256 self-hash over all preceding fields (zeroed for hash).
    pub self_digest: [u8; 32],
}

impl ClusterAuthorityRecord {
    // ── Construction ──────────────────────────────────────────

    /// Create a genesis authority record for a newly formed cluster.
    ///
    /// All fields are initialized from the provided parameters.
    /// `self_digest` is computed by [`seal`](Self::seal).
    pub fn genesis(
        pool_guid: [u8; 16],
        voter_set: BTreeSet<u64>,
        learner_set: BTreeSet<u64>,
        import_owner: u64,
        placement_map_digest: [u8; 32],
        topology_generation: u64,
    ) -> Self {
        let epoch = if voter_set.is_empty() && learner_set.is_empty() {
            EpochId(0)
        } else {
            EpochId(1)
        };
        let mut rec = Self {
            magic: CLUSTER_AUTHORITY_MAGIC,
            version: CLUSTER_AUTHORITY_VERSION,
            pool_guid,
            membership_epoch: epoch,
            voter_set,
            learner_set,
            fenced_nodes: BTreeSet::new(),
            import_owner,
            placement_map_epoch: 0,
            placement_map_digest,
            last_authority_receipt: 0,
            topology_generation,
            committed_txg: 0,
            sequence: 0,
            prev_digest: [0u8; 32],
            self_digest: [0u8; 32],
        };
        rec.self_digest = rec.compute_self_digest();
        rec
    }

    /// Create a successor authority record that advances the chain.
    ///
    /// `self_digest` is computed by [`seal`](Self::seal).
    pub fn successor(&self) -> ClusterAuthorityRecordBuilder {
        ClusterAuthorityRecordBuilder {
            pool_guid: self.pool_guid,
            membership_epoch: self.membership_epoch,
            voter_set: self.voter_set.clone(),
            learner_set: self.learner_set.clone(),
            fenced_nodes: self.fenced_nodes.clone(),
            import_owner: self.import_owner,
            placement_map_epoch: self.placement_map_epoch,
            placement_map_digest: self.placement_map_digest,
            last_authority_receipt: self.last_authority_receipt,
            topology_generation: self.topology_generation,
            committed_txg: self.committed_txg,
            sequence: self.sequence + 1,
            prev_digest: self.self_digest,
        }
    }

    // ── Integrity ─────────────────────────────────────────────

    /// Compute the BLAKE3-256 self-hash over all fields except
    /// `self_digest` (which is zeroed for hashing).
    fn compute_self_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(AUTHORITY_RECORD_DOMAIN);
        hasher.update(&self.magic);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.pool_guid);
        hasher.update(&self.membership_epoch.0.to_le_bytes());
        // Hash voter set deterministically (sorted by BTreeSet).
        for &voter in &self.voter_set {
            hasher.update(&voter.to_le_bytes());
        }
        for &learner in &self.learner_set {
            hasher.update(&learner.to_le_bytes());
        }
        for &fenced in &self.fenced_nodes {
            hasher.update(&fenced.to_le_bytes());
        }
        hasher.update(&self.import_owner.to_le_bytes());
        hasher.update(&self.placement_map_epoch.to_le_bytes());
        hasher.update(&self.placement_map_digest);
        hasher.update(&self.last_authority_receipt.to_le_bytes());
        hasher.update(&self.topology_generation.to_le_bytes());
        hasher.update(&self.committed_txg.to_le_bytes());
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(&self.prev_digest);
        hasher.finalize().into()
    }

    /// Verify the self-digest matches the computed digest.
    pub fn verify(&self) -> bool {
        let computed = self.compute_self_digest();
        computed == self.self_digest
    }

    /// Compute and set `self_digest`, returning the sealed record.
    pub fn seal(mut self) -> Self {
        self.self_digest = self.compute_self_digest();
        self
    }

    // ── Queries ───────────────────────────────────────────────

    /// Total voting members (voters).
    pub fn voter_count(&self) -> usize {
        self.voter_set.len()
    }

    /// Quorum size: simple majority of voters (floor(N/2) + 1).
    /// Returns 0 when the voter set is empty.
    pub fn quorum_size(&self) -> usize {
        let n = self.voter_set.len();
        if n == 0 {
            0
        } else {
            (n / 2) + 1
        }
    }

    /// Whether `node_id` is a current voter.
    pub fn is_voter(&self, node_id: u64) -> bool {
        self.voter_set.contains(&node_id)
    }

    /// Whether `node_id` is a current learner.
    pub fn is_learner(&self, node_id: u64) -> bool {
        self.learner_set.contains(&node_id)
    }

    /// Whether `node_id` is currently fenced.
    pub fn is_fenced(&self, node_id: u64) -> bool {
        self.fenced_nodes.contains(&node_id)
    }

    /// Whether the authority has a non-empty voter set (i.e. cluster is
    /// formed).
    pub fn is_cluster_formed(&self) -> bool {
        !self.voter_set.is_empty()
    }

    /// Whether this is the genesis record (sequence 0, prev_digest all
    /// zeros).
    pub fn is_genesis(&self) -> bool {
        self.sequence == 0 && self.prev_digest == [0u8; 32]
    }

    /// Return a human-readable one-line summary for operator output.
    pub fn summary(&self) -> String {
        format!(
            "authority seq={} epoch={:?} voters={} learners={} fenced={} import_owner={} map_epoch={} txg={}",
            self.sequence,
            self.membership_epoch,
            self.voter_set.len(),
            self.learner_set.len(),
            self.fenced_nodes.len(),
            self.import_owner,
            self.placement_map_epoch,
            self.committed_txg,
        )
    }

    // ── Encode / Decode ───────────────────────────────────────

    /// Serialize to a byte vector (bincode).
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from a byte slice (bincode).
    pub fn decode(buf: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(buf)
    }
}

// ── ClusterAuthorityRecordBuilder ─────────────────────────────────

/// Builder for constructing a successor [`ClusterAuthorityRecord`].
///
/// Created by [`ClusterAuthorityRecord::successor`]. Call setters to
/// mutate fields, then call [`build`](Self::build) to produce the sealed
/// record.
#[derive(Clone, Debug)]
pub struct ClusterAuthorityRecordBuilder {
    pool_guid: [u8; 16],
    membership_epoch: EpochId,
    voter_set: BTreeSet<u64>,
    learner_set: BTreeSet<u64>,
    fenced_nodes: BTreeSet<u64>,
    import_owner: u64,
    placement_map_epoch: u64,
    placement_map_digest: [u8; 32],
    last_authority_receipt: u64,
    topology_generation: u64,
    committed_txg: u64,
    sequence: u64,
    prev_digest: [u8; 32],
}

impl ClusterAuthorityRecordBuilder {
    pub fn membership_epoch(mut self, epoch: EpochId) -> Self {
        self.membership_epoch = epoch;
        self
    }

    pub fn voter_set(mut self, voters: BTreeSet<u64>) -> Self {
        self.voter_set = voters;
        self
    }

    pub fn learner_set(mut self, learners: BTreeSet<u64>) -> Self {
        self.learner_set = learners;
        self
    }

    pub fn fenced_nodes(mut self, fenced: BTreeSet<u64>) -> Self {
        self.fenced_nodes = fenced;
        self
    }

    pub fn import_owner(mut self, owner: u64) -> Self {
        self.import_owner = owner;
        self
    }

    pub fn placement_map_epoch(mut self, epoch: u64) -> Self {
        self.placement_map_epoch = epoch;
        self
    }

    pub fn placement_map_digest(mut self, digest: [u8; 32]) -> Self {
        self.placement_map_digest = digest;
        self
    }

    pub fn last_authority_receipt(mut self, receipt: u64) -> Self {
        self.last_authority_receipt = receipt;
        self
    }

    pub fn topology_generation(mut self, gen: u64) -> Self {
        self.topology_generation = gen;
        self
    }

    pub fn committed_txg(mut self, txg: u64) -> Self {
        self.committed_txg = txg;
        self
    }

    /// Produce the sealed [`ClusterAuthorityRecord`].
    pub fn build(self) -> ClusterAuthorityRecord {
        ClusterAuthorityRecord {
            magic: CLUSTER_AUTHORITY_MAGIC,
            version: CLUSTER_AUTHORITY_VERSION,
            pool_guid: self.pool_guid,
            membership_epoch: self.membership_epoch,
            voter_set: self.voter_set,
            learner_set: self.learner_set,
            fenced_nodes: self.fenced_nodes,
            import_owner: self.import_owner,
            placement_map_epoch: self.placement_map_epoch,
            placement_map_digest: self.placement_map_digest,
            last_authority_receipt: self.last_authority_receipt,
            topology_generation: self.topology_generation,
            committed_txg: self.committed_txg,
            sequence: self.sequence,
            prev_digest: self.prev_digest,
            self_digest: [0u8; 32],
        }
        .seal()
    }
}

// ── ClusterAuthorityVerdict ───────────────────────────────────────

/// Outcome of validating a cluster authority record during boot scan.
///
/// Fail-closed semantics: any validation failure produces `Refused` with
/// a structured reason, preventing the node from proceeding with stale
/// or corrupt authority state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClusterAuthorityVerdict {
    /// Authority record is valid and current.
    Valid {
        /// The validated record.
        record: Box<ClusterAuthorityRecord>,
    },
    /// Authority record failed validation.
    Refused {
        /// Machine-readable refusal reason.
        reason: AuthorityRefusalReason,
        /// Human-readable detail.
        detail: String,
    },
    /// No authority record found on any scanned device.
    NotFound,
}

/// Structured refusal reasons for authority record validation failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityRefusalReason {
    /// Magic bytes do not match [`CLUSTER_AUTHORITY_MAGIC`].
    BadMagic,
    /// Unsupported format version.
    UnsupportedVersion,
    /// Self-digest verification failed (corrupt record).
    ChecksumMismatch,
    /// Chain integrity broken: prev_digest does not match expected.
    ChainBroken,
    /// Zero membership epoch with a non-empty voter set.
    ZeroEpochWithVoters,
    /// Non-zero membership epoch with an empty voter set.
    NonZeroEpochEmptyVoters,
    /// Import owner is fenced.
    ImportOwnerFenced,
    /// Placement map epoch exceeds membership epoch.
    MapEpochAheadOfMembership,
    /// Sequence is not strictly greater than the previous record.
    SequenceNotMonotonic,
}

impl std::fmt::Display for AuthorityRefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => f.write_str("bad_magic"),
            Self::UnsupportedVersion => f.write_str("unsupported_version"),
            Self::ChecksumMismatch => f.write_str("checksum_mismatch"),
            Self::ChainBroken => f.write_str("chain_broken"),
            Self::ZeroEpochWithVoters => f.write_str("zero_epoch_with_voters"),
            Self::NonZeroEpochEmptyVoters => f.write_str("non_zero_epoch_empty_voters"),
            Self::ImportOwnerFenced => f.write_str("import_owner_fenced"),
            Self::MapEpochAheadOfMembership => f.write_str("map_epoch_ahead_of_membership"),
            Self::SequenceNotMonotonic => f.write_str("sequence_not_monotonic"),
        }
    }
}

// ── Validation functions ──────────────────────────────────────────

/// Validate a stand-alone authority record (no chain context).
///
/// Checks magic, version, self-digest, and internal invariants.
pub fn validate_authority_record(record: &ClusterAuthorityRecord) -> ClusterAuthorityVerdict {
    if record.magic != CLUSTER_AUTHORITY_MAGIC {
        return ClusterAuthorityVerdict::Refused {
            reason: AuthorityRefusalReason::BadMagic,
            detail: format!(
                "expected {:?}, got {:?}",
                CLUSTER_AUTHORITY_MAGIC, record.magic
            ),
        };
    }
    if record.version != CLUSTER_AUTHORITY_VERSION {
        return ClusterAuthorityVerdict::Refused {
            reason: AuthorityRefusalReason::UnsupportedVersion,
            detail: format!(
                "expected {}, got {}",
                CLUSTER_AUTHORITY_VERSION, record.version
            ),
        };
    }
    if !record.verify() {
        return ClusterAuthorityVerdict::Refused {
            reason: AuthorityRefusalReason::ChecksumMismatch,
            detail: "self-digest verification failed".into(),
        };
    }
    // Invariant: if epoch > 0, voter set must be non-empty.
    if record.membership_epoch.0 > 0 && record.voter_set.is_empty() {
        return ClusterAuthorityVerdict::Refused {
            reason: AuthorityRefusalReason::NonZeroEpochEmptyVoters,
            detail: format!("epoch {:?} with empty voter set", record.membership_epoch),
        };
    }
    // Invariant: if epoch == 0, voter set must be empty.
    if record.membership_epoch.0 == 0 && !record.voter_set.is_empty() {
        return ClusterAuthorityVerdict::Refused {
            reason: AuthorityRefusalReason::ZeroEpochWithVoters,
            detail: "epoch 0 with non-empty voter set".into(),
        };
    }
    // Invariant: import owner must not be fenced.
    if record.import_owner != 0 && record.is_fenced(record.import_owner) {
        return ClusterAuthorityVerdict::Refused {
            reason: AuthorityRefusalReason::ImportOwnerFenced,
            detail: format!("import owner {} is in fenced set", record.import_owner),
        };
    }
    // Invariant: placement map epoch cannot exceed membership epoch
    // (map follows membership, not leads it).
    if record.placement_map_epoch > record.membership_epoch.0 {
        return ClusterAuthorityVerdict::Refused {
            reason: AuthorityRefusalReason::MapEpochAheadOfMembership,
            detail: format!(
                "map epoch {} > membership epoch {:?}",
                record.placement_map_epoch, record.membership_epoch
            ),
        };
    }

    ClusterAuthorityVerdict::Valid {
        record: Box::new(record.clone()),
    }
}

/// Validate a successor record against a known previous record.
///
/// In addition to stand-alone validation, checks chain integrity
/// (`prev_digest` match) and monotonic sequence.
pub fn validate_authority_chain(
    prev: &ClusterAuthorityRecord,
    successor: &ClusterAuthorityRecord,
) -> ClusterAuthorityVerdict {
    // Stand-alone validation first.
    let stand_alone = validate_authority_record(successor);
    if let ClusterAuthorityVerdict::Refused { .. } = &stand_alone {
        return stand_alone;
    }

    // Chain integrity: prev_digest must match previous self_digest.
    if successor.prev_digest != prev.self_digest {
        return ClusterAuthorityVerdict::Refused {
            reason: AuthorityRefusalReason::ChainBroken,
            detail: "prev_digest does not match previous record self_digest".into(),
        };
    }

    // Sequence must be strictly greater.
    if successor.sequence <= prev.sequence {
        return ClusterAuthorityVerdict::Refused {
            reason: AuthorityRefusalReason::SequenceNotMonotonic,
            detail: format!(
                "successor sequence {} <= previous sequence {}",
                successor.sequence, prev.sequence
            ),
        };
    }

    ClusterAuthorityVerdict::Valid {
        record: Box::new(successor.clone()),
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn voters(ids: &[u64]) -> BTreeSet<u64> {
        ids.iter().copied().collect()
    }

    fn learners(ids: &[u64]) -> BTreeSet<u64> {
        ids.iter().copied().collect()
    }

    // ── Genesis and basic accessors ──────────────────────────

    #[test]
    fn genesis_record_is_valid() {
        let rec = ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1, 2, 3]),
            learners(&[4]),
            1,
            [0xCD; 32],
            5,
        );
        assert!(rec.verify());
        assert!(rec.is_genesis());
        assert_eq!(rec.magic, CLUSTER_AUTHORITY_MAGIC);
        assert_eq!(rec.version, CLUSTER_AUTHORITY_VERSION);
        assert_eq!(rec.pool_guid, [0xAB; 16]);
        assert_eq!(rec.membership_epoch, EpochId(1));
        assert_eq!(rec.voter_count(), 3);
        assert_eq!(rec.quorum_size(), 2); // floor(3/2)+1 = 2
        assert!(rec.is_voter(1));
        assert!(rec.is_voter(2));
        assert!(rec.is_voter(3));
        assert!(!rec.is_voter(99));
        assert!(rec.is_learner(4));
        assert!(!rec.is_learner(1));
        assert!(rec.is_cluster_formed());
        assert_eq!(rec.import_owner, 1);
        assert_eq!(rec.placement_map_epoch, 0);
        assert_eq!(rec.placement_map_digest, [0xCD; 32]);
        assert_eq!(rec.topology_generation, 5);
        assert_eq!(rec.sequence, 0);
        assert_eq!(rec.prev_digest, [0u8; 32]);
    }

    #[test]
    fn empty_genesis_has_epoch_zero() {
        let rec = ClusterAuthorityRecord::genesis(
            [0x00; 16],
            BTreeSet::new(),
            BTreeSet::new(),
            0,
            [0u8; 32],
            0,
        );
        assert!(rec.verify());
        assert_eq!(rec.membership_epoch, EpochId(0));
        assert!(!rec.is_cluster_formed());
        assert_eq!(rec.quorum_size(), 0);
    }

    // ── Quorum ───────────────────────────────────────────────

    #[test]
    fn quorum_size_single_node() {
        let rec = ClusterAuthorityRecord::genesis(
            [0x01; 16],
            voters(&[1]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            0,
        );
        assert_eq!(rec.quorum_size(), 1);
    }

    #[test]
    fn quorum_size_five_nodes() {
        let rec = ClusterAuthorityRecord::genesis(
            [0x01; 16],
            voters(&[1, 2, 3, 4, 5]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            0,
        );
        assert_eq!(rec.quorum_size(), 3); // floor(5/2)+1 = 3
    }

    #[test]
    fn quorum_size_even() {
        let rec = ClusterAuthorityRecord::genesis(
            [0x01; 16],
            voters(&[1, 2, 3, 4]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            0,
        );
        assert_eq!(rec.quorum_size(), 3); // floor(4/2)+1 = 3
    }

    // ── Fencing ──────────────────────────────────────────────

    #[test]
    fn is_fenced_returns_true_for_fenced_node() {
        let rec = ClusterAuthorityRecord::genesis(
            [0x01; 16],
            voters(&[1, 2, 3]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            0,
        );
        // Genesis has empty fenced set
        assert!(!rec.is_fenced(2));

        // Successor with fencing
        let succ = rec.successor().fenced_nodes(voters(&[2])).build();
        assert!(succ.is_fenced(2));
        assert!(!succ.is_fenced(1));
        assert!(!succ.is_fenced(3));
    }

    // ── Successor chain ──────────────────────────────────────

    #[test]
    fn successor_chain_integrity() {
        let genesis = ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1, 2, 3]),
            BTreeSet::new(),
            1,
            [0xCD; 32],
            1,
        );
        assert!(genesis.verify());

        let succ = genesis
            .successor()
            .membership_epoch(EpochId(2))
            .placement_map_epoch(1)
            .committed_txg(42)
            .build();
        assert!(succ.verify());
        assert_eq!(succ.sequence, 1);
        assert_eq!(succ.prev_digest, genesis.self_digest);

        // Chain validation passes
        let verdict = validate_authority_chain(&genesis, &succ);
        assert!(matches!(verdict, ClusterAuthorityVerdict::Valid { .. }));
    }

    #[test]
    fn chain_broken_by_tampering() {
        let genesis = ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1, 2]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            1,
        );
        let mut succ = genesis.successor().membership_epoch(EpochId(2)).build();

        // Tamper: break the prev_digest link
        succ.prev_digest = [0xFF; 32];
        // Recompute self_digest so stand-alone passes but chain fails
        succ = succ.seal();

        let verdict = validate_authority_chain(&genesis, &succ);
        match verdict {
            ClusterAuthorityVerdict::Refused { reason, .. } => {
                assert_eq!(reason, AuthorityRefusalReason::ChainBroken);
            }
            other => panic!("expected ChainBroken refusal, got {:?}", other),
        }
    }

    // ── Validation: invariants ───────────────────────────────

    #[test]
    fn validate_rejects_bad_magic() {
        let mut rec = ClusterAuthorityRecord::genesis(
            [0x01; 16],
            voters(&[1]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            0,
        );
        rec.magic = *b"BADC";
        rec = rec.seal();

        let verdict = validate_authority_record(&rec);
        match verdict {
            ClusterAuthorityVerdict::Refused { reason, .. } => {
                assert_eq!(reason, AuthorityRefusalReason::BadMagic);
            }
            other => panic!("expected BadMagic refusal, got {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_checksum_mismatch() {
        let mut rec = ClusterAuthorityRecord::genesis(
            [0x01; 16],
            voters(&[1]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            0,
        );
        // Flip a byte without resealing
        rec.import_owner = 999;
        // self_digest was computed for import_owner=1

        let verdict = validate_authority_record(&rec);
        match verdict {
            ClusterAuthorityVerdict::Refused { reason, .. } => {
                assert_eq!(reason, AuthorityRefusalReason::ChecksumMismatch);
            }
            other => panic!("expected ChecksumMismatch refusal, got {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_nonzero_epoch_empty_voters() {
        let mut rec = ClusterAuthorityRecord::genesis(
            [0x01; 16],
            voters(&[1]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            0,
        );
        // Manually set epoch > 0 with empty voters (invalid invariant)
        rec.membership_epoch = EpochId(5);
        rec.voter_set.clear();
        rec = rec.seal();

        let verdict = validate_authority_record(&rec);
        match verdict {
            ClusterAuthorityVerdict::Refused { reason, .. } => {
                assert_eq!(reason, AuthorityRefusalReason::NonZeroEpochEmptyVoters);
            }
            other => panic!("expected NonZeroEpochEmptyVoters refusal, got {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_zero_epoch_with_voters() {
        let mut rec = ClusterAuthorityRecord::genesis(
            [0x01; 16],
            BTreeSet::new(),
            BTreeSet::new(),
            0,
            [0u8; 32],
            0,
        );
        assert_eq!(rec.membership_epoch, EpochId(0));
        // Manually add voters while epoch stays 0
        rec.voter_set = voters(&[1, 2]);
        rec = rec.seal();

        let verdict = validate_authority_record(&rec);
        match verdict {
            ClusterAuthorityVerdict::Refused { reason, .. } => {
                assert_eq!(reason, AuthorityRefusalReason::ZeroEpochWithVoters);
            }
            other => panic!("expected ZeroEpochWithVoters refusal, got {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_import_owner_fenced() {
        let rec = ClusterAuthorityRecord::genesis(
            [0x01; 16],
            voters(&[1, 2, 3]),
            BTreeSet::new(),
            2,
            [0u8; 32],
            0,
        );
        // Fence the import owner
        let succ = rec.successor().fenced_nodes(voters(&[2])).build();

        let verdict = validate_authority_record(&succ);
        match verdict {
            ClusterAuthorityVerdict::Refused { reason, .. } => {
                assert_eq!(reason, AuthorityRefusalReason::ImportOwnerFenced);
            }
            other => panic!("expected ImportOwnerFenced refusal, got {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_map_epoch_ahead_of_membership() {
        let mut rec = ClusterAuthorityRecord::genesis(
            [0x01; 16],
            voters(&[1]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            0,
        );
        // membership_epoch=1, placement_map_epoch=2 (invalid)
        rec.placement_map_epoch = 2;
        rec = rec.seal();

        let verdict = validate_authority_record(&rec);
        match verdict {
            ClusterAuthorityVerdict::Refused { reason, .. } => {
                assert_eq!(reason, AuthorityRefusalReason::MapEpochAheadOfMembership);
            }
            other => panic!(
                "expected MapEpochAheadOfMembership refusal, got {:?}",
                other
            ),
        }
    }

    // ── Encode / decode roundtrip ─────────────────────────────

    #[test]
    fn encode_decode_roundtrip() {
        let rec = ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1, 2, 3, 4, 5]),
            learners(&[6, 7]),
            1,
            [0x11; 32],
            3,
        );
        let encoded = rec.encode().unwrap();
        let decoded = ClusterAuthorityRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
        assert!(decoded.verify());
    }

    #[test]
    fn encode_decode_with_fenced_nodes() {
        let genesis = ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1, 2, 3]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            0,
        );
        let succ = genesis.successor().fenced_nodes(voters(&[3])).build();

        let encoded = succ.encode().unwrap();
        let decoded = ClusterAuthorityRecord::decode(&encoded).unwrap();
        assert_eq!(succ, decoded);
        assert!(decoded.verify());
        assert!(decoded.is_fenced(3));
    }

    // ── Builder setters ───────────────────────────────────────

    #[test]
    fn builder_all_setters() {
        let genesis = ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            0,
        );
        let built = genesis
            .successor()
            .membership_epoch(EpochId(7))
            .voter_set(voters(&[1, 2, 3]))
            .learner_set(learners(&[4]))
            .fenced_nodes(voters(&[5]))
            .import_owner(2)
            .placement_map_epoch(5)
            .placement_map_digest([0xAA; 32])
            .last_authority_receipt(42)
            .topology_generation(3)
            .committed_txg(100)
            .build();

        assert!(built.verify());
        assert_eq!(built.membership_epoch, EpochId(7));
        assert_eq!(built.voter_set, voters(&[1, 2, 3]));
        assert_eq!(built.learner_set, learners(&[4]));
        assert_eq!(built.fenced_nodes, voters(&[5]));
        assert_eq!(built.import_owner, 2);
        assert_eq!(built.placement_map_epoch, 5);
        assert_eq!(built.placement_map_digest, [0xAA; 32]);
        assert_eq!(built.last_authority_receipt, 42);
        assert_eq!(built.topology_generation, 3);
        assert_eq!(built.committed_txg, 100);
        assert_eq!(built.sequence, 1);
        assert_eq!(built.prev_digest, genesis.self_digest);
    }

    // ── Summary ───────────────────────────────────────────────

    #[test]
    fn summary_contains_key_fields() {
        let rec = ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1, 2, 3]),
            learners(&[4]),
            1,
            [0u8; 32],
            5,
        );
        let summary = rec.summary();
        assert!(summary.contains("seq=0"));
        assert!(summary.contains("voters=3"));
        assert!(summary.contains("learners=1"));
        assert!(summary.contains("import_owner=1"));
    }

    // ── Seal produces consistent digest ───────────────────────

    #[test]
    fn seal_is_deterministic() {
        let rec1 = ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1, 2]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            0,
        );
        let rec2 = ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1, 2]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            0,
        );
        assert_eq!(rec1.self_digest, rec2.self_digest);
    }

    #[test]
    fn seal_produces_different_digest_for_different_content() {
        let rec1 = ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1, 2]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            0,
        );
        let rec2 = ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1, 2, 3]), // different voter set
            BTreeSet::new(),
            1,
            [0u8; 32],
            0,
        );
        assert_ne!(rec1.self_digest, rec2.self_digest);
    }

    // ── Refusal reason display ────────────────────────────────

    #[test]
    fn refusal_reason_display() {
        assert_eq!(AuthorityRefusalReason::BadMagic.to_string(), "bad_magic");
        assert_eq!(
            AuthorityRefusalReason::ChainBroken.to_string(),
            "chain_broken"
        );
        assert_eq!(
            AuthorityRefusalReason::ChecksumMismatch.to_string(),
            "checksum_mismatch"
        );
    }

    // ── Multiple successors form a valid chain ────────────────

    #[test]
    fn three_record_chain() {
        let r0 = ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            1,
        );
        let r1 = r0
            .successor()
            .membership_epoch(EpochId(2))
            .voter_set(voters(&[1, 2]))
            .build();
        let r2 = r1
            .successor()
            .membership_epoch(EpochId(3))
            .voter_set(voters(&[1, 2, 3]))
            .placement_map_epoch(2)
            .build();

        assert!(r0.verify());
        assert!(r1.verify());
        assert!(r2.verify());
        assert_eq!(r0.sequence, 0);
        assert_eq!(r1.sequence, 1);
        assert_eq!(r2.sequence, 2);

        let v1 = validate_authority_chain(&r0, &r1);
        assert!(matches!(v1, ClusterAuthorityVerdict::Valid { .. }));
        let v2 = validate_authority_chain(&r1, &r2);
        assert!(matches!(v2, ClusterAuthorityVerdict::Valid { .. }));
    }

    #[test]
    fn sequence_not_monotonic_rejected() {
        let r0 = ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            1,
        );
        let r1 = r0.successor().membership_epoch(EpochId(2)).build();
        assert_eq!(r1.sequence, 1);

        // Try to validate r0 as successor to r1 (sequence goes backward)
        // Manually build a record that has the right prev_digest link
        // but lower sequence, bypassing the builder which auto-increments.
        let mut bad_succ = r1.successor().build();
        bad_succ.sequence = r1.sequence; // same sequence, not greater
        bad_succ = bad_succ.seal();

        let verdict = validate_authority_chain(&r1, &bad_succ);
        match verdict {
            ClusterAuthorityVerdict::Refused { reason, .. } => {
                assert_eq!(reason, AuthorityRefusalReason::SequenceNotMonotonic);
            }
            other => panic!("expected SequenceNotMonotonic, got {:?}", other),
        }
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut rec = ClusterAuthorityRecord::genesis(
            [0x01; 16],
            voters(&[1]),
            BTreeSet::new(),
            1,
            [0u8; 32],
            0,
        );
        rec.version = 99;
        rec = rec.seal();

        let verdict = validate_authority_record(&rec);
        match verdict {
            ClusterAuthorityVerdict::Refused { reason, .. } => {
                assert_eq!(reason, AuthorityRefusalReason::UnsupportedVersion);
            }
            other => panic!("expected UnsupportedVersion refusal, got {:?}", other),
        }
    }

    #[test]
    fn not_found_verdict_is_not_valid() {
        let verdict = ClusterAuthorityVerdict::NotFound;
        assert!(!matches!(verdict, ClusterAuthorityVerdict::Valid { .. }));
    }
}
