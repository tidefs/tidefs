use ed25519_dalek::{Keypair, Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::{EpochId, HealthClass, MemberClass, MemberId};
use tidefs_node_drain::FenceToken;

// ---------------------------------------------------------------------------
// SWIM protocol wire messages
// ---------------------------------------------------------------------------

/// SWIM ping message: sent by pinger to target every PING_INTERVAL (200ms).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SwimPing {
    pub pinger: MemberId,
    pub ping_target: MemberId,
    pub seq_no: u64,
    pub pinger_epoch: EpochId,
    pub pinger_epoch_receipt: u64,
    pub sent_at_millis: u64,
    /// Up to k=3 indirect peers for suspicion confirmation
    pub indirect_via: Vec<MemberId>,
    pub signature: Vec<u8>,
}

impl SwimPing {
    pub fn sign(&mut self, keypair: &Keypair) {
        self.signature = Vec::new();
        let preimage = self.preimage_for_signing();
        self.signature = keypair.sign(&preimage).to_bytes().to_vec();
    }

    pub fn verify(&self, verifying_key: &ed25519_dalek::PublicKey) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        let preimage = self.preimage_for_signing();
        if let Ok(sig) = Signature::from_bytes(&self.signature) {
            verifying_key.verify(&preimage, &sig).is_ok()
        } else {
            false
        }
    }

    fn preimage_for_signing(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.pinger.0.to_le_bytes());
        buf.extend_from_slice(&self.ping_target.0.to_le_bytes());
        buf.extend_from_slice(&self.seq_no.to_le_bytes());
        buf.extend_from_slice(&self.pinger_epoch.0.to_le_bytes());
        buf.extend_from_slice(&self.pinger_epoch_receipt.to_le_bytes());
        buf.extend_from_slice(&self.sent_at_millis.to_le_bytes());
        for peer in &self.indirect_via {
            buf.extend_from_slice(&peer.0.to_le_bytes());
        }
        buf
    }
}

/// SWIM ack: response to a ping, piggybacking suspicion and membership deltas.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SwimAck {
    pub ping_seq_no: u64,
    pub acker: MemberId,
    pub acker_epoch: EpochId,
    pub acker_epoch_receipt: u64,
    pub suspicion_list: Vec<SuspicionRecord>,
    pub membership_delta: Vec<MembershipDelta>,
    pub acked_at_millis: u64,
    pub signature: Vec<u8>,
}

impl SwimAck {
    pub fn sign(&mut self, keypair: &Keypair) {
        self.signature = Vec::new();
        let preimage = self.preimage_for_signing();
        self.signature = keypair.sign(&preimage).to_bytes().to_vec();
    }

    pub fn verify(&self, verifying_key: &ed25519_dalek::PublicKey) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        let preimage = self.preimage_for_signing();
        if let Ok(sig) = Signature::from_bytes(&self.signature) {
            verifying_key.verify(&preimage, &sig).is_ok()
        } else {
            false
        }
    }

    fn preimage_for_signing(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.ping_seq_no.to_le_bytes());
        buf.extend_from_slice(&self.acker.0.to_le_bytes());
        buf.extend_from_slice(&self.acker_epoch.0.to_le_bytes());
        buf.extend_from_slice(&self.acker_epoch_receipt.to_le_bytes());
        for s in &self.suspicion_list {
            buf.extend_from_slice(&s.subject.0.to_le_bytes());
            buf.extend_from_slice(&s.reported_at_millis.to_le_bytes());
        }
        for d in &self.membership_delta {
            buf.extend_from_slice(&d.member_id.0.to_le_bytes());
            buf.push(d.kind as u8);
        }
        buf.extend_from_slice(&self.acked_at_millis.to_le_bytes());
        buf
    }
}

/// SWIM indirect ping request: sent to k random peers when direct ping times out.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SwimIndirectPingRequest {
    pub requester: MemberId,
    pub target: MemberId,
    pub original_seq_no: u64,
    /// Monotonic relay sequence number for stale-response rejection.
    pub relay_seq_no: u64,
    pub sent_at_millis: u64,
    pub signature: Vec<u8>,
}

impl SwimIndirectPingRequest {
    pub fn sign(&mut self, keypair: &Keypair) {
        self.signature = Vec::new();
        let preimage = self.preimage();
        self.signature = keypair.sign(&preimage).to_bytes().to_vec();
    }

    pub fn verify(&self, verifying_key: &ed25519_dalek::PublicKey) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        if let Ok(sig) = Signature::from_bytes(&self.signature) {
            verifying_key.verify(&self.preimage(), &sig).is_ok()
        } else {
            false
        }
    }

    fn preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.requester.0.to_le_bytes());
        buf.extend_from_slice(&self.target.0.to_le_bytes());
        buf.extend_from_slice(&self.original_seq_no.to_le_bytes());
        buf.extend_from_slice(&self.relay_seq_no.to_le_bytes());
        buf.extend_from_slice(&self.sent_at_millis.to_le_bytes());
        buf
    }
}

/// Response to an indirect ping request.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SwimIndirectPingResponse {
    pub responder: MemberId,
    pub target: MemberId,
    pub target_reachable: bool,
    /// Monotonic relay sequence number echoed from the request.
    pub relay_seq_no: u64,
    pub responded_at_millis: u64,
    pub signature: Vec<u8>,
}

impl SwimIndirectPingResponse {
    pub fn sign(&mut self, keypair: &Keypair) {
        self.signature = Vec::new();
        let preimage = self.preimage();
        self.signature = keypair.sign(&preimage).to_bytes().to_vec();
    }

    pub fn verify(&self, verifying_key: &ed25519_dalek::PublicKey) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        if let Ok(sig) = Signature::from_bytes(&self.signature) {
            verifying_key.verify(&self.preimage(), &sig).is_ok()
        } else {
            false
        }
    }

    fn preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.responder.0.to_le_bytes());
        buf.extend_from_slice(&self.target.0.to_le_bytes());
        buf.push(self.target_reachable as u8);
        buf.extend_from_slice(&self.relay_seq_no.to_le_bytes());
        buf.extend_from_slice(&self.responded_at_millis.to_le_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// Suspicion and membership delta records
// ---------------------------------------------------------------------------

/// A suspicion record: raised when a node is suspected dead.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuspicionRecord {
    pub subject: MemberId,
    pub reported_by: MemberId,
    pub reported_at_millis: u64,
    pub suspicion_source: SuspicionSource,
}

impl SuspicionRecord {
    pub fn new(
        subject: MemberId,
        reported_by: MemberId,
        reported_at_millis: u64,
        source: SuspicionSource,
    ) -> Self {
        Self {
            subject,
            reported_by,
            reported_at_millis,
            suspicion_source: source,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuspicionSource {
    /// Direct ping timed out
    DirectTimeout,
    /// All k indirect pings timed out
    IndirectAllTimeout,
    /// Piggybacked from another node's ack
    Piggybacked,
}

/// A membership delta: join or leave event.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct MembershipDelta {
    pub member_id: MemberId,
    pub kind: MembershipDeltaKind,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MembershipDeltaKind {
    Joined = 0,
    Left = 1,
    Suspect = 2,
    Cleared = 3,
}

// ---------------------------------------------------------------------------
// Epoch transition protocol messages
// ---------------------------------------------------------------------------

/// Reason for an epoch transition.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionReason {
    FailureDetected,
    GracefulLeave,
    JoinRequested,
    PromotedToVoter,
    DemotedFromVoter,
}

/// Phase 1: propose a new epoch.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EpochTransitionProposal {
    pub proposal_id: u64,
    pub proposer: MemberId,
    pub from_epoch: EpochId,
    pub to_epoch: EpochId,
    pub members_added: Vec<MemberId>,
    pub members_removed: Vec<MemberId>,
    pub reason: TransitionReason,
    pub validation: Vec<SuspicionRecord>,
    pub proposed_at_millis: u64,
    /// Optional fence token carried when this transition fences a node.
    /// Present when a node is being forcibly fenced (Timeout or Operator trigger).
    pub fence_token: Option<FenceToken>,
    pub proposer_signature: Vec<u8>,
}

impl EpochTransitionProposal {
    pub fn sign(&mut self, keypair: &Keypair) {
        self.proposer_signature = Vec::new();
        let preimage = self.preimage();
        self.proposer_signature = keypair.sign(&preimage).to_bytes().to_vec();
    }

    pub fn verify(&self, verifying_key: &ed25519_dalek::PublicKey) -> bool {
        if self.proposer_signature.is_empty() {
            return false;
        }
        if let Ok(sig) = Signature::from_bytes(&self.proposer_signature) {
            verifying_key.verify(&self.preimage(), &sig).is_ok()
        } else {
            false
        }
    }

    fn preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.proposal_id.to_le_bytes());
        buf.extend_from_slice(&self.proposer.0.to_le_bytes());
        buf.extend_from_slice(&self.from_epoch.0.to_le_bytes());
        buf.extend_from_slice(&self.to_epoch.0.to_le_bytes());
        for m in &self.members_added {
            buf.extend_from_slice(&m.0.to_le_bytes());
        }
        for m in &self.members_removed {
            buf.extend_from_slice(&m.0.to_le_bytes());
        }
        buf.extend_from_slice(&(self.reason as u8).to_le_bytes());
        buf.extend_from_slice(&self.proposed_at_millis.to_le_bytes());
        // Include fence token in preimage for authenticated fencing
        if let Some(token) = self.fence_token {
            buf.extend_from_slice(&token.value().to_le_bytes());
        }
        buf
    }
}

/// Phase 2: accept a proposal.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EpochTransitionAccept {
    pub proposal_id: u64,
    pub acceptor: MemberId,
    pub accepted_at_millis: u64,
    pub resulting_voter_set: Vec<MemberId>,
    pub signature: Vec<u8>,
}

impl EpochTransitionAccept {
    pub fn sign(&mut self, keypair: &Keypair) {
        self.signature = Vec::new();
        let preimage = self.preimage();
        self.signature = keypair.sign(&preimage).to_bytes().to_vec();
    }

    pub fn verify(&self, verifying_key: &ed25519_dalek::PublicKey) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        if let Ok(sig) = Signature::from_bytes(&self.signature) {
            verifying_key.verify(&self.preimage(), &sig).is_ok()
        } else {
            false
        }
    }

    fn preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.proposal_id.to_le_bytes());
        buf.extend_from_slice(&self.acceptor.0.to_le_bytes());
        buf.extend_from_slice(&self.accepted_at_millis.to_le_bytes());
        for v in &self.resulting_voter_set {
            buf.extend_from_slice(&v.0.to_le_bytes());
        }
        buf
    }
}

/// Phase 3: commit the epoch transition after quorum accepts.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EpochTransitionCommit {
    pub proposal_id: u64,
    pub new_epoch: EpochId,
    pub accept_receipts: Vec<u64>,
    pub committed_at_millis: u64,
    pub proposer_signature: Vec<u8>,
}

impl EpochTransitionCommit {
    pub fn sign(&mut self, keypair: &Keypair) {
        self.proposer_signature = Vec::new();
        let preimage = self.preimage();
        self.proposer_signature = keypair.sign(&preimage).to_bytes().to_vec();
    }

    pub fn verify(&self, verifying_key: &ed25519_dalek::PublicKey) -> bool {
        if self.proposer_signature.is_empty() {
            return false;
        }
        if let Ok(sig) = Signature::from_bytes(&self.proposer_signature) {
            verifying_key.verify(&self.preimage(), &sig).is_ok()
        } else {
            false
        }
    }

    fn preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.proposal_id.to_le_bytes());
        buf.extend_from_slice(&self.new_epoch.0.to_le_bytes());
        for r in &self.accept_receipts {
            buf.extend_from_slice(&r.to_le_bytes());
        }
        buf.extend_from_slice(&self.committed_at_millis.to_le_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// Runtime types
// ---------------------------------------------------------------------------

/// Immutable snapshot of one member in a membership view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MembershipViewNode {
    pub member_id: MemberId,
    pub member_class: MemberClass,
    pub health: HealthClass,
    pub epoch: EpochId,
    pub failure_domain: u64,
    pub joining: bool,
    pub draining: bool,
}

/// Epoch-sequenced membership snapshot suitable for transport exchange.
///
/// `placement_version` carries the placement map version at the time this
/// view was generated. When > 0, receivers can use it to verify they observe
/// the same placement map version as the coordinator. Version 0 means
/// "no placement map yet" (pre-versioning nodes or initial bootstrap).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MembershipView {
    pub epoch: EpochId,
    pub config_class: tidefs_membership_epoch::ConfigClass,
    pub local_member: MemberId,
    pub nodes: Vec<MembershipViewNode>,
    /// Placement map version active when this view was generated.
    /// 0 = no placement map yet.
    #[serde(default)]
    pub placement_version: u64,
}

/// Per-member state tracked by the MembershipRuntime.
#[derive(Clone, Debug)]
pub struct PeerState {
    pub member_id: MemberId,
    pub member_class: MemberClass,
    pub health: HealthClass,
    pub epoch: EpochId,
    pub last_ack_millis: u64,
    pub ping_seq_no: u64,
    pub failure_domain: u64,
    /// Number of consecutive failed pings
    pub failed_ping_count: u32,
    /// When this peer entered the suspect state (0 = not suspect)
    pub suspect_since_millis: u64,
    /// Indicates this peer is in the process of joining
    pub joining: bool,
    /// Indicates this peer is draining
    pub draining: bool,
}

impl PeerState {
    pub fn new(member_id: MemberId, member_class: MemberClass, failure_domain: u64) -> Self {
        Self {
            member_id,
            member_class,
            health: HealthClass::Healthy,
            epoch: EpochId::ZERO,
            last_ack_millis: 0,
            ping_seq_no: 0,
            failure_domain,
            failed_ping_count: 0,
            suspect_since_millis: 0,
            joining: false,
            draining: false,
        }
    }

    pub fn is_alive(&self) -> bool {
        matches!(self.health, HealthClass::Healthy | HealthClass::Suspect)
    }

    pub fn is_voter(&self) -> bool {
        self.member_class == MemberClass::Voter
    }

    pub fn can_hold_data(&self) -> bool {
        self.member_class.can_hold_replicas()
    }
}

/// Configuration for the membership runtime.
#[derive(Clone, Debug)]
pub struct MembershipConfig {
    pub ping_interval_ms: u64,
    pub ping_timeout_ms: u64,
    pub suspicion_window_ms: u64,
    pub indirect_ping_count: usize,
    pub min_voters_for_quorum: usize,
    pub max_failed_pings_before_suspect: u32,
}

impl Default for MembershipConfig {
    fn default() -> Self {
        Self {
            ping_interval_ms: 200,
            ping_timeout_ms: 1000,
            suspicion_window_ms: 3000,
            indirect_ping_count: 3,
            min_voters_for_quorum: 2,
            max_failed_pings_before_suspect: 5,
        }
    }
}

/// Helper: approximate current time in milliseconds.
pub(crate) fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Epoch proposal and commit protocol types (#5044)
// ---------------------------------------------------------------------------
// These types complement the existing EpochTransitionProposal / Accept / Commit
// with BLAKE3-keyed proposal digests for idempotency, a structured Vote enum
// (Accept/Reject/Timeout), and a quorum proof embedded in EpochCommit.

/// Reason a voter rejected a proposal.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionReason {
    EpochMismatch,
    InvalidSignature,
    ProposerNotAlive,
    InsufficientValidation,
    MemberSetConflict,
    LeaderTermStale,
    Unknown = 255,
}

/// Leader-driven epoch proposal with BLAKE3-keyed digest for idempotency.
///
/// The proposal digest is computed via BLAKE3 keyed hashing using the
/// `proposal_nonce` zero-extended to 32 bytes as the key. Every voter
/// binds its vote to this digest so that accept/reject signatures cover
/// a stable proposal identity even after bincode re-encoding.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EpochProposal {
    pub proposer: MemberId,
    pub proposed_member_set: Vec<MemberId>,
    pub epoch_number: EpochId,
    pub leader_term: u64,
    /// Idempotency nonce; also used as the BLAKE3 key for proposal digest.
    pub proposal_nonce: u64,
    pub created_at_millis: u64,
    pub proposer_signature: Vec<u8>,
}

impl EpochProposal {
    /// Compute the BLAKE3 digest of this proposal keyed by `proposal_nonce`.
    ///
    /// The nonce is zero-extended to 32 bytes to form a valid BLAKE3 key.
    /// All fields that identify the proposal are hashed in canonical order
    /// so that every node computes an identical digest for the same proposal.
    pub fn proposal_digest(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&self.proposal_nonce.to_le_bytes());
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(&self.proposer.0.to_le_bytes());
        hasher.update(&self.epoch_number.0.to_le_bytes());
        hasher.update(&self.leader_term.to_le_bytes());
        // Sort member set for deterministic digest independent of insertion order
        let mut sorted_members = self.proposed_member_set.clone();
        sorted_members.sort();
        for m in &sorted_members {
            hasher.update(&m.0.to_le_bytes());
        }
        hasher.finalize().into()
    }

    /// Sign the proposal with an Ed25519 keypair.
    pub fn sign(&mut self, keypair: &ed25519_dalek::Keypair) {
        self.proposer_signature = Vec::new();
        let preimage = self.preimage();
        self.proposer_signature = keypair.sign(&preimage).to_bytes().to_vec();
    }

    /// Verify the proposal's Ed25519 signature.
    pub fn verify(&self, verifying_key: &ed25519_dalek::PublicKey) -> bool {
        if self.proposer_signature.is_empty() {
            return false;
        }
        if let Ok(sig) = ed25519_dalek::Signature::from_bytes(&self.proposer_signature) {
            verifying_key.verify(&self.preimage(), &sig).is_ok()
        } else {
            false
        }
    }

    fn preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.proposer.0.to_le_bytes());
        buf.extend_from_slice(&self.epoch_number.0.to_le_bytes());
        buf.extend_from_slice(&self.leader_term.to_le_bytes());
        buf.extend_from_slice(&self.proposal_nonce.to_le_bytes());
        let mut sorted = self.proposed_member_set.clone();
        sorted.sort();
        for m in &sorted {
            buf.extend_from_slice(&m.0.to_le_bytes());
        }
        buf.extend_from_slice(&self.created_at_millis.to_le_bytes());
        buf
    }
}

/// A signed accept vote bound to a specific proposal digest.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignedAccept {
    pub voter: MemberId,
    pub proposal_digest: [u8; 32],
    pub voted_at_millis: u64,
    pub signature: Vec<u8>,
}

impl SignedAccept {
    /// Sign this accept with an Ed25519 keypair.
    pub fn sign(&mut self, keypair: &ed25519_dalek::Keypair) {
        self.signature = Vec::new();
        let preimage = self.preimage();
        self.signature = keypair.sign(&preimage).to_bytes().to_vec();
    }

    /// Verify the accept's Ed25519 signature.
    pub fn verify(&self, verifying_key: &ed25519_dalek::PublicKey) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        if let Ok(sig) = ed25519_dalek::Signature::from_bytes(&self.signature) {
            verifying_key.verify(&self.preimage(), &sig).is_ok()
        } else {
            false
        }
    }

    fn preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.voter.0.to_le_bytes());
        buf.extend_from_slice(&self.proposal_digest);
        buf.extend_from_slice(&self.voted_at_millis.to_le_bytes());
        buf
    }
}

/// A vote cast by a member in response to an [`EpochProposal`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum EpochVote {
    /// Voter accepts the proposal and binds their signature over the digest.
    Accept(SignedAccept),
    /// Voter rejects with a reason code.
    Reject {
        voter: MemberId,
        proposal_digest: [u8; 32],
        reason: RejectionReason,
        voted_at_millis: u64,
        signature: Vec<u8>,
    },
    /// Sentinel produced when the vote timeout expires without a response.
    Timeout {
        proposal_digest: [u8; 32],
        timed_out_at_millis: u64,
    },
}

impl EpochVote {
    /// Return the proposal digest this vote references, if any.
    pub fn proposal_digest(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Accept(a) => Some(&a.proposal_digest),
            Self::Reject {
                proposal_digest, ..
            } => Some(proposal_digest),
            Self::Timeout {
                proposal_digest, ..
            } => Some(proposal_digest),
        }
    }
}

/// Quorum proof: threshold number of signed Accept votes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct QuorumProof {
    /// Minimum number of Accepts required to commit (e.g. simple-majority floor(N/2)+1).
    pub threshold: usize,
    /// Signed accept votes from distinct voters meeting or exceeding the threshold.
    pub signed_accepts: Vec<SignedAccept>,
}

impl QuorumProof {
    /// Returns true when the number of distinct signed accepts meets or
    /// exceeds the threshold.
    pub fn quorum_met(&self) -> bool {
        let mut voters: Vec<MemberId> = self.signed_accepts.iter().map(|a| a.voter).collect();
        voters.sort();
        voters.dedup();
        voters.len() >= self.threshold
    }
}

/// Atomic epoch commit record carrying the committed member set, epoch
/// number, and quorum proof. This is the persistent epoch log entry.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EpochCommit {
    pub committed_member_set: Vec<MemberId>,
    pub epoch_number: EpochId,
    /// Quorum proof (threshold + signed accept votes).
    pub quorum_proof: QuorumProof,
    /// Monotonic epoch counter for crash-consistency on restart.
    pub monotonic_epoch_counter: u64,
    pub committed_at_millis: u64,
    pub leader_signature: Vec<u8>,
}

impl EpochCommit {
    /// Sign the commit with an Ed25519 keypair.
    pub fn sign(&mut self, keypair: &ed25519_dalek::Keypair) {
        self.leader_signature = Vec::new();
        let preimage = self.preimage();
        self.leader_signature = keypair.sign(&preimage).to_bytes().to_vec();
    }

    /// Verify the commit's Ed25519 signature.
    pub fn verify(&self, verifying_key: &ed25519_dalek::PublicKey) -> bool {
        if self.leader_signature.is_empty() {
            return false;
        }
        if let Ok(sig) = ed25519_dalek::Signature::from_bytes(&self.leader_signature) {
            verifying_key.verify(&self.preimage(), &sig).is_ok()
        } else {
            false
        }
    }

    fn preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut sorted = self.committed_member_set.clone();
        sorted.sort();
        for m in &sorted {
            buf.extend_from_slice(&m.0.to_le_bytes());
        }
        buf.extend_from_slice(&self.epoch_number.0.to_le_bytes());
        buf.extend_from_slice(&self.monotonic_epoch_counter.to_le_bytes());
        buf.extend_from_slice(&self.committed_at_millis.to_le_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// Tests for EpochProposal, EpochVote, and EpochCommit
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proposal_commit_tests {
    use super::*;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    fn make_keypair() -> Keypair {
        let mut csprng = OsRng;
        Keypair::generate(&mut csprng)
    }

    // ----- EpochProposal bincode round-trip -----

    #[test]
    fn proposal_bincode_roundtrip() {
        let kp = make_keypair();
        let mut prop = EpochProposal {
            proposer: MemberId::new(1),
            proposed_member_set: vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            epoch_number: EpochId::new(7),
            leader_term: 3,
            proposal_nonce: 0xDEAD_BEEF_CAFE_BABE,
            created_at_millis: 1_700_000_000_000,
            proposer_signature: Vec::new(),
        };
        prop.sign(&kp);

        let encoded = bincode::serialize(&prop).expect("bincode serialize");
        let decoded: EpochProposal = bincode::deserialize(&encoded).expect("bincode deserialize");

        assert_eq!(prop.proposer, decoded.proposer);
        assert_eq!(prop.proposed_member_set, decoded.proposed_member_set);
        assert_eq!(prop.epoch_number, decoded.epoch_number);
        assert_eq!(prop.leader_term, decoded.leader_term);
        assert_eq!(prop.proposal_nonce, decoded.proposal_nonce);
        assert_eq!(prop.created_at_millis, decoded.created_at_millis);
        assert_eq!(prop.proposer_signature, decoded.proposer_signature);
        assert!(decoded.verify(&kp.public));
    }

    // ----- BLAKE3 proposal digest -----

    #[test]
    fn proposal_digest_is_deterministic() {
        let kp = make_keypair();
        let mut prop1 = EpochProposal {
            proposer: MemberId::new(1),
            proposed_member_set: vec![MemberId::new(2), MemberId::new(1), MemberId::new(3)],
            epoch_number: EpochId::new(5),
            leader_term: 2,
            proposal_nonce: 42,
            created_at_millis: 1_700_000_000_000,
            proposer_signature: Vec::new(),
        };
        prop1.sign(&kp);

        let mut prop2 = prop1.clone();
        // Member set in different order → same digest (members are sorted)
        prop2.proposed_member_set = vec![MemberId::new(3), MemberId::new(2), MemberId::new(1)];
        prop2.proposer_signature = Vec::new();
        prop2.sign(&kp);

        let d1 = prop1.proposal_digest();
        let d2 = prop2.proposal_digest();
        assert_eq!(
            d1, d2,
            "digest must be independent of member set insertion order"
        );
    }

    #[test]
    fn proposal_digest_changes_with_nonce() {
        let kp = make_keypair();
        let mut prop1 = EpochProposal {
            proposer: MemberId::new(1),
            proposed_member_set: vec![MemberId::new(1), MemberId::new(2)],
            epoch_number: EpochId::new(3),
            leader_term: 1,
            proposal_nonce: 100,
            created_at_millis: 1_700_000_000_000,
            proposer_signature: Vec::new(),
        };
        prop1.sign(&kp);

        let mut prop2 = prop1.clone();
        prop2.proposal_nonce = 200;
        prop2.proposer_signature = Vec::new();
        prop2.sign(&kp);

        let d1 = prop1.proposal_digest();
        let d2 = prop2.proposal_digest();
        assert_ne!(d1, d2, "different nonces must produce different digests");
    }

    #[test]
    fn proposal_digest_changes_with_member_set() {
        let kp = make_keypair();
        let mut prop1 = EpochProposal {
            proposer: MemberId::new(1),
            proposed_member_set: vec![MemberId::new(1), MemberId::new(2)],
            epoch_number: EpochId::new(3),
            leader_term: 1,
            proposal_nonce: 1,
            created_at_millis: 1_700_000_000_000,
            proposer_signature: Vec::new(),
        };
        prop1.sign(&kp);

        let mut prop2 = prop1.clone();
        prop2.proposed_member_set = vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)];
        prop2.proposer_signature = Vec::new();
        prop2.sign(&kp);

        let d1 = prop1.proposal_digest();
        let d2 = prop2.proposal_digest();
        assert_ne!(
            d1, d2,
            "different member sets must produce different digests"
        );
    }

    // ----- SignedAccept bincode round-trip -----

    #[test]
    fn signed_accept_bincode_roundtrip() {
        let kp = make_keypair();
        let digest = [0xABu8; 32];
        let mut accept = SignedAccept {
            voter: MemberId::new(2),
            proposal_digest: digest,
            voted_at_millis: 1_700_000_000_100,
            signature: Vec::new(),
        };
        accept.sign(&kp);

        let encoded = bincode::serialize(&accept).expect("bincode serialize");
        let decoded: SignedAccept = bincode::deserialize(&encoded).expect("bincode deserialize");

        assert_eq!(accept.voter, decoded.voter);
        assert_eq!(accept.proposal_digest, decoded.proposal_digest);
        assert_eq!(accept.voted_at_millis, decoded.voted_at_millis);
        assert_eq!(accept.signature, decoded.signature);
        assert!(decoded.verify(&kp.public));
    }

    // ----- EpochVote bincode round-trip (all three variants) -----

    #[test]
    fn epoch_vote_accept_bincode_roundtrip() {
        let kp = make_keypair();
        let digest = [0xCDu8; 32];
        let mut accept = SignedAccept {
            voter: MemberId::new(3),
            proposal_digest: digest,
            voted_at_millis: 1_700_000_000_200,
            signature: Vec::new(),
        };
        accept.sign(&kp);
        let vote = EpochVote::Accept(accept);

        let encoded = bincode::serialize(&vote).expect("bincode serialize");
        let decoded: EpochVote = bincode::deserialize(&encoded).expect("bincode deserialize");

        match decoded {
            EpochVote::Accept(a) => {
                assert_eq!(a.voter, MemberId::new(3));
                assert_eq!(a.proposal_digest, digest);
                assert!(a.verify(&kp.public));
            }
            _ => panic!("expected Accept, got {decoded:?}"),
        }
    }

    #[test]
    fn epoch_vote_reject_bincode_roundtrip() {
        let kp = make_keypair();
        let digest = [0xEFu8; 32];
        let preimage = {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MemberId::new(4).0.to_le_bytes());
            buf.extend_from_slice(&digest);
            buf.push(RejectionReason::MemberSetConflict as u8);
            buf.extend_from_slice(&1_700_000_000_300u64.to_le_bytes());
            buf
        };
        let sig = kp.sign(&preimage).to_bytes().to_vec();
        let reject = EpochVote::Reject {
            voter: MemberId::new(4),
            proposal_digest: digest,
            reason: RejectionReason::MemberSetConflict,
            voted_at_millis: 1_700_000_000_300,
            signature: sig,
        };

        let encoded = bincode::serialize(&reject).expect("bincode serialize");
        let decoded: EpochVote = bincode::deserialize(&encoded).expect("bincode deserialize");

        match decoded {
            EpochVote::Reject {
                voter,
                proposal_digest,
                reason,
                voted_at_millis,
                signature,
            } => {
                assert_eq!(voter, MemberId::new(4));
                assert_eq!(proposal_digest, digest);
                assert_eq!(reason, RejectionReason::MemberSetConflict);
                assert_eq!(voted_at_millis, 1_700_000_000_300);
                assert!(!signature.is_empty());
            }
            _ => panic!("expected Reject, got {decoded:?}"),
        }
    }

    #[test]
    fn epoch_vote_timeout_bincode_roundtrip() {
        let digest = [0x11u8; 32];
        let vote = EpochVote::Timeout {
            proposal_digest: digest,
            timed_out_at_millis: 1_700_000_000_400,
        };

        let encoded = bincode::serialize(&vote).expect("bincode serialize");
        let decoded: EpochVote = bincode::deserialize(&encoded).expect("bincode deserialize");

        match decoded {
            EpochVote::Timeout {
                proposal_digest,
                timed_out_at_millis,
            } => {
                assert_eq!(proposal_digest, digest);
                assert_eq!(timed_out_at_millis, 1_700_000_000_400);
            }
            _ => panic!("expected Timeout, got {decoded:?}"),
        }
    }

    // ----- EpochCommit bincode round-trip -----

    #[test]
    fn epoch_commit_bincode_roundtrip() {
        let kp = make_keypair();
        let accept_kp = make_keypair();

        let digest = [0x22u8; 32];
        let mut sa = SignedAccept {
            voter: MemberId::new(2),
            proposal_digest: digest,
            voted_at_millis: 1_700_000_000_100,
            signature: Vec::new(),
        };
        sa.sign(&accept_kp);

        let qp = QuorumProof {
            threshold: 2,
            signed_accepts: vec![sa],
        };

        let mut commit = EpochCommit {
            committed_member_set: vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            epoch_number: EpochId::new(7),
            quorum_proof: qp,
            monotonic_epoch_counter: 7,
            committed_at_millis: 1_700_000_000_500,
            leader_signature: Vec::new(),
        };
        commit.sign(&kp);

        let encoded = bincode::serialize(&commit).expect("bincode serialize");
        let decoded: EpochCommit = bincode::deserialize(&encoded).expect("bincode deserialize");

        assert_eq!(commit.epoch_number, decoded.epoch_number);
        assert_eq!(commit.committed_member_set, decoded.committed_member_set);
        assert_eq!(
            commit.monotonic_epoch_counter,
            decoded.monotonic_epoch_counter
        );
        assert_eq!(
            commit.quorum_proof.threshold,
            decoded.quorum_proof.threshold
        );
        assert_eq!(
            commit.quorum_proof.signed_accepts.len(),
            decoded.quorum_proof.signed_accepts.len(),
        );
        assert_eq!(commit.committed_at_millis, decoded.committed_at_millis);
        assert_eq!(commit.leader_signature, decoded.leader_signature);
        assert!(decoded.verify(&kp.public));
    }

    // ----- QuorumProof logic -----

    #[test]
    fn quorum_proof_met_with_sufficient_distinct_accepts() {
        let kp1 = make_keypair();
        let kp2 = make_keypair();
        let digest = [0x33u8; 32];

        let mut sa1 = SignedAccept {
            voter: MemberId::new(1),
            proposal_digest: digest,
            voted_at_millis: 100,
            signature: Vec::new(),
        };
        sa1.sign(&kp1);

        let mut sa2 = SignedAccept {
            voter: MemberId::new(2),
            proposal_digest: digest,
            voted_at_millis: 200,
            signature: Vec::new(),
        };
        sa2.sign(&kp2);

        let qp = QuorumProof {
            threshold: 2,
            signed_accepts: vec![sa1, sa2],
        };
        assert!(qp.quorum_met());
    }

    #[test]
    fn quorum_proof_not_met_with_insufficient_distinct_accepts() {
        let kp1 = make_keypair();
        let digest = [0x44u8; 32];

        let mut sa1 = SignedAccept {
            voter: MemberId::new(1),
            proposal_digest: digest,
            voted_at_millis: 100,
            signature: Vec::new(),
        };
        sa1.sign(&kp1);

        let qp = QuorumProof {
            threshold: 2,
            signed_accepts: vec![sa1],
        };
        assert!(!qp.quorum_met());
    }

    #[test]
    fn quorum_proof_duplicate_voter_counts_once() {
        let kp1 = make_keypair();
        let digest = [0x55u8; 32];

        let mut sa1 = SignedAccept {
            voter: MemberId::new(1),
            proposal_digest: digest,
            voted_at_millis: 100,
            signature: Vec::new(),
        };
        sa1.sign(&kp1);

        let mut sa2 = SignedAccept {
            voter: MemberId::new(1), // same voter
            proposal_digest: digest,
            voted_at_millis: 200,
            signature: Vec::new(),
        };
        sa2.sign(&kp1);

        let qp = QuorumProof {
            threshold: 2,
            signed_accepts: vec![sa1, sa2],
        };
        assert!(
            !qp.quorum_met(),
            "duplicate voter should count once, threshold 2 not met"
        );
    }
}
