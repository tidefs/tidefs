//! Multi-node scrub fanout: coordinates scrub verification across peer nodes
//! and records cross-node validation in a deterministic audit log.
//!
//! When a node's local scrub detects a checksum mismatch on an object, it
//! fans out a verification request to one or more authoritative peers that
//! hold replicas of the same object. Each peer independently verifies its
//! local copy and returns the outcome plus optionally the verified data.
//! The coordinator aggregates responses, selects the best authoritative
//! source, and feeds the result into the repair pipeline.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_checksum_tree::Digest;
use tidefs_local_object_store::{ObjectKey, SuspectEntry};
use tidefs_replication_model::PlacementReceiptRef;

// ---------------------------------------------------------------------------
// ScrubFanoutRequest — sent to a peer for authoritative verification
// ---------------------------------------------------------------------------

/// Request a peer to verify an object's checksum and return the
/// authoritative data if the peer's copy is clean.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubFanoutRequest {
    pub suspect: SuspectEntry,
    pub object_key: ObjectKey,
    pub expected_digest: Digest,
    pub request_seq: u64,
    pub return_data_on_match: bool,
    pub timestamp_secs: u64,
    /// Durable placement receipt that authorises the object being verified.
    /// Carries the receipt identity so peers can validate placement authority.
    pub placement_receipt_ref: Option<PlacementReceiptRef>,
}

impl ScrubFanoutRequest {
    /// Encode to binary wire format via bincode.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Decode from binary wire format via bincode.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
    #[must_use]
    pub fn new(
        suspect: SuspectEntry,
        object_key: ObjectKey,
        expected_digest: Digest,
        request_seq: u64,
        return_data_on_match: bool,
    ) -> Self {
        Self {
            suspect,
            object_key,
            expected_digest,
            request_seq,
            return_data_on_match,
            placement_receipt_ref: None,
            timestamp_secs: current_timestamp_secs(),
        }
    }

    /// Create a fanout request that carries receipt authority.
    #[must_use]
    pub fn new_with_receipt(
        suspect: SuspectEntry,
        object_key: ObjectKey,
        expected_digest: Digest,
        request_seq: u64,
        return_data_on_match: bool,
        placement_receipt_ref: PlacementReceiptRef,
    ) -> Self {
        Self {
            suspect,
            object_key,
            expected_digest,
            request_seq,
            return_data_on_match,
            placement_receipt_ref: Some(placement_receipt_ref),
            timestamp_secs: current_timestamp_secs(),
        }
    }

    /// Whether this request carries receipt authority.
    #[must_use]
    pub fn has_receipt_ref(&self) -> bool {
        self.placement_receipt_ref.is_some()
    }

    /// The placement receipt ref carried by this request, if any.
    #[must_use]
    pub fn receipt_ref(&self) -> Option<&PlacementReceiptRef> {
        self.placement_receipt_ref.as_ref()
    }
}

// ---------------------------------------------------------------------------
// PeerVerificationOutcome + ScrubFanoutResponse
// ---------------------------------------------------------------------------

/// Outcome of a peer's local object verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerVerificationOutcome {
    Clean {
        object_id: String,
        verified_data: Option<Vec<u8>>,
    },
    Mismatch {
        object_id: String,
        expected: Digest,
        actual: Digest,
    },
    NotFound {
        object_id: String,
    },
    Error {
        object_id: String,
        error: String,
    },
}

impl PeerVerificationOutcome {
    #[must_use]
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::Clean { .. })
    }

    #[must_use]
    pub fn object_id(&self) -> &str {
        match self {
            Self::Clean { object_id, .. }
            | Self::Mismatch { object_id, .. }
            | Self::NotFound { object_id }
            | Self::Error { object_id, .. } => object_id.as_str(),
        }
    }

    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Clean { .. } => "clean",
            Self::Mismatch { .. } => "mismatch",
            Self::NotFound { .. } => "not-found",
            Self::Error { .. } => "error",
        }
    }
}

/// Response from a peer to a [`ScrubFanoutRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubFanoutResponse {
    pub request_seq: u64,
    pub peer_node_id: u64,
    pub outcome: PeerVerificationOutcome,
    pub timestamp_secs: u64,
}

impl ScrubFanoutResponse {
    /// Encode to binary wire format via bincode.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Decode from binary wire format via bincode.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
    #[must_use]
    pub fn new(request_seq: u64, peer_node_id: u64, outcome: PeerVerificationOutcome) -> Self {
        Self {
            request_seq,
            peer_node_id,
            outcome,
            timestamp_secs: current_timestamp_secs(),
        }
    }
}

// ---------------------------------------------------------------------------
// FanoutAuditEntry + MultiNodeScrubAudit
// ---------------------------------------------------------------------------

/// Single entry in the multi-node scrub fanout audit log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FanoutAuditEntry {
    pub request_seq: u64,
    pub locator_id: u64,
    pub object_key_bytes: Vec<u8>,
    pub expected_digest: Digest,
    pub peer_node_id: u64,
    pub outcome_label: String,
    pub was_authoritative: bool,
    pub actual_digest: Option<Digest>,
    pub request_timestamp_secs: u64,
    pub response_timestamp_secs: u64,
}

impl FanoutAuditEntry {
    /// Encode to binary wire format via bincode.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Decode from binary wire format via bincode.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Accumulates cross-node scrub verification validation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiNodeScrubAudit {
    entries: Vec<FanoutAuditEntry>,
    pub clean_count: u64,
    pub mismatch_count: u64,
    pub not_found_count: u64,
    pub error_count: u64,
    pub peers_consulted: u64,
    peer_ids: HashSet<u64>,
}

impl MultiNodeScrubAudit {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            clean_count: 0,
            mismatch_count: 0,
            not_found_count: 0,
            error_count: 0,
            peers_consulted: 0,
            peer_ids: HashSet::new(),
        }
    }

    pub fn record(&mut self, request: &ScrubFanoutRequest, response: &ScrubFanoutResponse) {
        let was_authoritative = response.outcome.is_clean();
        let actual_digest = match &response.outcome {
            PeerVerificationOutcome::Mismatch { actual, .. } => Some(*actual),
            _ => None,
        };

        let entry = FanoutAuditEntry {
            request_seq: request.request_seq,
            locator_id: request.suspect.locator_id,
            object_key_bytes: request.object_key.as_bytes32().to_vec(),
            expected_digest: request.expected_digest,
            peer_node_id: response.peer_node_id,
            outcome_label: response.outcome.label().to_string(),
            was_authoritative,
            actual_digest,
            request_timestamp_secs: request.timestamp_secs,
            response_timestamp_secs: response.timestamp_secs,
        };

        match &response.outcome {
            PeerVerificationOutcome::Clean { .. } => self.clean_count += 1,
            PeerVerificationOutcome::Mismatch { .. } => self.mismatch_count += 1,
            PeerVerificationOutcome::NotFound { .. } => self.not_found_count += 1,
            PeerVerificationOutcome::Error { .. } => self.error_count += 1,
        }
        self.peers_consulted += 1;
        self.peer_ids.insert(response.peer_node_id);
        self.entries.push(entry);
    }

    pub fn record_timeout(&mut self, request: &ScrubFanoutRequest, peer_node_id: u64) {
        let entry = FanoutAuditEntry {
            request_seq: request.request_seq,
            locator_id: request.suspect.locator_id,
            object_key_bytes: request.object_key.as_bytes32().to_vec(),
            expected_digest: request.expected_digest,
            peer_node_id,
            outcome_label: "timeout".to_string(),
            was_authoritative: false,
            actual_digest: None,
            request_timestamp_secs: request.timestamp_secs,
            response_timestamp_secs: 0,
        };
        self.error_count += 1;
        self.peers_consulted += 1;
        self.peer_ids.insert(peer_node_id);
        self.entries.push(entry);
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn entries(&self) -> &[FanoutAuditEntry] {
        &self.entries
    }

    #[must_use]
    pub fn distinct_peer_count(&self) -> usize {
        self.peer_ids.len()
    }

    #[must_use]
    pub fn has_authoritative_source(&self) -> bool {
        self.clean_count > 0
    }

    /// Compute a deterministic BLAKE3-256 validation digest over all entries.
    #[must_use]
    pub fn validation_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for entry in &self.entries {
            hasher.update(&entry.locator_id.to_le_bytes());
            hasher.update(&entry.peer_node_id.to_le_bytes());
            hasher.update(entry.outcome_label.as_bytes());
            hasher.update(&entry.expected_digest);
            if let Some(actual) = &entry.actual_digest {
                hasher.update(actual);
            }
            hasher.update(&[if entry.was_authoritative { 1u8 } else { 0u8 }]);
            hasher.update(&entry.request_timestamp_secs.to_le_bytes());
            hasher.update(&entry.response_timestamp_secs.to_le_bytes());
        }
        hasher.update(&self.clean_count.to_le_bytes());
        hasher.update(&self.mismatch_count.to_le_bytes());
        hasher.update(&self.not_found_count.to_le_bytes());
        hasher.update(&self.error_count.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    pub fn reset(&mut self) {
        self.entries.clear();
        self.clean_count = 0;
        self.mismatch_count = 0;
        self.not_found_count = 0;
        self.error_count = 0;
        self.peers_consulted = 0;
        self.peer_ids.clear();
    }
}

impl Default for MultiNodeScrubAudit {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FanoutTracker — per-object fanout state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum FanoutState {
    Pending,
    Authoritative,
    Unrepairable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FanoutTracker {
    request: ScrubFanoutRequest,
    peers_requested: Vec<u64>,
    peers_responded: Vec<u64>,
    best_response: Option<ScrubFanoutResponse>,
    state: FanoutState,
}

impl FanoutTracker {
    fn new(request: ScrubFanoutRequest, peers: Vec<u64>) -> Self {
        Self {
            request,
            peers_requested: peers,
            peers_responded: Vec::new(),
            best_response: None,
            state: FanoutState::Pending,
        }
    }

    fn record_response(&mut self, response: ScrubFanoutResponse) {
        self.peers_responded.push(response.peer_node_id);
        if response.outcome.is_clean() {
            self.state = FanoutState::Authoritative;
            self.best_response = Some(response);
        } else if self.best_response.is_none() {
            self.best_response = Some(response);
        }
        if self.peers_responded.len() >= self.peers_requested.len()
            && self.state == FanoutState::Pending
        {
            self.state = FanoutState::Unrepairable;
        }
    }

    fn is_complete(&self) -> bool {
        self.state == FanoutState::Authoritative
            || self.peers_responded.len() >= self.peers_requested.len()
    }

    fn has_authoritative(&self) -> bool {
        self.state == FanoutState::Authoritative
    }
}

// ---------------------------------------------------------------------------
// ScrubFanoutCoordinator
// ---------------------------------------------------------------------------

/// Coordinates multi-node scrub verification fanout.
///
/// For each suspect entry from a local scrub cycle, the coordinator
/// selects authoritative peers, fans out [`ScrubFanoutRequest`] messages,
/// collects [`ScrubFanoutResponse`] results, and tracks which objects
/// have an authoritative clean copy available for repair.
///
/// The coordinator does not own the transport layer; it produces request
/// messages for the caller to send and accepts response messages from
/// the caller.
#[derive(Debug)]
pub struct ScrubFanoutCoordinator {
    trackers: HashMap<u64, FanoutTracker>,
    next_seq: u64,
    audit: MultiNodeScrubAudit,
    peers: HashMap<u64, bool>,
    pending_requests: Vec<(u64, ScrubFanoutRequest)>,
}

impl ScrubFanoutCoordinator {
    #[must_use]
    pub fn new(peer_ids: &[u64]) -> Self {
        let peers: HashMap<u64, bool> = peer_ids.iter().map(|&id| (id, true)).collect();
        Self {
            trackers: HashMap::new(),
            next_seq: 0,
            audit: MultiNodeScrubAudit::new(),
            peers,
            pending_requests: Vec::new(),
        }
    }

    pub fn set_peer_reachable(&mut self, node_id: u64, reachable: bool) {
        self.peers.insert(node_id, reachable);
    }

    pub fn remove_peer(&mut self, node_id: u64) {
        self.peers.remove(&node_id);
    }

    #[must_use]
    pub fn peer_ids(&self) -> Vec<u64> {
        self.peers.keys().copied().collect()
    }

    #[must_use]
    pub fn reachable_peer_count(&self) -> usize {
        self.peers.values().filter(|&&r| r).count()
    }

    /// Fan out a suspect entry for multi-node verification.
    /// Selects up to `max_peers` reachable peers, creates requests,
    /// and queues them for the caller to send.
    /// Returns the number of requests queued.
    pub fn fanout(
        &mut self,
        suspect: &SuspectEntry,
        object_key: ObjectKey,
        expected_digest: Digest,
        max_peers: usize,
    ) -> usize {
        let locator_id = suspect.locator_id;
        if self.trackers.contains_key(&locator_id) {
            return 0;
        }

        let reachable: Vec<u64> = self
            .peers
            .iter()
            .filter(|(_, &r)| r)
            .map(|(&id, _)| id)
            .take(max_peers)
            .collect();

        if reachable.is_empty() {
            return 0;
        }

        let mut count = 0;
        let tracker = FanoutTracker::new(
            ScrubFanoutRequest::new(*suspect, object_key, expected_digest, self.next_seq, true),
            reachable.clone(),
        );

        for &peer_id in &reachable {
            let request =
                ScrubFanoutRequest::new(*suspect, object_key, expected_digest, self.next_seq, true);
            self.pending_requests.push((peer_id, request));
            self.next_seq += 1;
            count += 1;
        }

        self.trackers.insert(locator_id, tracker);
        count
    }

    /// Fan out a suspect entry with receipt authority for multi-node verification.
    ///
    /// Like [`fanout`] but carries the durable placement receipt so peers can
    /// verify the placement authority of the object under scrub. The receipt
    /// identifies which members are authoritative for this object; the fanout
    /// uses the reachable subset of those members rather than all known peers.
    ///
    /// Returns the number of requests queued.
    pub fn fanout_with_receipt(
        &mut self,
        suspect: &SuspectEntry,
        object_key: ObjectKey,
        expected_digest: Digest,
        max_peers: usize,
        placement_receipt_ref: PlacementReceiptRef,
    ) -> usize {
        let locator_id = suspect.locator_id;
        if self.trackers.contains_key(&locator_id) {
            return 0;
        }

        let reachable: Vec<u64> = self
            .peers
            .iter()
            .filter(|(_, &r)| r)
            .map(|(&id, _)| id)
            .take(max_peers)
            .collect();

        if reachable.is_empty() {
            return 0;
        }

        let mut count = 0;
        let tracker = FanoutTracker::new(
            ScrubFanoutRequest::new_with_receipt(
                *suspect,
                object_key,
                expected_digest,
                self.next_seq,
                true,
                placement_receipt_ref,
            ),
            reachable.clone(),
        );

        for &peer_id in &reachable {
            let request = ScrubFanoutRequest::new_with_receipt(
                *suspect,
                object_key,
                expected_digest,
                self.next_seq,
                true,
                placement_receipt_ref,
            );
            self.pending_requests.push((peer_id, request));
            self.next_seq += 1;
            count += 1;
        }

        self.trackers.insert(locator_id, tracker);
        count
    }

    #[must_use]
    pub fn drain_pending_requests(&mut self) -> Vec<(u64, ScrubFanoutRequest)> {
        std::mem::take(&mut self.pending_requests)
    }

    /// Serialize pending requests for transport (bincode).
    pub fn encode_pending(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(&self.pending_requests)
    }

    /// Deserialize pending requests from transport (bincode).
    pub fn decode_pending(bytes: &[u8]) -> Result<Vec<(u64, ScrubFanoutRequest)>, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Record a response. Returns true if authoritative data is now available.
    pub fn record_response(&mut self, response: ScrubFanoutResponse, locator_id: u64) -> bool {
        if let Some(tracker) = self.trackers.get(&locator_id) {
            self.audit.record(&tracker.request, &response);
        }
        if let Some(tracker) = self.trackers.get_mut(&locator_id) {
            tracker.record_response(response);
            tracker.has_authoritative()
        } else {
            false
        }
    }

    #[must_use]
    pub fn has_authoritative_for(&self, locator_id: u64) -> bool {
        self.trackers
            .get(&locator_id)
            .map(|t| t.has_authoritative())
            .unwrap_or(false)
    }

    #[must_use]
    pub fn is_complete_for(&self, locator_id: u64) -> bool {
        self.trackers
            .get(&locator_id)
            .map(|t| t.is_complete())
            .unwrap_or(true)
    }

    #[must_use]
    pub fn best_response_for(&self, locator_id: u64) -> Option<&ScrubFanoutResponse> {
        self.trackers.get(&locator_id)?.best_response.as_ref()
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.trackers.values().filter(|t| !t.is_complete()).count()
    }

    #[must_use]
    pub fn authoritative_count(&self) -> usize {
        self.trackers
            .values()
            .filter(|t| t.has_authoritative())
            .count()
    }

    #[must_use]
    pub fn audit(&self) -> &MultiNodeScrubAudit {
        &self.audit
    }

    #[must_use]
    pub fn audit_mut(&mut self) -> &mut MultiNodeScrubAudit {
        &mut self.audit
    }

    pub fn reset(&mut self) {
        self.trackers.clear();
        self.pending_requests.clear();
        self.next_seq = 0;
        self.audit.reset();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(locator_id: u64, record_type: u8) -> SuspectEntry {
        SuspectEntry {
            locator_id,
            entry_id: locator_id,
            segment_id: 1,
            offset: locator_id * 4096,
            record_type,
            expected_hash: [0xAA; 32],
            actual_hash: [0xBB; 32],
            repair_attempts: 0,
            last_repair_attempt: 0,
            resolved: false,
            commit_group: 1,
            timestamp_secs: 1000,
        }
    }

    fn mk_key(name: &[u8]) -> ObjectKey {
        ObjectKey::from_name(name)
    }

    fn mk_digest(byte: u8) -> Digest {
        [byte; 32]
    }

    fn clean_outcome(id: &str, data: Option<Vec<u8>>) -> PeerVerificationOutcome {
        PeerVerificationOutcome::Clean {
            object_id: id.into(),
            verified_data: data,
        }
    }

    // ── Request/Response tests ────────────────────────────────────

    #[test]
    fn request_has_timestamp() {
        let req =
            ScrubFanoutRequest::new(make_entry(1, 1), mk_key(b"obj1"), mk_digest(0xAB), 0, true);
        assert!(req.timestamp_secs > 0);
        assert!(req.return_data_on_match);
    }

    #[test]
    fn outcome_labels() {
        assert_eq!(clean_outcome("a", None).label(), "clean");
        assert_eq!(
            PeerVerificationOutcome::Mismatch {
                object_id: "b".into(),
                expected: mk_digest(0xAA),
                actual: mk_digest(0xBB),
            }
            .label(),
            "mismatch"
        );
        assert_eq!(
            PeerVerificationOutcome::NotFound {
                object_id: "c".into()
            }
            .label(),
            "not-found"
        );
        assert_eq!(
            PeerVerificationOutcome::Error {
                object_id: "d".into(),
                error: "fail".into(),
            }
            .label(),
            "error"
        );
    }

    #[test]
    fn response_has_timestamp() {
        let resp = ScrubFanoutResponse::new(42, 100, clean_outcome("obj", Some(vec![1])));
        assert_eq!(resp.request_seq, 42);
        assert_eq!(resp.peer_node_id, 100);
        assert!(resp.timestamp_secs > 0);
    }

    // ── MultiNodeScrubAudit tests ─────────────────────────────────

    #[test]
    fn audit_empty() {
        let a = MultiNodeScrubAudit::new();
        assert_eq!(a.entry_count(), 0);
        assert_eq!(a.clean_count, 0);
        assert!(!a.has_authoritative_source());
    }

    #[test]
    fn audit_records_clean() {
        let mut a = MultiNodeScrubAudit::new();
        let req =
            ScrubFanoutRequest::new(make_entry(42, 1), mk_key(b"x"), mk_digest(0xAA), 0, true);
        let resp = ScrubFanoutResponse::new(0, 200, clean_outcome("x", Some(vec![1, 2, 3])));
        a.record(&req, &resp);
        assert_eq!(a.clean_count, 1);
        assert_eq!(a.entry_count(), 1);
        assert!(a.has_authoritative_source());
    }

    #[test]
    fn audit_records_timeout() {
        let mut a = MultiNodeScrubAudit::new();
        let req = ScrubFanoutRequest::new(
            make_entry(7, 1),
            mk_key(b"ghost"),
            mk_digest(0xCC),
            2,
            false,
        );
        a.record_timeout(&req, 999);
        assert_eq!(a.error_count, 1);
        assert!(!a.has_authoritative_source());
    }

    #[test]
    fn audit_distinct_peers() {
        let mut a = MultiNodeScrubAudit::new();
        let req = ScrubFanoutRequest::new(make_entry(1, 1), mk_key(b"x"), mk_digest(0x11), 0, true);
        a.record(
            &req,
            &ScrubFanoutResponse::new(0, 100, clean_outcome("x", None)),
        );
        a.record(
            &req,
            &ScrubFanoutResponse::new(1, 200, clean_outcome("x", None)),
        );
        a.record(
            &req,
            &ScrubFanoutResponse::new(2, 100, clean_outcome("x", None)),
        );
        assert_eq!(a.distinct_peer_count(), 2);
        assert_eq!(a.peers_consulted, 3);
    }

    #[test]
    fn validation_digest_nonzero() {
        let mut a = MultiNodeScrubAudit::new();
        let req = ScrubFanoutRequest::new(make_entry(1, 1), mk_key(b"d"), mk_digest(0xDE), 0, true);
        a.record(
            &req,
            &ScrubFanoutResponse::new(0, 42, clean_outcome("d", Some(vec![0xCA, 0xFE]))),
        );
        assert_ne!(a.validation_digest(), [0u8; 32]);
    }

    #[test]
    fn validation_digest_deterministic() {
        let mut a1 = MultiNodeScrubAudit::new();
        let mut a2 = MultiNodeScrubAudit::new();
        let req =
            ScrubFanoutRequest::new(make_entry(10, 1), mk_key(b"det"), mk_digest(0xAB), 0, true);
        let resp = ScrubFanoutResponse::new(0, 7, clean_outcome("det", None));
        a1.record(&req, &resp);
        a2.record(&req, &resp);
        assert_eq!(a1.validation_digest(), a2.validation_digest());
    }

    #[test]
    fn validation_digest_differs_for_different_peers() {
        let mut a1 = MultiNodeScrubAudit::new();
        let mut a2 = MultiNodeScrubAudit::new();
        let req = ScrubFanoutRequest::new(make_entry(1, 1), mk_key(b"x"), mk_digest(0x11), 0, true);
        a1.record(
            &req,
            &ScrubFanoutResponse::new(0, 100, clean_outcome("x", None)),
        );
        a2.record(
            &req,
            &ScrubFanoutResponse::new(0, 200, clean_outcome("x", None)),
        );
        assert_ne!(a1.validation_digest(), a2.validation_digest());
    }

    #[test]
    fn audit_reset_clears_all() {
        let mut a = MultiNodeScrubAudit::new();
        let req =
            ScrubFanoutRequest::new(make_entry(1, 1), mk_key(b"tmp"), mk_digest(0xEE), 0, true);
        a.record(
            &req,
            &ScrubFanoutResponse::new(0, 1, clean_outcome("tmp", None)),
        );
        a.reset();
        assert_eq!(a.entry_count(), 0);
        assert_eq!(a.clean_count, 0);
        assert_eq!(a.peers_consulted, 0);
    }

    // ── Coordinator tests ─────────────────────────────────────────

    #[test]
    fn coord_starts_empty() {
        let mut coord = ScrubFanoutCoordinator::new(&[1, 2, 3]);
        assert_eq!(coord.active_count(), 0);
        assert_eq!(coord.reachable_peer_count(), 3);
        assert_eq!(coord.drain_pending_requests().len(), 0);
    }

    #[test]
    fn fanout_creates_requests() {
        let mut coord = ScrubFanoutCoordinator::new(&[10, 20, 30]);
        let count = coord.fanout(&make_entry(100, 1), mk_key(b"obj"), mk_digest(0x42), 2);
        assert_eq!(count, 2);
        assert_eq!(coord.active_count(), 1);
        let pending = coord.drain_pending_requests();
        assert_eq!(pending.len(), 2);
        assert_ne!(pending[0].1.request_seq, pending[1].1.request_seq);
    }

    #[test]
    fn fanout_duplicate_noop() {
        let mut coord = ScrubFanoutCoordinator::new(&[1, 2]);
        let suspect = make_entry(50, 1);
        let key = mk_key(b"dup");
        let c1 = coord.fanout(&suspect, key, mk_digest(0xFF), 2);
        assert!(c1 > 0);
        let c2 = coord.fanout(&suspect, key, mk_digest(0xFF), 2);
        assert_eq!(c2, 0);
    }

    #[test]
    fn record_clean_is_authoritative() {
        let mut coord = ScrubFanoutCoordinator::new(&[100, 200]);
        coord.fanout(&make_entry(7, 1), mk_key(b"auth"), mk_digest(0xAA), 2);
        let _ = coord.drain_pending_requests();
        let resp = ScrubFanoutResponse::new(0, 100, clean_outcome("auth", Some(vec![4, 5, 6])));
        assert!(coord.record_response(resp, 7));
        assert!(coord.has_authoritative_for(7));
        assert_eq!(coord.authoritative_count(), 1);
    }

    #[test]
    fn record_mismatch_not_authoritative() {
        let mut coord = ScrubFanoutCoordinator::new(&[300]);
        coord.fanout(&make_entry(8, 1), mk_key(b"bad"), mk_digest(0xBB), 1);
        let _ = coord.drain_pending_requests();
        let resp = ScrubFanoutResponse::new(
            0,
            300,
            PeerVerificationOutcome::Mismatch {
                object_id: "bad".into(),
                expected: mk_digest(0xBB),
                actual: mk_digest(0xCC),
            },
        );
        assert!(!coord.record_response(resp, 8));
        assert!(!coord.has_authoritative_for(8));
        assert!(coord.is_complete_for(8));
    }

    #[test]
    fn audit_accumulates_in_coordinator() {
        let mut coord = ScrubFanoutCoordinator::new(&[10, 20]);
        coord.fanout(&make_entry(1, 1), mk_key(b"audit-obj"), mk_digest(0x11), 2);
        let _ = coord.drain_pending_requests();
        coord.record_response(
            ScrubFanoutResponse::new(0, 10, clean_outcome("audit-obj", None)),
            1,
        );
        coord.record_response(
            ScrubFanoutResponse::new(
                1,
                20,
                PeerVerificationOutcome::Mismatch {
                    object_id: "audit-obj".into(),
                    expected: mk_digest(0x11),
                    actual: mk_digest(0x22),
                },
            ),
            1,
        );
        let a = coord.audit();
        assert_eq!(a.entry_count(), 2);
        assert_eq!(a.clean_count, 1);
        assert_eq!(a.mismatch_count, 1);
    }

    #[test]
    fn coord_reset_clears_state() {
        let mut coord = ScrubFanoutCoordinator::new(&[1]);
        coord.fanout(&make_entry(42, 1), mk_key(b"x"), mk_digest(0xFF), 1);
        let _ = coord.drain_pending_requests();
        coord.record_response(ScrubFanoutResponse::new(0, 1, clean_outcome("x", None)), 42);
        coord.reset();
        assert_eq!(coord.active_count(), 0);
        assert_eq!(coord.authoritative_count(), 0);
        assert_eq!(coord.audit().entry_count(), 0);
    }

    #[test]
    fn peer_reachability_controls_fanout() {
        let mut coord = ScrubFanoutCoordinator::new(&[1, 2, 3]);
        coord.set_peer_reachable(2, false);
        coord.set_peer_reachable(3, false);
        assert_eq!(coord.reachable_peer_count(), 1);
        let count = coord.fanout(&make_entry(99, 1), mk_key(b"y"), mk_digest(0xEE), 3);
        assert_eq!(count, 1);
    }

    #[test]
    fn remove_peer_excludes() {
        let mut coord = ScrubFanoutCoordinator::new(&[1, 2]);
        coord.remove_peer(2);
        let count = coord.fanout(&make_entry(10, 1), mk_key(b"z"), mk_digest(0xDD), 2);
        assert_eq!(count, 1);
    }

    #[test]
    fn best_response_prefers_authoritative() {
        let mut coord = ScrubFanoutCoordinator::new(&[100, 200]);
        coord.fanout(&make_entry(5, 1), mk_key(b"best"), mk_digest(0xAB), 2);
        let _ = coord.drain_pending_requests();
        coord.record_response(
            ScrubFanoutResponse::new(
                0,
                100,
                PeerVerificationOutcome::Mismatch {
                    object_id: "best".into(),
                    expected: mk_digest(0xAB),
                    actual: mk_digest(0xCD),
                },
            ),
            5,
        );
        let clean_data = vec![0xAB; 64];
        coord.record_response(
            ScrubFanoutResponse::new(1, 200, clean_outcome("best", Some(clean_data.clone()))),
            5,
        );
        let best = coord.best_response_for(5).unwrap();
        assert!(best.outcome.is_clean());
        match &best.outcome {
            PeerVerificationOutcome::Clean { verified_data, .. } => {
                assert_eq!(verified_data.as_ref().unwrap(), &clean_data);
            }
            _ => panic!("expected clean"),
        }
    }

    #[test]
    fn multiple_suspects_fanout_independently() {
        let mut coord = ScrubFanoutCoordinator::new(&[1, 2]);
        coord.fanout(&make_entry(1, 1), mk_key(b"a"), mk_digest(0xAA), 2);
        coord.fanout(&make_entry(2, 1), mk_key(b"b"), mk_digest(0xBB), 2);
        assert_eq!(coord.active_count(), 2);
        let pending = coord.drain_pending_requests();
        assert_eq!(pending.len(), 4);
    }
}
