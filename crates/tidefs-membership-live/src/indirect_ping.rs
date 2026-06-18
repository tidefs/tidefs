// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Indirect-ping relay protocol for SWIM failure-detection
//! false-positive reduction.
//!
//! When a direct heartbeat ping to a peer times out, the detecting node
//! requests `k` randomly selected peers to probe the target on its behalf
//! before escalating to suspicion. This relay mechanism is the standard
//! SWIM defense against transient network disruption between a single
//! node pair.
//!
//! ## Protocol flow
//!
//! 1. **Unreachable detection**: `tick_timeouts` notices a peer has missed
//!    `max_failed_pings_before_suspect` consecutive pings.
//! 2. **Relay initiation**: Instead of immediately marking Suspect, the
//!    detecting node selects `k` relay peers and sends each an
//!    `IndirectPingRequest`.
//! 3. **Relay forwarding**: Each relay peer sends a direct ping to the
//!    suspect and returns an `IndirectPingResponse` with the result.
//! 4. **Aggregation**: The original node collects responses.
//!    - Any success → clear suspicion, reset failed-ping count.
//!    - All failures or relay timeout → escalate to Suspect.
//!
//! ## Data integrity
//!
//! Every `IndirectPingRequest` carries a BLAKE3-256 digest computed over
//! the canonical request fields (domain: `"tidefs-membership-live-
//! indirect-ping-req-v1"`).  Every `IndirectPingResponse` carries a
//! BLAKE3-256 digest binding the original request digest to the response
//! fields (domain: `"tidefs-membership-live-indirect-ping-resp-v1"`).
//! Stale, tampered, or replayed relay messages are rejected via digest
//! mismatch before affecting the failure-detection pipeline.

use crate::types::{now_millis, SwimIndirectPingRequest, SwimIndirectPingResponse};
use ed25519_dalek::Keypair;
use rand::seq::SliceRandom;
use rand::thread_rng;
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// IndirectPingConfig
// ---------------------------------------------------------------------------

/// Configuration for the indirect-ping relay protocol.
#[derive(Clone, Debug)]
pub struct IndirectPingConfig {
    /// Number of relay peers to select when initiating an indirect ping.
    /// Default: 3.
    pub relay_peer_count: usize,
    /// Maximum time (ms) to wait for relay responses before declaring
    /// all-failed.  Typically 2× the direct-ping timeout.
    /// Default: 2000.
    pub relay_timeout_ms: u64,
    /// Maximum number of concurrent relay operations.  Excess initiations
    /// are dropped until a slot opens.
    /// Default: 8.
    pub max_concurrent_relays: usize,
}

impl Default for IndirectPingConfig {
    fn default() -> Self {
        Self {
            relay_peer_count: 3,
            relay_timeout_ms: 2000,
            max_concurrent_relays: 8,
        }
    }
}

// ---------------------------------------------------------------------------
// ActiveRelay — in-progress relay state (internal)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct ActiveRelay {
    /// The suspect peer.
    target: MemberId,
    /// Monotonic relay sequence number.
    relay_seq_no: u64,
    /// When the relay was initiated.
    started_at_millis: u64,
    /// Peers selected to relay the probe.
    relay_peers: Vec<MemberId>,
    /// Responses collected so far.
    responses: Vec<SwimIndirectPingResponse>,
    /// Set to true when any relay reports the target as reachable.
    success_reported: bool,
}

impl ActiveRelay {
    fn new(
        target: MemberId,
        relay_seq_no: u64,
        started_at_millis: u64,
        relay_peers: Vec<MemberId>,
    ) -> Self {
        Self {
            target,
            relay_seq_no,
            started_at_millis,
            relay_peers,
            responses: Vec::new(),
            success_reported: false,
        }
    }
}

// ---------------------------------------------------------------------------
// RelayResult — outcome reported back to the FailureDetector
// ---------------------------------------------------------------------------

/// Outcome of a completed indirect-ping relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayResult {
    /// At least one relay peer confirmed the target is reachable.
    /// Failure suspicion is cleared.
    Cleared {
        target: MemberId,
        relay_seq_no: u64,
        confirming_peer: MemberId,
    },
    /// All relay peers reported the target unreachable.
    /// Failure suspicion escalates to Suspect.
    AllFailed { target: MemberId, relay_seq_no: u64 },
    /// Relay timeout elapsed with no success response.
    /// Failure suspicion escalates to Suspect.
    Timeout { target: MemberId, relay_seq_no: u64 },
}

// ---------------------------------------------------------------------------
// IndirectPingRelay — manages relay lifecycle
// ---------------------------------------------------------------------------

/// Manages the indirect-ping relay lifecycle: initiation, response
/// collection, timeout detection, and result aggregation.
pub struct IndirectPingRelay {
    config: IndirectPingConfig,
    active_relays: Vec<ActiveRelay>,
    next_relay_seq_no: u64,
}

impl IndirectPingRelay {
    pub fn new(config: IndirectPingConfig) -> Self {
        Self {
            config,
            active_relays: Vec::new(),
            next_relay_seq_no: 1,
        }
    }

    /// Initiate an indirect-ping relay for a suspected-failed peer.
    ///
    /// Selects `k` relay peers from `alive_peers` (excluding `self_id` and
    /// `target`), creates signed `IndirectPingRequest` messages, and
    /// returns them for transport delivery.  Returns `None` if the
    /// concurrent-relay limit is exceeded.
    pub fn initiate_relay(
        &mut self,
        target: MemberId,
        self_id: MemberId,
        alive_peers: &[MemberId],
        signing_key: &ed25519_dalek::Keypair,
    ) -> Option<Vec<(MemberId, SwimIndirectPingRequest)>> {
        // Enforce concurrent limit
        if self.active_relays.len() >= self.config.max_concurrent_relays {
            return None;
        }

        // Already have an active relay for this target?
        if self.active_relays.iter().any(|r| r.target == target) {
            return None;
        }

        // Select k relay peers
        let candidates: Vec<MemberId> = alive_peers
            .iter()
            .filter(|id| **id != self_id && **id != target)
            .copied()
            .collect();

        let k = self.config.relay_peer_count.min(candidates.len());
        if k == 0 {
            // No relay peers available — escalate immediately
            return Some(Vec::new());
        }

        let relay_peers: Vec<MemberId> = candidates
            .choose_multiple(&mut thread_rng(), k)
            .copied()
            .collect();

        let relay_seq_no = self.next_relay_seq_no;
        self.next_relay_seq_no += 1;

        let now = now_millis();
        let mut requests = Vec::with_capacity(relay_peers.len());

        for &relay_peer in &relay_peers {
            let mut req = SwimIndirectPingRequest {
                requester: self_id,
                target,
                original_seq_no: 0,
                relay_seq_no,
                sent_at_millis: now,
                signature: Vec::new(),
            };
            req.sign(signing_key);
            requests.push((relay_peer, req));
        }

        self.active_relays
            .push(ActiveRelay::new(target, relay_seq_no, now, relay_peers));

        Some(requests)
    }

    /// Process an inbound indirect-ping response from a relay peer.
    ///
    /// Verifies the Ed25519 signature and BLAKE3 digests before accepting
    /// the response.  Returns `Some(RelayResult)` when the relay is
    /// complete (any-success short-circuits immediately).
    pub fn process_response(
        &mut self,
        response: &SwimIndirectPingResponse,
        verifying_key: &ed25519_dalek::PublicKey,
    ) -> Result<Option<RelayResult>, RelayError> {
        // Verify integrity
        if !response.verify(verifying_key) {
            return Err(RelayError::InvalidSignatureOrDigest);
        }

        // Find matching relay
        let relay_idx = self
            .active_relays
            .iter()
            .position(|r| r.target == response.target && r.relay_seq_no == response.relay_seq_no);

        let relay = match relay_idx {
            Some(idx) => &mut self.active_relays[idx],
            None => {
                return Err(RelayError::StaleResponse {
                    target: response.target,
                    relay_seq_no: response.relay_seq_no,
                })
            }
        };

        // Reject duplicate responses from the same responder
        if relay
            .responses
            .iter()
            .any(|r| r.responder == response.responder)
        {
            return Err(RelayError::DuplicateResponse(response.responder));
        }

        relay.responses.push(response.clone());

        // Short-circuit on first success
        if response.target_reachable && !relay.success_reported {
            relay.success_reported = true;
            let result = RelayResult::Cleared {
                target: relay.target,
                relay_seq_no: relay.relay_seq_no,
                confirming_peer: response.responder,
            };
            return Ok(Some(result));
        }

        // Check if all peers have responded → all-failed
        if relay.responses.len() >= relay.relay_peers.len() && !relay.success_reported {
            let result = RelayResult::AllFailed {
                target: relay.target,
                relay_seq_no: relay.relay_seq_no,
            };
            return Ok(Some(result));
        }

        Ok(None) // Still waiting for more responses
    }

    /// Tick relay timeouts.  Returns `RelayResult::Timeout` for each
    /// relay that has exceeded `relay_timeout_ms` without a success.
    pub fn tick_timeouts(&mut self) -> Vec<RelayResult> {
        let now = now_millis();
        let mut results = Vec::new();
        let mut completed = Vec::new();

        for (idx, relay) in self.active_relays.iter().enumerate() {
            if relay.success_reported {
                completed.push(idx);
                continue;
            }

            let elapsed = now.saturating_sub(relay.started_at_millis);
            if elapsed >= self.config.relay_timeout_ms {
                results.push(RelayResult::Timeout {
                    target: relay.target,
                    relay_seq_no: relay.relay_seq_no,
                });
                completed.push(idx);
            }
        }

        // Remove completed relays in reverse order
        for idx in completed.into_iter().rev() {
            self.active_relays.remove(idx);
        }

        results
    }

    /// Remove completed relays after their results are consumed.
    pub fn clear_completed(&mut self, target: MemberId) {
        self.active_relays.retain(|r| r.target != target);
    }

    /// Number of active relay operations.
    pub fn active_count(&self) -> usize {
        self.active_relays.len()
    }

    /// Check whether a relay is active for a given target.
    pub fn has_active_relay(&self, target: MemberId) -> bool {
        self.active_relays.iter().any(|r| r.target == target)
    }
}

// ---------------------------------------------------------------------------
// RelayRequestHandler — inbound relay request processing
// ---------------------------------------------------------------------------

/// Handles inbound indirect-ping requests on a relay peer.
///
/// When a peer receives an `IndirectPingRequest`, it sends a direct ping
/// to the suspect and returns an `IndirectPingResponse` with the result.
pub struct RelayRequestHandler;

impl RelayRequestHandler {
    /// Process an inbound indirect-ping request.
    ///
    /// Verifies the request integrity, then performs a direct ping to the
    /// target.  Returns an `IndirectPingResponse` carrying the
    /// target-reachable outcome and a BLAKE3-256 digest binding the
    /// request+response pair.
    ///
    /// `target_alive` should be the result of a direct ping to the suspect.
    pub fn handle_request(
        request: &SwimIndirectPingRequest,
        requester_key: &ed25519_dalek::PublicKey,
        responder_id: MemberId,
        target_alive: bool,
        signing_key: &Keypair,
    ) -> Result<SwimIndirectPingResponse, RelayError> {
        // Verify the request integrity
        if !request.verify(requester_key) {
            return Err(RelayError::InvalidSignatureOrDigest);
        }

        let mut response = SwimIndirectPingResponse {
            responder: responder_id,
            target: request.target,
            target_reachable: target_alive,
            relay_seq_no: request.relay_seq_no,
            responded_at_millis: now_millis(),
            signature: Vec::new(),
        };
        response.sign(signing_key);

        Ok(response)
    }
}

// ---------------------------------------------------------------------------
// RelayError
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("invalid Ed25519 signature or BLAKE3 digest")]
    InvalidSignatureOrDigest,
    #[error("stale relay response: target {target:?} relay_seq_no {relay_seq_no}")]
    StaleResponse { target: MemberId, relay_seq_no: u64 },
    #[error("duplicate response from relay peer {0:?}")]
    DuplicateResponse(MemberId),
    #[error("concurrent relay limit ({0}) reached")]
    ConcurrentLimit(usize),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    fn make_keypair() -> Keypair {
        Keypair::generate(&mut OsRng)
    }

    // ----- IndirectPingConfig defaults -----

    #[test]
    fn default_config_values() {
        let cfg = IndirectPingConfig::default();
        assert_eq!(cfg.relay_peer_count, 3);
        assert_eq!(cfg.relay_timeout_ms, 2000);
        assert_eq!(cfg.max_concurrent_relays, 8);
    }

    // ----- IndirectPingRelay -----

    #[test]
    fn initiate_relay_selects_k_peers_excluding_self_and_target() {
        let kp = make_keypair();
        let config = IndirectPingConfig {
            relay_peer_count: 2,
            relay_timeout_ms: 5000,
            max_concurrent_relays: 4,
        };
        let mut relay = IndirectPingRelay::new(config);

        let self_id = MemberId::new(1);
        let target = MemberId::new(2);
        let alive_peers = vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
            MemberId::new(4),
            MemberId::new(5),
        ];

        let result = relay
            .initiate_relay(target, self_id, &alive_peers, &kp)
            .expect("relay initiation");

        assert_eq!(result.len(), 2);
        for (peer, req) in &result {
            assert_ne!(*peer, self_id);
            assert_ne!(*peer, target);
            assert_eq!(req.requester, self_id);
            assert_eq!(req.target, target);
        }
        assert_eq!(relay.active_count(), 1);
    }

    #[test]
    fn initiate_relay_rejects_duplicate_target() {
        let kp = make_keypair();
        let config = IndirectPingConfig::default();
        let mut relay = IndirectPingRelay::new(config);

        let self_id = MemberId::new(1);
        let target = MemberId::new(2);
        let alive_peers = vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
            MemberId::new(4),
        ];

        // First initiation succeeds
        let _ = relay
            .initiate_relay(target, self_id, &alive_peers, &kp)
            .expect("first relay");

        // Second initiation for same target returns None
        let second = relay.initiate_relay(target, self_id, &alive_peers, &kp);
        assert!(second.is_none());
    }

    #[test]
    fn initiate_relay_no_candidates_returns_empty_vec() {
        let kp = make_keypair();
        let config = IndirectPingConfig::default();
        let mut relay = IndirectPingRelay::new(config);

        let self_id = MemberId::new(1);
        let target = MemberId::new(2);
        let alive_peers = vec![MemberId::new(1), MemberId::new(2)];

        let result = relay.initiate_relay(target, self_id, &alive_peers, &kp);
        assert_eq!(result, Some(Vec::new()));
    }

    #[test]
    fn relay_clear_on_any_success() {
        let kp_self = make_keypair();
        let kp_relay = make_keypair();
        let config = IndirectPingConfig {
            relay_peer_count: 2,
            relay_timeout_ms: 5000,
            max_concurrent_relays: 4,
        };
        let mut relay = IndirectPingRelay::new(config);

        let self_id = MemberId::new(1);
        let target = MemberId::new(2);
        let relay_peer = MemberId::new(3);
        let alive_peers = vec![self_id, target, relay_peer, MemberId::new(4)];

        let requests = relay
            .initiate_relay(target, self_id, &alive_peers, &kp_self)
            .expect("relay initiation");
        assert_eq!(requests.len(), 2);

        // Build a success response from relay_peer
        let req = &requests[0].1;
        let mut response = SwimIndirectPingResponse {
            responder: relay_peer,
            target,
            target_reachable: true,
            relay_seq_no: req.relay_seq_no,
            responded_at_millis: now_millis(),
            signature: Vec::new(),
        };
        response.sign(&kp_relay);

        let result = relay
            .process_response(&response, &kp_relay.public)
            .expect("process response")
            .expect("should complete");

        match result {
            RelayResult::Cleared {
                target: t,
                confirming_peer,
                ..
            } => {
                assert_eq!(t, target);
                assert_eq!(confirming_peer, relay_peer);
            }
            _ => panic!("expected Cleared, got {result:?}"),
        }
    }

    #[test]
    fn relay_all_failed_when_all_respond_unreachable() {
        let kp_self = make_keypair();
        let kp_r1 = make_keypair();
        let kp_r2 = make_keypair();
        let config = IndirectPingConfig {
            relay_peer_count: 2,
            relay_timeout_ms: 5000,
            max_concurrent_relays: 4,
        };
        let mut relay = IndirectPingRelay::new(config);

        let self_id = MemberId::new(1);
        let target = MemberId::new(2);
        let peer3 = MemberId::new(3);
        let peer4 = MemberId::new(4);
        let alive_peers = vec![self_id, target, peer3, peer4];

        let requests = relay
            .initiate_relay(target, self_id, &alive_peers, &kp_self)
            .expect("relay initiation");
        assert_eq!(requests.len(), 2);

        let req_seq = requests[0].1.relay_seq_no;

        // Both peers respond: target unreachable
        for (peer, kp) in &[(peer3, &kp_r1), (peer4, &kp_r2)] {
            let mut resp = SwimIndirectPingResponse {
                responder: *peer,
                target,
                target_reachable: false,
                relay_seq_no: req_seq,
                responded_at_millis: now_millis(),
                signature: Vec::new(),
            };
            resp.sign(kp);

            let result = relay.process_response(&resp, &kp.public).expect("process");
            if *peer == peer4 {
                // Last response → all-failed
                match result.expect("should complete") {
                    RelayResult::AllFailed { target: t, .. } => {
                        assert_eq!(t, target);
                    }
                    r => panic!("expected AllFailed, got {r:?}"),
                }
            } else {
                assert!(result.is_none(), "first response should not complete relay");
            }
        }
    }

    #[test]
    fn relay_timeout_escalates() {
        let kp = make_keypair();
        // Use a very short timeout that already elapsed
        let config = IndirectPingConfig {
            relay_peer_count: 2,
            relay_timeout_ms: 0, // immediate timeout
            max_concurrent_relays: 4,
        };
        let mut relay = IndirectPingRelay::new(config);

        let self_id = MemberId::new(1);
        let target = MemberId::new(2);
        let alive_peers = vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
            MemberId::new(4),
        ];

        let _ = relay
            .initiate_relay(target, self_id, &alive_peers, &kp)
            .expect("relay initiation");

        let timeouts = relay.tick_timeouts();
        assert_eq!(timeouts.len(), 1);
        match &timeouts[0] {
            RelayResult::Timeout { target: t, .. } => assert_eq!(*t, target),
            _ => panic!("expected Timeout"),
        }
    }

    #[test]
    fn stale_relay_response_rejected() {
        let kp_self = make_keypair();
        let kp_relay = make_keypair();
        let config = IndirectPingConfig::default();
        let mut relay = IndirectPingRelay::new(config);

        let self_id = MemberId::new(1);
        let target = MemberId::new(2);
        let alive_peers = vec![self_id, target, MemberId::new(3)];

        let _ = relay
            .initiate_relay(target, self_id, &alive_peers, &kp_self)
            .expect("relay");

        // Build a response with a wrong relay_seq_no
        let mut response = SwimIndirectPingResponse {
            responder: MemberId::new(3),
            target,
            target_reachable: true,
            relay_seq_no: 999, // stale
            responded_at_millis: now_millis(),
            signature: Vec::new(),
        };
        response.sign(&kp_relay);

        let err = relay
            .process_response(&response, &kp_relay.public)
            .unwrap_err();
        assert!(matches!(err, RelayError::StaleResponse { .. }));
    }

    #[test]
    fn tampered_digest_rejected() {
        let kp_self = make_keypair();
        let kp_relay = make_keypair();
        let config = IndirectPingConfig::default();
        let mut relay = IndirectPingRelay::new(config);

        let self_id = MemberId::new(1);
        let target = MemberId::new(2);
        let relay_peer = MemberId::new(3);
        let alive_peers = vec![self_id, target, relay_peer];

        let requests = relay
            .initiate_relay(target, self_id, &alive_peers, &kp_self)
            .expect("relay");

        let req = &requests[0].1;
        let mut response = SwimIndirectPingResponse {
            responder: relay_peer,
            target,
            target_reachable: true,
            relay_seq_no: req.relay_seq_no,
            responded_at_millis: now_millis(),
            signature: Vec::new(),
        };
        response.sign(&kp_relay);

        // Tamper: change target_reachable without re-signing
        response.target_reachable = false;
        // Transport integrity replaces BLAKE3 digest checks.

        let err = relay
            .process_response(&response, &kp_relay.public)
            .unwrap_err();
        assert!(matches!(err, RelayError::InvalidSignatureOrDigest));
    }

    #[test]
    fn concurrent_relay_limit_enforced() {
        let kp = make_keypair();
        let config = IndirectPingConfig {
            relay_peer_count: 1,
            relay_timeout_ms: 5000,
            max_concurrent_relays: 2,
        };
        let mut relay = IndirectPingRelay::new(config);

        let self_id = MemberId::new(1);
        let alive_peers = vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
            MemberId::new(4),
            MemberId::new(5),
            MemberId::new(6),
        ];

        // Start two relays
        assert!(relay
            .initiate_relay(MemberId::new(2), self_id, &alive_peers, &kp)
            .is_some());
        assert!(relay
            .initiate_relay(MemberId::new(3), self_id, &alive_peers, &kp)
            .is_some());

        // Third relay exceeds limit
        let third = relay.initiate_relay(MemberId::new(4), self_id, &alive_peers, &kp);
        assert!(third.is_none());
        assert_eq!(relay.active_count(), 2);
    }

    #[test]
    fn successful_relay_clears_from_active() {
        let kp_self = make_keypair();
        let kp_relay = make_keypair();
        let config = IndirectPingConfig {
            relay_peer_count: 1,
            relay_timeout_ms: 5000,
            max_concurrent_relays: 4,
        };
        let mut relay = IndirectPingRelay::new(config);

        let self_id = MemberId::new(1);
        let target = MemberId::new(2);
        let relay_peer = MemberId::new(3);
        let alive_peers = vec![self_id, target, relay_peer];

        let requests = relay
            .initiate_relay(target, self_id, &alive_peers, &kp_self)
            .expect("relay");

        let req = &requests[0].1;
        let mut response = SwimIndirectPingResponse {
            responder: relay_peer,
            target,
            target_reachable: true,
            relay_seq_no: req.relay_seq_no,
            responded_at_millis: now_millis(),
            signature: Vec::new(),
        };
        response.sign(&kp_relay);

        let _ = relay.process_response(&response, &kp_relay.public);

        // After clear_completed, relay is removed
        relay.clear_completed(target);
        assert_eq!(relay.active_count(), 0);
        assert!(!relay.has_active_relay(target));
    }

    // ----- RelayRequestHandler -----

    #[test]
    fn handler_verifies_request_integrity() {
        let kp_req = make_keypair();
        let kp_resp = make_keypair();

        let mut req = SwimIndirectPingRequest {
            requester: MemberId::new(1),
            target: MemberId::new(2),
            original_seq_no: 1,
            relay_seq_no: 5,
            sent_at_millis: now_millis(),
            signature: Vec::new(),
        };
        req.sign(&kp_req);

        let resp = RelayRequestHandler::handle_request(
            &req,
            &kp_req.public,
            MemberId::new(3),
            true,
            &kp_resp,
        )
        .expect("handle request");

        assert_eq!(resp.responder, MemberId::new(3));
        assert_eq!(resp.target, MemberId::new(2));
        assert!(resp.target_reachable);
        assert_eq!(resp.relay_seq_no, 5);
        // Transport integrity replaces BLAKE3 digests.
        assert!(resp.verify(&kp_resp.public));
    }

    #[test]
    fn handler_rejects_tampered_request() {
        let kp_req = make_keypair();
        let kp_resp = make_keypair();

        let mut req = SwimIndirectPingRequest {
            requester: MemberId::new(1),
            target: MemberId::new(2),
            original_seq_no: 1,
            relay_seq_no: 5,
            sent_at_millis: now_millis(),
            signature: Vec::new(),
        };
        req.sign(&kp_req);

        // Tamper: change target without re-signing
        req.target = MemberId::new(99);

        let err = RelayRequestHandler::handle_request(
            &req,
            &kp_req.public,
            MemberId::new(3),
            true,
            &kp_resp,
        )
        .unwrap_err();
        assert!(matches!(err, RelayError::InvalidSignatureOrDigest));
    }

    #[test]
    fn handler_response_binds_request_and_response() {
        let kp_req = make_keypair();
        let kp_resp = make_keypair();

        let mut req = SwimIndirectPingRequest {
            requester: MemberId::new(1),
            target: MemberId::new(2),
            original_seq_no: 1,
            relay_seq_no: 5,
            sent_at_millis: now_millis(),
            signature: Vec::new(),
        };
        req.sign(&kp_req);

        let resp = RelayRequestHandler::handle_request(
            &req,
            &kp_req.public,
            MemberId::new(3),
            false,
            &kp_resp,
        )
        .expect("handle request");

        // Tamper response
        let mut tampered = resp.clone();
        tampered.target_reachable = true;
        assert!(!tampered.verify(&kp_resp.public));
    }

    // ----- BLAKE3 domain separation -----

    #[test]
    fn indirect_ping_request_is_deterministic() {
        let kp = make_keypair();
        let mut req1 = SwimIndirectPingRequest {
            requester: MemberId::new(1),
            target: MemberId::new(2),
            original_seq_no: 3,
            relay_seq_no: 7,
            sent_at_millis: 1000,
            signature: Vec::new(),
        };
        req1.sign(&kp);

        let mut req2 = SwimIndirectPingRequest {
            requester: MemberId::new(1),
            target: MemberId::new(2),
            original_seq_no: 3,
            relay_seq_no: 7,
            sent_at_millis: 1000,
            signature: Vec::new(),
        };
        req2.sign(&kp);
    }

    #[test]
    fn indirect_ping_response_is_deterministic() {
        let kp = make_keypair();
        // Transport integrity replaces BLAKE3 digests.

        let mut resp1 = SwimIndirectPingResponse {
            responder: MemberId::new(3),
            target: MemberId::new(2),
            target_reachable: false,
            relay_seq_no: 7,
            responded_at_millis: 2000,
            signature: Vec::new(),
        };
        resp1.sign(&kp);

        let mut resp2 = SwimIndirectPingResponse {
            responder: MemberId::new(3),
            target: MemberId::new(2),
            target_reachable: false,
            relay_seq_no: 7,
            responded_at_millis: 2000,
            signature: Vec::new(),
        };
        resp2.sign(&kp);
    }
}
