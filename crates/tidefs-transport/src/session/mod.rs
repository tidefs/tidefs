// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
pub mod handshake;
pub mod stats;

use serde::{Deserialize, Serialize};
use std::fmt;

use std::time::Duration;

use crate::addr::TransportAddr;
use crate::backend::TransportBackendKind;
use crate::lane_demux::LaneDemux;
use crate::reconnect::{ReconnectConfig, ReconnectDriver, ReconnectState};
use crate::request_response::RequestResponseHandle;
use crate::session_cipher::{CipherError, Direction, SessionKeyMaterial, TransportSessionCipher};
use crate::types::{CohortMembership, FamilyVersion, HlcTimestamp, NodeIdentity, SessionId};
use std::time::Instant;
use tidefs_clock_timing::{HlcValue, HybridLogicalClock};
pub use tidefs_types_transport_session::MessageSequenceNumber;
use tidefs_types_transport_session::{ClosureClass, DrainResultClass, EndpointFamily};

use crate::keepalive::{
    session_keepalive_check, HeartbeatState, KeepaliveHealth, SessionKeepalive,
};
// ---------------------------------------------------------------------------
use crate::compression::{
    is_marked_compression, CompressionConfig, CompressionError, CompressionState,
    COMPRESSION_MARKER,
};
use crate::message_priority::MessagePriorityQueue;
use crate::message_priority::QueuedMessage;
use crate::send_backpressure::{SendCapacity, SendCapacitySet};
use crate::send_buffer::{Backpressure, PeerSendBuffer, SendBufferConfig};
use crate::send_scheduler::SendPriority;

// Session: persistent, bidirectional, authenticated channel between two nodes
// ---------------------------------------------------------------------------

/// A session survives connection drops (reconnection).
///
/// ## Endpoint lifecycle within a Session
///
/// Every [`Session`] is bound to exactly one [`EndpointFamily`]
/// (`endpoint_family` field), selected by the transport layer when
/// the transport layer. The endpoint family governs:
///
/// - **Which session classes are legal** — each endpoint family only admits
///   the session classes listed in
///   [`EndpointFamily::allowed_session_classes()`].
/// - **Which lanes are admitted** — lane budgets must be compatible with the
///   endpoint family (e.g., `Data` endpoints only admit bulk lanes).
/// - **Which cohorts may attach** — cohort classes must be compatible with
///   the endpoint family (e.g., `Shadow` endpoints only admit `ShadowCompare`
///   and `TransitionStage` cohorts).
///
/// ### Endpoint-driven state invariants
///
/// - The `endpoint_family` field is set once during construction and never
///   changes for the lifetime of the session.
/// - State transitions through the session state machine
///   (`Unconnected → Connecting → Handshaking → Bound → CohortAttached →
///   Established`) are validated against the endpoint family at each step:
///   the endpoint family determines which transitions are legal.
/// - A session on a `Data` endpoint cannot transition to `Established`
///   with a `CohortAttached` that names a control cohort; the cohort graph
///   enforces endpoint-cohort consistency.
/// - The `peer_addr` field stores the remote socket address; for
///   `LocalEmbed` endpoints this is the loopback address.
/// - Reconnection (via [`ReconnectState`]) preserves the endpoint family;
///   a reconnected session retains the same endpoint family it was
///   originally created with.
///
/// Outcome of accepting a received message sequence number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeqReceiveOutcome {
    /// In-order delivery: sequence number exactly one past last delivered.
    Accepted,
    /// Duplicate: sequence number at or below the last delivered.
    Duplicate,
    /// Gap detected: one or more sequence numbers were skipped.
    /// `missing_start..missing_end` (exclusive end) identifies the lost range.
    Gap {
        /// First missing sequence number (inclusive).
        missing_start: MessageSequenceNumber,
        /// One past the last missing sequence number (exclusive).
        missing_end: MessageSequenceNumber,
    },
}

pub struct Session {
    /// Unique session identifier assigned at creation time.
    pub session_id: SessionId,
    /// Local node ID for this session's initiating node.
    pub local_node: u64,
    /// Peer node ID for the remote endpoint of this session.
    pub peer_node: u64,

    /// Established during handshake: peer's identity and supported versions
    pub peer_info: Option<PeerSessionInfo>,

    /// Session state machine
    pub state: SessionState,

    /// Lane demux: 5 lanes multiplexed over one connection
    pub lane_demux: LaneDemux,

    /// Remote address of the peer (for reconnection)
    pub peer_addr: TransportAddr,
    /// Endpoint family (e0–e3 per P8-01 §4). Set once during
    /// construction and never changed for the lifetime of the session.
    pub endpoint_family: EndpointFamily,

    /// Reconnection state
    pub reconnect: ReconnectState,

    /// Reconnect configuration for this session.
    pub reconnect_config: ReconnectConfig,

    /// Keepalive heartbeat tracker for dead-connection detection.
    pub heartbeat: SessionKeepalive,
    pub send_buffer: PeerSendBuffer,
    /// Session statistics
    pub stats: SessionStats,

    /// Transport backend kind (TCP, TLS, or RDMA). Set once during construction
    /// and never changed for the lifetime of the session.
    pub backend_kind: TransportBackendKind,

    /// Whether the RDMA carrier has been permanently lost. When true, TCP
    /// fallback is the only recovery path per OW-308.
    pub carrier_lost: bool,
    /// Per-session monotonic outbound message sequence counter.
    /// Incremented by `next_send_seq()` before each outbound message.
    pub send_seq: MessageSequenceNumber,
    /// Highest consecutive inbound message sequence number received.
    /// Updated only on in-order delivery; stays put across gaps.
    pub recv_seq: MessageSequenceNumber,

    /// Membership epoch this session is bound to. Set during handshake;
    /// validated on message send/receive for epoch-gated session establishment.
    pub current_epoch: u64,

    /// Session key material (32 bytes) for reconnect resume token.
    /// Set during handshake; used by ReconnectDriver for
    /// SessionResumeRequest construction.
    pub session_key: Option<[u8; 32]>,

    /// Outbound encryption cipher for sealing messages to the peer.
    pub outbound_cipher: Option<TransportSessionCipher>,
    /// Inbound encryption cipher for opening messages from the peer.
    pub inbound_cipher: Option<TransportSessionCipher>,

    /// Hybrid Logical Clock for causal timestamping of session events.
    /// Advanced on every state transition and message send/receive.
    pub hlc: HybridLogicalClock,

    /// Process-start monotonic baseline for HLC physical time.
    start_instant: Instant,

    /// Per-session response tracker for in-flight request cleanup.
    /// Set during session establishment; used by send/receive dispatch
    /// to correlate requests with responses and enforce timeouts.
    pub response_tracker: Option<RequestResponseHandle<Vec<u8>>>,

    /// Background timeout-scanning task for the response tracker.
    ///
    /// Stored so it can be aborted when the session transitions to a closed
    /// or terminal state, preventing a leaked task that would otherwise
    /// hold the last `Arc` to the correlation table and run forever.
    pub response_timeout_task: Option<tokio::task::JoinHandle<()>>,

    /// Per-session message priority queue for Control/Data head-of-line
    /// bypass on the outbound send path.
    pub(crate) message_priority_queue: MessagePriorityQueue<QueuedMessage>,

    /// Per-session message batcher for coalescing multiple small outbound
    /// messages into a single wire send. Configured via [`batch_config`].
    pub message_batcher: crate::message_batcher::MessageBatcher,

    /// Batch configuration for this session. When `enabled` is false (default),
    /// every send bypasses the batcher and is written immediately.
    pub batch_config: crate::message_batcher::BatchConfig,

    /// Per-priority capacity signal set for external backpressure queries.
    ///
    /// When set, callers can obtain per-priority [`SendCapacity`] handles
    /// via [`data_lane_capacity`](Self::data_lane_capacity) to drive
    /// background-operation throttling (e.g. rebuild backpressure).
    pub capacity_set: Option<SendCapacitySet>,

    /// Per-session compression state for outbound compression and inbound
    /// decompression of transport message payloads. `None` means compression
    /// is disabled for this session.
    pub compression: Option<CompressionState>,

    /// Rolling upgrade compatibility gate: gated by negotiated feature
    /// flags from session handshake.  `None` before handshake completes.
    pub rollback_gate: Option<crate::rollback_compat::RollingUpgradeGate>,
}

impl Session {
    #[must_use]
    /// Create a new Session with the given parameters.
    pub fn new(
        session_id: SessionId,
        local_node: u64,
        peer_node: u64,
        peer_addr: TransportAddr,
        endpoint_family: EndpointFamily,
        backend_kind: TransportBackendKind,
    ) -> Self {
        Self {
            session_id,
            local_node,
            peer_node,
            peer_info: None,
            state: SessionState::Unconnected,
            lane_demux: LaneDemux::new(),
            peer_addr,
            endpoint_family,
            reconnect: ReconnectState::new(),
            reconnect_config: ReconnectConfig::default(),
            heartbeat: SessionKeepalive::new(),
            send_buffer: PeerSendBuffer::new(&SendBufferConfig::default()),
            stats: SessionStats::default(),
            backend_kind,
            carrier_lost: false,
            send_seq: MessageSequenceNumber::ZERO,
            recv_seq: MessageSequenceNumber::ZERO,
            current_epoch: 0,
            session_key: None,
            outbound_cipher: None,
            inbound_cipher: None,
            hlc: HybridLogicalClock::new(),
            start_instant: Instant::now(),
            response_tracker: None,
            message_priority_queue: MessagePriorityQueue::with_defaults(),
            message_batcher: crate::message_batcher::MessageBatcher::new(
                crate::message_batcher::BatchConfig::disabled(),
            ),
            batch_config: crate::message_batcher::BatchConfig::disabled(),
            response_timeout_task: None,
            compression: None,
            rollback_gate: None,
            capacity_set: None,
        }
    }

    /// Initialize session encryption ciphers from handshake key material.
    ///
    /// Derives two direction-specific ChaCha20-Poly1305 keys via HKDF-SHA256
    /// from the provided key material. The `as_initiator` flag determines
    /// which direction each cipher handles:
    ///
    /// - If `as_initiator` is true: outbound uses InitiatorToResponder,
    ///   inbound uses ResponderToInitiator.
    /// - If `as_initiator` is false: outbound uses ResponderToInitiator,
    ///   inbound uses InitiatorToResponder.
    ///
    /// The ciphers are stored on the session and can be used immediately
    /// via [`seal_message`] and [`open_message`].
    pub fn init_ciphers(&mut self, key_material: &impl SessionKeyMaterial, as_initiator: bool) {
        // Gate: only initialize ciphers if peer negotiated session encryption.
        if let Some(ref gate) = self.rollback_gate {
            if gate.forbids(crate::rollback_compat::NodeFeatureFlags::SESSION_ENCRYPTION) {
                tracing::debug!(
                    "session encryption disabled: peer did not negotiate SESSION_ENCRYPTION flag"
                );
                return;
            }
        }
        use crate::session_cipher::EncryptionContext;
        let (out_dir, in_dir) = if as_initiator {
            (
                Direction::InitiatorToResponder,
                Direction::ResponderToInitiator,
            )
        } else {
            (
                Direction::ResponderToInitiator,
                Direction::InitiatorToResponder,
            )
        };
        let mut out_cipher = TransportSessionCipher::new(key_material, out_dir);
        let mut in_cipher = TransportSessionCipher::new(key_material, in_dir);

        // Bind session metadata as AEAD associated data so ciphertext
        // cannot be replayed across sessions, endpoints, directions, or lanes.
        let out_dir_val: u8 = match out_dir {
            Direction::InitiatorToResponder => 0,
            Direction::ResponderToInitiator => 1,
        };
        let in_dir_val: u8 = match in_dir {
            Direction::InitiatorToResponder => 0,
            Direction::ResponderToInitiator => 1,
        };
        // endpoint_family is stored as u32 from tidefs_types_transport_session
        let ef: u32 = self.endpoint_family as u32;

        // Session_id is not bound into AAD because each peer's local
        // session_id may differ; session isolation is provided by the
        // HKDF-derived encryption keys which are unique per handshake.
        out_cipher.set_encryption_context(EncryptionContext {
            session_id: 0,
            endpoint_family: ef,
            direction: out_dir_val,
            message_family: 0,
            sequence_no: 0,
        });
        in_cipher.set_encryption_context(EncryptionContext {
            session_id: 0,
            endpoint_family: ef,
            direction: in_dir_val,
            message_family: 0,
            sequence_no: 0,
        });

        self.outbound_cipher = Some(out_cipher);
        self.inbound_cipher = Some(in_cipher);
    }

    /// Encrypt a plaintext payload for sending to the peer.
    ///
    /// Uses the session's outbound cipher. Returns the wire-format frame
    /// `[nonce:12][ciphertext+tag:N+16]`.
    ///
    /// # Errors
    ///
    /// Returns [`CipherError::NonceExhausted`] if the encrypt nonce counter
    /// has overflowed. Panics if ciphers have not been initialized.
    pub fn seal_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.outbound_cipher
            .as_mut()
            .expect("outbound cipher not initialized; call init_ciphers first")
            .seal(plaintext)
    }

    /// Decrypt and authenticate a wire-format frame received from the peer.
    ///
    /// Uses the session's inbound cipher. Validates nonce monotonicity
    /// before decrypting.
    ///
    /// # Errors
    ///
    /// Returns [`CipherError`] on truncation, nonce reuse, or AEAD failure.
    /// Panics if ciphers have not been initialized.
    pub fn open_message(&mut self, wire_bytes: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.inbound_cipher
            .as_mut()
            .expect("inbound cipher not initialized; call init_ciphers first")
            .open(wire_bytes)
    }

    // ── Per-session compression ────────────────────────────────────────

    /// Configure outbound compression for this session.
    ///
    /// Compression is applied on the outbound send path before encryption.
    /// The inbound path auto-detects compressed frames via the wire marker
    /// and does not depend on this setting.
    pub fn set_compression(&mut self, config: CompressionConfig) {
        // Gate: only enable compression if peer negotiated the flag.
        if let Some(ref gate) = self.rollback_gate {
            if gate.forbids(crate::rollback_compat::NodeFeatureFlags::COMPRESSION) {
                tracing::debug!("compression disabled: peer did not negotiate COMPRESSION flag");
                return;
            }
        }
        self.compression = Some(CompressionState::new(config));
    }

    /// Disable outbound compression for this session.
    pub fn disable_compression(&mut self) {
        self.compression = None;
    }

    /// Whether outbound compression is active for this session.
    #[must_use]
    pub fn has_compression(&self) -> bool {
        self.compression.is_some()
    }

    /// Compress an outbound payload.
    ///
    /// When compression is active, the output is prefixed with
    /// `COMPRESSION_MARKER` so the receiver can auto-detect compressed
    /// frames without relying on hidden session-local state.
    #[must_use]
    pub fn compress_outbound(&mut self, payload: &[u8]) -> Vec<u8> {
        if let Some(ref mut state) = self.compression {
            let frame = state.compress(payload);
            [&COMPRESSION_MARKER[..], &frame].concat()
        } else {
            payload.to_vec()
        }
    }

    /// Decompress an inbound payload.
    ///
    /// Auto-detects compression via the wire marker. If the payload
    /// starts with `COMPRESSION_MARKER`, the marker is stripped and
    /// the frame is decompressed and verified. If not, the payload is
    /// returned as-is. This makes the receive path independent of the
    /// local session's outbound compression configuration.
    pub fn decompress_inbound(&mut self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        if is_marked_compression(data) {
            let frame = crate::compression::decompress_frame(&data[COMPRESSION_MARKER.len()..])?;
            // Update inbound stats on the session compression state (if present).
            if let Some(ref mut state) = self.compression {
                state.frames_decompressed += 1;
                state.total_compressed_bytes += data.len() as u64;
                state.total_uncompressed_bytes += frame.payload.len() as u64;
            }
            Ok(frame.payload)
        } else {
            Ok(data.to_vec())
        }
    }

    /// Initialize session encryption ciphers from a raw 32-byte session key.
    ///
    /// Convenience wrapper around [`init_ciphers`] for callers that already
    /// have the session key bytes (e.g., the HMAC key from
    /// [`tidefs_auth::HelloHandshakeResult`]).  The key MUST come from a
    /// real authenticated key agreement.  Do NOT pass the public
    /// [`NegotiationComplete`] token: it is derived from public transcript
    /// data and provides no secrecy.
    ///
    /// Production callers should prefer [`apply_auth_handshake`], which
    /// derives ciphers from the authenticated handshake result directly.
    pub fn init_ciphers_from_key(&mut self, session_key: &[u8; 32], as_initiator: bool) {
        struct RawKeyMaterial([u8; 32]);
        impl SessionKeyMaterial for RawKeyMaterial {
            fn shared_secret(&self) -> &[u8; 32] {
                &self.0
            }
        }
        self.init_ciphers(&RawKeyMaterial(*session_key), as_initiator)
    }

    /// Whether session encryption ciphers have been initialized.
    #[must_use]
    pub fn has_ciphers(&self) -> bool {
        self.outbound_cipher.is_some() && self.inbound_cipher.is_some()
    }

    /// Complete the auth handshake integration: apply the 7-step mutual
    /// attestation result to this transport session.
    ///
    /// This wires the tidefs-auth [`HelloHandshakeResult`] into the session,
    /// storing peer identity, initializing encryption ciphers from the
    /// HMAC session key, and binding the membership epoch.
    ///
    /// Called after both sides have completed Steps 1-4 of the HELLO
    /// handshake (identity verification and VERIFY exchange).
    pub fn apply_auth_handshake(
        &mut self,
        result: &tidefs_auth::HelloHandshakeResult,
        as_initiator: bool,
    ) {
        // Store peer identity for authorization and audit.
        self.peer_info = Some(PeerSessionInfo {
            node_id: result.peer_identity.node_id,
            identity: result.peer_identity.clone(),
            supported_families: vec![crate::types::FamilyVersion::new(
                result.accepted_protocol,
                result.accepted_protocol,
                0,
            )],
            cohort_membership: crate::types::CohortMembership::default(),
            hlc_offset: 0,
            endpoint_family: self.endpoint_family,
            peer_epoch: result.session_token.session_id,
        });

        // Derive ciphers from the HMAC session key
        self.init_ciphers_from_key(&result.session_keys.hmac_key, as_initiator);

        // Bind epoch from the session token's session_id (epoch tracking)
        let _ = self.bind_epoch(result.session_token.session_id);
    }

    /// Establish a session from a completed parameter negotiation.
    ///
    /// Stores peer identity, binds the epoch, and transitions the session
    /// state to `Established`. Returns [`SessionParams`] describing the
    /// negotiated session for subsequent stream multiplexing and keepalive
    /// management.
    ///
    /// **Ciphers are NOT initialized here.** The negotiation token is
    /// derived from public transcript data and MUST NOT be used as key
    /// material. Production callers must use [`apply_auth_handshake`] or
    /// [`init_ciphers`] with real key material from `tidefs-auth`.
    pub fn establish(
        mut self,
        complete: &crate::session::handshake::NegotiationComplete,
        negotiated_version: u32,
        capability_mask: u64,
        local_node: u64,
        _as_initiator: bool,
    ) -> Result<(Self, SessionParams), super::error::SessionError> {
        use rand::Rng;

        // Store peer identity
        self.peer_info = Some(PeerSessionInfo {
            node_id: complete.peer_node_id,
            identity: crate::types::NodeIdentityPublic {
                node_id: complete.peer_node_id,
                verifying_key_bytes: complete.peer_identity.verifying_key_bytes,
                attested_at_millis: complete.peer_identity.attested_at_millis,
                identity_version: complete.peer_identity.identity_version,
                self_signature: complete.peer_identity.self_signature.clone(),
            },
            supported_families: complete.peer_families.clone(),
            cohort_membership: crate::types::CohortMembership::default(),
            hlc_offset: 0,
            endpoint_family: self.endpoint_family,
            peer_epoch: complete.peer_epoch,
        });

        // NOTE: Ciphers are NOT initialized from the negotiation token
        // because it is derived from public transcript data and provides
        // no secrecy. Production deployments must call apply_auth_handshake()
        // or init_ciphers() with real key material from tidefs-auth.

        // Bind epoch
        self.bind_epoch(complete.peer_epoch)?;

        // Transition to Established
        self.transition(SessionState::Established {
            since: HlcTimestamp::from_hlc_value(self.hlc.current()),
        })?;

        // Generate a unique 64-bit session_id
        let mut rng = rand::thread_rng();
        let session_id: u64 = rng.gen::<u64>();

        let params = SessionParams::from_negotiation_complete(
            complete,
            negotiated_version,
            capability_mask,
            session_id,
        );

        self.session_id = crate::types::SessionId(session_id);
        self.local_node = local_node;
        self.peer_node = complete.peer_node_id;

        self.rollback_gate = Some(crate::rollback_compat::RollingUpgradeGate::from_raw(
            capability_mask,
        ));

        Ok((self, params))
    }

    /// Transition session to a new state, validating the transition is legal.
    /// Stamp a SessionState with the current HLC value.
    fn stamp_state(&self, state: &SessionState) -> SessionState {
        let ts = HlcTimestamp::from_hlc_value(self.hlc.current());
        match state {
            SessionState::Connecting { .. } => SessionState::Connecting { started_at: ts },
            SessionState::Handshaking { .. } => SessionState::Handshaking { started_at: ts },
            SessionState::Established { .. } => SessionState::Established { since: ts },
            SessionState::Reconnecting {
                attempt, backoff, ..
            } => SessionState::Reconnecting {
                attempt: *attempt,
                since: ts,
                backoff: *backoff,
            },
            other => other.clone(),
        }
    }

    /// Current monotonic time in nanoseconds, relative to process start.
    fn physical_ns(&self) -> u64 {
        self.start_instant.elapsed().as_nanos() as u64
    }

    /// Allocate and return the next outbound sequence number for this session.
    ///
    /// Monotonically increments `send_seq` with wrapping arithmetic.
    /// The first call returns sequence number 1.
    #[must_use]
    pub fn next_send_seq(&mut self) -> MessageSequenceNumber {
        self.send_seq = MessageSequenceNumber(self.send_seq.0.wrapping_add(1));
        self.send_seq
    }

    /// Accept a received message sequence number and classify the delivery.
    ///
    /// Returns:
    /// - `Accepted` for in-order delivery (advances `recv_seq`).
    /// - `Duplicate` when `seq <= recv_seq` (silently dropped).
    /// - `Gap` when `seq > recv_seq.0.wrapping_add(1)`.
    ///
    /// Gaps are recorded for retransmission requests by higher layers.
    /// `recv_seq` is advanced only on in-order delivery.
    #[must_use]
    pub fn accept_recv_seq(&mut self, seq: MessageSequenceNumber) -> SeqReceiveOutcome {
        let delta = seq.0.wrapping_sub(self.recv_seq.0);
        if delta == 1 {
            self.recv_seq = seq;
            SeqReceiveOutcome::Accepted
        } else if (delta as i64) <= 0 {
            // Zero delta (exact duplicate) or negative (replayed old message):
            // wrapping subtraction treats numbers within half the u64 range
            // as "before or equal" to recv_seq.
            SeqReceiveOutcome::Duplicate
        } else {
            // delta > 1: gap detected
            let missing_start = MessageSequenceNumber(self.recv_seq.0.wrapping_add(1));
            SeqReceiveOutcome::Gap {
                missing_start,
                missing_end: seq,
            }
        }
    }

    /// Return the last sent sequence number (0 if none yet).
    #[must_use]
    pub fn last_sent_seq(&self) -> MessageSequenceNumber {
        self.send_seq
    }

    /// Return the highest consecutive received sequence number (0 if none).
    #[must_use]
    pub fn last_recv_seq(&self) -> MessageSequenceNumber {
        self.recv_seq
    }

    /// Advance receive window to `through_seq` after retransmission fills a gap.
    pub fn resolve_recv_gap(&mut self, through_seq: MessageSequenceNumber) {
        if through_seq.0 > self.recv_seq.0 {
            self.recv_seq = through_seq;
        }
    }

    /// Transition session to a new state, validating the transition is legal.
    ///
    /// On success, stamps the new state with the current HLC value, advances
    /// the HLC with the current monotonic physical time, and updates the
    /// session state.
    pub fn transition(
        &mut self,
        new_state: SessionState,
    ) -> Result<(), super::error::SessionError> {
        let valid = match (&self.state, &new_state) {
            // Initial connection flow
            (SessionState::Unconnected, SessionState::Connecting { .. }) => true,
            (SessionState::Connecting { .. }, SessionState::Handshaking { .. }) => true,

            // Post-handshake protocol states (P8-01 session state machine)
            (SessionState::Handshaking { .. }, SessionState::Bound { .. }) => true,
            (SessionState::Bound { .. }, SessionState::CohortAttached { .. }) => true,
            (SessionState::CohortAttached { .. }, SessionState::Established { .. }) => true,
            (SessionState::Established { .. }, SessionState::Degraded { .. }) => true,
            (SessionState::Degraded { .. }, SessionState::ResumePending { .. }) => true,
            (SessionState::ResumePending { .. }, SessionState::Connecting { .. }) => true,

            // Degraded recovery path (heartbeat restores)
            (SessionState::Degraded { .. }, SessionState::Established { .. }) => true,

            // Keep direct Handshaking -> Established for backward compatibility
            (SessionState::Handshaking { .. }, SessionState::Established { .. }) => true,

            // Disconnection and reconnection
            (SessionState::Established { .. }, SessionState::Reconnecting { .. }) => true,
            (SessionState::Degraded { .. }, SessionState::Reconnecting { .. }) => true,
            (SessionState::Reconnecting { .. }, SessionState::Handshaking { .. }) => true,
            (SessionState::Reconnecting { .. }, SessionState::Connecting { .. }) => true,
            // Session resumption: Reconnecting -> Established (domain-separated resume-token verified)
            (SessionState::Reconnecting { .. }, SessionState::Established { .. }) => true,

            // Terminal states
            (_, SessionState::Closed { .. }) => true,

            // Conn-level retry and resume-level retry
            (SessionState::Connecting { .. }, SessionState::Connecting { .. }) => true,
            (SessionState::ResumePending { .. }, SessionState::ResumePending { .. }) => true,

            _ => false,
        };

        if valid {
            let now = self.hlc.current();
            self.state = self.stamp_state(&new_state);
            // Update session stats
            self.stats.last_activity = Some(HlcTimestamp::from_hlc_value(now));
            if matches!(self.state, SessionState::Established { .. }) {
                self.stats.established_at = Some(HlcTimestamp::from_hlc_value(now));
            }
            self.hlc.advance_local(self.physical_ns());
            Ok(())
        } else {
            Err(super::error::SessionError::InvalidTransition {
                session_id: self.session_id,
                from: self.state.clone(),
                to: new_state,
            })
        }
    }

    /// Enable or reconfigure message batching for this session.
    ///
    /// When enabled, outbound messages are coalesced into batches per the
    /// provided config. Call [`crate::Transport::flush_batches`] to drain
    /// accumulated batches, or rely on the session background flush.
    ///
    /// Store a capacity set on this session so external callers can
    /// query per-priority backpressure state (e.g. for rebuild throttling).
    pub fn set_capacity_set(&mut self, cs: SendCapacitySet) {
        self.capacity_set = Some(cs);
    }

    /// Return a [`SendCapacity`] handle for the Data lane, if a capacity
    /// set is configured on this session.
    ///
    /// Returns `None` if no capacity set has been stored. The returned
    /// handle can be wrapped in an `IoPressureProbe` to drive background
    /// rebuild throttling from transport backpressure.
    #[must_use]
    pub fn data_lane_capacity(&self) -> Option<SendCapacity> {
        self.capacity_set
            .as_ref()
            .map(|cs| cs.capacity(SendPriority::Data))
    }

    /// When disabled (default), every send writes immediately through the
    /// existing priority-queue path.
    pub fn configure_batching(&mut self, config: crate::message_batcher::BatchConfig) {
        self.batch_config = config.clone();
        self.message_batcher = crate::message_batcher::MessageBatcher::new(config);
    }

    /// Whether the session is in a state that can send/receive messages.
    #[must_use]
    pub fn is_established(&self) -> bool {
        matches!(
            self.state,
            SessionState::Bound { .. }
                | SessionState::CohortAttached { .. }
                | SessionState::Established { .. }
                | SessionState::Degraded { .. }
        )
    }

    /// Activate keepalive heartbeats when session becomes Established.
    pub fn activate_keepalive(&mut self) {
        self.heartbeat.activate();
    }

    /// Deactivate keepalive heartbeats on teardown or session close.
    pub fn deactivate_keepalive(&mut self) {
        self.heartbeat.deactivate();
    }

    /// Return the current keepalive health classification.
    #[must_use]
    pub fn keepalive_health(&self) -> KeepaliveHealth {
        self.heartbeat.health()
    }

    /// Check keepalive health and transition session state if dead.
    ///
    /// If the keepalive detects a newly dead connection, the session is
    /// transitioned to `Degraded`. The caller should subsequently initiate
    /// teardown or reconnection.
    ///
    /// Returns the health classification and whether the connection was
    /// newly detected as dead.
    pub fn check_keepalive(&mut self) -> (KeepaliveHealth, bool) {
        let (health, newly_dead) = session_keepalive_check(&mut self.heartbeat);
        if newly_dead {
            // Transition to Degraded if currently Established
            if matches!(self.state, SessionState::Established { .. }) {
                let _ = self.transition(SessionState::Degraded {
                    since: HlcTimestamp::from_hlc_value(self.hlc.current()),
                });
            }
        }
        (health, newly_dead)
    }

    /// Record a keepalive ping was sent. Returns the sequence number.
    pub fn record_keepalive_ping(&mut self) -> u64 {
        self.heartbeat.on_ping_sent()
    }

    /// Record a valid keepalive pong was received.
    /// If the session was Degraded and the pong restores health,
    /// transition back to Established.
    pub fn record_keepalive_pong(&mut self, seq: u64) {
        let old_state = self.heartbeat.on_pong_received(seq);
        // If we recovered from Suspect to Healthy and are Degraded,
        // attempt to transition back to Established
        if matches!(old_state, HeartbeatState::Suspect(_))
            && matches!(self.state, SessionState::Degraded { .. })
        {
            let _ = self.transition(SessionState::Established {
                since: HlcTimestamp::from_hlc_value(self.hlc.current()),
            });
        }
    }
    /// Advance HLC on message send and record stats for `byte_count` bytes
    /// sent with the given priority.
    pub fn on_send(&mut self, byte_count: u64, priority: crate::message_priority::MessagePriority) {
        self.stats.record_send(byte_count, priority);
        self.stats.last_activity = Some(HlcTimestamp::from_hlc_value(self.hlc.current()));
        self.hlc.advance_local(self.physical_ns());
    }

    /// Merge remote HLC on message receive and record stats for `byte_count`
    /// bytes received. Priority classification on receive is best-effort.
    pub fn on_recv(
        &mut self,
        remote_hlc: Option<HlcValue>,
        byte_count: u64,
        priority: Option<crate::message_priority::MessagePriority>,
    ) {
        self.stats.record_recv(byte_count, priority);
        let now = if let Some(remote) = remote_hlc {
            self.hlc.merge_remote(remote, self.physical_ns())
        } else {
            self.hlc.advance_local(self.physical_ns())
        };
        self.stats.last_activity = Some(HlcTimestamp::from_hlc_value(now));
    }

    /// Whether the session is terminal.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        matches!(self.state, SessionState::Closed { .. })
    }

    /// P8-01 session state string for wire-level gate identifiers.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.state.as_str()
    }

    /// Whether the session is in a terminal state (cannot be resumed).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Whether the session can be resumed from its current state.
    #[must_use]
    pub fn can_resume(&self) -> bool {
        self.state.can_resume()
    }
    #[must_use]
    /// Check whether this session is bound to the given epoch.
    /// Returns true if the session's current_epoch matches the provided epoch.
    pub fn is_bound_to_epoch(&self, epoch: u64) -> bool {
        self.current_epoch == epoch
    }

    #[must_use]
    /// Check if this session is epoch-gated (has a non-zero epoch bound).
    pub fn has_epoch_binding(&self) -> bool {
        self.current_epoch != 0
    }

    /// Bind this session to a specific membership epoch.
    /// Bind this session to a specific membership epoch.
    /// Must only be called once during handshake; subsequent calls
    /// that change the epoch return an error.
    ///
    /// ## Errors
    ///
    /// Returns `SessionError::EpochMismatch` if the session is already bound
    /// to a different non-zero epoch.
    pub fn bind_epoch(&mut self, epoch: u64) -> Result<(), super::error::SessionError> {
        if self.current_epoch != 0 && self.current_epoch != epoch {
            return Err(super::error::SessionError::EpochMismatch {
                session_id: self.session_id,
                session_epoch: self.current_epoch,
                expected_epoch: epoch,
            });
        }
        self.current_epoch = epoch;
        Ok(())
    }

    /// Validate that the session's bound epoch matches the given epoch.
    /// Returns `Err(SessionError)` if the epochs don't match, indicating
    /// an epoch mismatch between peers.
    pub fn validate_epoch(&self, expected_epoch: u64) -> Result<(), super::error::SessionError> {
        if self.current_epoch != expected_epoch {
            return Err(super::error::SessionError::EpochMismatch {
                session_id: self.session_id,
                session_epoch: self.current_epoch,
                expected_epoch,
            });
        }
        Ok(())
    }

    /// Handle RDMA carrier degradation: transition to Degraded state.
    ///
    /// When the RDMA carrier fails (e.g., NIC reset, memory registration
    /// failure, or persistent connection loss), the session enters Degraded
    /// state. Only sessions in Established state may degrade. The transport
    /// layer may then attempt a TCP fallback.
    ///
    /// ## Errors
    ///
    /// Returns [] if the session is not in a
    /// state that permits degradation (must be Established).
    pub fn handle_rdma_degraded(&mut self, reason: &str) -> Result<(), super::error::SessionError> {
        // Degraded is also acceptable — the session is already degraded;
        // this is a no-op re-degradation.
        if matches!(self.state, SessionState::Degraded { .. }) {
            tracing::info!(
                session_id = %self.session_id,
                reason = %reason,
                "RDMA session {} already degraded; no-op re-degradation",
                self.session_id
            );
            return Ok(());
        }
        if !matches!(self.state, SessionState::Established { .. }) {
            return Err(super::error::SessionError::NotEstablished {
                session_id: self.session_id,
                state: self.state.clone(),
            });
        }
        let ts = HlcTimestamp::from_hlc_value(self.hlc.current());
        self.transition(SessionState::Degraded { since: ts })
            .map_err(|e| super::error::SessionError::RdmaDegraded {
                session_id: self.session_id,
                reason: format!("{reason}: transition to Degraded failed: {e}"),
            })
    }

    /// Fall back to TCP after RDMA degradation.
    ///
    /// Resets the reconnection state machine for TCP retry semantics
    /// and records the fallback. The caller must also update the
    /// transport backend and active connection to TCP.
    pub fn fallback_to_tcp(&mut self) {
        self.reconnect.reset();
        self.backend_kind = TransportBackendKind::Tcp;
        self.carrier_lost = false;
        tracing::info!(
            session_id = %self.session_id,
            "RDMA session {} falling back to TCP; backend_kind set to Tcp, carrier_lost cleared, reconnect attempt counter reset",
            self.session_id
        );
    }

    /// Whether this session is degraded from RDMA (has entered Degraded state
    /// and may fall back to TCP).
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        matches!(self.state, SessionState::Degraded { .. })
    }

    /// Whether the RDMA carrier has been permanently lost.
    #[must_use]
    pub fn is_carrier_lost(&self) -> bool {
        self.carrier_lost
    }

    /// Handle permanent RDMA carrier loss: the RDMA NIC is unavailable and
    /// no recovery is possible without operator intervention.
    ///
    /// Unlike [], this indicates a permanent loss,
    /// not a transient degradation. The session state is not modified;
    /// the caller should close the session or fall back to TCP.
    ///
    /// ## Errors
    ///
    /// Returns [] with the reason for the
    /// permanent carrier loss.
    pub fn handle_rdma_carrier_lost(
        &mut self,
        reason: &str,
    ) -> Result<(), super::error::SessionError> {
        self.carrier_lost = true;
        tracing::warn!(
            session_id = %self.session_id,
            reason = %reason,
            "RDMA carrier permanently lost for session {}; TCP fallback required per OW-308",
            self.session_id
        );
        // Return the typed error so callers can match on RdmaCarrierLost
        // and choose the appropriate recovery path (TCP fallback or close).
        Err(super::error::SessionError::RdmaCarrierLost {
            session_id: self.session_id,
            reason: reason.to_string(),
        })
    }

    /// Handle a failed RDMA-to-TCP fallback.
    ///
    /// When the session cannot recover either via RDMA retry or TCP
    /// fallback, this records the failure reason. The caller should
    /// close the session after this call.
    ///
    /// ## Errors
    ///
    /// Returns [] with the reason
    /// for the fallback failure.
    pub fn handle_rdma_fallback_failed(
        &mut self,
        reason: &str,
    ) -> Result<(), super::error::SessionError> {
        self.carrier_lost = true;
        tracing::error!(
            session_id = %self.session_id,
            reason = %reason,
            "RDMA-to-TCP fallback failed for session {}; session must be closed",
            self.session_id
        );
        // Return the typed error so callers can match on RdmaFallbackFailed
        // and close the session.
        Err(super::error::SessionError::RdmaFallbackFailed {
            session_id: self.session_id,
            reason: reason.to_string(),
        })
    }

    /// Store the session key for later reconnect resume token construction.
    ///
    /// Called once during or after handshake when session keys are established.
    pub fn init_reconnect_session_key(&mut self, key: [u8; 32]) {
        self.session_key = Some(key);
    }

    /// Set the reconnect configuration for this session.
    pub fn set_reconnect_config(&mut self, config: ReconnectConfig) {
        self.reconnect_config = config;
    }

    /// Create a [`ReconnectDriver`] from this session's current state.
    ///
    /// Returns `None` if the session key has not been set (no handshake
    /// completed yet).
    #[must_use]
    pub fn create_reconnect_driver(&self) -> Option<ReconnectDriver> {
        let key = self.session_key?;
        Some(ReconnectDriver::new(
            self.session_id.0,
            key,
            self.reconnect_config.clone(),
        ))
    }

    /// Transition the session to `Reconnecting` state with the given
    /// attempt number and backoff.
    ///
    /// ## Errors
    ///
    /// Returns `SessionError::InvalidTransition` if the current state
    /// does not permit reconnection.
    pub fn enter_reconnecting(
        &mut self,
        attempt: u32,
        backoff: Duration,
    ) -> Result<(), super::error::SessionError> {
        if !self.can_resume() {
            return Err(super::error::SessionError::NotEstablished {
                session_id: self.session_id,
                state: self.state.clone(),
            });
        }
        self.stats.record_reconnect();
        let ts = HlcTimestamp::from_hlc_value(self.hlc.current());
        self.transition(SessionState::Reconnecting {
            attempt,
            since: ts,
            backoff,
        })
        .map_err(|_e| super::error::SessionError::InvalidTransition {
            session_id: self.session_id,
            from: self.state.clone(),
            to: SessionState::Reconnecting {
                attempt,
                since: ts,
                backoff,
            },
        })
    }

    /// Complete a successful reconnection: transition back to `Established`.
    pub fn complete_reconnect(&mut self) -> Result<(), super::error::SessionError> {
        if !matches!(self.state, SessionState::Reconnecting { .. }) {
            return Err(super::error::SessionError::InvalidTransition {
                session_id: self.session_id,
                from: self.state.clone(),
                to: SessionState::Established {
                    since: HlcTimestamp::from_hlc_value(self.hlc.current()),
                },
            });
        }
        self.reconnect.reset();
        let ts = HlcTimestamp::from_hlc_value(self.hlc.current());
        self.transition(SessionState::Established { since: ts })
            .map_err(|_e| super::error::SessionError::InvalidTransition {
                session_id: self.session_id,
                from: self.state.clone(),
                to: SessionState::Established { since: ts },
            })
    }

    /// Abandon reconnection and close the session.
    pub fn abandon_reconnect(
        &mut self,
        reason: SessionCloseReason,
    ) -> Result<(), super::error::SessionError> {
        if !matches!(self.state, SessionState::Reconnecting { .. }) {
            return Err(super::error::SessionError::InvalidTransition {
                session_id: self.session_id,
                from: self.state.clone(),
                to: SessionState::Closed { reason },
            });
        }
        self.transition(SessionState::Closed { reason })
            .map_err(|_e| super::error::SessionError::InvalidTransition {
                session_id: self.session_id,
                from: self.state.clone(),
                to: SessionState::Closed { reason },
            })
    }
    // ------------------------------------------------------------------
    // Response tracker methods
    // ------------------------------------------------------------------

    /// Create and attach a response tracker to this session.
    ///
    /// Called during session establishment. Creates a
    /// [](crate::request_response::RequestResponseTable),
    /// spawns the background timeout-reaping task, and stores the handle
    /// for use by the send/receive dispatch paths.
    ///
    /// The timeout task is aborted when the session transitions to a closed
    /// state (via [](Self::abort_response_timeout_task)).
    pub fn set_response_tracker(
        &mut self,
        max_pending: Option<usize>,
        default_timeout: std::time::Duration,
        reap_interval: std::time::Duration,
    ) {
        use crate::request_response::{RequestResponseTable, TimeoutConfig};
        let table: RequestResponseTable<Vec<u8>> =
            RequestResponseTable::new(max_pending, default_timeout);
        let handle = table.handle();
        let timeout_task = table.try_spawn_timeout_task(TimeoutConfig {
            scan_interval: reap_interval,
        });
        self.response_tracker = Some(handle);
        self.response_timeout_task = timeout_task;
    }

    /// Abort the background response-timeout reaping task.
    ///
    /// Called when the session closes or transitions to a terminal state.
    /// After this call the session will no longer automatically reap expired
    /// response entries.
    pub fn abort_response_timeout_task(&mut self) {
        if let Some(task) = self.response_timeout_task.take() {
            task.abort();
        }
    }

    /// Register a new in-flight request and return a correlation ID plus a
    /// oneshot receiver that will be signalled when the response arrives or
    /// the request times out.
    ///
    /// Returns `None` if no response tracker is attached to this session.
    pub async fn register_response_waiter(
        &self,
    ) -> Option<
        Result<
            (
                u64,
                tokio::sync::oneshot::Receiver<
                    Result<Vec<u8>, crate::request_response::CorrelationError>,
                >,
            ),
            crate::request_response::CorrelationError,
        >,
    > {
        let tracker = self.response_tracker.as_ref()?;
        Some(tracker.register_request().await)
    }

    /// Deliver a response payload for the given correlation ID, waking the
    /// blocked caller.
    ///
    /// Returns `None` if no response tracker is attached.
    pub async fn deliver_response(
        &self,
        correlation_id: u64,
        data: Vec<u8>,
    ) -> Option<Result<(), crate::request_response::CorrelationError>> {
        let tracker = self.response_tracker.as_ref()?;
        Some(tracker.deliver_response(correlation_id, data).await)
    }

    /// Fail all pending response waiters (used on session drain/close).
    ///
    /// Returns the number of entries cancelled, or `None` if no tracker
    /// is attached.
    pub async fn fail_all_pending_responses(&self) -> Option<usize> {
        let tracker = self.response_tracker.as_ref()?;
        Some(tracker.fail_all_pending().await)
    }

    /// Return the number of currently pending response entries, or `None`
    /// if no tracker is attached.
    pub async fn pending_response_count(&self) -> Option<usize> {
        let tracker = self.response_tracker.as_ref()?;
        Some(tracker.pending_count().await)
    }

    // ------------------------------------------------------------------
    // Send buffer convenience methods
    // ------------------------------------------------------------------

    /// Try to enqueue a serialized frame into the per-peer send buffer.
    ///
    /// Returns [`Backpressure::Ok`] on success, [`Backpressure::PeerFull`]
    /// if the buffer is at capacity, or [`Backpressure::Shutdown`] if the
    /// buffer has been closed.
    pub fn try_enqueue_send(&mut self, frame: bytes::Bytes) -> Backpressure {
        match self.send_buffer.try_enqueue(frame).outcome {
            crate::send_admission::SendAdmissionOutcome::Accepted
            | crate::send_admission::SendAdmissionOutcome::Queued
            | crate::send_admission::SendAdmissionOutcome::DroppedOldest => Backpressure::Ok,
            crate::send_admission::SendAdmissionOutcome::Backpressured
            | crate::send_admission::SendAdmissionOutcome::Blocked
            | crate::send_admission::SendAdmissionOutcome::ExpiredBeforeEnqueue => {
                Backpressure::PeerFull
            }
            crate::send_admission::SendAdmissionOutcome::Closed
            | crate::send_admission::SendAdmissionOutcome::NoConnection => Backpressure::Shutdown,
        }
    }

    /// Dequeue the next frame from the send buffer for wire transmission.
    pub fn dequeue_send(&mut self) -> Option<bytes::Bytes> {
        self.send_buffer.dequeue()
    }

    /// Drain all queued frames from the send buffer (e.g., on peer close).
    pub fn drain_send_buffer(&mut self) {
        self.send_buffer.drain();
    }

    /// Shut down the send buffer (marks closed and drains).
    pub fn shutdown_send_buffer(&mut self) {
        self.send_buffer.shutdown();
    }

    /// Return `true` if the send buffer has reached capacity.
    pub fn is_send_buffer_full(&self) -> bool {
        self.send_buffer.remaining_capacity() == 0
    }

    /// Return the send buffer stats snapshot.
    pub fn send_buffer_stats(&self) -> crate::send_buffer::BufferStatsSnapshot {
        self.send_buffer.stats.snapshot()
    }

    /// Return a mutable reference to the send buffer stats counters
    /// (for direct counter increments from the transport layer).
    pub fn send_buffer_stats_mut(&mut self) -> &crate::send_buffer::PeerBufferStats {
        &self.send_buffer.stats
    }

    /// Return a copy of the send buffer configuration.
    pub fn send_buffer_config(&self) -> crate::send_buffer::SendBufferConfig {
        crate::send_buffer::SendBufferConfig {
            max_memory: self.send_buffer.max_memory(),
            backpressure_policy: self.send_buffer.policy(),
        }
    }

    /// Pop the oldest Data-priority message from the priority queue,
    /// skipping any Control-priority messages that are ahead of it.
    ///
    /// Returns `None` if the Data sub-queue is empty.
    pub(crate) fn pop_oldest_data_message(&mut self) -> Option<QueuedMessage> {
        self.message_priority_queue.pop_oldest_data()
    }

    /// Return a point-in-time snapshot of session operational statistics,
    /// including current queue depths.
    pub fn stats(&self) -> SessionStatsSnapshot {
        let mut snap = self.stats.snapshot();
        snap.send_queue_depth = self.send_buffer.len() as u64;
        snap.priority_queue_control_depth = self.message_priority_queue.control_len() as u64;
        snap.priority_queue_data_depth = self.message_priority_queue.data_len() as u64;
        snap
    }

    /// Reset all session statistics counters to zero and clear timestamps.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }

    /// Return a reference to the per-session statistics for direct
    /// instrumentation from the transport layer.
    pub fn stats_ref(&self) -> &SessionStats {
        &self.stats
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("session_id", &self.session_id)
            .field("local_node", &self.local_node)
            .field("peer_node", &self.peer_node)
            .field("state", &self.state)
            .field("peer_addr", &self.peer_addr)
            .field("endpoint_family", &self.endpoint_family)
            .field("backend_kind", &self.backend_kind)
            .field("carrier_lost", &self.carrier_lost)
            .field("send_seq", &self.send_seq)
            .field("recv_seq", &self.recv_seq)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Peer info exchanged during handshake
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
/// Information about the peer node collected during session handshake.
pub struct PeerSessionInfo {
    pub node_id: u64,
    pub identity: NodeIdentity,
    pub supported_families: Vec<FamilyVersion>,
    pub cohort_membership: CohortMembership,
    pub hlc_offset: i64,
    pub endpoint_family: EndpointFamily,
    pub peer_epoch: u64,
}

impl PeerSessionInfo {
    #[must_use]
    /// Create a new PeerSessionInfo from a Session.
    pub fn new(
        node_id: u64,
        identity: NodeIdentity,
        supported_families: Vec<FamilyVersion>,
        cohort_membership: CohortMembership,
        hlc_offset: i64,
        endpoint_family: EndpointFamily,
    ) -> Self {
        Self {
            node_id,
            identity,
            supported_families,
            cohort_membership,
            hlc_offset,
            endpoint_family,
            peer_epoch: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Session params: handshake negotiation outcome
// ---------------------------------------------------------------------------

/// Output of a successful transport session parameter negotiation, capturing the
/// negotiated protocol version, capability bitmask, session identifier,
/// remote node identity, and negotiation token for subsequent stream
/// multiplexing and keepalive management.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionParams {
    /// Negotiated feature flags for rolling upgrade compatibility
    /// gating. Derived from the capability_mask intersection of
    /// local and remote feature sets.
    pub negotiated_features: crate::rollback_compat::NodeFeatureFlags,
    /// Protocol version negotiated during the handshake.
    pub negotiated_version: u32,
    /// Capability bitmask: intersection of local and remote capabilities.
    pub capability_mask: u64,
    /// 128-bit session identifier assigned by the server.
    pub session_id: u64,
    /// Remote node's numeric identifier.
    pub remote_node_id: u64,
    /// Remote node's Ed25519 identity (BLAKE3-keyed public-key hash).
    pub remote_identity: crate::types::NodeIdentityPublic,
    /// 32-byte negotiation token derived from the transcript. NOT A SECRET.
    pub negotiation_token: [u8; 32],
    /// Final handshake transcript hash for audit logging.
    pub transcript_hash: [u8; 32],
}

impl SessionParams {
    /// Create from a completed parameter-negotiation result
    /// plus the negotiated version and capability mask.
    #[must_use]
    pub fn from_negotiation_complete(
        complete: &crate::session::handshake::NegotiationComplete,
        negotiated_version: u32,
        capability_mask: u64,
        session_id: u64,
    ) -> Self {
        Self {
            negotiated_version,
            negotiated_features: crate::rollback_compat::NodeFeatureFlags::from_raw(
                capability_mask,
            ),
            capability_mask,
            session_id,
            remote_node_id: complete.peer_node_id,
            remote_identity: complete.peer_identity.clone(),
            negotiation_token: complete.negotiation_token,
            transcript_hash: complete.transcript_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// Session state machine
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
/// States of a session (P8-01 session state machine).
pub enum SessionState {
    /// Initial state
    Unconnected,

    /// TCP/TLS handshake in progress
    Connecting { started_at: HlcTimestamp },

    /// Connected, version + identity exchange in progress
    Handshaking { started_at: HlcTimestamp },

    /// Session bound: handshake completed, auth checked, ready for cohort attach
    Bound { since: HlcTimestamp },

    /// Cohort attachment completed, session fully joined to cohort
    CohortAttached { since: HlcTimestamp },

    /// Degraded: connection degraded but still alive, heartbeat-based recovery
    Degraded { since: HlcTimestamp },

    /// Resume pending: token-based resume requested, distinct from TCP retry
    ResumePending { since: HlcTimestamp },

    /// Session established, ready for messages
    Established { since: HlcTimestamp },

    /// Connection lost, reconnecting
    Reconnecting {
        attempt: u32,
        since: HlcTimestamp,
        backoff: Duration,
    },

    /// Session closed (peer removed from cluster)
    Closed { reason: SessionCloseReason },
}

impl Default for SessionState {
    fn default() -> Self {
        Self::Unconnected
    }
}

impl SessionState {
    #[must_use]
    /// Return the canonical string representation of this state.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unconnected => "session_state_0.unconnected",
            Self::Connecting { .. } => "session_state_1.connecting",
            Self::Handshaking { .. } => "session_state_2.handshaking",
            Self::Bound { .. } => "session_state_3.bound",
            Self::CohortAttached { .. } => "session_state_4.cohort_attached",
            Self::Established { .. } => "session_state_5.flowing",
            Self::Degraded { .. } => "session_state_6.degraded",
            Self::ResumePending { .. } => "session_state_7.resume_pending",
            Self::Reconnecting { .. } => "session_state_8.reconnecting",
            Self::Closed { .. } => "session_state_9.closed",
        }
    }

    #[must_use]
    /// Whether this session state is terminal (cannot transition further).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed { .. })
    }

    #[must_use]
    /// Whether this session state allows resumption.
    pub fn can_resume(&self) -> bool {
        matches!(self, Self::Degraded { .. } | Self::Established { .. })
    }

    #[must_use]
    /// Whether the session is in an established (post-bootstrap) state.
    pub fn is_established(&self) -> bool {
        matches!(
            self,
            Self::Bound { .. }
                | Self::CohortAttached { .. }
                | Self::Established { .. }
                | Self::Degraded { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// Session close reason
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
/// Reason a session was closed.
pub enum SessionCloseReason {
    PeerRemoved,
    AuthFailed,
    ProtocolVersionMismatch,
    LocalShutdown,
    TransportError,
    RdmaCarrierLost,
    RdmaRegistrationFailure,
}

impl SessionCloseReason {
    #[must_use]
    /// Convert the runtime close reason to the shared transport-session model.
    pub const fn to_type_model(self) -> tidefs_types_transport_session::SessionCloseReason {
        match self {
            Self::PeerRemoved => tidefs_types_transport_session::SessionCloseReason::PeerRemoved,
            Self::AuthFailed => tidefs_types_transport_session::SessionCloseReason::AuthFailed,
            Self::ProtocolVersionMismatch => {
                tidefs_types_transport_session::SessionCloseReason::ProtocolVersionMismatch
            }
            Self::LocalShutdown => {
                tidefs_types_transport_session::SessionCloseReason::LocalShutdown
            }
            Self::TransportError => {
                tidefs_types_transport_session::SessionCloseReason::TransportError
            }
            Self::RdmaCarrierLost => {
                tidefs_types_transport_session::SessionCloseReason::RdmaCarrierLost
            }
            Self::RdmaRegistrationFailure => {
                tidefs_types_transport_session::SessionCloseReason::RdmaRegistrationFailure
            }
        }
    }

    #[must_use]
    /// Return the authoritative closure class for this runtime close reason.
    pub const fn closure_class(self) -> ClosureClass {
        self.to_type_model().closure_class()
    }

    #[must_use]
    /// Return the default drain result class for this runtime close reason.
    pub const fn drain_result_class(self) -> DrainResultClass {
        self.to_type_model().drain_result_class()
    }

    #[must_use]
    /// Return the shared model label used as the close receipt trigger.
    pub const fn trigger_ref(self) -> &'static str {
        self.to_type_model().as_str()
    }
}

impl fmt::Display for SessionCloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerRemoved => write!(f, "peer_removed"),
            Self::AuthFailed => write!(f, "auth_failed"),
            Self::ProtocolVersionMismatch => write!(f, "protocol_version_mismatch"),
            Self::LocalShutdown => write!(f, "local_shutdown"),
            Self::TransportError => write!(f, "transport_error"),
            Self::RdmaCarrierLost => write!(f, "rdma_carrier_lost"),
            Self::RdmaRegistrationFailure => write!(f, "rdma_registration_failure"),
        }
    }
}

// ---------------------------------------------------------------------------
// Session statistics re-exported from the stats submodule.
pub use self::stats::{SessionStats, SessionStatsSnapshot, TransportStats};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression::CompressionAlgorithm;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn hlc_now() -> HlcTimestamp {
        HlcTimestamp::new(0, 0)
    }

    fn make_session() -> Session {
        Session::new(
            crate::types::SessionId::new(1),
            10,
            20,
            crate::TransportAddr::Tcp(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                8000,
            )),
            EndpointFamily::LocalEmbed,
            TransportBackendKind::Tcp,
        )
    }

    #[test]
    fn full_p8_01_flow() {
        let mut s = make_session();
        let ts = hlc_now();
        s.transition(SessionState::Connecting { started_at: ts })
            .unwrap();
        assert!(matches!(s.state, SessionState::Connecting { .. }));
        s.transition(SessionState::Handshaking { started_at: ts })
            .unwrap();
        assert!(matches!(s.state, SessionState::Handshaking { .. }));
        s.transition(SessionState::Bound { since: ts }).unwrap();
        assert!(matches!(s.state, SessionState::Bound { .. }) && s.is_established());
        s.transition(SessionState::CohortAttached { since: ts })
            .unwrap();
        assert!(matches!(s.state, SessionState::CohortAttached { .. }) && s.is_established());
        s.transition(SessionState::Established { since: ts })
            .unwrap();
        assert!(
            matches!(s.state, SessionState::Established { .. })
                && s.is_established()
                && s.can_resume()
        );
        s.transition(SessionState::Degraded { since: ts }).unwrap();
        assert!(
            matches!(s.state, SessionState::Degraded { .. })
                && s.is_established()
                && s.can_resume()
        );
        s.transition(SessionState::ResumePending { since: ts })
            .unwrap();
        assert!(
            matches!(s.state, SessionState::ResumePending { .. })
                && !s.is_established()
                && !s.can_resume()
                && !s.is_terminal()
        );
        s.transition(SessionState::Connecting { started_at: ts })
            .unwrap();
        assert!(matches!(s.state, SessionState::Connecting { .. }));
    }

    #[test]
    fn degraded_recovery_path() {
        let mut s = make_session();
        let ts = hlc_now();
        s.transition(SessionState::Connecting { started_at: ts })
            .unwrap();
        s.transition(SessionState::Handshaking { started_at: ts })
            .unwrap();
        s.transition(SessionState::Bound { since: ts }).unwrap();
        s.transition(SessionState::CohortAttached { since: ts })
            .unwrap();
        s.transition(SessionState::Established { since: ts })
            .unwrap();
        s.transition(SessionState::Degraded { since: ts }).unwrap();
        assert!(matches!(s.state, SessionState::Degraded { .. }));
        s.transition(SessionState::Established { since: ts })
            .unwrap();
        assert!(matches!(s.state, SessionState::Established { .. }));
    }

    #[test]
    fn established_reconnecting_close() {
        let mut s = make_session();
        let ts = hlc_now();
        s.transition(SessionState::Connecting { started_at: ts })
            .unwrap();
        s.transition(SessionState::Handshaking { started_at: ts })
            .unwrap();
        s.transition(SessionState::Bound { since: ts }).unwrap();
        s.transition(SessionState::CohortAttached { since: ts })
            .unwrap();
        s.transition(SessionState::Established { since: ts })
            .unwrap();
        s.transition(SessionState::Reconnecting {
            attempt: 1,
            since: ts,
            backoff: Duration::from_millis(100),
        })
        .unwrap();
        assert!(matches!(s.state, SessionState::Reconnecting { .. }));
        s.transition(SessionState::Closed {
            reason: SessionCloseReason::LocalShutdown,
        })
        .unwrap();
        assert!(matches!(s.state, SessionState::Closed { .. }) && s.is_terminal() && s.is_closed());
    }

    #[test]
    fn degraded_to_reconnecting() {
        let mut s = make_session();
        let ts = hlc_now();
        s.transition(SessionState::Connecting { started_at: ts })
            .unwrap();
        s.transition(SessionState::Handshaking { started_at: ts })
            .unwrap();
        s.transition(SessionState::Bound { since: ts }).unwrap();
        s.transition(SessionState::CohortAttached { since: ts })
            .unwrap();
        s.transition(SessionState::Established { since: ts })
            .unwrap();
        s.transition(SessionState::Degraded { since: ts }).unwrap();
        s.transition(SessionState::Reconnecting {
            attempt: 1,
            since: ts,
            backoff: Duration::from_millis(100),
        })
        .unwrap();
        assert!(matches!(s.state, SessionState::Reconnecting { .. }));
    }

    #[test]
    fn resume_pending_self_retry() {
        let mut s = make_session();
        let ts = hlc_now();
        s.transition(SessionState::Connecting { started_at: ts })
            .unwrap();
        s.transition(SessionState::Handshaking { started_at: ts })
            .unwrap();
        s.transition(SessionState::Established { since: ts })
            .unwrap();
        s.transition(SessionState::Degraded { since: ts }).unwrap();
        s.transition(SessionState::ResumePending { since: ts })
            .unwrap();
        s.transition(SessionState::ResumePending { since: ts })
            .unwrap();
        assert!(matches!(s.state, SessionState::ResumePending { .. }));
    }

    #[test]
    fn illegal_bound_to_handshaking() {
        let mut s = make_session();
        let ts = hlc_now();
        s.transition(SessionState::Connecting { started_at: ts })
            .unwrap();
        s.transition(SessionState::Handshaking { started_at: ts })
            .unwrap();
        s.transition(SessionState::Bound { since: ts }).unwrap();
        assert!(s
            .transition(SessionState::Handshaking { started_at: ts })
            .is_err());
    }

    #[test]
    fn illegal_resume_to_established() {
        let mut s = make_session();
        let ts = hlc_now();
        s.transition(SessionState::Connecting { started_at: ts })
            .unwrap();
        s.transition(SessionState::Handshaking { started_at: ts })
            .unwrap();
        s.transition(SessionState::Bound { since: ts }).unwrap();
        s.transition(SessionState::CohortAttached { since: ts })
            .unwrap();
        s.transition(SessionState::Established { since: ts })
            .unwrap();
        s.transition(SessionState::Degraded { since: ts }).unwrap();
        s.transition(SessionState::ResumePending { since: ts })
            .unwrap();
        assert!(s
            .transition(SessionState::Established { since: ts })
            .is_err());
    }

    #[test]
    fn as_str_prefix() {
        assert!(SessionState::Unconnected
            .as_str()
            .starts_with("session_state_"));
        assert!(SessionState::Bound { since: hlc_now() }
            .as_str()
            .starts_with("session_state_"));
        assert!(SessionState::CohortAttached { since: hlc_now() }
            .as_str()
            .starts_with("session_state_"));
        assert!(SessionState::Degraded { since: hlc_now() }
            .as_str()
            .starts_with("session_state_"));
        assert!(SessionState::ResumePending { since: hlc_now() }
            .as_str()
            .starts_with("session_state_"));
    }

    #[test]
    fn terminal_property() {
        let ts = hlc_now();
        assert!(!SessionState::Unconnected.is_terminal());
        assert!(!SessionState::Bound { since: ts }.is_terminal());
        assert!(!SessionState::Established { since: ts }.is_terminal());
        assert!(!SessionState::Degraded { since: ts }.is_terminal());
        assert!(!SessionState::ResumePending { since: ts }.is_terminal());
        assert!(SessionState::Closed {
            reason: SessionCloseReason::LocalShutdown
        }
        .is_terminal());
    }

    #[test]
    fn resume_property() {
        let ts = hlc_now();
        assert!(SessionState::Established { since: ts }.can_resume());
        assert!(SessionState::Degraded { since: ts }.can_resume());
        assert!(!SessionState::ResumePending { since: ts }.can_resume());
        assert!(!SessionState::Closed {
            reason: SessionCloseReason::LocalShutdown
        }
        .can_resume());
        assert!(!SessionState::Bound { since: ts }.can_resume());
        assert!(!SessionState::Unconnected.can_resume());
    }

    #[test]
    fn runtime_close_reasons_convert_to_shared_receipt_model() {
        let cases = [
            SessionCloseReason::PeerRemoved,
            SessionCloseReason::AuthFailed,
            SessionCloseReason::ProtocolVersionMismatch,
            SessionCloseReason::LocalShutdown,
            SessionCloseReason::TransportError,
            SessionCloseReason::RdmaCarrierLost,
            SessionCloseReason::RdmaRegistrationFailure,
        ];

        for reason in cases {
            let model = reason.to_type_model();
            assert_eq!(reason.trigger_ref(), model.as_str());
            assert_eq!(reason.closure_class(), model.closure_class());
            assert_eq!(reason.drain_result_class(), model.drain_result_class());
        }
    }

    #[test]
    fn state_is_established() {
        let ts = hlc_now();
        assert!(!SessionState::Unconnected.is_established());
        assert!(SessionState::Bound { since: ts }.is_established());
        assert!(SessionState::CohortAttached { since: ts }.is_established());
        assert!(SessionState::Established { since: ts }.is_established());
        assert!(SessionState::Degraded { since: ts }.is_established());
        assert!(!SessionState::ResumePending { since: ts }.is_established());
        assert!(!SessionState::Reconnecting {
            attempt: 0,
            since: ts,
            backoff: Duration::from_millis(100)
        }
        .is_established());
    }

    // ── Sequence number tests ─────────────────────────────────────────

    #[test]
    fn send_seq_monotonically_increments() {
        let mut s = make_session();
        assert_eq!(s.send_seq.0, 0);
        let s1 = s.next_send_seq();
        assert_eq!(s1.0, 1);
        assert_eq!(s.send_seq.0, 1);
        let s2 = s.next_send_seq();
        assert_eq!(s2.0, 2);
        assert_eq!(s.send_seq.0, 2);
        let s3 = s.next_send_seq();
        assert_eq!(s3.0, 3);
    }

    #[test]
    fn recv_seq_in_order_delivery() {
        let mut s = make_session();
        // First message
        let outcome = s.accept_recv_seq(MessageSequenceNumber::new(1));
        assert_eq!(outcome, SeqReceiveOutcome::Accepted);
        assert_eq!(s.recv_seq.0, 1);

        // Second in order
        let outcome = s.accept_recv_seq(MessageSequenceNumber::new(2));
        assert_eq!(outcome, SeqReceiveOutcome::Accepted);
        assert_eq!(s.recv_seq.0, 2);

        // Third in order
        let outcome = s.accept_recv_seq(MessageSequenceNumber::new(3));
        assert_eq!(outcome, SeqReceiveOutcome::Accepted);
        assert_eq!(s.recv_seq.0, 3);
    }

    #[test]
    fn recv_seq_duplicate_detection_exact_match() {
        let mut s = make_session();
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber::new(1)),
            SeqReceiveOutcome::Accepted
        );
        // Same seq number again → duplicate
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber::new(1)),
            SeqReceiveOutcome::Duplicate
        );
        assert_eq!(s.recv_seq.0, 1); // recv_seq unchanged
    }

    #[test]
    fn recv_seq_duplicate_detection_replayed() {
        let mut s = make_session();
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber::new(1)),
            SeqReceiveOutcome::Accepted
        );
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber::new(2)),
            SeqReceiveOutcome::Accepted
        );
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber::new(3)),
            SeqReceiveOutcome::Accepted
        );
        // Replay seq 2 → duplicate (2 <= 3)
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber::new(2)),
            SeqReceiveOutcome::Duplicate
        );
        assert_eq!(s.recv_seq.0, 3); // recv_seq unchanged
    }

    #[test]
    fn recv_seq_gap_detection_single_skip() {
        let mut s = make_session();
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber::new(1)),
            SeqReceiveOutcome::Accepted
        );
        // Skip seq 2, deliver 3 → gap
        let outcome = s.accept_recv_seq(MessageSequenceNumber::new(3));
        assert_eq!(
            outcome,
            SeqReceiveOutcome::Gap {
                missing_start: MessageSequenceNumber::new(2),
                missing_end: MessageSequenceNumber::new(3),
            }
        );
        assert_eq!(s.recv_seq.0, 1); // recv_seq stays at last consecutive
    }

    #[test]
    fn recv_seq_gap_detection_multi_skip() {
        let mut s = make_session();
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber::new(1)),
            SeqReceiveOutcome::Accepted
        );
        // Skip seq 2-4, deliver 5 → gap
        let outcome = s.accept_recv_seq(MessageSequenceNumber::new(5));
        assert_eq!(
            outcome,
            SeqReceiveOutcome::Gap {
                missing_start: MessageSequenceNumber::new(2),
                missing_end: MessageSequenceNumber::new(5),
            }
        );
        assert_eq!(s.recv_seq.0, 1);
    }

    #[test]
    fn recv_seq_gap_then_fill_resolves_window() {
        let mut s = make_session();
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber::new(1)),
            SeqReceiveOutcome::Accepted
        );
        // Gap at 3
        assert!(matches!(
            s.accept_recv_seq(MessageSequenceNumber::new(3)),
            SeqReceiveOutcome::Gap { .. }
        ));
        assert_eq!(s.recv_seq.0, 1);

        // Resolve gap through seq 3
        s.resolve_recv_gap(MessageSequenceNumber::new(3));
        assert_eq!(s.recv_seq.0, 3);

        // Now seq 4 is in-order again
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber::new(4)),
            SeqReceiveOutcome::Accepted
        );
        assert_eq!(s.recv_seq.0, 4);
    }

    #[test]
    fn recv_seq_gap_then_belated_delivery() {
        let mut s = make_session();
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber::new(1)),
            SeqReceiveOutcome::Accepted
        );
        // Skip 2, get 3
        assert!(matches!(
            s.accept_recv_seq(MessageSequenceNumber::new(3)),
            SeqReceiveOutcome::Gap { .. }
        ));
        // Belated delivery of 2 → duplicate (2 <= recv_seq=1 → wait, 2 > 1 so no)
        // Actually 2 > 1, so it would be: next_expected=2, seq.0=2 → Accepted!
        let outcome = s.accept_recv_seq(MessageSequenceNumber::new(2));
        assert_eq!(outcome, SeqReceiveOutcome::Accepted);
        assert_eq!(s.recv_seq.0, 2); // consecutive advances to 2
                                     // Now 3 is: next_expected=3, seq.0=3 → Accepted
        let outcome = s.accept_recv_seq(MessageSequenceNumber::new(3));
        assert_eq!(outcome, SeqReceiveOutcome::Accepted);
        assert_eq!(s.recv_seq.0, 3);
    }

    #[test]
    fn wraparound_max_u64_to_zero() {
        let mut s = make_session();
        // Set send_seq near u64::MAX
        s.send_seq = MessageSequenceNumber(u64::MAX - 1);
        let s1 = s.next_send_seq();
        assert_eq!(s1.0, u64::MAX);
        let s2 = s.next_send_seq();
        assert_eq!(s2.0, 0); // wrapping

        // Receive side wraparound
        s.recv_seq = MessageSequenceNumber(u64::MAX - 1);
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber(u64::MAX)),
            SeqReceiveOutcome::Accepted
        );
        assert_eq!(s.recv_seq.0, u64::MAX);
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber(0)),
            SeqReceiveOutcome::Accepted
        );
        assert_eq!(s.recv_seq.0, 0);
    }

    #[test]
    fn wraparound_gap_detection() {
        let mut s = make_session();
        s.recv_seq = MessageSequenceNumber(u64::MAX);
        // Next expected wraps to 0, but we get 2 → gap [0,2)
        let outcome = s.accept_recv_seq(MessageSequenceNumber(2));
        assert_eq!(
            outcome,
            SeqReceiveOutcome::Gap {
                missing_start: MessageSequenceNumber(0),
                missing_end: MessageSequenceNumber(2),
            }
        );
        assert_eq!(s.recv_seq.0, u64::MAX);
    }

    #[test]
    fn wraparound_duplicate_at_boundary() {
        let mut s = make_session();
        s.recv_seq = MessageSequenceNumber(u64::MAX);
        // Accept 0 (in-order after wrap)
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber(0)),
            SeqReceiveOutcome::Accepted
        );
        // Replay 0 → duplicate
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber(0)),
            SeqReceiveOutcome::Duplicate
        );
        // u64::MAX is now <= recv_seq (0), so duplicate too
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber(u64::MAX)),
            SeqReceiveOutcome::Duplicate
        );
    }

    #[test]
    fn last_sent_and_recv_introspection() {
        let mut s = make_session();
        assert_eq!(s.last_sent_seq().0, 0);
        assert_eq!(s.last_recv_seq().0, 0);

        let _ = s.next_send_seq();
        assert_eq!(s.last_sent_seq().0, 1);

        let _ = s.accept_recv_seq(MessageSequenceNumber::new(5));
        assert_eq!(s.last_recv_seq().0, 0); // gap, not advanced
        s.resolve_recv_gap(MessageSequenceNumber::new(5));
        assert_eq!(s.last_recv_seq().0, 5);
    }

    #[test]
    fn resolve_recv_gap_no_op_when_through_leq_current() {
        let mut s = make_session();
        s.recv_seq = MessageSequenceNumber(10);
        s.resolve_recv_gap(MessageSequenceNumber(5)); // through <= recv_seq
        assert_eq!(s.recv_seq.0, 10); // unchanged
        s.resolve_recv_gap(MessageSequenceNumber(10)); // through == recv_seq
        assert_eq!(s.recv_seq.0, 10); // unchanged
    }

    #[test]
    fn zero_seq_is_below_first_message() {
        let mut s = make_session();
        // recv_seq starts at 0, a message with seq 0 is rejected as duplicate
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber(0)),
            SeqReceiveOutcome::Duplicate
        );
        // First valid message is seq 1
        assert_eq!(
            s.accept_recv_seq(MessageSequenceNumber(1)),
            SeqReceiveOutcome::Accepted
        );
    }

    #[test]
    fn session_health_exposes_delivery_continuity() {
        let mut s = make_session();
        // Initial state
        assert_eq!(s.send_seq.0, 0);
        assert_eq!(s.recv_seq.0, 0);

        // After sending 3 messages and receiving 3
        let _ = s.next_send_seq();
        let _ = s.next_send_seq();
        let _ = s.next_send_seq();
        assert_eq!(s.send_seq.0, 3);

        let _ = s.accept_recv_seq(MessageSequenceNumber::new(1));
        let _ = s.accept_recv_seq(MessageSequenceNumber::new(2));
        let _ = s.accept_recv_seq(MessageSequenceNumber::new(3));
        assert_eq!(s.recv_seq.0, 3);

        // Gap on recv
        assert!(matches!(
            s.accept_recv_seq(MessageSequenceNumber::new(5)),
            SeqReceiveOutcome::Gap { .. }
        ));
        assert_eq!(s.recv_seq.0, 3); // still at 3
    }
    // -----------------------------------------------------------------------
    // Keepalive session integration tests
    // -----------------------------------------------------------------------

    /// Helper: transition a session through the full P8-01 flow to Established.
    fn establish_session(s: &mut Session) {
        let ts = hlc_now();
        s.transition(SessionState::Connecting { started_at: ts })
            .unwrap();
        s.transition(SessionState::Handshaking { started_at: ts })
            .unwrap();
        s.transition(SessionState::Bound { since: ts }).unwrap();
        s.transition(SessionState::CohortAttached { since: ts })
            .unwrap();
        s.transition(SessionState::Established { since: ts })
            .unwrap();
    }

    #[test]
    fn keepalive_session_starts_with_inactive_heartbeat() {
        let s = make_session();
        assert!(!s.heartbeat.is_active());
        assert_eq!(s.keepalive_health(), KeepaliveHealth::Alive);
    }

    #[test]
    fn keepalive_activate_sets_active() {
        let mut s = make_session();
        s.activate_keepalive();
        assert!(s.heartbeat.is_active());
    }

    #[test]
    fn keepalive_deactivate_clears_active() {
        let mut s = make_session();
        s.activate_keepalive();
        assert!(s.heartbeat.is_active());
        s.deactivate_keepalive();
        assert!(!s.heartbeat.is_active());
    }

    #[test]
    fn keepalive_check_healthy_established_no_transition() {
        let mut s = make_session();
        establish_session(&mut s);
        s.activate_keepalive();
        let (health, newly_dead) = s.check_keepalive();
        assert_eq!(health, KeepaliveHealth::Alive);
        assert!(!newly_dead);
        assert!(matches!(s.state, SessionState::Established { .. }));
    }

    #[test]
    fn keepalive_check_dead_transitions_to_degraded() {
        let mut s = make_session();
        establish_session(&mut s);
        s.activate_keepalive();

        // Manually drive the tracker to Dead
        s.heartbeat.tracker.record_ping_sent();
        s.heartbeat.tracker.consecutive_misses = s.heartbeat.tracker.config.miss_threshold;

        let (health, newly_dead) = s.check_keepalive();
        assert_eq!(health, KeepaliveHealth::Dead);
        assert!(newly_dead);
        // Session should have transitioned to Degraded
        assert!(matches!(s.state, SessionState::Degraded { .. }));
    }

    #[test]
    fn keepalive_check_no_transition_when_not_established() {
        // Dead detection should only transition Established → Degraded
        let mut s = make_session();
        // Session is Unconnected
        s.activate_keepalive();
        s.heartbeat.tracker.record_ping_sent();
        s.heartbeat.tracker.consecutive_misses = s.heartbeat.tracker.config.miss_threshold;

        let (health, newly_dead) = s.check_keepalive();
        assert_eq!(health, KeepaliveHealth::Dead);
        assert!(newly_dead);
        // Should NOT have transitioned since not Established
        assert!(matches!(s.state, SessionState::Unconnected));
    }

    #[test]
    fn keepalive_pong_recovers_degraded_to_established() {
        let mut s = make_session();
        establish_session(&mut s);
        s.activate_keepalive();

        // Drive to Degraded
        s.heartbeat.tracker.record_ping_sent();
        s.heartbeat.tracker.consecutive_misses = s.heartbeat.tracker.config.miss_threshold;
        let (_, newly_dead) = s.check_keepalive();
        assert!(newly_dead);
        assert!(matches!(s.state, SessionState::Degraded { .. }));

        // Now recover: set state back to Suspect (not Healthy yet)
        // record_keepalive_pong transitions Suspect → Healthy internally
        s.heartbeat.tracker.state = HeartbeatState::Suspect(2);
        s.record_keepalive_pong(s.heartbeat.tracker.next_seq.saturating_sub(1));
        // Should transition back to Established
        assert!(matches!(s.state, SessionState::Established { .. }));
        assert_eq!(s.keepalive_health(), KeepaliveHealth::Alive);
    }

    #[test]
    fn keepalive_ping_advances_sequence() {
        let mut s = make_session();
        establish_session(&mut s);
        s.activate_keepalive();

        let s1 = s.record_keepalive_ping();
        let s2 = s.record_keepalive_ping();
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
    }

    #[test]
    fn keepalive_two_sessions_independent() {
        let mut s_a = make_session();
        let mut s_b = make_session();
        establish_session(&mut s_a);
        establish_session(&mut s_b);
        s_a.activate_keepalive();
        s_b.activate_keepalive();

        // Drive s_a to Dead
        s_a.heartbeat.tracker.record_ping_sent();
        s_a.heartbeat.tracker.consecutive_misses = s_a.heartbeat.tracker.config.miss_threshold;
        let (health_a, newly_dead_a) = s_a.check_keepalive();
        assert_eq!(health_a, KeepaliveHealth::Dead);
        assert!(newly_dead_a);
        assert!(matches!(s_a.state, SessionState::Degraded { .. }));

        // s_b should still be healthy
        let (health_b, newly_dead_b) = s_b.check_keepalive();
        assert_eq!(health_b, KeepaliveHealth::Alive);
        assert!(!newly_dead_b);
        assert!(matches!(s_b.state, SessionState::Established { .. }));
    }

    #[test]
    fn keepalive_no_double_dead_report() {
        let mut s = make_session();
        establish_session(&mut s);
        s.activate_keepalive();

        // First dead detection
        s.heartbeat.tracker.record_ping_sent();
        s.heartbeat.tracker.consecutive_misses = s.heartbeat.tracker.config.miss_threshold;
        let (_, newly_dead1) = s.check_keepalive();
        assert!(newly_dead1);

        // Second check: still Dead but not newly dead
        let (health2, newly_dead2) = s.check_keepalive();
        assert_eq!(health2, KeepaliveHealth::Dead);
        assert!(!newly_dead2);
    }

    #[test]
    fn keepalive_inactive_always_reports_alive() {
        let mut s = make_session();
        establish_session(&mut s);
        // Keepalive is NOT activated
        let (health, newly_dead) = s.check_keepalive();
        assert_eq!(health, KeepaliveHealth::Alive);
        assert!(!newly_dead);
        assert!(matches!(s.state, SessionState::Established { .. }));
    }

    // ── Per-session compression tests ──────────────────────────────────

    #[test]
    fn compression_defaults_to_disabled() {
        let s = make_session();
        assert!(!s.has_compression());
        assert!(s.compression.is_none());
    }

    #[test]
    fn set_and_disable_compression() {
        let mut s = make_session();
        assert!(!s.has_compression());

        let cfg = CompressionConfig::new(CompressionAlgorithm::Lz4, 256);
        s.set_compression(cfg.clone());
        assert!(s.has_compression());
        assert_eq!(s.compression.as_ref().unwrap().config, cfg);

        s.disable_compression();
        assert!(!s.has_compression());
        assert!(s.compression.is_none());
    }

    #[test]
    fn compression_disabled_config() {
        let mut s = make_session();
        let cfg = CompressionConfig::disabled();
        s.set_compression(cfg);
        assert!(s.has_compression());
        assert_eq!(
            s.compression.as_ref().unwrap().config.algorithm,
            CompressionAlgorithm::None
        );
    }

    #[test]
    fn compress_outbound_disabled_passthrough() {
        let mut s = make_session();
        let payload = b"uncompressed payload data for session test";
        let result = s.compress_outbound(payload);
        assert_eq!(result, payload);
    }

    #[test]
    fn decompress_inbound_disabled_passthrough() {
        let mut s = make_session();
        let data = b"plain data passthrough";
        let result = s.decompress_inbound(data).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn round_trip_lz4_through_session() {
        let mut s = make_session();
        s.set_compression(CompressionConfig::new(CompressionAlgorithm::Lz4, 0));

        let payload = b"The quick brown fox jumps over the lazy dog. ".repeat(50);
        let compressed = s.compress_outbound(&payload);
        let decompressed = s.decompress_inbound(&compressed).unwrap();

        assert_eq!(decompressed, payload);
        assert_eq!(s.compression.as_ref().unwrap().frames_compressed, 1);
        assert_eq!(s.compression.as_ref().unwrap().frames_decompressed, 1);
    }

    #[test]
    fn round_trip_zstd_through_session() {
        let mut s = make_session();
        s.set_compression(CompressionConfig::new(CompressionAlgorithm::Zstd, 0));

        let payload = b"abcdefghijklmnopqrstuvwxyz".repeat(100);
        let compressed = s.compress_outbound(&payload);
        let decompressed = s.decompress_inbound(&compressed).unwrap();

        assert_eq!(decompressed, payload);
    }

    #[test]
    fn round_trip_none_through_session() {
        let mut s = make_session();
        s.set_compression(CompressionConfig::new(CompressionAlgorithm::None, 0));

        let payload = b"passthrough test data";
        let compressed = s.compress_outbound(payload);
        // None algorithm still produces the wire frame format
        let decompressed = s.decompress_inbound(&compressed).unwrap();
        assert_eq!(decompressed, payload);
    }

    #[test]
    fn threshold_skip_small_payload_through_session() {
        let mut s = make_session();
        s.set_compression(CompressionConfig::new(CompressionAlgorithm::Lz4, 512));

        let tiny = b"tiny";
        let frame = s.compress_outbound(tiny);
        let decompressed = s.decompress_inbound(&frame).unwrap();
        assert_eq!(decompressed, tiny);
    }

    #[test]
    fn threshold_compress_large_payload_through_session() {
        let mut s = make_session();
        s.set_compression(CompressionConfig::new(CompressionAlgorithm::Lz4, 64));

        let large = vec![b'X'; 1024];
        let frame = s.compress_outbound(&large);
        let decompressed = s.decompress_inbound(&frame).unwrap();
        assert_eq!(decompressed, large);
    }

    #[test]
    fn mixed_compressed_uncompressed_sessions() {
        let mut comp_s = make_session();
        let mut plain_s = make_session();

        comp_s.set_compression(CompressionConfig::new(CompressionAlgorithm::Lz4, 0));
        // plain_s has no compression

        let payload =
            b"mixed session test data that should be compressed in one session".repeat(10);

        let comp_frame = comp_s.compress_outbound(&payload);
        let plain_frame = plain_s.compress_outbound(&payload);

        // Plain (no compression) just copies the payload verbatim.
        assert_eq!(plain_frame, payload);
        // Compressed frame includes the wire marker, so it differs from the raw payload.
        assert_ne!(comp_frame, payload);

        // Each session round-trips its own output.
        assert_eq!(comp_s.decompress_inbound(&comp_frame).unwrap(), payload);
        assert_eq!(plain_s.decompress_inbound(&plain_frame).unwrap(), payload);

        // Cross-session auto-detection: uncompressed receiver accepts
        // compressed sender frames by detecting the wire marker.
        assert_eq!(
            plain_s.decompress_inbound(&comp_frame).unwrap(),
            payload,
            "uncompressed receiver must auto-detect compressed frames via wire marker"
        );
    }

    #[test]
    fn compression_stats_accumulate() {
        let mut s = make_session();
        s.set_compression(CompressionConfig::new(CompressionAlgorithm::Lz4, 0));

        for _ in 0..5 {
            let payload = vec![0x42u8; 512];
            let frame = s.compress_outbound(&payload);
            let _ = s.decompress_inbound(&frame).unwrap();
        }

        let state = s.compression.as_ref().unwrap();
        assert_eq!(state.frames_compressed, 5);
        assert_eq!(state.frames_decompressed, 5);
        assert!(state.total_uncompressed_bytes > 0);
        assert!(state.total_compressed_bytes > 0);
    }

    #[test]
    fn compression_round_trip_all_algorithms_varying_sizes() {
        let algorithms = [
            CompressionAlgorithm::None,
            CompressionAlgorithm::Lz4,
            CompressionAlgorithm::Zstd,
        ];
        let sizes = [0, 1, 64, 128, 256, 512, 1024, 4096];

        for &alg in &algorithms {
            for &size in &sizes {
                let mut s = make_session();
                s.set_compression(CompressionConfig::new(alg, 0));

                let payload = vec![(size % 256) as u8; size];
                let frame = s.compress_outbound(&payload);
                let decompressed = s.decompress_inbound(&frame).unwrap();

                assert_eq!(
                    decompressed, payload,
                    "round-trip failed for alg={alg}, size={size}"
                );
            }
        }
    }

    #[test]
    fn compression_empty_payload_round_trip() {
        let mut s = make_session();
        s.set_compression(CompressionConfig::new(CompressionAlgorithm::Lz4, 0));

        let frame = s.compress_outbound(b"");
        let decompressed = s.decompress_inbound(&frame).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn compression_reset_counters_preserves_config() {
        let mut s = make_session();
        let cfg = CompressionConfig::new(CompressionAlgorithm::Zstd, 128);
        s.set_compression(cfg.clone());

        let _ = s.compress_outbound(b"data one");
        let _ = s.compress_outbound(b"data two");

        {
            let state = s.compression.as_mut().unwrap();
            assert!(state.frames_compressed > 0);
            state.reset_counters();
        }

        let state = s.compression.as_ref().unwrap();
        assert_eq!(state.frames_compressed, 0);
        assert_eq!(state.frames_decompressed, 0);
        assert_eq!(state.config, cfg);
    }

    #[test]
    fn decompress_corrupted_frame_fails() {
        let mut s = make_session();
        s.set_compression(CompressionConfig::new(CompressionAlgorithm::Lz4, 0));

        let payload = b"sensitive data that must not be altered";
        let mut frame = s.compress_outbound(payload);

        // Corrupt the algorithm byte (after the 2-byte marker, at index 2).
        frame[2] ^= 0xFF;

        let result = s.decompress_inbound(&frame);
        assert!(result.is_err(), "corrupted compressed frame must fail");
    }

    #[test]
    fn compression_ratio_decreases_for_repeated_data() {
        let mut s = make_session();
        s.set_compression(CompressionConfig::new(CompressionAlgorithm::Lz4, 0));

        let payload = vec![0x41u8; 4096];
        let frame = s.compress_outbound(&payload);
        let _ = s.decompress_inbound(&frame).unwrap();

        let ratio = s.compression.as_ref().unwrap().compression_ratio();
        assert!(
            ratio < 1.0,
            "expected ratio < 1.0 for repeated data, got {ratio}"
        );
        assert!(ratio > 0.0);
    }

    // ── Cross-session compression compatibility (marker auto-detection) ─

    #[test]
    fn compressed_sender_uncompressed_receiver_auto_detect() {
        // Simulates two peers where only the sender configured compression.
        let mut sender = make_session();
        let mut receiver = make_session();

        sender.set_compression(CompressionConfig::new(CompressionAlgorithm::Lz4, 0));
        // receiver has no compression configured

        let payload = b"cross-session compression auto-detection payload".repeat(20);
        let wire = sender.compress_outbound(&payload);

        // Receiver auto-detects the marker and decompresses.
        let delivered = receiver.decompress_inbound(&wire).unwrap();
        assert_eq!(delivered, payload);
    }

    #[test]
    fn uncompressed_sender_compressed_receiver_passthrough() {
        // Sender does not compress; receiver has compression configured but
        // should still accept raw payloads (no marker = passthrough).
        let mut sender = make_session();
        let mut receiver = make_session();

        receiver.set_compression(CompressionConfig::new(CompressionAlgorithm::Lz4, 0));
        // sender has no compression

        let payload = b"raw uncompressed data from uncompressed sender";
        let wire = sender.compress_outbound(payload);
        // Uncompressed sender produces raw payload (no marker).

        let delivered = receiver.decompress_inbound(&wire).unwrap();
        assert_eq!(delivered, payload);
    }

    #[test]
    fn malformed_marker_payload_fails_closed() {
        // A payload that starts with the compression marker but contains
        // garbage (not a valid compressed frame) must return an error,
        // never silently deliver garbage to the application.
        let mut s = make_session();

        let mut fake = Vec::new();
        fake.extend_from_slice(&[0x1C, 0xCC]); // marker
        fake.extend_from_slice(b"garbage payload after marker");
        // Pad to minimum header size so it doesn't fail on FrameTooShort.
        while fake.len() < 2 + 13 {
            fake.push(0);
        }

        let result = s.decompress_inbound(&fake);
        assert!(result.is_err(), "malformed marker payload must fail closed");
    }

    #[test]
    fn marker_bytes_in_raw_payload_passthrough() {
        // A raw uncompressed payload that happens to contain 0x1C 0xCC later
        // (not at the very start) is passed through as-is.
        let mut s = make_session();
        // Compression disabled — just testing receive-side behavior.

        let payload = b"some data \x1C\xCC in the middle";
        let delivered = s.decompress_inbound(payload).unwrap();
        assert_eq!(delivered, payload);
    }

    #[test]
    fn cross_peer_compression_compatibility_round_trip() {
        // Full round-trip: compressed peer A → uncompressed peer B → compressed peer A.
        // Peer A compresses outbound; Peer B auto-detects and round-trips back.
        let mut peer_a = make_session();
        let mut peer_b = make_session();

        peer_a.set_compression(CompressionConfig::new(CompressionAlgorithm::Zstd, 0));
        // peer_b has no compression

        for size in [0, 1, 64, 256, 1024, 4096] {
            let payload = vec![(size % 256) as u8; size];
            let a_to_b = peer_a.compress_outbound(&payload);
            let b_received = peer_b.decompress_inbound(&a_to_b).unwrap();
            assert_eq!(b_received, payload, "A->B failed for size={size}");

            // B returns the payload back (uncompressed, since B has no compression).
            let b_to_a = peer_b.compress_outbound(&b_received);
            let a_received = peer_a.decompress_inbound(&b_to_a).unwrap();
            assert_eq!(a_received, b_received, "B->A failed for size={size}");
        }
    }
}
