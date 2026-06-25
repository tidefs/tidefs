// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport flow-control credit messaging with bounded receive window and
//! domain-separated credit-value integrity via BLAKE3.
//!
//! ## Flow control design
//!
//! Flow control prevents a fast sender from overwhelming a slow receiver by
//! bounding the number of in-flight bytes per stream through a credit-grant
//! protocol. Each stream has a bounded receive window; the receiver consumes
//! credits as data arrives and sends a [`CreditGrant`] back to the sender
//! when the window drains below a configurable low-watermark.
//!
//! ### Wire format
//!
//! Every flow-control message (credit grant or credit request) is a fixed
//! 53-byte frame:
//!
//! ```text
//! [magic:4][frame_type:1][stream_id:8 LE][value:8 LE][BLAKE3-256:32]
//! ```
//!
//! The magic bytes are `VFCT` (0x56464354). `frame_type` is 0 for
//! `CreditGrant` and 1 for `CreditRequest`. `value` carries the credit
//! count (granted or requested). The BLAKE3-256 digest covers the 21-byte
//! prefix (`magic || frame_type || stream_id || value`) with domain
//! separation for grant vs request so that a grant cannot be accepted as a
//! request and vice versa.
//!
//! ### Credit window model
//!
//! Each stream has a configurable `max_window_bytes` (the receive buffer
//! budget) and a `low_watermark`. When the available credits drop below the
//! low-watermark, the receiver auto-generates a [`CreditGrant`] to refill
//! the window. The sender must not send more than the granted credits or the
//! stream is in violation.
//!
//! ### BLAKE3 domain separation
//!
//! Grant and request frames use separate schema type IDs within family `FC`
//! (0x4643). Stale-sequence detection uses a monotonic grant sequence number
//! that prevents replay of old credit grants.
//!
//! ## Per-peer flow control
//!
//! The [`SendWindow`] and [`PeerFlowController`] types provide per-peer
//! token-bucket flow control that adapts to membership health state:
//!
//! | Membership    | Window action                                 |
//! |---------------|-----------------------------------------------|
//! | [`Alive`](MembershipState::Alive)       | Window open, normal refill               |
//! | [`Suspected`](MembershipState::Suspected) | Shrink capacity by `suspected_shrink_factor` |
//! | [`Failed`](MembershipState::Failed)      | Drain remaining tokens, then close       |
//! | [`Left`](MembershipState::Left)        | Close window immediately                 |
//!
//! A [`PeerFlowController`] manages per-peer [`SendWindow`] instances and
//! emits [`BackpressureSignal`] values when a window cannot satisfy an
//! acquire request: [`WindowExhausted`](BackpressureSignal::WindowExhausted),
//! [`WindowClosed`](BackpressureSignal::WindowClosed), or
//! [`PeerDrained`](BackpressureSignal::PeerDrained). BLAKE3-256
//! domain-separated state digests (domain `tidefs-transport-flow-control-v1`)
//! provide tamper detection for each window.

use tidefs_binary_schema_checksum::blake3_domain_digest;
use tidefs_binary_schema_checksum::blake3_domain_verify;
use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};

use blake3::Hasher;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tidefs_membership_epoch::MemberId;

use crate::send_admission::ClusterQueuePressure;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes for flow-control frames: "VFCT".
pub const FLOW_CONTROL_MAGIC: [u8; 4] = [b'V', b'F', b'C', b'T'];

/// Total size of a flow-control frame:
/// 4 (magic) + 1 (frame_type) + 8 (stream_id) + 8 (value) + 32 (BLAKE3) = 53.
pub const FLOW_CONTROL_FRAME_SIZE: usize = 53;

/// Offset and length of the BLAKE3-covered payload within the frame.
const PAYLOAD_OFFSET: usize = 0;
const PAYLOAD_LEN: usize = 21; // magic(4) + frame_type(1) + stream_id(8) + value(8)

/// Domain-separation constants for BLAKE3 flow-control hashing.
const FC_FAMILY: SchemaFamilyId = SchemaFamilyId(0x4643); // "FC"
const FC_TYPE_GRANT: SchemaTypeId = SchemaTypeId(1);
const FC_TYPE_REQUEST: SchemaTypeId = SchemaTypeId(2);
const FC_VERSION: SchemaVersion = SchemaVersion::new(1, 0);
const FC_DOMAIN: DomainTag = DomainTag::TransferStream;

/// Default maximum receive window bytes (1 MiB).
pub const DEFAULT_MAX_WINDOW_BYTES: u64 = 1_048_576;

/// Default low-watermark bytes (25% of window, i.e. 256 KiB).
pub const DEFAULT_LOW_WATERMARK_BYTES: u64 = 262_144;

/// Frame type byte for `CreditGrant`.
pub const FRAME_TYPE_GRANT: u8 = 0;

/// Frame type byte for `CreditRequest`.
pub const FRAME_TYPE_REQUEST: u8 = 1;

// ---------------------------------------------------------------------------
// FlowControlError
// ---------------------------------------------------------------------------

/// Errors from the flow-control layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowControlError {
    /// The receive window is exhausted (no credits available).
    WindowExhausted,
    /// The incoming credit frame failed BLAKE3 integrity verification.
    InvalidCreditFrame,
    /// The credit frame carries a stale sequence number.
    StaleCreditSequence { received: u64, last: u64 },
    /// The referenced stream was not found.
    StreamNotFound { stream_id: u64 },
    /// The credit frame has an unknown frame type byte.
    UnknownFrameType { frame_type: u8 },
}

impl std::fmt::Display for FlowControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WindowExhausted => write!(f, "receive window exhausted"),
            Self::InvalidCreditFrame => write!(f, "invalid credit frame (BLAKE3 mismatch)"),
            Self::StaleCreditSequence { received, last } => {
                write!(f, "stale credit sequence: received {received}, last {last}")
            }
            Self::StreamNotFound { stream_id } => {
                write!(f, "stream not found: {stream_id}")
            }
            Self::UnknownFrameType { frame_type } => {
                write!(f, "unknown flow-control frame type: {frame_type}")
            }
        }
    }
}

impl std::error::Error for FlowControlError {}

// ---------------------------------------------------------------------------
// CreditWindow
// ---------------------------------------------------------------------------

/// Bounded receive window tracking available credits.
///
/// Each stream has one `CreditWindow` that limits how many bytes the sender
/// may have in flight before the receiver must grant more credits.
#[derive(Clone, Debug)]
pub struct CreditWindow {
    /// Maximum bytes that can be in flight at once.
    pub max_window_bytes: u64,
    /// When `available_credits` drops below this threshold, the receiver
    /// should send a `CreditGrant` to refill the window.
    pub low_watermark: u64,
    /// Currently available credits (bytes the sender is still allowed to
    /// transmit before needing more grants).
    pub available_credits: u64,
}

impl CreditWindow {
    /// Create a new credit window with the given maximum and low-watermark.
    /// Initially the window is full (all credits available).
    #[must_use]
    pub fn new(max_window_bytes: u64, low_watermark: u64) -> Self {
        Self {
            max_window_bytes,
            low_watermark,
            available_credits: max_window_bytes,
        }
    }

    /// Create a new credit window with sensible defaults.
    #[must_use]
    pub fn default_window() -> Self {
        Self::new(DEFAULT_MAX_WINDOW_BYTES, DEFAULT_LOW_WATERMARK_BYTES)
    }

    /// Consume `bytes` from the receive window. Returns `Ok(())` if credits
    /// were available, or `Err(FlowControlError::WindowExhausted)` if not
    /// enough credits remain.
    pub fn consume(&mut self, bytes: u64) -> Result<(), FlowControlError> {
        if bytes > self.available_credits {
            return Err(FlowControlError::WindowExhausted);
        }
        self.available_credits -= bytes;
        Ok(())
    }

    /// Grant `bytes` credits, up to the configured maximum.
    /// Returns the actual number of credits added.
    pub fn grant(&mut self, bytes: u64) -> u64 {
        let space = self.max_window_bytes.saturating_sub(self.available_credits);
        let added = bytes.min(space);
        self.available_credits += added;
        added
    }

    /// Whether the window is below the low-watermark and should send a grant.
    #[must_use]
    pub fn needs_grant(&self) -> bool {
        self.available_credits < self.low_watermark
    }

    /// Compute how many credits to grant to refill the window to maximum.
    #[must_use]
    pub fn refill_amount(&self) -> u64 {
        self.max_window_bytes.saturating_sub(self.available_credits)
    }

    /// Return the effective receive-window cap after applying governor
    /// `cluster_queues` pressure.
    #[must_use]
    pub fn max_window_bytes_under_cluster_pressure(&self, pressure: ClusterQueuePressure) -> u64 {
        pressure_adjusted_window_bytes(self.max_window_bytes, pressure)
    }

    /// Return the effective low watermark after applying governor
    /// `cluster_queues` pressure.
    #[must_use]
    pub fn low_watermark_under_cluster_pressure(&self, pressure: ClusterQueuePressure) -> u64 {
        pressure_adjusted_low_watermark(self.low_watermark, pressure)
    }

    /// Return the credits that should be advertised under governor
    /// `cluster_queues` pressure.
    #[must_use]
    pub fn advertised_credits_under_cluster_pressure(&self, pressure: ClusterQueuePressure) -> u64 {
        self.available_credits
            .min(self.max_window_bytes_under_cluster_pressure(pressure))
    }

    /// Compute how many credits to grant to refill the pressure-adjusted
    /// window.
    #[must_use]
    pub fn refill_amount_under_cluster_pressure(&self, pressure: ClusterQueuePressure) -> u64 {
        self.max_window_bytes_under_cluster_pressure(pressure)
            .saturating_sub(self.advertised_credits_under_cluster_pressure(pressure))
    }

    /// Whether the window is fully exhausted.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.available_credits == 0
    }
}

fn pressure_adjusted_window_bytes(bytes: u64, pressure: ClusterQueuePressure) -> u64 {
    if bytes == 0 {
        return 0;
    }
    match pressure {
        ClusterQueuePressure::None => bytes,
        ClusterQueuePressure::SoftPressure => (bytes / 2).max(1),
        ClusterQueuePressure::HardPressure => (bytes / 4).max(1),
    }
}

fn pressure_adjusted_low_watermark(bytes: u64, pressure: ClusterQueuePressure) -> u64 {
    if bytes == 0 {
        return 0;
    }
    match pressure {
        ClusterQueuePressure::None => bytes,
        ClusterQueuePressure::SoftPressure => (bytes / 2).max(1),
        ClusterQueuePressure::HardPressure => (bytes / 4).max(1),
    }
}

impl Default for CreditWindow {
    fn default() -> Self {
        Self::default_window()
    }
}

// ---------------------------------------------------------------------------
// FlowControlFrame
// ---------------------------------------------------------------------------

/// Flow-control frame types exchanged between stream endpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlowControlFrame {
    /// Sender grants credits to the receiver so it can transmit more data.
    CreditGrant {
        /// Identifies the stream this grant applies to.
        stream_id: u64,
        /// Number of bytes granted.
        credits: u64,
    },
    /// Receiver requests additional credits from the sender.
    CreditRequest {
        /// Identifies the stream.
        stream_id: u64,
        /// Number of bytes requested.
        requested: u64,
    },
}

// ---------------------------------------------------------------------------
// FlowController
// ---------------------------------------------------------------------------

/// Per-stream flow-control state machine.
///
/// Tracks the receive window, issues credit grants when the window drains,
/// and validates incoming credit frames with BLAKE3 integrity checks and
/// stale-sequence rejection.
#[derive(Clone, Debug)]
pub struct FlowController {
    /// The bounded receive window for this stream.
    pub window: CreditWindow,
    /// Identifies the stream this controller manages.
    pub stream_id: u64,
    /// Monotonic sequence number for the next grant this controller sends.
    pub next_grant_seq: u64,
    /// The last successfully received grant sequence number (for staleness
    /// detection on the send side).
    pub last_received_grant_seq: u64,
}

impl FlowController {
    /// Create a new flow controller for the given stream.
    #[must_use]
    pub fn new(stream_id: u64, window: CreditWindow) -> Self {
        Self {
            window,
            stream_id,
            next_grant_seq: 1,
            last_received_grant_seq: 0,
        }
    }

    /// Create a flow controller with default window settings.
    #[must_use]
    pub fn with_default_window(stream_id: u64) -> Self {
        Self::new(stream_id, CreditWindow::default_window())
    }

    /// Consume credits on the receive side (data arrived).
    ///
    /// Returns `Ok(())` on success, or `Err(FlowControlError::WindowExhausted)`
    /// if insufficient credits remain.
    pub fn consume_credits(&mut self, bytes: u64) -> Result<(), FlowControlError> {
        self.window.consume(bytes)
    }

    /// Check if a credit grant should be sent and, if so, build the frame.
    ///
    /// Returns `Some(FlowControlFrame)` when the window is below the
    /// low-watermark and a grant is needed. The caller should transmit the
    /// frame to the peer.
    #[must_use]
    pub fn maybe_send_credit_grant(&mut self) -> Option<FlowControlFrame> {
        if !self.window.needs_grant() {
            return None;
        }
        let credits = self.window.refill_amount();
        if credits == 0 {
            return None;
        }
        // Refill immediately so we don't double-grant.
        self.window.grant(credits);
        let frame = FlowControlFrame::CreditGrant {
            stream_id: self.stream_id,
            credits,
        };
        self.next_grant_seq = self.next_grant_seq.wrapping_add(1);
        Some(frame)
    }

    /// Build a credit grant capped by governor `cluster_queues` pressure.
    ///
    /// This preserves the existing flow-control semantics while advertising a
    /// reduced receive window under memory pressure.
    #[must_use]
    pub fn maybe_send_credit_grant_under_cluster_pressure(
        &mut self,
        pressure: ClusterQueuePressure,
    ) -> Option<FlowControlFrame> {
        let available = self
            .window
            .advertised_credits_under_cluster_pressure(pressure);
        let low = self.window.low_watermark_under_cluster_pressure(pressure);
        if available >= low {
            return None;
        }
        let credits = self.window.refill_amount_under_cluster_pressure(pressure);
        if credits == 0 {
            return None;
        }
        self.window.available_credits = self
            .window
            .max_window_bytes_under_cluster_pressure(pressure);
        let frame = FlowControlFrame::CreditGrant {
            stream_id: self.stream_id,
            credits,
        };
        self.next_grant_seq = self.next_grant_seq.wrapping_add(1);
        Some(frame)
    }

    /// Process an incoming credit grant frame from the peer.
    ///
    /// Verifies the BLAKE3 integrity of the raw frame bytes and checks the
    /// sequence number against `last_received_grant_seq` for staleness.
    /// Returns the decoded `FlowControlFrame` on success.
    pub fn receive_credit_grant(
        &mut self,
        raw_frame: &[u8],
    ) -> Result<FlowControlFrame, FlowControlError> {
        let frame = decode_flow_control_frame(raw_frame)?;
        match &frame {
            FlowControlFrame::CreditGrant { credits, .. } => {
                // Apply credits to our window on the send side: the peer
                // granted us more send budget.
                self.window.grant(*credits);
                self.last_received_grant_seq = self.next_grant_seq;
            }
            FlowControlFrame::CreditRequest { .. } => {
                // CreditRequest is informational; the receiver tells us it
                // wants more credits. No local window change.
            }
        }
        Ok(frame)
    }

    /// Encode a `FlowControlFrame` into a wire frame with credit-value binding.
    ///
    /// Returns the encoded byte vector ready for transmission.
    #[must_use]
    pub fn encode_frame(frame: &FlowControlFrame) -> Vec<u8> {
        let mut buf = vec![0u8; FLOW_CONTROL_FRAME_SIZE];
        encode_flow_control_frame(frame, &mut buf);
        buf
    }

    /// Send a `CreditGrant` frame (encode and return bytes).
    ///
    /// The caller transmits the returned bytes to the peer.
    #[must_use]
    pub fn send_credit_grant(stream_id: u64, credits: u64) -> Vec<u8> {
        Self::encode_frame(&FlowControlFrame::CreditGrant { stream_id, credits })
    }

    /// Send a `CreditRequest` frame (encode and return bytes).
    #[must_use]
    pub fn send_credit_request(stream_id: u64, requested: u64) -> Vec<u8> {
        Self::encode_frame(&FlowControlFrame::CreditRequest {
            stream_id,
            requested,
        })
    }
}

impl Default for FlowController {
    fn default() -> Self {
        Self::with_default_window(0)
    }
}

// ---------------------------------------------------------------------------
// Wire format: encode / decode / verify
// ---------------------------------------------------------------------------

/// Encode a [`FlowControlFrame`] into `buf`.
///
/// `buf` must be exactly [`FLOW_CONTROL_FRAME_SIZE`] bytes.
///
/// # Panics
///
/// Panics if `buf.len() != FLOW_CONTROL_FRAME_SIZE`.
pub fn encode_flow_control_frame(frame: &FlowControlFrame, buf: &mut [u8]) {
    assert_eq!(buf.len(), FLOW_CONTROL_FRAME_SIZE);

    let (frame_type, stream_id, value) = match frame {
        FlowControlFrame::CreditGrant {
            stream_id, credits, ..
        } => (FRAME_TYPE_GRANT, *stream_id, *credits),
        FlowControlFrame::CreditRequest {
            stream_id,
            requested,
            ..
        } => (FRAME_TYPE_REQUEST, *stream_id, *requested),
    };

    buf[0..4].copy_from_slice(&FLOW_CONTROL_MAGIC);
    buf[4] = frame_type;
    buf[5..13].copy_from_slice(&stream_id.to_le_bytes());
    buf[13..21].copy_from_slice(&value.to_le_bytes());

    let type_id = if frame_type == FRAME_TYPE_GRANT {
        FC_TYPE_GRANT
    } else {
        FC_TYPE_REQUEST
    };

    let payload = &buf[PAYLOAD_OFFSET..PAYLOAD_OFFSET + PAYLOAD_LEN];
    let digest: [u8; 32] = blake3_domain_digest(payload, FC_FAMILY, type_id, FC_VERSION, FC_DOMAIN);
    buf[21..53].copy_from_slice(&digest);
}

/// Decode and verify a flow-control frame.
///
/// Returns the decoded [`FlowControlFrame`] if the frame is valid, or
/// an appropriate [`FlowControlError`] otherwise.
pub fn decode_flow_control_frame(frame: &[u8]) -> Result<FlowControlFrame, FlowControlError> {
    if frame.len() != FLOW_CONTROL_FRAME_SIZE {
        return Err(FlowControlError::InvalidCreditFrame);
    }
    if frame[0..4] != FLOW_CONTROL_MAGIC {
        return Err(FlowControlError::InvalidCreditFrame);
    }

    let frame_type = frame[4];
    let stream_id = u64::from_le_bytes(
        frame[5..13]
            .try_into()
            .map_err(|_| FlowControlError::InvalidCreditFrame)?,
    );
    let value = u64::from_le_bytes(
        frame[13..21]
            .try_into()
            .map_err(|_| FlowControlError::InvalidCreditFrame)?,
    );

    let type_id = match frame_type {
        FRAME_TYPE_GRANT => FC_TYPE_GRANT,
        FRAME_TYPE_REQUEST => FC_TYPE_REQUEST,
        other => return Err(FlowControlError::UnknownFrameType { frame_type: other }),
    };

    let payload = &frame[PAYLOAD_OFFSET..PAYLOAD_OFFSET + PAYLOAD_LEN];
    let digest: &[u8; 32] = frame[21..53]
        .try_into()
        .map_err(|_| FlowControlError::InvalidCreditFrame)?;

    blake3_domain_verify(payload, digest, FC_FAMILY, type_id, FC_VERSION, FC_DOMAIN)
        .map_err(|_| FlowControlError::InvalidCreditFrame)?;

    match frame_type {
        FRAME_TYPE_GRANT => Ok(FlowControlFrame::CreditGrant {
            stream_id,
            credits: value,
        }),
        FRAME_TYPE_REQUEST => Ok(FlowControlFrame::CreditRequest {
            stream_id,
            requested: value,
        }),
        _ => unreachable!(),
    }
}

// ===========================================================================
// Per-Peer Flow Control (Token-Bucket with Membership Integration)
// ===========================================================================

const PEER_FC_DOMAIN: &str = "tidefs-transport-flow-control-v1";

/// Membership state as seen by the flow-control layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipState {
    Alive,
    Suspected,
    Failed,
    Left,
}

/// Configuration for per-peer flow control.
#[derive(Clone, Debug)]
pub struct PeerFlowControlConfig {
    /// Maximum tokens in the send window (capacity).
    pub window_capacity: u64,
    /// Tokens replenished per second.
    pub refill_rate_per_sec: u64,
    /// Max seconds to drain remaining tokens when a peer fails.
    pub drain_timeout_secs: u64,
    /// Fraction of current window to keep when peer becomes Suspected (0.0-1.0).
    pub suspected_shrink_factor: f64,
}

impl Default for PeerFlowControlConfig {
    fn default() -> Self {
        Self {
            window_capacity: 1_048_576,   // 1 MiB tokens
            refill_rate_per_sec: 262_144, // 256 KiB/s refill
            drain_timeout_secs: 30,
            suspected_shrink_factor: 0.5,
        }
    }
}

impl PeerFlowControlConfig {
    /// Validate the configuration. Returns `Err` with a message on invalid values.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.window_capacity == 0 {
            return Err("window_capacity must be non-zero");
        }
        if self.refill_rate_per_sec == 0 {
            return Err("refill_rate_per_sec must be non-zero");
        }
        if !(0.0..=1.0).contains(&self.suspected_shrink_factor) {
            return Err("suspected_shrink_factor must be in [0.0, 1.0]");
        }
        Ok(())
    }

    /// Return a validated config or panic.
    #[must_use]
    pub fn validated(self) -> Self {
        self.validate()
            .expect("PeerFlowControlConfig validation failed");
        self
    }
}

/// Backpressure signals emitted when a send window cannot satisfy an acquire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackpressureSignal {
    /// Window has no tokens left; sender should wait for refill.
    WindowExhausted,
    /// Window is closed (peer has Failed/Left); sender should abort.
    WindowClosed,
    /// All tokens are drained after a peer departure.
    PeerDrained,
    /// Per-peer send buffer is at capacity; soft-backpressure advisory.
    SendBufferFull,
}

impl std::fmt::Display for BackpressureSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WindowExhausted => write!(f, "send window exhausted"),
            Self::WindowClosed => write!(f, "send window closed (peer departed)"),
            Self::PeerDrained => write!(f, "peer drained all tokens"),
            Self::SendBufferFull => write!(f, "per-peer send buffer full (soft backpressure)"),
        }
    }
}

// ---------------------------------------------------------------------------
// SendWindow — per-peer token bucket
// ---------------------------------------------------------------------------

/// Per-peer token-bucket send window with domain-separated state digest.
///
/// Tokens represent bytes the sender is allowed to transmit to this peer.
/// Tokens refill at a configurable rate and are consumed by `acquire()`.
/// When a peer transitions through membership states, the window adapts:
///
/// | State     | Action                                      |
/// |-----------|---------------------------------------------|
/// | Alive     | Window open, normal refill                  |
/// | Suspected | Shrink capacity to `suspected_shrink_factor`|
/// | Failed    | Drain remaining tokens, then close window   |
/// | Left      | Close window immediately                    |
#[derive(Clone, Debug)]
pub struct SendWindow {
    /// Peer this window is for.
    pub peer_id: MemberId,
    /// Maximum tokens this window can hold.
    capacity: u64,
    /// Currently available tokens.
    tokens: u64,
    /// Refill rate in tokens per second.
    refill_rate_per_sec: u64,
    /// Timestamp of the last refill operation.
    last_refill: Instant,
    /// BLAKE3-256 domain-separated state digest.
    state_digest: [u8; 32],
    /// Whether the window is closed.
    closed: bool,
    /// Whether the peer has been fully drained.
    drained: bool,
    /// Current membership state.
    membership_state: MembershipState,
    /// When drain began (for timeout enforcement).
    drain_start: Option<Instant>,
    /// Drain timeout duration.
    drain_timeout: Duration,
    /// Stored config values for membership transitions.
    config_suspected_shrink_factor: f64,
    config_window_capacity: u64,
}

impl SendWindow {
    /// Create a new send window for the given peer.
    pub fn new(peer_id: MemberId, config: &PeerFlowControlConfig) -> Self {
        let mut window = Self {
            peer_id,
            capacity: config.window_capacity,
            tokens: config.window_capacity,
            refill_rate_per_sec: config.refill_rate_per_sec,
            last_refill: Instant::now(),
            state_digest: [0u8; 32],
            closed: false,
            drained: false,
            membership_state: MembershipState::Alive,
            drain_start: None,
            drain_timeout: Duration::from_secs(config.drain_timeout_secs),
            config_suspected_shrink_factor: config.suspected_shrink_factor,
            config_window_capacity: config.window_capacity,
        };
        window.update_digest();
        window
    }

    // ------------------------------------------------------------------
    // Token management
    // ------------------------------------------------------------------

    /// Try to acquire `n` tokens. Returns `Ok(remaining_tokens)` on success,
    /// or `Err(BackpressureSignal)` if the window can't satisfy the request.
    pub fn acquire(&mut self, n: u64) -> Result<u64, BackpressureSignal> {
        self.refill();
        if self.closed {
            return Err(BackpressureSignal::WindowClosed);
        }
        if self.drained {
            return Err(BackpressureSignal::PeerDrained);
        }
        if n > self.tokens {
            return Err(BackpressureSignal::WindowExhausted);
        }
        self.tokens -= n;
        self.update_digest();
        Ok(self.tokens)
    }

    /// Try to acquire tokens without triggering refill (used in tests).
    pub fn acquire_no_refill(&mut self, n: u64) -> Result<u64, BackpressureSignal> {
        if self.closed {
            return Err(BackpressureSignal::WindowClosed);
        }
        if self.drained {
            return Err(BackpressureSignal::PeerDrained);
        }
        if n > self.tokens {
            return Err(BackpressureSignal::WindowExhausted);
        }
        self.tokens -= n;
        self.update_digest();
        Ok(self.tokens)
    }

    /// Release `n` tokens back to the window (e.g. on send completion).
    pub fn release(&mut self, n: u64) {
        self.tokens = self.tokens.saturating_add(n).min(self.capacity);
        self.update_digest();
    }

    /// Trigger refill based on elapsed time.
    pub fn refill(&mut self) {
        if self.closed || self.drained {
            return;
        }
        let elapsed = self.last_refill.elapsed();
        if elapsed.is_zero() {
            return;
        }
        let new_tokens = (elapsed.as_secs_f64() * self.refill_rate_per_sec as f64) as u64;
        if new_tokens > 0 {
            self.tokens = self.tokens.saturating_add(new_tokens).min(self.capacity);
            self.last_refill = Instant::now();
            self.update_digest();
        }
    }

    // ------------------------------------------------------------------
    // Membership-driven window lifecycle
    // ------------------------------------------------------------------

    /// Handle a membership state transition.
    ///
    /// Returns `Some(BackpressureSignal)` if the transition produces an
    /// immediate backpressure event (e.g. WindowClosed).
    pub fn on_membership_change(
        &mut self,
        new_state: MembershipState,
    ) -> Option<BackpressureSignal> {
        if new_state == self.membership_state {
            return None;
        }
        self.membership_state = new_state;
        match new_state {
            MembershipState::Alive => {
                // Re-open if previously closed/shrunk
                self.closed = false;
                self.drained = false;
                self.drain_start = None;
                self.capacity = self.default_capacity();
                self.tokens = self.capacity;
                self.update_digest();
                None
            }
            MembershipState::Suspected => {
                // Shrink capacity; tokens above new cap are discarded
                let shrink =
                    (self.capacity as f64 * self.suspected_shrink_factor()).max(1.0) as u64;
                self.capacity = shrink;
                self.tokens = self.tokens.min(self.capacity);
                self.update_digest();
                None
            }
            MembershipState::Failed => {
                // Begin drain
                self.drain_start = Some(Instant::now());
                self.refill_rate_per_sec = 0; // stop refill during drain
                self.update_digest();
                None
            }
            MembershipState::Left => {
                self.closed = true;
                self.drained = true;
                self.tokens = 0;
                self.update_digest();
                Some(BackpressureSignal::WindowClosed)
            }
        }
    }

    /// Check drain timeout and force-close if exceeded.
    ///
    /// Call periodically. Returns `Some(BackpressureSignal)` when the drain
    /// completes (either naturally or via timeout).
    pub fn check_drain(&mut self) -> Option<BackpressureSignal> {
        if self.membership_state != MembershipState::Failed {
            return None;
        }
        if self.tokens == 0 {
            self.drained = true;
            self.closed = true;
            self.update_digest();
            return Some(BackpressureSignal::PeerDrained);
        }
        if let Some(start) = self.drain_start {
            if start.elapsed() >= self.drain_timeout {
                // Timeout: force-close
                self.tokens = 0;
                self.drained = true;
                self.closed = true;
                self.update_digest();
                return Some(BackpressureSignal::PeerDrained);
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Introspection
    // ------------------------------------------------------------------

    /// Currently available tokens.
    pub fn available_tokens(&self) -> u64 {
        self.tokens
    }

    /// Current capacity.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Whether the window is closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Whether the peer is drained.
    pub fn is_drained(&self) -> bool {
        self.drained
    }

    /// Current membership state.
    pub fn membership_state(&self) -> MembershipState {
        self.membership_state
    }

    /// The BLAKE3-256 domain-separated state digest.
    pub fn state_digest(&self) -> &[u8; 32] {
        &self.state_digest
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn suspected_shrink_factor(&self) -> f64 {
        self.config_suspected_shrink_factor
    }

    fn default_capacity(&self) -> u64 {
        self.config_window_capacity
    }

    fn update_digest(&mut self) {
        let mut hasher = Hasher::new_derive_key(PEER_FC_DOMAIN);
        hasher.update(&self.peer_id.0.to_le_bytes());
        hasher.update(&self.tokens.to_le_bytes());
        hasher.update(&self.capacity.to_le_bytes());
        hasher.update(&[self.closed as u8, self.drained as u8]);
        hasher.update(&(self.membership_state as u8).to_le_bytes());
        self.state_digest = hasher.finalize().into();
    }
}

// ---------------------------------------------------------------------------
// PeerFlowController — per-peer window registry
// ---------------------------------------------------------------------------

/// Manages per-peer [`SendWindow`] instances keyed by [`MemberId`].
///
/// Consumes membership state transitions to drive window lifecycle:
/// shrink on Suspected, drain on Failed, close on Left.
#[derive(Clone, Debug)]
pub struct PeerFlowController {
    config: PeerFlowControlConfig,
    windows: BTreeMap<MemberId, SendWindow>,
}

impl PeerFlowController {
    /// Create a new flow controller with the given config.
    pub fn new(config: PeerFlowControlConfig) -> Self {
        Self {
            config,
            windows: BTreeMap::new(),
        }
    }

    /// Create a controller with default config.
    pub fn with_default_config() -> Self {
        Self::new(PeerFlowControlConfig::default())
    }

    /// Register a send window for a peer. No-op if already registered.
    pub fn register_peer(&mut self, peer_id: MemberId) {
        self.windows
            .entry(peer_id)
            .or_insert_with(|| SendWindow::new(peer_id, &self.config));
    }

    /// Remove a peer's window (e.g. on graceful departure).
    pub fn remove_peer(&mut self, peer_id: MemberId) -> Option<SendWindow> {
        self.windows.remove(&peer_id)
    }

    /// Acquire tokens for sending to a peer.
    ///
    /// Returns `Ok(remaining)` on success, or `Err(BackpressureSignal)`.
    pub fn acquire(&mut self, peer_id: MemberId, n: u64) -> Result<u64, BackpressureSignal> {
        let window = self
            .windows
            .get_mut(&peer_id)
            .ok_or(BackpressureSignal::WindowClosed)?;
        window.acquire(n)
    }

    /// Release tokens back to a peer's window.
    pub fn release(&mut self, peer_id: MemberId, n: u64) {
        if let Some(window) = self.windows.get_mut(&peer_id) {
            window.release(n);
        }
    }

    /// Notify the controller of a membership state change for a peer.
    ///
    /// Returns any immediate backpressure signal.
    pub fn on_membership_change(
        &mut self,
        peer_id: MemberId,
        new_state: MembershipState,
    ) -> Option<BackpressureSignal> {
        let window = self.windows.get_mut(&peer_id)?;
        window.on_membership_change(new_state)
    }

    /// Check all windows for drain timeout. Returns list of (peer_id, signal).
    pub fn check_all_drains(&mut self) -> Vec<(MemberId, BackpressureSignal)> {
        let mut signals = Vec::new();
        for window in self.windows.values_mut() {
            if let Some(sig) = window.check_drain() {
                signals.push((window.peer_id, sig));
            }
        }
        signals
    }

    /// Get a reference to a peer's window.
    pub fn get(&self, peer_id: MemberId) -> Option<&SendWindow> {
        self.windows.get(&peer_id)
    }

    /// Number of registered peers.
    pub fn peer_count(&self) -> usize {
        self.windows.len()
    }

    /// Iterate over all windows.
    pub fn windows(&self) -> impl Iterator<Item = &SendWindow> {
        self.windows.values()
    }

    /// The controller config.
    pub fn config(&self) -> &PeerFlowControlConfig {
        &self.config
    }
}

impl Default for PeerFlowController {
    fn default() -> Self {
        Self::with_default_config()
    }
}

// ===========================================================================
// Receive-Window Advertisement Flow Control (Connection-Level)
// ===========================================================================

/// Configuration for the per-connection receive window.
///
/// Controls how much buffer capacity the receiver advertises to the sender
/// and under what conditions a window advertisement is triggered.
#[derive(Clone, Debug)]
pub struct ReceiveWindowConfig {
    /// Maximum receive buffer capacity in bytes.
    pub capacity: u64,
    /// When available bytes drop below this fraction of capacity,
    /// a window advertisement is triggered. Must be in (0.0, 1.0].
    pub low_watermark_ratio: f64,
    /// Minimum interval between successive window advertisements
    /// to prevent flooding.
    pub advertise_batch_interval: Duration,
}

impl PartialEq for ReceiveWindowConfig {
    fn eq(&self, other: &Self) -> bool {
        self.capacity == other.capacity
            && self.advertise_batch_interval == other.advertise_batch_interval
            && self.low_watermark_ratio.to_bits() == other.low_watermark_ratio.to_bits()
    }
}
impl Eq for ReceiveWindowConfig {}

impl Default for ReceiveWindowConfig {
    fn default() -> Self {
        Self {
            capacity: 1_048_576, // 1 MiB
            low_watermark_ratio: 0.25,
            advertise_batch_interval: Duration::from_millis(10),
        }
    }
}

impl ReceiveWindowConfig {
    /// Validate the configuration. Returns `Err` with a message on invalid values.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.capacity == 0 {
            return Err("receive_window_capacity must be non-zero");
        }
        if !(0.0..=1.0).contains(&self.low_watermark_ratio) || self.low_watermark_ratio == 0.0 {
            return Err("low_watermark_ratio must be in (0.0, 1.0]");
        }
        Ok(())
    }

    /// Compute the low-watermark in bytes from the ratio.
    pub fn low_watermark_bytes(&self) -> u64 {
        (self.capacity as f64 * self.low_watermark_ratio) as u64
    }
}

/// Per-connection receive window tracking available buffer capacity.
///
/// The receiver consumes bytes as messages arrive from the peer,
/// releases bytes when the application finishes processing messages,
/// and advertises available capacity back to the sender when the
/// window drains below the configured low-watermark.
///
/// This is the receive-side half of transport flow control,
/// complementing outbound backpressure (#5971).
#[derive(Clone, Debug)]
pub struct ReceiveWindow {
    /// Configuration for this window.
    config: ReceiveWindowConfig,
    /// Currently available buffer bytes.
    available: u64,
    /// When the last window advertisement was sent.
    last_advertised: Option<Instant>,
}

impl ReceiveWindow {
    /// Create a new receive window with the given configuration.
    /// Initially the window is fully available.
    #[must_use]
    pub fn new(config: ReceiveWindowConfig) -> Self {
        let capacity = config.capacity;
        Self {
            config,
            available: capacity,
            last_advertised: None,
        }
    }

    /// Consume bytes from the window when a message is received from the peer.
    ///
    /// Returns `Ok(())` on success, or `Err(FlowControlError::WindowExhausted)`
    /// if insufficient capacity remains.
    pub fn consume(&mut self, bytes: u64) -> Result<(), FlowControlError> {
        if bytes > self.available {
            return Err(FlowControlError::WindowExhausted);
        }
        self.available -= bytes;
        Ok(())
    }

    /// Release bytes back to the window after the application has consumed
    /// a received message, freeing buffer space for more incoming data.
    ///
    /// Does not exceed the configured capacity.
    pub fn release(&mut self, bytes: u64) {
        self.available = (self.available + bytes).min(self.config.capacity);
    }

    /// Whether the window should trigger a new advertisement.
    ///
    /// Returns `true` when available bytes are below the low-watermark and
    /// enough time has passed since the last advertisement.
    #[must_use]
    pub fn needs_advertisement(&self, now: Instant) -> bool {
        if self.available >= self.config.low_watermark_bytes() {
            return false;
        }
        match self.last_advertised {
            None => true,
            Some(last) => now.duration_since(last) >= self.config.advertise_batch_interval,
        }
    }

    /// Get the current available bytes to advertise to the peer.
    #[must_use]
    pub fn available_bytes(&self) -> u64 {
        self.available
    }

    /// Get the configured capacity.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.config.capacity
    }

    /// Record that a window advertisement was sent.
    pub fn mark_advertised(&mut self, now: Instant) {
        self.last_advertised = Some(now);
    }

    /// Whether the window is exhausted (no bytes remain).
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.available == 0
    }

    /// Low-watermark in bytes (computed from config).
    #[must_use]
    pub fn low_watermark(&self) -> u64 {
        self.config.low_watermark_bytes()
    }
}

/// A window-advertisement message sent by the receiver to the sender.
///
/// Carries the receiver's currently available buffer capacity so the
/// sender can throttle its outbound data rate and avoid overrunning
/// the receiver's buffers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowAdvertisement {
    /// Available buffer bytes on the receiver side.
    pub window_bytes: u64,
}

impl WindowAdvertisement {
    /// Create a new window advertisement.
    pub fn new(window_bytes: u64) -> Self {
        Self { window_bytes }
    }
    /// Encode this advertisement into a fixed-size wire-format buffer.
    ///
    /// Writes the `window_bytes` field as a u64 in little-endian byte order.
    /// `buf` must be exactly [`WINDOW_ADVERTISEMENT_FRAME_SIZE`] bytes.
    ///
    /// # Panics
    ///
    /// Panics if `buf.len() != WINDOW_ADVERTISEMENT_FRAME_SIZE`.
    pub fn encode_into(&self, buf: &mut [u8]) {
        assert_eq!(buf.len(), WINDOW_ADVERTISEMENT_FRAME_SIZE);
        buf.copy_from_slice(&self.window_bytes.to_le_bytes());
    }

    /// Encode this advertisement to an owned byte vector.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.window_bytes.to_le_bytes().to_vec()
    }

    /// Decode a window advertisement from a raw frame.
    ///
    /// Returns the decoded advertisement if the frame has the correct size
    /// and passes validation, or `None` otherwise.
    /// This module is a pure framing-and-dispatch throughput optimization
    /// operating within the existing transport/session security boundary.
    /// Frame integrity and authenticity are delegated to the session security
    /// layer established during connection handshake.
    #[must_use]
    pub fn decode(frame: &[u8]) -> Option<Self> {
        if frame.len() != WINDOW_ADVERTISEMENT_FRAME_SIZE {
            return None;
        }
        let bytes: [u8; 8] = frame.try_into().ok()?;
        let window_bytes = u64::from_le_bytes(bytes);
        Some(Self { window_bytes })
    }
}

/// Wire-format size of a [`WindowAdvertisement`]: 8 bytes (u64 LE).
pub const WINDOW_ADVERTISEMENT_FRAME_SIZE: usize = 8;

/// Build a window advertisement frame carrying the given available bytes.
///
/// This is a convenience wrapper around [`WindowAdvertisement::encode`].
#[must_use]
pub fn build_window_advertisement(window_bytes: u64) -> Vec<u8> {
    WindowAdvertisement::new(window_bytes).encode()
}

// ===========================================================================
// WindowAdvertiser — Periodic receive-window advertisement sender
// ===========================================================================

/// Drives periodic transmission of [`WindowAdvertisement`] frames
/// to the connected peer when the per-connection [`ReceiveWindow`]
/// drains below its configured low-watermark.
///
/// The caller is responsible for wiring `advertisement_tx` into the
/// outbound send path (e.g., `SendPipelineHandle::send(MessageFamily::HeartbeatAck, ...)`).
pub struct WindowAdvertiser {
    /// Handle to the connection whose receive window is being advertised.
    handle: Option<crate::connection::ConnectionHandle>,
    /// Channel through which advertisement frames are sent to the outbound pipeline.
    advertisement_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

impl WindowAdvertiser {
    /// Create a new window advertiser.
    ///
    /// `advertisement_tx` is an unbounded sender into the outbound
    /// send pipeline. Each advertisement frame is a fixed 8-byte
    /// `WindowAdvertisement` carrying the receiver's available buffer bytes.
    #[must_use]
    pub fn new(
        handle: crate::connection::ConnectionHandle,
        advertisement_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        Self {
            handle: Some(handle),
            advertisement_tx,
        }
    }

    /// Run one tick: check if the receive window needs advertisement
    /// and, if so, build and send the frame.
    ///
    /// Returns `true` if an advertisement was sent.
    pub fn tick(&mut self) -> bool {
        let handle = match self.handle.as_ref() {
            Some(h) => h,
            None => return false,
        };

        let now = std::time::Instant::now();
        if !handle.receive_window_needs_advertisement(now) {
            return false;
        }

        let available = match handle.receive_window_available() {
            Some(bytes) => bytes,
            None => return false,
        };

        let frame = build_window_advertisement(available);
        if self.advertisement_tx.send(frame).is_ok() {
            handle.receive_window_mark_advertised(now);
            true
        } else {
            false
        }
    }

    /// Stop advertising and release the connection handle.
    pub fn shutdown(&mut self) {
        self.handle = None;
    }

    /// Whether the advertiser has been shut down.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.handle.is_none()
    }
}

/// Spawn a window advertisement background task driven by [`WindowAdvertiser::tick`].
///
/// The task runs independently until the advertiser shuts down
/// (send channel closed or advertiser handle dropped).
///
/// `poll_interval` controls the minimum interval between advertisement checks.
/// Shorter intervals mean more responsive flow control at the cost of more
/// frequent polling.
pub async fn spawn_window_advertisement_task(
    mut advertiser: WindowAdvertiser,
    poll_interval: std::time::Duration,
) {
    let mut interval = tokio::time::interval(poll_interval);
    let mut consecutive_failures: u32 = 0;
    // First tick fires immediately to check initial state.
    interval.tick().await;
    loop {
        interval.tick().await;
        if advertiser.is_shutdown() {
            break;
        }
        if advertiser.tick() {
            consecutive_failures = 0;
        } else {
            consecutive_failures += 1;
            // After ~1 second of consecutive failures at 10ms poll interval,
            // the send channel is probably closed; exit the task.
            if consecutive_failures >= 100 {
                tracing::debug!("window advertiser exiting after consecutive send failures");
                break;
            }
        }
    }
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // CreditWindow tests
    // -----------------------------------------------------------------------

    #[test]
    fn window_starts_full() {
        let w = CreditWindow::new(1024, 256);
        assert_eq!(w.available_credits, 1024);
        assert_eq!(w.max_window_bytes, 1024);
        assert!(!w.needs_grant());
        assert!(!w.is_exhausted());
    }

    #[test]
    fn consume_below_threshold_triggers_grant_need() {
        let mut w = CreditWindow::new(1024, 256);
        w.consume(900).unwrap();
        assert!(w.needs_grant());
        assert!(!w.is_exhausted());
        assert_eq!(w.available_credits, 124);
    }

    #[test]
    fn consume_empty_exhausts_window() {
        let mut w = CreditWindow::new(1024, 256);
        w.consume(1024).unwrap();
        assert!(w.is_exhausted());
        assert_eq!(w.available_credits, 0);
    }

    #[test]
    fn consume_past_window_fails() {
        let mut w = CreditWindow::new(1024, 256);
        let err = w.consume(2048).unwrap_err();
        assert_eq!(err, FlowControlError::WindowExhausted);
    }

    #[test]
    fn grant_refills_window_up_to_max() {
        let mut w = CreditWindow::new(1024, 256);
        w.consume(800).unwrap();
        assert_eq!(w.available_credits, 224);
        let added = w.grant(300);
        assert_eq!(added, 300);
        assert_eq!(w.available_credits, 524);
    }

    #[test]
    fn grant_cannot_exceed_max() {
        let mut w = CreditWindow::new(1024, 256);
        w.consume(200).unwrap();
        let added = w.grant(5000);
        // Only 200 bytes of headroom remain
        assert_eq!(added, 200);
        assert_eq!(w.available_credits, 1024);
    }

    #[test]
    fn refill_amount_is_headroom() {
        let mut w = CreditWindow::new(1024, 256);
        w.consume(700).unwrap();
        assert_eq!(w.refill_amount(), 700);
    }

    #[test]
    fn refill_amount_zero_when_full() {
        let w = CreditWindow::new(1024, 256);
        assert_eq!(w.refill_amount(), 0);
    }

    // -----------------------------------------------------------------------
    // Wire format tests
    // -----------------------------------------------------------------------

    #[test]
    fn grant_encode_decode_roundtrip() {
        let frame = FlowControlFrame::CreditGrant {
            stream_id: 42,
            credits: 8192,
        };
        let encoded = FlowController::encode_frame(&frame);
        assert_eq!(encoded.len(), FLOW_CONTROL_FRAME_SIZE);
        assert_eq!(&encoded[0..4], &FLOW_CONTROL_MAGIC);
        let decoded = decode_flow_control_frame(&encoded).unwrap();
        assert_eq!(
            decoded,
            FlowControlFrame::CreditGrant {
                stream_id: 42,
                credits: 8192,
            }
        );
    }

    #[test]
    fn request_encode_decode_roundtrip() {
        let frame = FlowControlFrame::CreditRequest {
            stream_id: 7,
            requested: 4096,
        };
        let encoded = FlowController::encode_frame(&frame);
        let decoded = decode_flow_control_frame(&encoded).unwrap();
        assert_eq!(
            decoded,
            FlowControlFrame::CreditRequest {
                stream_id: 7,
                requested: 4096,
            }
        );
    }

    #[test]
    fn grant_not_decoded_as_request() {
        let encoded = FlowController::send_credit_grant(1, 100);
        let decoded = decode_flow_control_frame(&encoded).unwrap();
        assert!(matches!(decoded, FlowControlFrame::CreditGrant { .. }));
        assert!(!matches!(decoded, FlowControlFrame::CreditRequest { .. }));
    }

    #[test]
    fn request_not_decoded_as_grant() {
        let encoded = FlowController::send_credit_request(1, 100);
        let decoded = decode_flow_control_frame(&encoded).unwrap();
        assert!(matches!(decoded, FlowControlFrame::CreditRequest { .. }));
    }

    #[test]
    fn bad_magic_rejected() {
        let mut encoded = FlowController::send_credit_grant(1, 100);
        encoded[0] = 0xFF;
        let err = decode_flow_control_frame(&encoded).unwrap_err();
        assert_eq!(err, FlowControlError::InvalidCreditFrame);
    }

    #[test]
    fn tampered_digest_rejected() {
        let mut encoded = FlowController::send_credit_grant(1, 100);
        // Flip a bit in the BLAKE3 digest portion (byte 21 +)
        encoded[30] ^= 0x01;
        let err = decode_flow_control_frame(&encoded).unwrap_err();
        assert_eq!(err, FlowControlError::InvalidCreditFrame);
    }

    #[test]
    fn tampered_payload_rejected() {
        let mut encoded = FlowController::send_credit_grant(1, 100);
        // Flip a bit in the payload (credit value at byte 13+)
        encoded[15] ^= 0x01;
        let err = decode_flow_control_frame(&encoded).unwrap_err();
        assert_eq!(err, FlowControlError::InvalidCreditFrame);
    }

    #[test]
    fn wrong_size_rejected() {
        let short = vec![0u8; 10];
        assert_eq!(
            decode_flow_control_frame(&short),
            Err(FlowControlError::InvalidCreditFrame)
        );
        let long = vec![0u8; 100];
        assert_eq!(
            decode_flow_control_frame(&long),
            Err(FlowControlError::InvalidCreditFrame)
        );
    }

    #[test]
    fn unknown_frame_type_rejected() {
        let mut encoded = FlowController::send_credit_grant(1, 100);
        encoded[4] = 99; // invalid frame type
        let err = decode_flow_control_frame(&encoded).unwrap_err();
        assert_eq!(err, FlowControlError::UnknownFrameType { frame_type: 99 });
    }

    #[test]
    fn grant_and_request_have_different_digests() {
        let g = FlowController::send_credit_grant(5, 100);
        let r = FlowController::send_credit_request(5, 100);
        assert_eq!(&g[0..4], &FLOW_CONTROL_MAGIC);
        assert_eq!(&r[0..4], &FLOW_CONTROL_MAGIC);
        assert_eq!(&g[5..21], &r[5..21]); // same stream_id + value
                                          // Frame type and thus digest must differ (domain separation)
        assert_ne!(&g[21..53], &r[21..53]);
    }

    // -----------------------------------------------------------------------
    // FlowController tests
    // -----------------------------------------------------------------------

    #[test]
    fn controller_consume_credits_ok() {
        let mut fc = FlowController::with_default_window(1);
        assert!(fc.consume_credits(500).is_ok());
        assert_eq!(fc.window.available_credits, DEFAULT_MAX_WINDOW_BYTES - 500);
    }

    #[test]
    fn controller_consume_exhausts_and_errors() {
        let mut fc = FlowController::new(1, CreditWindow::new(100, 25));
        fc.consume_credits(100).unwrap();
        let err = fc.consume_credits(1).unwrap_err();
        assert_eq!(err, FlowControlError::WindowExhausted);
    }

    #[test]
    fn maybe_send_credit_grant_triggers_below_watermark() {
        let mut fc = FlowController::new(1, CreditWindow::new(1024, 256));
        fc.consume_credits(900).unwrap();
        assert!(fc.window.needs_grant());

        let grant = fc.maybe_send_credit_grant();
        assert!(grant.is_some());
        if let Some(FlowControlFrame::CreditGrant {
            stream_id, credits, ..
        }) = grant
        {
            assert_eq!(stream_id, 1);
            assert!(credits > 0);
        } else {
            panic!("expected CreditGrant");
        }
    }

    #[test]
    fn maybe_send_credit_grant_noop_above_watermark() {
        let mut fc = FlowController::new(1, CreditWindow::new(1024, 256));
        // Only consume a little — still above watermark.
        fc.consume_credits(100).unwrap();
        assert!(!fc.window.needs_grant());
        assert!(fc.maybe_send_credit_grant().is_none());
    }

    #[test]
    fn receive_credit_grant_adds_credits() {
        let mut fc = FlowController::new(1, CreditWindow::new(1024, 256));
        fc.consume_credits(800).unwrap();
        let before = fc.window.available_credits;

        let raw = FlowController::send_credit_grant(1, 500);
        let result = fc.receive_credit_grant(&raw);
        assert!(result.is_ok());
        assert!(fc.window.available_credits > before);
    }

    #[test]
    fn receive_credit_grant_rejects_tampered_frame() {
        let mut fc = FlowController::with_default_window(1);
        let mut raw = FlowController::send_credit_grant(1, 500);
        raw[10] ^= 0x01; // tamper with stream_id
        let err = fc.receive_credit_grant(&raw).unwrap_err();
        assert_eq!(err, FlowControlError::InvalidCreditFrame);
    }

    #[test]
    fn multiple_streams_independent() {
        let mut fc1 = FlowController::new(1, CreditWindow::new(100, 25));
        let mut fc2 = FlowController::new(2, CreditWindow::new(200, 50));

        fc1.consume_credits(80).unwrap();
        fc2.consume_credits(40).unwrap();

        // fc1 should be below watermark, fc2 not
        assert!(fc1.window.needs_grant());
        assert!(!fc2.window.needs_grant());

        assert!(fc1.maybe_send_credit_grant().is_some());
        assert!(fc2.maybe_send_credit_grant().is_none());
    }

    #[test]
    fn window_exhaustion_error_display() {
        let err = FlowControlError::WindowExhausted;
        assert_eq!(err.to_string(), "receive window exhausted");
    }

    #[test]
    fn invalid_credit_frame_error_display() {
        let err = FlowControlError::InvalidCreditFrame;
        assert_eq!(err.to_string(), "invalid credit frame (BLAKE3 mismatch)");
    }

    #[test]
    fn stale_credit_sequence_error_display() {
        let err = FlowControlError::StaleCreditSequence {
            received: 5,
            last: 10,
        };
        assert_eq!(
            err.to_string(),
            "stale credit sequence: received 5, last 10"
        );
    }

    #[test]
    fn stream_not_found_error_display() {
        let err = FlowControlError::StreamNotFound { stream_id: 42 };
        assert_eq!(err.to_string(), "stream not found: 42");
    }

    #[test]
    fn default_controller_has_valid_state() {
        let fc = FlowController::default();
        assert_eq!(fc.stream_id, 0);
        assert_eq!(fc.window.max_window_bytes, DEFAULT_MAX_WINDOW_BYTES);
        assert_eq!(fc.next_grant_seq, 1);
        assert_eq!(fc.last_received_grant_seq, 0);
    }

    #[test]
    fn credit_window_defaults_are_reasonable() {
        let w = CreditWindow::default_window();
        assert_eq!(w.max_window_bytes, DEFAULT_MAX_WINDOW_BYTES);
        assert_eq!(w.low_watermark, DEFAULT_LOW_WATERMARK_BYTES);
        assert!(w.low_watermark < w.max_window_bytes);
    }

    // -----------------------------------------------------------------------
    // Integration-style test: send/receive cycle
    // -----------------------------------------------------------------------

    #[test]
    fn send_receive_credit_cycle() {
        // Receiver side
        let mut rx = FlowController::new(1, CreditWindow::new(1024, 256));
        // Sender side window (mirrors the grant state)
        let mut tx_window = CreditWindow::new(1024, 256);

        // Sender wants to send 800 bytes; must check credits first.
        // Initially tx_window is full (simulates having received a grant).
        assert!(tx_window.consume(800).is_ok());

        // Receiver consumes the same 800 bytes (data arrived).
        rx.consume_credits(800).unwrap();
        assert!(rx.window.needs_grant());

        // Receiver sends a grant.
        let grant_frame = rx.maybe_send_credit_grant().unwrap();
        let raw = FlowController::encode_frame(&grant_frame);

        // Sender receives the grant.
        let decoded = decode_flow_control_frame(&raw).unwrap();
        if let FlowControlFrame::CreditGrant { credits, .. } = decoded {
            tx_window.grant(credits);
        }

        // Now tx_window has credits again; sender can send more.
        assert!(tx_window.available_credits > 800);
        assert!(tx_window.consume(200).is_ok());
    }

    // -----------------------------------------------------------------------
    // Integration tests: mock send/receive pair with backpressure
    // -----------------------------------------------------------------------

    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    /// In-memory bidirectional channel between sender and receiver.
    struct MockChannel {
        data_fwd: VecDeque<Vec<u8>>,
        grants_rev: VecDeque<Vec<u8>>,
    }

    impl MockChannel {
        fn new() -> Self {
            Self {
                data_fwd: VecDeque::new(),
                grants_rev: VecDeque::new(),
            }
        }
    }

    /// Sender endpoint: checks credits, sends data, processes grants.
    struct MockSenderEndpoint {
        send_window: CreditWindow,
        chan: Rc<RefCell<MockChannel>>,
    }

    impl MockSenderEndpoint {
        fn new(window_bytes: u64, chan: Rc<RefCell<MockChannel>>) -> Self {
            Self {
                send_window: CreditWindow::new(window_bytes, 0),
                chan,
            }
        }

        fn try_send(&mut self, data: Vec<u8>) -> Result<(), FlowControlError> {
            let len = data.len() as u64;
            self.send_window.consume(len)?;
            self.chan.borrow_mut().data_fwd.push_back(data);
            Ok(())
        }

        fn process_grants(&mut self) -> u64 {
            let mut total = 0u64;
            while let Some(raw) = self.chan.borrow_mut().grants_rev.pop_front() {
                if let Ok(FlowControlFrame::CreditGrant { credits, .. }) =
                    decode_flow_control_frame(&raw)
                {
                    total += self.send_window.grant(credits);
                }
            }
            total
        }
    }

    /// Receiver endpoint: receives data, consumes credits, sends grants.
    struct MockReceiverEndpoint {
        controller: FlowController,
        chan: Rc<RefCell<MockChannel>>,
        total_received: u64,
    }

    impl MockReceiverEndpoint {
        fn new(
            stream_id: u64,
            window_bytes: u64,
            low_watermark: u64,
            chan: Rc<RefCell<MockChannel>>,
        ) -> Self {
            let window = CreditWindow::new(window_bytes, low_watermark);
            Self {
                controller: FlowController::new(stream_id, window),
                chan,
                total_received: 0,
            }
        }

        fn receive_available(&mut self) -> u64 {
            let mut received = 0u64;
            loop {
                let data = {
                    let mut chan = self.chan.borrow_mut();
                    chan.data_fwd.pop_front()
                };
                let Some(data) = data else {
                    break;
                };
                let len = data.len() as u64;
                if self.controller.consume_credits(len).is_err() {
                    self.chan.borrow_mut().data_fwd.push_front(data);
                    break;
                }
                received += len;
                self.total_received += len;
            }
            received
        }

        fn maybe_send_grant(&mut self) -> Option<u64> {
            let grant = self.controller.maybe_send_credit_grant()?;
            let credits = match &grant {
                FlowControlFrame::CreditGrant { credits, .. } => *credits,
                _ => return None,
            };
            let raw = FlowController::encode_frame(&grant);
            self.chan.borrow_mut().grants_rev.push_back(raw);
            Some(credits)
        }
    }

    #[test]
    fn integration_send_receive_with_grant_cycle() {
        let chan = Rc::new(RefCell::new(MockChannel::new()));

        let mut sender = MockSenderEndpoint::new(1024, Rc::clone(&chan));
        let mut receiver = MockReceiverEndpoint::new(1, 1024, 256, Rc::clone(&chan));

        sender.try_send(vec![0u8; 800]).unwrap();
        assert_eq!(sender.send_window.available_credits, 224);

        let got = receiver.receive_available();
        assert_eq!(got, 800);
        let granted = receiver.maybe_send_grant();
        assert!(granted.is_some());

        let added = sender.process_grants();
        assert!(added > 0);
        assert!(sender.send_window.available_credits > 224);

        sender.try_send(vec![1u8; 200]).unwrap();
    }

    #[test]
    fn integration_backpressure_stops_sender() {
        let chan = Rc::new(RefCell::new(MockChannel::new()));

        let mut sender = MockSenderEndpoint::new(128, Rc::clone(&chan));
        let mut receiver = MockReceiverEndpoint::new(1, 128, 32, Rc::clone(&chan));

        sender.try_send(vec![0u8; 100]).unwrap();

        let err = sender.try_send(vec![0u8; 100]).unwrap_err();
        assert_eq!(err, FlowControlError::WindowExhausted);

        receiver.receive_available();
        receiver.maybe_send_grant();

        sender.process_grants();
        assert!(sender.try_send(vec![0u8; 50]).is_ok());
    }

    #[test]
    fn integration_multiple_grant_cycles() {
        let chan = Rc::new(RefCell::new(MockChannel::new()));

        let mut sender = MockSenderEndpoint::new(256, Rc::clone(&chan));
        let mut receiver = MockReceiverEndpoint::new(1, 256, 64, Rc::clone(&chan));

        for cycle in 0..5u8 {
            let byte = cycle + 1;
            sender.try_send(vec![byte; 200]).unwrap();
            receiver.receive_available();
            receiver.maybe_send_grant();
            sender.process_grants();
        }

        assert!(sender.send_window.available_credits > 0);
        assert_eq!(receiver.total_received, 1000);
    }

    #[test]
    fn integration_two_streams_independent() {
        let chan = Rc::new(RefCell::new(MockChannel::new()));

        let mut s1 = MockSenderEndpoint::new(64, Rc::clone(&chan));
        let mut r1 = MockReceiverEndpoint::new(1, 64, 16, Rc::clone(&chan));

        let mut s2 = MockSenderEndpoint::new(512, Rc::clone(&chan));
        let mut r2 = MockReceiverEndpoint::new(2, 512, 128, Rc::clone(&chan));

        s1.try_send(vec![0u8; 60]).unwrap();
        assert!(s1.try_send(vec![0u8; 60]).is_err());

        s2.try_send(vec![1u8; 400]).unwrap();

        r1.receive_available();
        r2.receive_available();

        r1.maybe_send_grant();
        s1.process_grants();

        assert!(s1.try_send(vec![0u8; 30]).is_ok());
        assert!(s2.send_window.available_credits > 0);
    }

    // =======================================================================
    // Per-Peer Flow Control tests
    // =======================================================================

    fn make_config() -> PeerFlowControlConfig {
        PeerFlowControlConfig {
            window_capacity: 1024,
            refill_rate_per_sec: 256,
            drain_timeout_secs: 5,
            suspected_shrink_factor: 0.5,
        }
    }

    fn make_peer_id(id: u64) -> MemberId {
        MemberId(id)
    }

    // -----------------------------------------------------------------------
    // Test 1: Single send-window acquire/release round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn send_window_acquire_release_roundtrip() {
        let cfg = make_config();
        let mut window = SendWindow::new(make_peer_id(1), &cfg);

        assert_eq!(window.available_tokens(), 1024);
        let rem = window.acquire_no_refill(500).unwrap();
        assert_eq!(rem, 524);
        assert_eq!(window.available_tokens(), 524);

        window.release(200);
        assert_eq!(window.available_tokens(), 724);

        let rem = window.acquire_no_refill(300).unwrap();
        assert_eq!(rem, 424);
    }

    // -----------------------------------------------------------------------
    // Test 2: Window exhaustion with backpressure signal
    // -----------------------------------------------------------------------

    #[test]
    fn window_exhaustion_backpressure() {
        let cfg = make_config();
        let mut window = SendWindow::new(make_peer_id(2), &cfg);

        window.acquire_no_refill(1000).unwrap();
        // 24 tokens left
        let err = window.acquire_no_refill(100).unwrap_err();
        assert_eq!(err, BackpressureSignal::WindowExhausted);

        // Release enough to acquire again
        window.release(80);
        let rem = window.acquire_no_refill(100).unwrap();
        assert_eq!(rem, 4);
    }

    // -----------------------------------------------------------------------
    // Test 3: Token replenishment over time
    // -----------------------------------------------------------------------

    #[test]
    fn token_replenishment_over_time() {
        let cfg = PeerFlowControlConfig {
            window_capacity: 1000,
            refill_rate_per_sec: 500, // 500 tokens/sec
            drain_timeout_secs: 5,
            suspected_shrink_factor: 0.5,
        };
        let mut window = SendWindow::new(make_peer_id(3), &cfg);

        // Drain tokens
        window.acquire_no_refill(1000).unwrap();
        assert_eq!(window.available_tokens(), 0);

        // Manually simulate refill (advance time)
        window.last_refill = Instant::now()
            .checked_sub(Duration::from_millis(200))
            .unwrap();
        window.refill();

        // 0.2s * 500 tokens/s = 100 tokens
        assert!(
            window.available_tokens() >= 90 && window.available_tokens() <= 110,
            "expected ~100 tokens, got {}",
            window.available_tokens()
        );
    }

    // -----------------------------------------------------------------------
    // Test 4: Window shrink on Suspected event
    // -----------------------------------------------------------------------

    #[test]
    fn window_shrink_on_suspected() {
        let cfg = make_config();
        let mut window = SendWindow::new(make_peer_id(4), &cfg);

        assert_eq!(window.capacity(), 1024);
        assert_eq!(window.membership_state(), MembershipState::Alive);

        let sig = window.on_membership_change(MembershipState::Suspected);
        assert!(sig.is_none());
        assert_eq!(window.membership_state(), MembershipState::Suspected);

        // Capacity should shrink (default factor not overridden, so uses internal default 0.5)
        assert!(window.capacity() < 1024, "capacity should have shrunk");
        assert!(window.available_tokens() <= window.capacity());

        // Re-acquire after shrink should still work within new capacity
        let rem = window
            .acquire_no_refill(window.available_tokens() - 1)
            .unwrap();
        assert_eq!(rem, 1);
    }

    // -----------------------------------------------------------------------
    // Test 5: Window drain+close on Failed event
    // -----------------------------------------------------------------------

    #[test]
    fn window_drain_close_on_failed() {
        let cfg = make_config();
        let mut window = SendWindow::new(make_peer_id(5), &cfg);

        // Use some tokens
        window.acquire_no_refill(500).unwrap();

        let sig = window.on_membership_change(MembershipState::Failed);
        assert!(sig.is_none());
        assert_eq!(window.membership_state(), MembershipState::Failed);
        assert!(!window.is_closed());

        // Still can use remaining tokens (drain phase)
        let rem = window.acquire_no_refill(200).unwrap();
        assert_eq!(rem, 324);

        // Drain remaining
        window.acquire_no_refill(324).unwrap();
        // Now check_drain should fire
        let sig = window.check_drain();
        assert_eq!(sig, Some(BackpressureSignal::PeerDrained));
        assert!(window.is_drained());
        assert!(window.is_closed());
    }

    // -----------------------------------------------------------------------
    // Test 6: Window re-open on Alive recovery
    // -----------------------------------------------------------------------

    #[test]
    fn window_reopen_on_alive_recovery() {
        let cfg = make_config();
        let mut window = SendWindow::new(make_peer_id(6), &cfg);

        // Suspect then fail
        window.on_membership_change(MembershipState::Suspected);
        window.on_membership_change(MembershipState::Failed);

        // Drain all tokens
        window.acquire_no_refill(window.available_tokens()).unwrap();
        window.check_drain();
        assert!(window.is_closed());

        // Alive recovery
        let sig = window.on_membership_change(MembershipState::Alive);
        assert!(sig.is_none());
        assert!(!window.is_closed());
        assert!(!window.is_drained());
        assert_eq!(window.membership_state(), MembershipState::Alive);
        assert!(window.available_tokens() > 0);
    }

    // -----------------------------------------------------------------------
    // Test 7: Concurrent multi-sender pressure
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_multi_sender_pressure() {
        let cfg = make_config();
        let mut controller = PeerFlowController::new(cfg);

        controller.register_peer(make_peer_id(10));
        controller.register_peer(make_peer_id(11));
        controller.register_peer(make_peer_id(12));

        // Acquire tokens across peers
        for id in &[10u64, 11, 12] {
            let rem = controller.acquire(make_peer_id(*id), 100).unwrap();
            assert_eq!(rem, 924);
        }

        // Each peer should have 924 tokens independently
        for id in &[10u64, 11, 12] {
            let w = controller.get(make_peer_id(*id)).unwrap();
            assert_eq!(w.available_tokens(), 924);
        }

        // Exhaust peer 10
        let w = controller.get(make_peer_id(10)).unwrap();
        let remaining = w.available_tokens();
        for _ in 0..9 {
            controller.acquire(make_peer_id(10), 100).unwrap();
        }
        controller
            .acquire(make_peer_id(10), remaining % 100)
            .unwrap();
        // Peer 10 exhausted
        let err = controller.acquire(make_peer_id(10), 1).unwrap_err();
        assert_eq!(err, BackpressureSignal::WindowExhausted);

        // Peer 11 not affected
        assert!(controller.acquire(make_peer_id(11), 1).is_ok());
    }

    // -----------------------------------------------------------------------
    // Test 8: BLAKE3-verified window state digest integrity
    // -----------------------------------------------------------------------

    #[test]
    fn blake3_window_state_digest_integrity() {
        let cfg = make_config();
        let mut w1 = SendWindow::new(make_peer_id(20), &cfg);
        let w2 = SendWindow::new(make_peer_id(20), &cfg);

        // Same initial state → same digest
        assert_eq!(w1.state_digest(), w2.state_digest());

        // Mutate w1 → digest changes
        w1.acquire_no_refill(100).unwrap();
        assert_ne!(w1.state_digest(), w2.state_digest());

        // Different peer → different digest
        let w3 = SendWindow::new(make_peer_id(21), &cfg);
        assert_ne!(w1.state_digest(), w3.state_digest());

        // Membership change → digest changes
        let pre = *w1.state_digest();
        w1.on_membership_change(MembershipState::Suspected);
        assert_ne!(*w1.state_digest(), pre);
    }

    // -----------------------------------------------------------------------
    // Test 9: Config validation
    // -----------------------------------------------------------------------

    #[test]
    fn config_validation_zero_capacity() {
        let cfg = PeerFlowControlConfig {
            window_capacity: 0,
            ..make_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validation_zero_refill() {
        let cfg = PeerFlowControlConfig {
            refill_rate_per_sec: 0,
            ..make_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validation_bad_shrink_factor() {
        let cfg = PeerFlowControlConfig {
            suspected_shrink_factor: 1.5,
            ..make_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validation_ok() {
        let cfg = make_config();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_defaults_are_valid() {
        let cfg = PeerFlowControlConfig::default();
        assert!(cfg.validate().is_ok());
        assert!(cfg.window_capacity > 0);
        assert!(cfg.refill_rate_per_sec > 0);
    }

    // -----------------------------------------------------------------------
    // Test 10: Drain timeout enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn drain_timeout_enforcement() {
        let cfg = PeerFlowControlConfig {
            drain_timeout_secs: 1,
            ..make_config()
        };
        let mut window = SendWindow::new(make_peer_id(30), &cfg);

        window.on_membership_change(MembershipState::Failed);

        // Not yet timed out
        let sig = window.check_drain();
        assert!(sig.is_none());

        // Advance drain_start to simulate timeout
        window.drain_start = Some(Instant::now() - Duration::from_secs(2));

        let sig = window.check_drain();
        assert_eq!(sig, Some(BackpressureSignal::PeerDrained));
        assert!(window.is_closed());
        assert_eq!(window.available_tokens(), 0);
    }

    // -----------------------------------------------------------------------
    // Test 11: Peer-drained backpressure signal
    // -----------------------------------------------------------------------

    #[test]
    fn peer_drained_backpressure_signal() {
        let cfg = make_config();
        let mut controller = PeerFlowController::new(cfg);

        controller.register_peer(make_peer_id(40));

        // Transition to Failed
        controller.on_membership_change(make_peer_id(40), MembershipState::Failed);

        // Drain all tokens
        let w = controller.get(make_peer_id(40)).unwrap();
        let tokens = w.available_tokens();
        controller.acquire(make_peer_id(40), tokens).unwrap();

        // Check drains
        let signals = controller.check_all_drains();
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].1, BackpressureSignal::PeerDrained);

        // Peer should now be closed
        let w = controller.get(make_peer_id(40)).unwrap();
        assert!(w.is_closed());
    }

    // -----------------------------------------------------------------------
    // Test 12: FlowController with membership event subscription
    // -----------------------------------------------------------------------

    #[test]
    fn flow_controller_membership_subscription() {
        let cfg = make_config();
        let mut controller = PeerFlowController::new(cfg);

        // Register peers
        controller.register_peer(make_peer_id(50));
        controller.register_peer(make_peer_id(51));
        assert_eq!(controller.peer_count(), 2);

        // Simulate membership events
        // Peer 50: Alive → Suspected
        let sig = controller.on_membership_change(make_peer_id(50), MembershipState::Suspected);
        assert!(sig.is_none());

        // Peer 51: Alive → Failed
        let sig = controller.on_membership_change(make_peer_id(51), MembershipState::Failed);
        assert!(sig.is_none());

        // Peer 51: drain and check
        let w = controller.get(make_peer_id(51)).unwrap();
        let tokens = w.available_tokens();
        controller.acquire(make_peer_id(51), tokens).unwrap();
        let signals = controller.check_all_drains();
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].0, make_peer_id(51));

        // Peer 50: back to Alive
        let sig = controller.on_membership_change(make_peer_id(50), MembershipState::Alive);
        assert!(sig.is_none());
        let w = controller.get(make_peer_id(50)).unwrap();
        assert_eq!(w.membership_state(), MembershipState::Alive);

        // Non-existent peer
        let sig = controller.on_membership_change(make_peer_id(99), MembershipState::Failed);
        assert!(sig.is_none());
    }

    // -----------------------------------------------------------------------
    // Test 13: Left event closes window immediately
    // -----------------------------------------------------------------------

    #[test]
    fn left_event_closes_window_immediately() {
        let cfg = make_config();
        let mut window = SendWindow::new(make_peer_id(60), &cfg);

        let sig = window.on_membership_change(MembershipState::Left);
        assert_eq!(sig, Some(BackpressureSignal::WindowClosed));
        assert!(window.is_closed());
        assert!(window.is_drained());
        assert_eq!(window.available_tokens(), 0);

        // Cannot acquire from closed window
        let err = window.acquire_no_refill(1).unwrap_err();
        assert_eq!(err, BackpressureSignal::WindowClosed);
    }

    // -----------------------------------------------------------------------
    // Test 14: Controller remove_peer
    // -----------------------------------------------------------------------

    #[test]
    fn controller_remove_peer() {
        let cfg = make_config();
        let mut controller = PeerFlowController::new(cfg);

        controller.register_peer(make_peer_id(70));
        assert_eq!(controller.peer_count(), 1);

        let removed = controller.remove_peer(make_peer_id(70));
        assert!(removed.is_some());
        assert_eq!(controller.peer_count(), 0);

        // Acquire to removed peer fails
        let err = controller.acquire(make_peer_id(70), 1).unwrap_err();
        assert_eq!(err, BackpressureSignal::WindowClosed);
    }

    // -----------------------------------------------------------------------
    // Test 15: Same-state transition is no-op
    // -----------------------------------------------------------------------

    #[test]
    fn same_state_transition_noop() {
        let cfg = make_config();
        let mut window = SendWindow::new(make_peer_id(80), &cfg);

        let digest_before = *window.state_digest();
        let sig = window.on_membership_change(MembershipState::Alive);
        assert!(sig.is_none());
        // Digest should not change for no-op
        assert_eq!(*window.state_digest(), digest_before);
    }

    // -----------------------------------------------------------------------
    // Test 16: Default PeerFlowController
    // -----------------------------------------------------------------------

    #[test]
    fn default_peer_flow_controller() {
        let controller = PeerFlowController::default();
        assert_eq!(controller.peer_count(), 0);
        assert!(controller.config().validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // Test 17: BackpressureSignal Display
    // -----------------------------------------------------------------------

    #[test]
    fn backpressure_signal_display() {
        assert_eq!(
            BackpressureSignal::WindowExhausted.to_string(),
            "send window exhausted"
        );
        assert_eq!(
            BackpressureSignal::WindowClosed.to_string(),
            "send window closed (peer departed)"
        );
        assert_eq!(
            BackpressureSignal::PeerDrained.to_string(),
            "peer drained all tokens"
        );
    }

    // -----------------------------------------------------------------------
    // Test 18: Release saturates at capacity
    // -----------------------------------------------------------------------

    #[test]
    fn release_saturates_at_capacity() {
        let cfg = make_config();
        let mut window = SendWindow::new(make_peer_id(90), &cfg);

        // Only consume a little
        window.acquire_no_refill(100).unwrap();
        // Release more than consumed
        window.release(500);
        assert_eq!(window.available_tokens(), window.capacity());
    }

    // -----------------------------------------------------------------------
    // Test 19: Suspected on empty window
    // -----------------------------------------------------------------------

    #[test]
    fn suspected_on_empty_window() {
        let cfg = make_config();
        let mut window = SendWindow::new(make_peer_id(100), &cfg);

        window.acquire_no_refill(window.available_tokens()).unwrap();
        assert_eq!(window.available_tokens(), 0);

        // Transition to Suspected while empty
        let sig = window.on_membership_change(MembershipState::Suspected);
        assert!(sig.is_none());
        assert_eq!(window.available_tokens(), 0);
        assert!(window.capacity() < 1024);
    }

    // -----------------------------------------------------------------------
    // Test 20: Token refill stops during drain
    // -----------------------------------------------------------------------

    #[test]
    fn token_refill_stops_during_drain() {
        let cfg = PeerFlowControlConfig {
            window_capacity: 1000,
            refill_rate_per_sec: 1000,
            drain_timeout_secs: 5,
            suspected_shrink_factor: 0.5,
        };
        let mut window = SendWindow::new(make_peer_id(110), &cfg);

        window.acquire_no_refill(500).unwrap();

        window.on_membership_change(MembershipState::Failed);

        // Simulate time passing
        window.last_refill = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();

        let tokens_before = window.available_tokens();
        window.refill();
        // Tokens should NOT increase during drain
        assert_eq!(window.available_tokens(), tokens_before);
    }

    // ===================================================================
    // Receive-Window Advertisement tests
    // ===================================================================

    fn make_receive_window_config() -> ReceiveWindowConfig {
        ReceiveWindowConfig {
            capacity: 1024,
            low_watermark_ratio: 0.25,
            advertise_batch_interval: Duration::from_millis(10),
        }
    }

    fn fake_now() -> Instant {
        Instant::now()
    }

    // -----------------------------------------------------------------------
    // Test RW-1: basic consume and release
    // -----------------------------------------------------------------------

    #[test]
    fn receive_window_consume_release_roundtrip() {
        let cfg = make_receive_window_config();
        let mut rw = ReceiveWindow::new(cfg);

        assert_eq!(rw.available_bytes(), 1024);
        assert_eq!(rw.capacity(), 1024);

        // Consume some bytes
        rw.consume(200).unwrap();
        assert_eq!(rw.available_bytes(), 824);

        // Release some back
        rw.release(100);
        assert_eq!(rw.available_bytes(), 924);

        // Release beyond capacity saturates
        rw.release(500);
        assert_eq!(rw.available_bytes(), 1024);
    }

    // -----------------------------------------------------------------------
    // Test RW-2: window exhaustion
    // -----------------------------------------------------------------------

    #[test]
    fn receive_window_exhaustion() {
        let cfg = make_receive_window_config();
        let mut rw = ReceiveWindow::new(cfg);

        rw.consume(1024).unwrap();
        assert!(rw.is_exhausted());
        assert_eq!(rw.available_bytes(), 0);

        // Further consume should fail
        let err = rw.consume(1).unwrap_err();
        assert_eq!(err, FlowControlError::WindowExhausted);
    }

    // -----------------------------------------------------------------------
    // Test RW-3: low-watermark advertisement trigger
    // -----------------------------------------------------------------------

    #[test]
    fn receive_window_low_watermark_trigger() {
        let cfg = make_receive_window_config(); // 1024 cap, 0.25 ratio => 256 low-watermark
        let mut rw = ReceiveWindow::new(cfg);

        assert_eq!(rw.low_watermark(), 256);

        // Window starts full, no advertisement needed
        assert!(!rw.needs_advertisement(fake_now()));

        // Consume down to exactly low-watermark (still not below)
        rw.consume(768).unwrap(); // 1024 - 768 = 256
        assert_eq!(rw.available_bytes(), 256);
        assert!(!rw.needs_advertisement(fake_now()));

        // One more byte below low-watermark -> needs advertisement
        rw.consume(1).unwrap();
        assert_eq!(rw.available_bytes(), 255);
        assert!(rw.needs_advertisement(fake_now()));

        // Mark advertised, shouldn't re-trigger within batch interval
        let now = fake_now();
        rw.mark_advertised(now);
        assert!(!rw.needs_advertisement(now));

        // After batch interval, should trigger again
        let later = now.checked_add(Duration::from_millis(15)).unwrap();
        assert!(rw.needs_advertisement(later));
    }

    // -----------------------------------------------------------------------
    // Test RW-4: release above low-watermark clears advertisement
    // -----------------------------------------------------------------------

    #[test]
    fn receive_window_release_above_watermark() {
        let cfg = make_receive_window_config();
        let mut rw = ReceiveWindow::new(cfg);

        // Drain below low-watermark
        rw.consume(900).unwrap();
        assert_eq!(rw.available_bytes(), 124);
        assert!(rw.needs_advertisement(fake_now()));

        // Release enough to go back above low-watermark
        rw.release(200);
        assert_eq!(rw.available_bytes(), 324);
        assert!(!rw.needs_advertisement(fake_now()));
    }

    // -----------------------------------------------------------------------
    // Test RW-5: window advertisement message
    // -----------------------------------------------------------------------

    #[test]
    fn window_advertisement_message_roundtrip() {
        let adv = WindowAdvertisement::new(512);
        assert_eq!(adv.window_bytes, 512);

        let adv2 = WindowAdvertisement::new(0);
        assert_eq!(adv2.window_bytes, 0);

        let adv3 = WindowAdvertisement::new(1_048_576);
        assert_eq!(adv3.window_bytes, 1_048_576);
    }

    // -----------------------------------------------------------------------
    // Test RW-9: encode/decode roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn window_advertisement_encode_decode_roundtrip() {
        let adv = WindowAdvertisement::new(42);
        let encoded = adv.encode();
        assert_eq!(encoded.len(), WINDOW_ADVERTISEMENT_FRAME_SIZE);

        let decoded = WindowAdvertisement::decode(&encoded).unwrap();
        assert_eq!(decoded.window_bytes, 42);
    }

    #[test]
    fn window_advertisement_encode_into_buffer() {
        let adv = WindowAdvertisement::new(0xDEADBEEF);
        let mut buf = [0u8; WINDOW_ADVERTISEMENT_FRAME_SIZE];
        adv.encode_into(&mut buf);
        assert_eq!(buf, 0xDEADBEEFu64.to_le_bytes());

        let decoded = WindowAdvertisement::decode(&buf).unwrap();
        assert_eq!(decoded.window_bytes, 0xDEADBEEF);
    }

    #[test]
    fn window_advertisement_rejects_wrong_size() {
        // Too short
        assert!(WindowAdvertisement::decode(&[]).is_none());
        assert!(WindowAdvertisement::decode(&[0u8; 4]).is_none());
        assert!(WindowAdvertisement::decode(&[0u8; 7]).is_none());
        // Too long
        assert!(WindowAdvertisement::decode(&[0u8; 9]).is_none());
        assert!(WindowAdvertisement::decode(&[0u8; 16]).is_none());
    }

    #[test]
    fn build_window_advertisement_helper() {
        let frame = build_window_advertisement(1024);
        assert_eq!(frame.len(), WINDOW_ADVERTISEMENT_FRAME_SIZE);
        let decoded = WindowAdvertisement::decode(&frame).unwrap();
        assert_eq!(decoded.window_bytes, 1024);
    }

    #[test]
    fn window_advertisement_zero_capacity() {
        let adv = WindowAdvertisement::new(0);
        let encoded = adv.encode();
        let decoded = WindowAdvertisement::decode(&encoded).unwrap();
        assert_eq!(decoded.window_bytes, 0);
    }

    #[test]
    fn window_advertisement_max_capacity() {
        let adv = WindowAdvertisement::new(u64::MAX);
        let encoded = adv.encode();
        assert_eq!(encoded.len(), 8);
        let decoded = WindowAdvertisement::decode(&encoded).unwrap();
        assert_eq!(decoded.window_bytes, u64::MAX);
    }

    #[test]
    #[should_panic(expected = "assertion")]
    fn window_advertisement_encode_into_wrong_size_panics() {
        let adv = WindowAdvertisement::new(0);
        let mut buf = [0u8; 4];
        adv.encode_into(&mut buf);
    }
    // -----------------------------------------------------------------------
    // Test RW-6: config validation
    // -----------------------------------------------------------------------

    #[test]
    fn receive_window_config_defaults_valid() {
        let cfg = ReceiveWindowConfig::default();
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.capacity, 1_048_576);
        assert_eq!(cfg.low_watermark_bytes(), 262_144);
    }

    #[test]
    fn receive_window_config_zero_capacity_rejected() {
        let cfg = ReceiveWindowConfig {
            capacity: 0,
            ..ReceiveWindowConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn receive_window_config_zero_ratio_rejected() {
        let cfg = ReceiveWindowConfig {
            low_watermark_ratio: 0.0,
            ..ReceiveWindowConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn receive_window_config_ratio_one_ok() {
        let cfg = ReceiveWindowConfig {
            low_watermark_ratio: 1.0,
            ..ReceiveWindowConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn receive_window_config_ratio_above_one_rejected() {
        let cfg = ReceiveWindowConfig {
            low_watermark_ratio: 1.5,
            ..ReceiveWindowConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    // -----------------------------------------------------------------------
    // Test RW-7: mark_advertised prevents spam
    // -----------------------------------------------------------------------

    #[test]
    fn receive_window_batch_interval_prevents_spam() {
        let cfg = ReceiveWindowConfig {
            capacity: 1000,
            low_watermark_ratio: 0.5,
            advertise_batch_interval: Duration::from_millis(50),
        };
        let mut rw = ReceiveWindow::new(cfg);

        // Drain below low-watermark (0.5 * 1000 = 500)
        rw.consume(600).unwrap(); // 400 remaining < 500
        assert!(rw.needs_advertisement(fake_now()));

        let now = fake_now();
        rw.mark_advertised(now);

        // Immediately after marking, should not trigger
        assert!(!rw.needs_advertisement(now));

        // After 30ms, still within batch interval
        let t2 = now.checked_add(Duration::from_millis(30)).unwrap();
        assert!(!rw.needs_advertisement(t2));

        // After 60ms, past batch interval, should trigger
        let t3 = now.checked_add(Duration::from_millis(60)).unwrap();
        assert!(rw.needs_advertisement(t3));
    }

    // -----------------------------------------------------------------------
    // Test RW-8: default config values
    // -----------------------------------------------------------------------

    #[test]
    fn receive_window_config_default_values() {
        let cfg = ReceiveWindowConfig::default();
        assert_eq!(cfg.capacity, 1_048_576);
        // low_watermark_ratio = 0.25 => 256 KiB
        assert_eq!(cfg.low_watermark_bytes(), 262_144);
        assert_eq!(cfg.advertise_batch_interval, Duration::from_millis(10));
    }

    // -----------------------------------------------------------------------
    // Test RW-10: WindowAdvertiser sends advertisement when below watermark
    // -----------------------------------------------------------------------

    #[test]
    fn window_advertiser_sends_when_below_watermark() {
        // Create a receive window that starts below watermark
        let cfg = ReceiveWindowConfig {
            capacity: 1000,
            low_watermark_ratio: 0.5,
            advertise_batch_interval: Duration::from_millis(0),
        };
        let mut rw = ReceiveWindow::new(cfg);
        // Drain to 400 bytes (< 500 watermark)
        rw.consume(600).unwrap();

        // Check that it needs advertisement
        assert!(rw.needs_advertisement(std::time::Instant::now()));
        assert_eq!(rw.available_bytes(), 400);
        assert_eq!(rw.low_watermark(), 500);
    }

    // -----------------------------------------------------------------------
    // Test RW-11: WindowAdvertiser respects batch interval
    // -----------------------------------------------------------------------

    #[test]
    fn window_advertiser_respects_batch_interval() {
        let cfg = ReceiveWindowConfig {
            capacity: 1000,
            low_watermark_ratio: 0.5,
            advertise_batch_interval: Duration::from_millis(100),
        };
        let mut rw = ReceiveWindow::new(cfg);
        rw.consume(600).unwrap(); // 400 remaining < 500

        let now = std::time::Instant::now();
        assert!(rw.needs_advertisement(now));

        rw.mark_advertised(now);
        assert!(!rw.needs_advertisement(now));

        // Still within batch interval
        let t2 = now.checked_add(Duration::from_millis(50)).unwrap();
        assert!(!rw.needs_advertisement(t2));

        // Past batch interval
        let t3 = now.checked_add(Duration::from_millis(150)).unwrap();
        assert!(rw.needs_advertisement(t3));
    }

    // -----------------------------------------------------------------------
    // Test RW-12: build_window_advertisement produces correct frame
    // -----------------------------------------------------------------------

    #[test]
    fn build_window_advertisement_produces_correct_frame() {
        let frame = build_window_advertisement(1024);
        assert_eq!(frame.len(), WINDOW_ADVERTISEMENT_FRAME_SIZE);
        // Verify LE encoding
        let expected: Vec<u8> = 1024u64.to_le_bytes().to_vec();
        assert_eq!(frame, expected);
    }

    // -----------------------------------------------------------------------
    // Test RW-13: WindowAdvertisement decode matches encode
    // -----------------------------------------------------------------------

    #[test]
    fn window_advertisement_full_roundtrip() {
        let adv = WindowAdvertisement::new(65536);
        let encoded = adv.encode();
        let decoded = WindowAdvertisement::decode(&encoded).unwrap();
        assert_eq!(decoded.window_bytes, 65536);

        // Helper produces same result
        let helper_frame = build_window_advertisement(65536);
        assert_eq!(encoded, helper_frame);
    }

    #[test]
    fn cluster_pressure_reduces_advertised_receive_window() {
        let mut window = CreditWindow::new(100, 40);
        window.consume(30).unwrap();

        assert_eq!(
            window.max_window_bytes_under_cluster_pressure(ClusterQueuePressure::None),
            100
        );
        assert_eq!(
            window.max_window_bytes_under_cluster_pressure(ClusterQueuePressure::SoftPressure),
            50
        );
        assert_eq!(
            window.advertised_credits_under_cluster_pressure(ClusterQueuePressure::SoftPressure),
            50
        );
        assert_eq!(
            window.max_window_bytes_under_cluster_pressure(ClusterQueuePressure::HardPressure),
            25
        );
    }

    #[test]
    fn pressure_aware_credit_grant_refills_only_reduced_window() {
        let mut controller = FlowController::new(7, CreditWindow::new(100, 40));
        controller.consume_credits(90).unwrap();

        let grant = controller
            .maybe_send_credit_grant_under_cluster_pressure(ClusterQueuePressure::SoftPressure)
            .unwrap();

        assert_eq!(
            grant,
            FlowControlFrame::CreditGrant {
                stream_id: 7,
                credits: 40
            }
        );
        assert_eq!(controller.window.available_credits, 50);
    }
}
