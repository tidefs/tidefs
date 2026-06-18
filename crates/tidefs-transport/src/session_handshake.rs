// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Session-level handshake protocol for multi-node link negotiation.
//!
//! Implements a Hello/Accept/Reject state machine with configurable timeout
//! over any generic `AsyncRead + AsyncWrite` transport. This is the
//! session-parameter negotiation layer that runs on top of the cryptographic
//! handshake to agree on protocol versions, feature flags, and session tokens
//! before data-plane traffic flows.
//!
//! ## Protocol flow
//!
//! ```text
//! Initiator                    Responder
//!     |                            |
//!     |-- Hello ------------------>|
//!     |                            | (validate Hello,
//!     |                            |  decide accept/reject,
//!     |                            |  generate session token)
//!     |<- Accept ------------------|
//!     |                            |
//!     |<== session negotiated ====>|
//!
//!     |-- Hello ------------------>|
//!     |<- Reject(reason) ----------|
//!     |<== session refused =======>|
//! ```
//!
//! ## Timeout
//!
//! If the initiator does not receive an Accept or Reject within the
//! configured timeout duration after sending Hello, the state machine
//! transitions to `Timeout`.

use std::time::Duration;
use thiserror::Error;
use tidefs_binary_schema_core::{U16Le, U32Le, U64Le};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Wire format constants
// ---------------------------------------------------------------------------

/// Magic bytes prepended to every handshake message: "VHND" (TideFS HaNDshake).
pub const HANDSHAKE_MAGIC: u32 = 0x444E_4856; // "VHND" in LE

/// Wire discriminant for Hello messages.
pub const MSG_KIND_HELLO: u8 = 0x01;
/// Wire discriminant for Accept messages.
pub const MSG_KIND_ACCEPT: u8 = 0x02;
/// Wire discriminant for Reject messages.
pub const MSG_KIND_REJECT: u8 = 0x03;

/// Maximum length of the human-readable message in a Reject frame.
pub const REJECT_MESSAGE_MAX_LEN: usize = 256;

/// Default feature flags advertised by the current release node.
/// Corresponds to [`crate::rollback_compat::NodeFeatureFlags::CURRENT`].
pub const DEFAULT_FEATURE_FLAGS: u64 = crate::rollback_compat::NodeFeatureFlags::CURRENT.to_raw();

// ---------------------------------------------------------------------------
// Reject reason codes
// ---------------------------------------------------------------------------

/// Reason a session handshake was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RejectReason {
    /// Peer's protocol version is incompatible.
    VersionMismatch = 0x0001,
    /// Peer is not authorized to connect (unknown identity, revoked key).
    Unauthorized = 0x0002,
    /// Responder has insufficient capacity to accept new sessions.
    InsufficientCapacity = 0x0003,
    /// Responder does not support the requested feature flags.
    FeatureMismatch = 0x0004,
    /// Responder received a malformed or unrecognized Hello message.
    BadHello = 0x0005,
    /// Internal error on the responder side.
    InternalError = 0x0006,
}

impl RejectReason {
    /// Decode from a raw `u16` discriminant.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0001 => Some(Self::VersionMismatch),
            0x0002 => Some(Self::Unauthorized),
            0x0003 => Some(Self::InsufficientCapacity),
            0x0004 => Some(Self::FeatureMismatch),
            0x0005 => Some(Self::BadHello),
            0x0006 => Some(Self::InternalError),
            _ => None,
        }
    }

    /// Human-readable label for this reason.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VersionMismatch => "version_mismatch",
            Self::Unauthorized => "unauthorized",
            Self::InsufficientCapacity => "insufficient_capacity",
            Self::FeatureMismatch => "feature_mismatch",
            Self::BadHello => "bad_hello",
            Self::InternalError => "internal_error",
        }
    }
}

// ---------------------------------------------------------------------------
// Handshake message types
// ---------------------------------------------------------------------------

/// Hello: sent by the initiator to begin session negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hello {
    /// Initiator's node ID.
    pub node_id: u64,
    /// Protocol version the initiator supports.
    pub protocol_version: u32,
    /// Feature flags the initiator requests (bitmask).
    pub feature_flags: u64,
}

/// Accept: sent by the responder to accept session negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Accept {
    /// Opaque session token for the established session.
    pub session_token: u64,
    /// Negotiated protocol version (min of initiator/responder).
    pub negotiated_version: u32,
    /// Negotiated feature flags (intersection of initiator/responder).
    pub negotiated_features: u64,
}

/// Reject: sent by the responder to refuse session negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reject {
    /// Reason code for the rejection.
    pub reason: RejectReason,
    /// Human-readable rejection message (max 256 bytes on wire).
    pub message: String,
}

// ---------------------------------------------------------------------------
// Binary encode / decode using tidefs-binary_schema-core primitives
// ---------------------------------------------------------------------------

/// Error type for handshake encode/decode operations.
#[derive(Error, Debug, Clone)]
pub enum HandshakeCodecError {
    #[error("encode error: {0}")]
    Encode(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("unknown message kind: {0:#04x}")]
    UnknownKind(u8),
    #[error("bad magic: expected {0:#010x}, got {1:#010x}")]
    BadMagic(u32, u32),
    #[error("message too short: {0} bytes")]
    TooShort(usize),
}

/// Wire frame header: magic (4 bytes) + kind (1 byte) + payload_len (4 bytes).
const FRAME_HEADER_SIZE: usize = 9;

impl Hello {
    /// Encode this Hello to wire bytes.
    ///
    /// Wire format (33 bytes total):
    /// `[magic:4 LE] [kind:1=0x01] [payload_len:4 LE=24]
    ///  [node_id:8 LE] [protocol_version:4 LE] [feature_flags:8 LE]
    ///  [reserved:4 zero]`
    pub fn encode(&self) -> Result<Vec<u8>, HandshakeCodecError> {
        let payload_len: u32 = 24;
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + payload_len as usize);
        buf.extend_from_slice(&HANDSHAKE_MAGIC.to_le_bytes());
        buf.push(MSG_KIND_HELLO);
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&U64Le::from_le(self.node_id).encode());
        buf.extend_from_slice(&U32Le::from_le(self.protocol_version).encode());
        buf.extend_from_slice(&U64Le::from_le(self.feature_flags).encode());
        buf.extend_from_slice(&[0u8; 4]);
        Ok(buf)
    }

    /// Decode a Hello from wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, HandshakeCodecError> {
        if bytes.len() < FRAME_HEADER_SIZE + 24 {
            return Err(HandshakeCodecError::TooShort(bytes.len()));
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != HANDSHAKE_MAGIC {
            return Err(HandshakeCodecError::BadMagic(HANDSHAKE_MAGIC, magic));
        }
        if bytes[4] != MSG_KIND_HELLO {
            return Err(HandshakeCodecError::Decode(format!(
                "expected kind=HELLO, got {:02x}",
                bytes[4]
            )));
        }
        let p = &bytes[FRAME_HEADER_SIZE..];
        let node_id =
            U64Le::from_le_bytes([p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]]).as_raw();
        let protocol_version = U32Le::from_le_bytes([p[8], p[9], p[10], p[11]]).as_raw();
        let feature_flags =
            U64Le::from_le_bytes([p[12], p[13], p[14], p[15], p[16], p[17], p[18], p[19]]).as_raw();
        Ok(Hello {
            node_id,
            protocol_version,
            feature_flags,
        })
    }
}

impl Accept {
    /// Encode this Accept to wire bytes.
    ///
    /// Wire format (33 bytes total):
    /// `[magic:4 LE] [kind:1=0x02] [payload_len:4 LE=24]
    ///  [session_token:8 LE] [negotiated_version:4 LE]
    ///  [negotiated_features:8 LE] [reserved:4 zero]`
    pub fn encode(&self) -> Result<Vec<u8>, HandshakeCodecError> {
        let payload_len: u32 = 24;
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + payload_len as usize);
        buf.extend_from_slice(&HANDSHAKE_MAGIC.to_le_bytes());
        buf.push(MSG_KIND_ACCEPT);
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&U64Le::from_le(self.session_token).encode());
        buf.extend_from_slice(&U32Le::from_le(self.negotiated_version).encode());
        buf.extend_from_slice(&U64Le::from_le(self.negotiated_features).encode());
        buf.extend_from_slice(&[0u8; 4]);
        Ok(buf)
    }

    /// Decode an Accept from wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, HandshakeCodecError> {
        if bytes.len() < FRAME_HEADER_SIZE + 24 {
            return Err(HandshakeCodecError::TooShort(bytes.len()));
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != HANDSHAKE_MAGIC {
            return Err(HandshakeCodecError::BadMagic(HANDSHAKE_MAGIC, magic));
        }
        if bytes[4] != MSG_KIND_ACCEPT {
            return Err(HandshakeCodecError::Decode(format!(
                "expected kind=ACCEPT, got {:02x}",
                bytes[4]
            )));
        }
        let p = &bytes[FRAME_HEADER_SIZE..];
        let session_token =
            U64Le::from_le_bytes([p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]]).as_raw();
        let negotiated_version = U32Le::from_le_bytes([p[8], p[9], p[10], p[11]]).as_raw();
        let negotiated_features =
            U64Le::from_le_bytes([p[12], p[13], p[14], p[15], p[16], p[17], p[18], p[19]]).as_raw();
        Ok(Accept {
            session_token,
            negotiated_version,
            negotiated_features,
        })
    }
}

impl Reject {
    /// Encode this Reject to wire bytes.
    ///
    /// Wire format:
    /// `[magic:4 LE] [kind:1=0x03] [payload_len:4 LE]
    ///  [reason:2 LE] [msg_len:2 LE] [message:msg_len bytes] [padding to 4]`
    pub fn encode(&self) -> Result<Vec<u8>, HandshakeCodecError> {
        let msg_bytes = self.message.as_bytes();
        let msg_len = msg_bytes.len().min(REJECT_MESSAGE_MAX_LEN);
        let data_len = 4 + msg_len;
        let padded = (data_len + 3) & !3;
        let payload_len: u32 = padded as u32;
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + padded);
        buf.extend_from_slice(&HANDSHAKE_MAGIC.to_le_bytes());
        buf.push(MSG_KIND_REJECT);
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&U16Le::from_le(self.reason as u16).encode());
        buf.extend_from_slice(&U16Le::from_le(msg_len as u16).encode());
        buf.extend_from_slice(&msg_bytes[..msg_len]);
        buf.extend(std::iter::repeat_n(0u8, padded - data_len));
        Ok(buf)
    }

    /// Decode a Reject from wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, HandshakeCodecError> {
        if bytes.len() < FRAME_HEADER_SIZE + 4 {
            return Err(HandshakeCodecError::TooShort(bytes.len()));
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != HANDSHAKE_MAGIC {
            return Err(HandshakeCodecError::BadMagic(HANDSHAKE_MAGIC, magic));
        }
        if bytes[4] != MSG_KIND_REJECT {
            return Err(HandshakeCodecError::Decode(format!(
                "expected kind=REJECT, got {:02x}",
                bytes[4]
            )));
        }
        let p = &bytes[FRAME_HEADER_SIZE..];
        let reason_code = U16Le::from_le_bytes([p[0], p[1]]).as_raw();
        let msg_len = U16Le::from_le_bytes([p[2], p[3]]).as_raw() as usize;
        let reason = RejectReason::from_u16(reason_code).ok_or_else(|| {
            HandshakeCodecError::Decode(format!("unknown reject reason: {reason_code:#06x}"))
        })?;
        let msg_end = (4 + msg_len).min(p.len());
        let message = String::from_utf8_lossy(&p[4..msg_end]).into_owned();
        Ok(Reject { reason, message })
    }
}

// ---------------------------------------------------------------------------
// Handshake frame wrapper for unified send/recv
// ---------------------------------------------------------------------------

/// A framed handshake message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandshakeFrame {
    Hello(Hello),
    Accept(Accept),
    Reject(Reject),
}

impl HandshakeFrame {
    /// Encode this frame to wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, HandshakeCodecError> {
        match self {
            Self::Hello(m) => m.encode(),
            Self::Accept(m) => m.encode(),
            Self::Reject(m) => m.encode(),
        }
    }

    /// Decode a frame from wire bytes using the kind byte at offset 4.
    pub fn decode(bytes: &[u8]) -> Result<Self, HandshakeCodecError> {
        if bytes.len() < FRAME_HEADER_SIZE {
            return Err(HandshakeCodecError::TooShort(bytes.len()));
        }
        match bytes[4] {
            MSG_KIND_HELLO => Ok(Self::Hello(Hello::decode(bytes)?)),
            MSG_KIND_ACCEPT => Ok(Self::Accept(Accept::decode(bytes)?)),
            MSG_KIND_REJECT => Ok(Self::Reject(Reject::decode(bytes)?)),
            other => Err(HandshakeCodecError::UnknownKind(other)),
        }
    }
}

// ---------------------------------------------------------------------------
// Handshake state machine
// ---------------------------------------------------------------------------

/// The handshake state machine for the session initiator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandshakeStateMachine {
    /// Initial state: no Hello sent yet.
    Idle,
    /// Hello has been sent, waiting for response.
    HelloSent { hello: Hello, timeout: Duration },
    /// Responder accepted; session parameters are negotiated.
    AcceptReceived { hello: Hello, accept: Accept },
    /// Responder rejected the session.
    RejectReceived { hello: Hello, reject: Reject },
    /// No response received within the timeout window.
    Timeout { hello: Hello },
}

impl Default for HandshakeStateMachine {
    fn default() -> Self {
        Self::Idle
    }
}

impl HandshakeStateMachine {
    /// Transition to HelloSent after sending a Hello.
    pub fn hello_sent(hello: Hello, timeout: Duration) -> Self {
        Self::HelloSent { hello, timeout }
    }

    /// Transition to AcceptReceived after receiving an Accept.
    pub fn accept_received(&self, accept: Accept) -> Result<Self, HandshakeError> {
        match self {
            Self::HelloSent { hello, .. } => Ok(Self::AcceptReceived {
                hello: hello.clone(),
                accept,
            }),
            other => Err(HandshakeError::StateMachine(format!(
                "expected HelloSent, got {other:?}"
            ))),
        }
    }

    /// Transition to RejectReceived after receiving a Reject.
    pub fn reject_received(&self, reject: Reject) -> Result<Self, HandshakeError> {
        match self {
            Self::HelloSent { hello, .. } => Ok(Self::RejectReceived {
                hello: hello.clone(),
                reject,
            }),
            other => Err(HandshakeError::StateMachine(format!(
                "expected HelloSent, got {other:?}"
            ))),
        }
    }

    /// Transition to Timeout when the response deadline expires.
    pub fn timeout(&self) -> Result<Self, HandshakeError> {
        match self {
            Self::HelloSent { hello, .. } => Ok(Self::Timeout {
                hello: hello.clone(),
            }),
            other => Err(HandshakeError::StateMachine(format!(
                "expected HelloSent, got {other:?}"
            ))),
        }
    }

    /// Whether the handshake is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::AcceptReceived { .. } | Self::RejectReceived { .. } | Self::Timeout { .. }
        )
    }

    /// Whether the handshake completed successfully.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::AcceptReceived { .. })
    }
}

// ---------------------------------------------------------------------------
// Handshake errors (I/O and state)
// ---------------------------------------------------------------------------

#[derive(Error, Debug, Clone)]
pub enum HandshakeError {
    #[error("handshake I/O error: {0}")]
    Io(String),
    #[error("handshake state machine error: {0}")]
    StateMachine(String),
    #[error("handshake codec error: {0}")]
    Codec(#[from] HandshakeCodecError),
    #[error("handshake timeout after {0:?}")]
    Timeout(Duration),
}

// ---------------------------------------------------------------------------
// Async handshake driver for initiator
// ---------------------------------------------------------------------------

/// Default handshake timeout: 5 seconds.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum frame size the initiator will attempt to read for a response.
const MAX_RESPONSE_FRAME_SIZE: usize = FRAME_HEADER_SIZE + REJECT_MESSAGE_MAX_LEN + 64;

async fn write_handshake_frame<T>(
    transport: &mut T,
    frame: HandshakeFrame,
    label: &'static str,
) -> Result<(), HandshakeError>
where
    T: AsyncWrite + Unpin,
{
    let wire = frame.encode()?;
    transport
        .write_all(&wire)
        .await
        .map_err(|e| HandshakeError::Io(format!("write {label}: {e}")))?;
    transport
        .flush()
        .await
        .map_err(|e| HandshakeError::Io(format!("flush {label}: {e}")))?;
    Ok(())
}

async fn read_handshake_frame<T>(
    transport: &mut T,
    max_frame_size: usize,
    label: &'static str,
) -> Result<HandshakeFrame, HandshakeError>
where
    T: AsyncRead + Unpin,
{
    let mut header_buf = [0u8; FRAME_HEADER_SIZE];
    let mut offset = 0usize;
    while offset < FRAME_HEADER_SIZE {
        let n = transport
            .read(&mut header_buf[offset..])
            .await
            .map_err(|e| HandshakeError::Io(format!("read {label} header: {e}")))?;
        if n == 0 {
            return Err(HandshakeError::Io(format!(
                "connection closed before {label} header"
            )));
        }
        offset += n;
    }

    let payload_len =
        u32::from_le_bytes([header_buf[5], header_buf[6], header_buf[7], header_buf[8]]) as usize;

    let total_len = FRAME_HEADER_SIZE + payload_len;
    if total_len > max_frame_size {
        return Err(HandshakeError::Codec(HandshakeCodecError::Decode(format!(
            "{label} frame too large: {total_len} bytes"
        ))));
    }

    let mut frame = Vec::with_capacity(total_len);
    frame.extend_from_slice(&header_buf);

    let mut payload_read = 0usize;
    let mut chunk = vec![0u8; payload_len];
    while payload_read < payload_len {
        let remaining = payload_len - payload_read;
        let n = transport
            .read(&mut chunk[..remaining])
            .await
            .map_err(|e| HandshakeError::Io(format!("read {label} payload: {e}")))?;
        if n == 0 {
            return Err(HandshakeError::Io(format!(
                "connection closed before {label} payload"
            )));
        }
        frame.extend_from_slice(&chunk[..n]);
        payload_read += n;
    }

    HandshakeFrame::decode(&frame).map_err(HandshakeError::from)
}

/// Run the initiator side of the session handshake over a generic transport.
///
/// Sends `hello`, then waits for either an Accept or Reject response within
/// `timeout`. Returns the final [`HandshakeStateMachine`] state.
pub async fn initiate_handshake<T>(
    transport: &mut T,
    hello: Hello,
    timeout: Duration,
) -> Result<HandshakeStateMachine, HandshakeError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    write_handshake_frame(transport, HandshakeFrame::Hello(hello.clone()), "Hello").await?;

    let state = HandshakeStateMachine::hello_sent(hello, timeout);

    let result = tokio::time::timeout(
        timeout,
        read_handshake_frame(transport, MAX_RESPONSE_FRAME_SIZE, "response"),
    )
    .await;

    match result {
        Ok(Ok(HandshakeFrame::Accept(accept))) => state
            .accept_received(accept)
            .map_err(|e| HandshakeError::StateMachine(e.to_string())),
        Ok(Ok(HandshakeFrame::Reject(reject))) => state
            .reject_received(reject)
            .map_err(|e| HandshakeError::StateMachine(e.to_string())),
        Ok(Ok(other)) => Err(HandshakeError::StateMachine(format!(
            "unexpected response frame: {other:?}"
        ))),
        Ok(Err(e)) => Err(e),
        Err(_elapsed) => state
            .timeout()
            .map_err(|e| HandshakeError::StateMachine(e.to_string())),
    }
}

/// Run the responder side: read a Hello, apply a policy closure, and respond.
///
/// The `policy` closure receives the decoded [`Hello`] and returns either
/// `Ok(Accept)` or `Err(Reject)`.
pub async fn respond_to_handshake<T, F>(
    transport: &mut T,
    policy: F,
) -> Result<(Hello, HandshakeFrame), HandshakeError>
where
    T: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&Hello) -> Result<Accept, Reject>,
{
    let hello_frame = read_handshake_frame(transport, MAX_RESPONSE_FRAME_SIZE, "Hello").await?;
    let hello = match hello_frame {
        HandshakeFrame::Hello(h) => h,
        other => {
            return Err(HandshakeError::StateMachine(format!(
                "expected Hello, got {other:?}"
            )))
        }
    };

    let response = match policy(&hello) {
        Ok(accept) => HandshakeFrame::Accept(accept),
        Err(reject) => HandshakeFrame::Reject(reject),
    };

    write_handshake_frame(transport, response.clone(), "response").await?;

    Ok((hello, response))
}

// ---------------------------------------------------------------------------
// Session lifecycle: full connect/accept/close state machine
// ---------------------------------------------------------------------------

/// Session-level state for the full lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionLifecycleState {
    /// No session in progress.
    Idle,
    /// Outgoing connection is negotiating its Hello response.
    Connecting,
    /// Incoming connection is validating a peer Hello.
    Accepting,
    /// Session is established and ready for data-plane traffic.
    Connected,
    /// Graceful teardown has started.
    Closing,
    /// Session has terminated.
    Closed,
}

impl Default for SessionLifecycleState {
    fn default() -> Self {
        Self::Idle
    }
}

impl SessionLifecycleState {
    /// Stable lowercase state label for logs and diagnostics.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Connecting => "connecting",
            Self::Accepting => "accepting",
            Self::Connected => "connected",
            Self::Closing => "closing",
            Self::Closed => "closed",
        }
    }

    /// Returns true when no normal lifecycle transition can leave this state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Returns true when the session may carry data-plane messages.
    pub fn is_established(&self) -> bool {
        matches!(self, Self::Connected)
    }
}

/// Error type for lifecycle operations around the session handshake.
#[derive(Error, Debug, Clone)]
pub enum LifecycleError {
    #[error("invalid state transition: from {from} to {to}")]
    InvalidTransition { from: String, to: String },
    #[error("handshake error: {0}")]
    Handshake(String),
    #[error("session already terminal")]
    AlreadyTerminal,
    #[error("rejected: {reason} - {message}")]
    Rejected { reason: String, message: String },
}

impl From<HandshakeError> for LifecycleError {
    fn from(e: HandshakeError) -> Self {
        LifecycleError::Handshake(e.to_string())
    }
}

/// Tracks client and server session state across connect, accept, and close.
pub struct SessionLifecycle {
    state: SessionLifecycleState,
    timeout: Duration,
    session_token: Option<u64>,
}

impl SessionLifecycle {
    /// Create a lifecycle tracker with the supplied handshake timeout.
    pub fn new(timeout: Duration) -> Self {
        Self {
            state: SessionLifecycleState::Idle,
            timeout,
            session_token: None,
        }
    }

    /// Current lifecycle state.
    pub fn state(&self) -> SessionLifecycleState {
        self.state
    }

    /// Session token negotiated during a successful accept response.
    pub fn session_token(&self) -> Option<u64> {
        self.session_token
    }

    fn transition(&mut self, to: SessionLifecycleState) -> Result<(), LifecycleError> {
        let valid = matches!(
            (self.state, to),
            (
                SessionLifecycleState::Idle,
                SessionLifecycleState::Connecting
            ) | (
                SessionLifecycleState::Idle,
                SessionLifecycleState::Accepting
            ) | (
                SessionLifecycleState::Connecting,
                SessionLifecycleState::Connected
            ) | (
                SessionLifecycleState::Connecting,
                SessionLifecycleState::Closed
            ) | (
                SessionLifecycleState::Accepting,
                SessionLifecycleState::Connected
            ) | (
                SessionLifecycleState::Accepting,
                SessionLifecycleState::Closed
            ) | (
                SessionLifecycleState::Connected,
                SessionLifecycleState::Closing
            ) | (
                SessionLifecycleState::Closing,
                SessionLifecycleState::Closing
            ) | (
                SessionLifecycleState::Closing,
                SessionLifecycleState::Closed
            )
        );
        if valid {
            self.state = to;
            Ok(())
        } else {
            Err(LifecycleError::InvalidTransition {
                from: self.state.as_str().to_string(),
                to: to.as_str().to_string(),
            })
        }
    }

    /// Client-side negotiation: send Hello and wait for Accept or Reject.
    pub async fn connect<S>(
        &mut self,
        stream: &mut S,
        node_id: u64,
        protocol_version: u32,
        feature_flags: u64,
    ) -> Result<(), LifecycleError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.transition(SessionLifecycleState::Connecting)?;

        let result = self
            .connect_inner(stream, node_id, protocol_version, feature_flags)
            .await;
        if result.is_err() {
            self.state = SessionLifecycleState::Closed;
        }
        result
    }

    async fn connect_inner<S>(
        &mut self,
        stream: &mut S,
        node_id: u64,
        protocol_version: u32,
        feature_flags: u64,
    ) -> Result<(), LifecycleError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let hello = Hello {
            node_id,
            protocol_version,
            feature_flags,
        };
        tokio::time::timeout(
            self.timeout,
            write_handshake_frame(stream, HandshakeFrame::Hello(hello), "Hello"),
        )
        .await
        .map_err(|_| LifecycleError::Handshake("write timeout".into()))??;

        let response_frame = tokio::time::timeout(
            self.timeout,
            read_handshake_frame(stream, MAX_RESPONSE_FRAME_SIZE, "response"),
        )
        .await
        .map_err(|_| LifecycleError::Handshake("read timeout".into()))??;

        match response_frame {
            HandshakeFrame::Accept(accept) => {
                self.session_token = Some(accept.session_token);
                self.transition(SessionLifecycleState::Connected)?;
                Ok(())
            }
            HandshakeFrame::Reject(reject) => Err(LifecycleError::Rejected {
                reason: reject.reason.as_str().to_string(),
                message: reject.message,
            }),
            other => Err(LifecycleError::Handshake(format!(
                "unexpected response frame: {other:?}"
            ))),
        }
    }

    /// Server-side negotiation: read Hello, apply policy, and send a response.
    pub async fn accept<S, F>(&mut self, stream: &mut S, decide: F) -> Result<(), LifecycleError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&Hello) -> Result<Accept, Reject>,
    {
        self.transition(SessionLifecycleState::Accepting)?;

        let result = self.accept_inner(stream, decide).await;
        if result.is_err() {
            self.state = SessionLifecycleState::Closed;
        }
        result
    }

    async fn accept_inner<S, F>(&mut self, stream: &mut S, decide: F) -> Result<(), LifecycleError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&Hello) -> Result<Accept, Reject>,
    {
        let hello_frame = tokio::time::timeout(
            self.timeout,
            read_handshake_frame(stream, MAX_RESPONSE_FRAME_SIZE, "Hello"),
        )
        .await
        .map_err(|_| LifecycleError::Handshake("read timeout".into()))??;

        let hello = match hello_frame {
            HandshakeFrame::Hello(h) => h,
            other => {
                return Err(LifecycleError::Handshake(format!(
                    "expected Hello, got {other:?}"
                )))
            }
        };

        match decide(&hello) {
            Ok(accept) => {
                self.session_token = Some(accept.session_token);
                tokio::time::timeout(
                    self.timeout,
                    write_handshake_frame(stream, HandshakeFrame::Accept(accept), "Accept"),
                )
                .await
                .map_err(|_| LifecycleError::Handshake("write timeout".into()))??;
                self.transition(SessionLifecycleState::Connected)?;
                Ok(())
            }
            Err(reject) => {
                let reason = reject.reason.as_str().to_string();
                let message = reject.message.clone();
                let _ = tokio::time::timeout(
                    self.timeout,
                    write_handshake_frame(stream, HandshakeFrame::Reject(reject), "Reject"),
                )
                .await;
                Err(LifecycleError::Rejected { reason, message })
            }
        }
    }

    /// Graceful local close. The caller still owns the underlying transport close.
    pub fn close(&mut self) -> Result<(), LifecycleError> {
        self.transition(SessionLifecycleState::Closing)?;
        self.transition(SessionLifecycleState::Closed)?;
        Ok(())
    }

    /// Force local lifecycle termination without transport I/O.
    pub fn force_close(&mut self) -> Result<(), LifecycleError> {
        if matches!(self.state, SessionLifecycleState::Closed) {
            return Err(LifecycleError::AlreadyTerminal);
        }
        self.state = SessionLifecycleState::Closed;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Hello encode/decode
    // -----------------------------------------------------------------------

    #[test]
    fn hello_encode_decode_roundtrip() {
        let original = Hello {
            node_id: 42,
            protocol_version: 1,
            feature_flags: 0xABCD,
        };
        let encoded = original.encode().expect("encode");
        let decoded = Hello::decode(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn hello_encode_known_length() {
        let h = Hello {
            node_id: 0,
            protocol_version: 0,
            feature_flags: 0,
        };
        let encoded = h.encode().expect("encode");
        assert_eq!(encoded.len(), 33);
        assert_eq!(&encoded[0..4], &HANDSHAKE_MAGIC.to_le_bytes());
        assert_eq!(encoded[4], MSG_KIND_HELLO);
    }

    #[test]
    fn hello_decode_bad_magic() {
        let mut bytes = vec![0u8; 33];
        bytes[0] = 0xFF;
        let result = Hello::decode(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("magic"));
    }

    #[test]
    fn hello_decode_wrong_kind() {
        let mut bytes = vec![0u8; 33];
        bytes[0..4].copy_from_slice(&HANDSHAKE_MAGIC.to_le_bytes());
        bytes[4] = MSG_KIND_REJECT;
        let result = Hello::decode(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn hello_decode_too_short() {
        let result = Hello::decode(&[0u8; 5]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("short"));
    }

    // -----------------------------------------------------------------------
    // Accept encode/decode
    // -----------------------------------------------------------------------

    #[test]
    fn accept_encode_decode_roundtrip() {
        let original = Accept {
            session_token: 0xDEAD_BEEF_CAFE_BABE,
            negotiated_version: 1,
            negotiated_features: 0xF00D,
        };
        let encoded = original.encode().expect("encode");
        let decoded = Accept::decode(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn accept_encode_known_length() {
        let a = Accept {
            session_token: 0,
            negotiated_version: 0,
            negotiated_features: 0,
        };
        let encoded = a.encode().expect("encode");
        assert_eq!(encoded.len(), 33);
        assert_eq!(encoded[4], MSG_KIND_ACCEPT);
    }

    #[test]
    fn accept_decode_bad_magic() {
        let mut bytes = vec![0u8; 33];
        bytes[4] = MSG_KIND_ACCEPT;
        bytes[0] = 0xFF;
        let result = Accept::decode(&bytes);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Reject encode/decode
    // -----------------------------------------------------------------------

    #[test]
    fn reject_encode_decode_roundtrip() {
        let original = Reject {
            reason: RejectReason::VersionMismatch,
            message: "protocol version 2 required".into(),
        };
        let encoded = original.encode().expect("encode");
        let decoded = Reject::decode(&encoded).expect("decode");
        assert_eq!(decoded.reason, original.reason);
        assert_eq!(decoded.message, original.message);
    }

    #[test]
    fn reject_encode_decode_all_reasons() {
        let reasons = [
            RejectReason::VersionMismatch,
            RejectReason::Unauthorized,
            RejectReason::InsufficientCapacity,
            RejectReason::FeatureMismatch,
            RejectReason::BadHello,
            RejectReason::InternalError,
        ];
        for &r in &reasons {
            let rej = Reject {
                reason: r,
                message: format!("test_{}", r.as_str()),
            };
            let encoded = rej.encode().expect("encode");
            let decoded = Reject::decode(&encoded).expect("decode");
            assert_eq!(decoded.reason, r);
            assert_eq!(decoded.message, format!("test_{}", r.as_str()));
        }
    }

    #[test]
    fn reject_encode_padding_is_4_byte_aligned() {
        let rej = Reject {
            reason: RejectReason::Unauthorized,
            message: "denied".into(),
        };
        let encoded = rej.encode().expect("encode");
        assert_eq!(encoded.len(), 21); // 9 header + 12 padded (4 + 6 = 10 -> 12)
    }

    #[test]
    fn reject_decode_unknown_reason() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&HANDSHAKE_MAGIC.to_le_bytes());
        buf.push(MSG_KIND_REJECT);
        buf.extend_from_slice(&4u32.to_le_bytes()); // payload_len
        buf.extend_from_slice(&0xFFFFu16.to_le_bytes()); // unknown reason
        buf.extend_from_slice(&0u16.to_le_bytes()); // zero-length message
        let result = Reject::decode(&buf);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unknown reject reason"));
    }

    // -----------------------------------------------------------------------
    // HandshakeFrame unified encode/decode
    // -----------------------------------------------------------------------

    #[test]
    fn frame_encode_decode_hello() {
        let hello = Hello {
            node_id: 1,
            protocol_version: 1,
            feature_flags: 0,
        };
        let frame = HandshakeFrame::Hello(hello.clone());
        let encoded = frame.encode().expect("encode");
        let decoded = HandshakeFrame::decode(&encoded).expect("decode");
        assert_eq!(decoded, HandshakeFrame::Hello(hello));
    }

    #[test]
    fn frame_encode_decode_accept() {
        let accept = Accept {
            session_token: 99,
            negotiated_version: 2,
            negotiated_features: 3,
        };
        let frame = HandshakeFrame::Accept(accept.clone());
        let encoded = frame.encode().expect("encode");
        let decoded = HandshakeFrame::decode(&encoded).expect("decode");
        assert_eq!(decoded, HandshakeFrame::Accept(accept));
    }

    #[test]
    fn frame_encode_decode_reject() {
        let reject = Reject {
            reason: RejectReason::InternalError,
            message: "oops".into(),
        };
        let frame = HandshakeFrame::Reject(reject.clone());
        let encoded = frame.encode().expect("encode");
        let decoded = HandshakeFrame::decode(&encoded).expect("decode");
        assert_eq!(decoded, HandshakeFrame::Reject(reject));
    }

    #[test]
    fn frame_decode_unknown_kind() {
        let mut buf = vec![0u8; FRAME_HEADER_SIZE];
        buf[0..4].copy_from_slice(&HANDSHAKE_MAGIC.to_le_bytes());
        buf[4] = 0xFF;
        buf[5..9].copy_from_slice(&0u32.to_le_bytes());
        let result = HandshakeFrame::decode(&buf);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HandshakeCodecError::UnknownKind(0xFF)
        ));
    }

    // -----------------------------------------------------------------------
    // HandshakeStateMachine transitions
    // -----------------------------------------------------------------------

    #[test]
    fn state_machine_happy_path() {
        let hello = Hello {
            node_id: 1,
            protocol_version: 1,
            feature_flags: 0,
        };
        let s = HandshakeStateMachine::hello_sent(hello.clone(), Duration::from_secs(5));
        assert!(matches!(s, HandshakeStateMachine::HelloSent { .. }));
        assert!(!s.is_terminal());

        let accept = Accept {
            session_token: 42,
            negotiated_version: 1,
            negotiated_features: 0,
        };
        let s = s.accept_received(accept).expect("accept");
        assert!(matches!(s, HandshakeStateMachine::AcceptReceived { .. }));
        assert!(s.is_terminal());
        assert!(s.is_accepted());
    }

    #[test]
    fn state_machine_reject_path() {
        let hello = Hello {
            node_id: 1,
            protocol_version: 1,
            feature_flags: 0,
        };
        let s = HandshakeStateMachine::hello_sent(hello.clone(), Duration::from_secs(5));
        let reject = Reject {
            reason: RejectReason::VersionMismatch,
            message: "nope".into(),
        };
        let s = s.reject_received(reject).expect("reject");
        assert!(matches!(s, HandshakeStateMachine::RejectReceived { .. }));
        assert!(s.is_terminal());
        assert!(!s.is_accepted());
    }

    #[test]
    fn state_machine_timeout_path() {
        let hello = Hello {
            node_id: 1,
            protocol_version: 1,
            feature_flags: 0,
        };
        let s = HandshakeStateMachine::hello_sent(hello.clone(), Duration::from_secs(5));
        let s = s.timeout().expect("timeout");
        assert!(matches!(s, HandshakeStateMachine::Timeout { .. }));
        assert!(s.is_terminal());
        assert!(!s.is_accepted());
    }

    #[test]
    fn state_machine_accept_from_idle_fails() {
        let s = HandshakeStateMachine::Idle;
        let accept = Accept {
            session_token: 0,
            negotiated_version: 0,
            negotiated_features: 0,
        };
        assert!(s.accept_received(accept).is_err());
    }

    #[test]
    fn state_machine_reject_from_idle_fails() {
        let s = HandshakeStateMachine::Idle;
        let reject = Reject {
            reason: RejectReason::BadHello,
            message: "x".into(),
        };
        assert!(s.reject_received(reject).is_err());
    }

    #[test]
    fn state_machine_timeout_from_idle_fails() {
        let s = HandshakeStateMachine::Idle;
        assert!(s.timeout().is_err());
    }

    #[test]
    fn state_machine_double_accept_fails() {
        let hello = Hello {
            node_id: 1,
            protocol_version: 1,
            feature_flags: 0,
        };
        let s = HandshakeStateMachine::hello_sent(hello, Duration::from_secs(5));
        let accept = Accept {
            session_token: 1,
            negotiated_version: 1,
            negotiated_features: 0,
        };
        let s = s.accept_received(accept.clone()).expect("first accept");
        assert!(s.accept_received(accept).is_err());
    }

    // -----------------------------------------------------------------------
    // RejectReason round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn reject_reason_from_u16_all_variants() {
        let all: &[(u16, RejectReason)] = &[
            (0x0001, RejectReason::VersionMismatch),
            (0x0002, RejectReason::Unauthorized),
            (0x0003, RejectReason::InsufficientCapacity),
            (0x0004, RejectReason::FeatureMismatch),
            (0x0005, RejectReason::BadHello),
            (0x0006, RejectReason::InternalError),
        ];
        for &(code, expected) in all {
            assert_eq!(RejectReason::from_u16(code), Some(expected));
        }
    }

    #[test]
    fn reject_reason_from_u16_unknown() {
        assert_eq!(RejectReason::from_u16(0x0000), None);
        assert_eq!(RejectReason::from_u16(0xFFFF), None);
    }

    #[test]
    fn reject_reason_as_str() {
        assert_eq!(RejectReason::VersionMismatch.as_str(), "version_mismatch");
        assert_eq!(RejectReason::Unauthorized.as_str(), "unauthorized");
        assert_eq!(
            RejectReason::InsufficientCapacity.as_str(),
            "insufficient_capacity"
        );
        assert_eq!(RejectReason::FeatureMismatch.as_str(), "feature_mismatch");
        assert_eq!(RejectReason::BadHello.as_str(), "bad_hello");
        assert_eq!(RejectReason::InternalError.as_str(), "internal_error");
    }

    // -----------------------------------------------------------------------
    // Async handshake integration tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn async_handshake_happy_path() {
        let (mut client, server) = tokio::io::duplex(1024);

        let hello = Hello {
            node_id: 7,
            protocol_version: 3,
            feature_flags: 0xCAFE,
        };

        let server_handle = tokio::spawn(async move {
            let mut s = server;
            let (h, response) = respond_to_handshake(&mut s, |h| {
                assert_eq!(h.node_id, 7);
                assert_eq!(h.protocol_version, 3);
                Ok(Accept {
                    session_token: 0xBEEF,
                    negotiated_version: 3,
                    negotiated_features: 0xCAFE,
                })
            })
            .await
            .expect("responder");

            assert_eq!(h.node_id, 7);
            assert!(matches!(response, HandshakeFrame::Accept(..)));
        });

        let state = initiate_handshake(&mut client, hello.clone(), Duration::from_secs(2))
            .await
            .expect("initiator");

        assert!(state.is_accepted());
        if let HandshakeStateMachine::AcceptReceived {
            hello: h,
            accept: a,
        } = &state
        {
            assert_eq!(h.node_id, 7);
            assert_eq!(a.session_token, 0xBEEF);
            assert_eq!(a.negotiated_version, 3);
        } else {
            panic!("unexpected state: {state:?}");
        }

        server_handle.await.expect("server join");
    }

    #[tokio::test]
    async fn async_handshake_version_mismatch() {
        let (mut client, server) = tokio::io::duplex(1024);

        let hello = Hello {
            node_id: 1,
            protocol_version: 99,
            feature_flags: 0,
        };

        let server_handle = tokio::spawn(async move {
            let mut s = server;
            let (_h, response) = respond_to_handshake(&mut s, |h| {
                if h.protocol_version > 10 {
                    return Err(Reject {
                        reason: RejectReason::VersionMismatch,
                        message: "unsupported protocol version".into(),
                    });
                }
                Ok(Accept {
                    session_token: 0,
                    negotiated_version: h.protocol_version,
                    negotiated_features: 0,
                })
            })
            .await
            .expect("responder");

            assert!(matches!(response, HandshakeFrame::Reject(..)));
        });

        let state = initiate_handshake(&mut client, hello.clone(), Duration::from_secs(2))
            .await
            .expect("initiator");

        assert!(matches!(
            state,
            HandshakeStateMachine::RejectReceived { .. }
        ));
        if let HandshakeStateMachine::RejectReceived { reject, .. } = &state {
            assert_eq!(reject.reason, RejectReason::VersionMismatch);
            assert_eq!(reject.message, "unsupported protocol version");
        }

        server_handle.await.expect("server join");
    }

    #[tokio::test]
    async fn async_handshake_timeout() {
        let (mut client, _server) = tokio::io::duplex(64);
        // _server stays alive but nobody reads from it;
        // the initiator's read will time out

        let hello = Hello {
            node_id: 1,
            protocol_version: 1,
            feature_flags: 0,
        };

        let state = initiate_handshake(&mut client, hello.clone(), Duration::from_millis(100))
            .await
            .expect("initiator");

        assert!(matches!(state, HandshakeStateMachine::Timeout { .. }));
        assert!(state.is_terminal());
    }

    #[test]
    fn lifecycle_default_is_idle() {
        let lc = SessionLifecycle::new(Duration::from_secs(5));
        assert!(matches!(lc.state(), SessionLifecycleState::Idle));
        assert!(!lc.state().is_terminal());
        assert!(!lc.state().is_established());
        assert_eq!(lc.session_token(), None);
    }

    #[test]
    fn lifecycle_state_labels_and_predicates() {
        assert_eq!(SessionLifecycleState::Idle.as_str(), "idle");
        assert_eq!(SessionLifecycleState::Connecting.as_str(), "connecting");
        assert_eq!(SessionLifecycleState::Accepting.as_str(), "accepting");
        assert_eq!(SessionLifecycleState::Connected.as_str(), "connected");
        assert_eq!(SessionLifecycleState::Closing.as_str(), "closing");
        assert_eq!(SessionLifecycleState::Closed.as_str(), "closed");

        assert!(!SessionLifecycleState::Idle.is_terminal());
        assert!(!SessionLifecycleState::Connecting.is_terminal());
        assert!(!SessionLifecycleState::Accepting.is_terminal());
        assert!(!SessionLifecycleState::Connected.is_terminal());
        assert!(!SessionLifecycleState::Closing.is_terminal());
        assert!(SessionLifecycleState::Closed.is_terminal());

        assert!(!SessionLifecycleState::Idle.is_established());
        assert!(!SessionLifecycleState::Connecting.is_established());
        assert!(!SessionLifecycleState::Accepting.is_established());
        assert!(SessionLifecycleState::Connected.is_established());
        assert!(!SessionLifecycleState::Closing.is_established());
        assert!(!SessionLifecycleState::Closed.is_established());
    }

    #[test]
    fn lifecycle_close_happy_path() {
        let mut lc = SessionLifecycle::new(Duration::from_secs(5));
        lc.state = SessionLifecycleState::Connected;
        lc.close().expect("close");
        assert!(matches!(lc.state(), SessionLifecycleState::Closed));
        assert!(lc.state().is_terminal());
    }

    #[test]
    fn lifecycle_close_from_idle_fails() {
        let mut lc = SessionLifecycle::new(Duration::from_secs(5));
        let result = lc.close();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid state transition"));
    }

    #[test]
    fn lifecycle_force_close_from_any_state() {
        let mut lc = SessionLifecycle::new(Duration::from_secs(5));
        lc.state = SessionLifecycleState::Connected;
        lc.force_close().expect("force close");
        assert!(matches!(lc.state(), SessionLifecycleState::Closed));
    }

    #[test]
    fn lifecycle_force_close_when_already_closed_fails() {
        let mut lc = SessionLifecycle::new(Duration::from_secs(5));
        lc.state = SessionLifecycleState::Closed;
        let result = lc.force_close();
        assert!(matches!(
            result.unwrap_err(),
            LifecycleError::AlreadyTerminal
        ));
    }

    #[test]
    fn lifecycle_invalid_transition_reports_states() {
        let mut lc = SessionLifecycle::new(Duration::from_secs(5));
        lc.state = SessionLifecycleState::Connected;
        let err = lc.transition(SessionLifecycleState::Idle).unwrap_err();
        assert!(err.to_string().contains("from connected to idle"));
    }

    #[tokio::test]
    async fn lifecycle_connect_accept_happy_path() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let server_handle = tokio::spawn(async move {
            let mut sl = SessionLifecycle::new(Duration::from_secs(2));
            sl.accept(&mut server, |hello| {
                assert_eq!(hello.node_id, 42);
                Ok(Accept {
                    session_token: 0xCAFE,
                    negotiated_version: hello.protocol_version,
                    negotiated_features: hello.feature_flags,
                })
            })
            .await
            .expect("server accept");
            assert!(matches!(sl.state(), SessionLifecycleState::Connected));
            assert_eq!(sl.session_token(), Some(0xCAFE));
        });

        let mut sl = SessionLifecycle::new(Duration::from_secs(2));
        sl.connect(&mut client, 42, 1, 0xABCD)
            .await
            .expect("client connect");
        assert!(matches!(sl.state(), SessionLifecycleState::Connected));
        assert_eq!(sl.session_token(), Some(0xCAFE));

        server_handle.await.expect("server join");
    }

    #[tokio::test]
    async fn lifecycle_connect_rejected() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let server_handle = tokio::spawn(async move {
            let mut sl = SessionLifecycle::new(Duration::from_secs(2));
            let result = sl
                .accept(&mut server, |_hello| {
                    Err(Reject {
                        reason: RejectReason::VersionMismatch,
                        message: "unsupported".into(),
                    })
                })
                .await;
            assert!(result.is_err());
            assert!(matches!(sl.state(), SessionLifecycleState::Closed));
        });

        let mut sl = SessionLifecycle::new(Duration::from_secs(2));
        let err = sl.connect(&mut client, 1, 99, 0).await.unwrap_err();
        assert!(matches!(err, LifecycleError::Rejected { .. }));
        assert!(err.to_string().contains("version_mismatch"));
        assert!(matches!(sl.state(), SessionLifecycleState::Closed));

        server_handle.await.expect("server join");
    }

    #[tokio::test]
    async fn lifecycle_connect_timeout() {
        let (mut client, _server) = tokio::io::duplex(64);

        let mut sl = SessionLifecycle::new(Duration::from_millis(50));
        let result = sl.connect(&mut client, 1, 1, 0).await;
        assert!(result.is_err());
        assert!(matches!(sl.state(), SessionLifecycleState::Closed));
    }

    #[tokio::test]
    async fn lifecycle_accept_timeout() {
        let (_client, mut server) = tokio::io::duplex(64);

        let mut sl = SessionLifecycle::new(Duration::from_millis(50));
        let result = sl
            .accept(&mut server, |_| {
                Ok(Accept {
                    session_token: 0,
                    negotiated_version: 0,
                    negotiated_features: 0,
                })
            })
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timeout"));
        assert!(matches!(sl.state(), SessionLifecycleState::Closed));
    }

    #[tokio::test]
    async fn lifecycle_accept_rejects_non_hello_frame() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let accept = Accept {
            session_token: 1,
            negotiated_version: 0,
            negotiated_features: 0,
        };
        let wire = HandshakeFrame::Accept(accept).encode().unwrap();
        let client_handle = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client.write_all(&wire).await.unwrap();
        });

        let mut sl = SessionLifecycle::new(Duration::from_secs(2));
        let result = sl
            .accept(&mut server, |_| {
                Ok(Accept {
                    session_token: 0,
                    negotiated_version: 0,
                    negotiated_features: 0,
                })
            })
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected Hello"));

        client_handle.await.expect("client join");
    }

    #[tokio::test]
    async fn lifecycle_full_connect_accept_close_flow() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let server_handle = tokio::spawn(async move {
            let mut sl = SessionLifecycle::new(Duration::from_secs(2));
            sl.accept(&mut server, |hello| {
                Ok(Accept {
                    session_token: 100,
                    negotiated_version: hello.protocol_version,
                    negotiated_features: hello.feature_flags,
                })
            })
            .await
            .expect("accept");
            sl.close().expect("server close");
            assert!(matches!(sl.state(), SessionLifecycleState::Closed));
        });

        let mut sl = SessionLifecycle::new(Duration::from_secs(2));
        sl.connect(&mut client, 7, 3, 0xBEEF)
            .await
            .expect("connect");
        assert!(sl.state().is_established());
        sl.close().expect("client close");
        assert!(sl.state().is_terminal());

        server_handle.await.expect("server join");
    }

    #[tokio::test]
    async fn lifecycle_connect_with_different_session_tokens() {
        for token in [0u64, 1, u64::MAX] {
            let (mut client, mut server) = tokio::io::duplex(1024);
            let server_handle = tokio::spawn(async move {
                let mut sl = SessionLifecycle::new(Duration::from_secs(2));
                sl.accept(&mut server, |_| {
                    Ok(Accept {
                        session_token: token,
                        negotiated_version: 1,
                        negotiated_features: 0,
                    })
                })
                .await
                .expect("accept");
                assert_eq!(sl.session_token(), Some(token));
            });

            let mut sl = SessionLifecycle::new(Duration::from_secs(2));
            sl.connect(&mut client, 1, 1, 0).await.expect("connect");
            assert_eq!(sl.session_token(), Some(token));

            server_handle.await.expect("server join");
        }
    }

    #[test]
    fn state_machine_default_is_idle() {
        let s = HandshakeStateMachine::default();
        assert!(matches!(s, HandshakeStateMachine::Idle));
    }
}
