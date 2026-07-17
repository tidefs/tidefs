// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport per-connection async receive loop: reads raw bytes from a TCP
//! socket, decodes length-delimited frames via [`tidefs_binary_schema_framing`],
//! demultiplexes by channel stream-ID, and dispatches complete messages to
//! the inbound router ([`crate::dispatch::MessageDispatch`]).
//!
//! ## Architecture
//!
//! ```text
//! TcpStream (read half)
//!   |
//!   v
//! ConnectionReceiver::recv_loop()
//!   |
//!   +-- tokio::io::read -- framing buffer
//!   |                         |
//!   |                         v
//!   |              FramingDecoder::feed()
//!   |                         |
//!   |                         v
//!   |                  Vec<FramedMessage>
//!   |                         |
//!   |     +-------------------+-------------------+
//!   |     v                                       v
//!   |  family_id -> MessageFamily            type_id -> ChannelId
//!   |     |                                       |
//!   |     +-------------------+-------------------+
//!   |                         v
//!   |                  DecodedMessage
//!   |                         |
//!   |                         v
//!   |              MessageDispatch::dispatch_or_warn()
//! ```
//!
//! ## Frame format
//!
//! Each frame on the wire uses the canonical binary-schema envelope header
//! (64 bytes) followed by the payload body:
//!
//! ```text
//! [0..4)     magic          u32 LE  "VBFS" (0x5346_4256)
//! [4..12)    family_id      u64 LE  TRANSPORT_FAMILY_ID_BASE + MessageFamily discriminant
//! [12..20)   type_id        u64 LE  channel stream-ID (lower 16 bits = ChannelId; 0 = untagged)
//! [20..22)   version.major  u16 LE  always 1
//! [22..24)   version.minor  u16 LE  always 0
//! [24..28)   flags          u32 LE  reserved (0)
//! [28..30)   section_count  u16 LE  reserved (0)
//! [30..32)   _reserved      u16     zero
//! [32..40)   total_body_bytes u64 LE  payload length
//! [40]       fast_checksum  u8      ChecksumProfile::None (0)
//! [41]       strong_digest  u8      ChecksumProfile::None (0)
//! [42..48)   _reserved2     [u8;6]  zero
//! [48..56)   fingerprint_low u64 LE  reserved (0)
//! [56..60)   _reserved3     [u8;4]  zero
//! [60..64)   header_crc32c  u32 LE  CRC32C of bytes [0..60)
//! [64..)     payload        [u8]    variable-length message payload
//! ```
//!
//! The frame is self-delimiting: `total_body_bytes` tells the decoder exactly
//! how many payload bytes to read. The framing decoder handles partial reads,
//! buffer underrun, multi-frame coalescing, and corruption resynchronization
//! automatically.
//!
//! ## Integration points
//!
//! - **Upstream**: The receive loop is spawned after connection handshake
//!   completes (#5840) and runs until the connection is torn down (#5854).
//! - **Downstream**: Decoded messages are dispatched through
//!   [`MessageDispatch::dispatch_or_warn`] (#5834).
//! - **Channel demux**: Channel stream-ID is extracted from the envelope
//!   `type_id` field and attached to [`DecodedMessage::channel_id`] for
//!   per-channel delivery (#5827).

use std::sync::Arc;

use tidefs_binary_schema_core::SchemaFamilyId;
use tidefs_binary_schema_framing::{
    EnvelopeBuilder, FramedMessage, FramingDecoder, MAX_FRAME_BODY_BYTES,
};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::channel::{ChannelId, SharedChannelTable};
use crate::connection::ConnectionHandle;
use crate::control_service_dispatch::{
    register_control_service_dispatch, ControlServiceDispatch, ControlServiceReplySink,
};
use crate::data_service_dispatch::{
    register_data_service_dispatch, DataServiceDispatch, DataServiceReplySink,
};
use crate::dispatch::{DecodedMessage, MessageDispatch};
use crate::envelope::MessageFamily;
use crate::epoch_gate::EpochGate;
use crate::frame_governance::FrameSizeGovernor;
use crate::idle_timeout::IdleTracker;
use crate::receive_flow::{
    ReceiveCredit, ReceiveFlowController, SenderCreditTracker, RECEIVE_CREDIT_FRAME_SIZE,
};
use crate::recv_batch::RecvBatchDecoder;
use crate::types::SessionId;
use tokio::task::JoinHandle;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Added to the [`MessageFamily`] u8 discriminant to form the binary-schema
/// `family_id` field.  `MessageFamily::HelloClose` (0) maps to
/// `SchemaFamilyId(100)`, `HeartbeatAck` (1) maps to `SchemaFamilyId(101)`,
/// and so on.
pub const TRANSPORT_FAMILY_ID_BASE: u64 = 100;

/// Default size of the per-read socket buffer (64 KiB).
pub const DEFAULT_READ_BUF_SIZE: usize = 65536;

// ---------------------------------------------------------------------------
// ReceiveLoopError
// ---------------------------------------------------------------------------

/// Errors from the receive loop.
#[derive(Debug, thiserror::Error)]
pub enum ReceiveLoopError {
    /// An I/O error occurred reading from the TCP socket.
    #[error("receive I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The `family_id` field in the envelope header does not map to any
    /// known transport [`MessageFamily`].
    #[error("unknown message family id {0} in envelope header")]
    UnknownFamily(u64),

    /// The decoded message could not be dispatched (handler error).
    #[error("dispatch error: {0}")]
    Dispatch(#[from] crate::dispatch::DispatchError),
}

// ---------------------------------------------------------------------------
// ReceiveLoopConfig
// ---------------------------------------------------------------------------

/// Configuration for a [`ConnectionReceiver`].
#[derive(Clone, Debug)]
pub struct ReceiveLoopConfig {
    /// Maximum payload bytes accepted per frame (default 16 MiB).
    pub max_body_bytes: u64,
    /// Size of the per-read socket buffer (default 64 KiB).
    pub read_buf_size: usize,
}

impl Default for ReceiveLoopConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: MAX_FRAME_BODY_BYTES,
            read_buf_size: DEFAULT_READ_BUF_SIZE,
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectionReceiver
// ---------------------------------------------------------------------------

/// Owns the TCP socket read half, a framing decoder with configurable capacity,
/// and handles to the inbound router.
///
/// After construction, call [`recv_loop`](Self::recv_loop) to start the receive
/// loop. The loop runs until TCP EOF (clean shutdown) or an unrecoverable I/O
/// error.
pub struct ConnectionReceiver {
    epoch_gate: Option<std::sync::Arc<EpochGate>>,
    stream: TcpStream,
    decoder: FramingDecoder,
    dispatch: Arc<MessageDispatch>,
    config: ReceiveLoopConfig,
    session_id: Option<SessionId>,
    channel_table: Option<SharedChannelTable>,
    idle_tracker: Option<IdleTracker>,
    /// Telemetry accumulator for per-connection receive metrics.
    telemetry: Option<std::sync::Arc<crate::connection_telemetry::TelemetryAccumulator>>,
    /// Optional receive-side batch decoder for vectored-socket-read dispatch.
    recv_batch_decoder: Option<RecvBatchDecoder>,
    /// Optional handle for receive-window flow control accounting.
    /// When set, the receive loop consumes bytes from the window on
    /// message receipt and releases them after dispatch.
    connection_handle: Option<ConnectionHandle>,
    /// Per-session frame-size governor for receive byte caps.
    /// When set, the framing decoder is configured with the governoru2019s
    /// recv limit, and each decoded frame is checked against the governor.
    frame_size_governor: Option<FrameSizeGovernor>,
    /// Optional receive-flow controller for credit-based backpressure.
    /// Tracks consumed bytes and issues credit-refresh frames to the sender.
    receive_flow_controller: Option<ReceiveFlowController>,
    /// Shared sender-side credit tracker for inbound credit detection.
    credit_tracker: Option<Arc<SenderCreditTracker>>,
    /// Channel to queue credit-refresh frames for outbound transmission.
    credit_refresh_tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
}

impl ConnectionReceiver {
    /// Create a new connection receiver.
    ///
    /// The `stream` must be the read half of an established TCP connection
    /// that has completed the connection initialization handshake (#5840).
    /// The `dispatch` handle must have subsystem handlers registered for
    /// the message families expected on this connection.
    #[must_use]
    pub fn new(
        stream: TcpStream,
        dispatch: Arc<MessageDispatch>,
        config: ReceiveLoopConfig,
    ) -> Self {
        let decoder = FramingDecoder::new().with_max_body_bytes(config.max_body_bytes);
        Self {
            stream,
            decoder,
            dispatch,
            config,
            session_id: None,
            channel_table: None,
            idle_tracker: None,
            telemetry: None,
            epoch_gate: None,
            recv_batch_decoder: None,
            connection_handle: None,
            frame_size_governor: None,
            receive_flow_controller: None,
            credit_tracker: None,
            credit_refresh_tx: None,
        }
    }
    /// Attach an idle tracker for recording inbound activity.
    #[must_use]
    pub fn with_idle_tracker(mut self, tracker: IdleTracker) -> Self {
        self.idle_tracker = Some(tracker);
        self
    }

    /// Attach the authenticated transport session id for downstream handlers.
    #[must_use]
    pub fn with_session_id(mut self, session_id: SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Bind DATA service-id dispatch to this receive loop's StateTransfer path.
    ///
    /// The caller supplies the already-authenticated session id from connection
    /// establishment. Reply frames are emitted through `reply_sink`; the receive
    /// loop itself does not choose an outbound transport.
    #[must_use]
    pub fn with_data_service_dispatch(
        mut self,
        session_id: SessionId,
        dispatch: DataServiceDispatch,
        reply_sink: Arc<dyn DataServiceReplySink>,
    ) -> Self {
        self.session_id = Some(session_id);
        register_data_service_dispatch(&self.dispatch, dispatch, reply_sink);
        self
    }

    /// Bind CONTROL service-id dispatch to this receive loop's control path.
    ///
    /// The caller supplies the already-authenticated session id from connection
    /// establishment. Reply frames are emitted through `reply_sink`; the receive
    /// loop itself does not choose an outbound transport.
    #[must_use]
    pub fn with_control_service_dispatch(
        mut self,
        session_id: SessionId,
        dispatch: ControlServiceDispatch,
        reply_sink: Arc<dyn ControlServiceReplySink>,
    ) -> Self {
        self.session_id = Some(session_id);
        register_control_service_dispatch(&self.dispatch, dispatch, reply_sink);
        self
    }

    /// Attach a shared channel table for recording per-channel received bytes.
    ///
    /// When set, each decoded frame with a non-zero channel ID will record
    /// its payload length via [`ChannelTable::record_bytes_received`].
    #[must_use]
    pub fn with_channel_table(mut self, table: SharedChannelTable) -> Self {
        self.channel_table = Some(table);
        self
    }

    /// Attach a telemetry accumulator for recording per-connection receive metrics.
    ///
    /// The accumulator records bytes received, messages received, and errors
    /// on the hot path with lock-free atomic operations.
    #[must_use]
    pub fn with_telemetry(
        mut self,
        acc: std::sync::Arc<crate::connection_telemetry::TelemetryAccumulator>,
    ) -> Self {
        self.telemetry = Some(acc);
        self
    }

    /// Attach an epoch gate for stale-epoch message rejection.
    ///
    /// When set, every decoded frame's header epoch field is checked against
    /// the gate before dispatch. Messages with epoch < the gate's current
    /// epoch are rejected and counted.
    #[must_use]
    pub fn with_epoch_gate(mut self, gate: std::sync::Arc<EpochGate>) -> Self {
        self.epoch_gate = Some(gate);
        self
    }

    /// Attach a receive-side batch decoder for vectored-socket-read dispatch.
    ///
    /// When set, the receive loop feeds raw socket bytes to the batch decoder
    /// instead of the default [`FramingDecoder`]. The batch decoder scans for
    /// complete length-delimited frames in a single pass, accumulating decoded
    /// messages into a batch that is dispatched to the inbound router.
    #[must_use]
    pub fn with_recv_batch(mut self, decoder: RecvBatchDecoder) -> Self {
        self.recv_batch_decoder = Some(decoder);
        self
    }

    /// Attach a connection handle for receive-window flow control accounting.
    ///
    /// When set, each decoded frame dispatched through the receive loop
    /// consumes bytes from the per-connection [`ReceiveWindow`] before
    /// dispatch and releases them after the handler completes.
    #[must_use]
    pub fn with_connection_handle(mut self, handle: ConnectionHandle) -> Self {
        self.connection_handle = Some(handle);
        self
    }

    /// Attach a frame-size governor for per-session receive byte caps.
    ///
    /// When set, every decoded frameu2019s body length is checked against
    /// the governoru2019s recv limit before dispatch. Frames exceeding
    /// the limit are dropped and logged.
    #[must_use]
    pub fn with_frame_size_governor(mut self, governor: FrameSizeGovernor) -> Self {
        self.frame_size_governor = Some(governor);
        self
    }

    /// Attach receive-flow control for credit-based backpressure.
    ///
    /// The `controller` tracks consumed bytes and issues credit-refresh
    /// frames when the window drains below the configured threshold.
    /// The `tracker` is shared with the outbound send path and receives
    /// credit updates from inbound [`ReceiveCredit`] frames.
    /// The `refresh_tx` sender queues credit-refresh frames for the
    /// outbound write path.
    #[must_use]
    pub fn with_receive_flow(
        mut self,
        controller: ReceiveFlowController,
        tracker: Arc<SenderCreditTracker>,
        refresh_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        self.receive_flow_controller = Some(controller);
        self.credit_tracker = Some(tracker);
        self.credit_refresh_tx = Some(refresh_tx);
        self
    }

    /// Run the receive loop until EOF or an unrecoverable error.
    ///
    /// On each iteration:
    /// 1. Reads bytes from the TCP socket into an internal buffer.
    /// 2. Feeds the bytes to the framing decoder.
    /// 3. For each complete frame decoded, maps the envelope header fields
    ///    to a [`DecodedMessage`] and dispatches through the inbound router.
    ///
    /// Returns `Ok(())` on clean EOF (peer closed write half). On EOF, any
    /// remaining complete frames in the decoder buffer are drained and
    /// dispatched before returning.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiveLoopError::Io`] if a non-EOF socket error occurs.
    pub async fn recv_loop(&mut self) -> Result<(), ReceiveLoopError> {
        let mut buf = vec![0u8; self.config.read_buf_size];

        loop {
            match self.stream.read(&mut buf).await {
                Ok(0) => {
                    // Peer closed write half -- deliver any final complete
                    // frames sitting in the decoder buffer, then exit.
                    if self.recv_batch_decoder.is_some() {
                        self.drain_remaining_batch();
                    } else {
                        self.drain_remaining();
                    }
                    return Ok(());
                }
                Ok(n) => {
                    if let Some(ref t) = self.telemetry {
                        t.record_bytes_received(n as u64);
                    }
                    if let Some(ref mut batch_dec) = self.recv_batch_decoder {
                        let batch = batch_dec.feed(&buf[..n]);
                        self.dispatch_batch(batch);
                    } else {
                        let frames = self.decoder.feed(&buf[..n]);
                        self.dispatch_frames(frames);
                    }
                }
                Err(e) => {
                    if let Some(ref t) = self.telemetry {
                        let class = crate::connection_telemetry::TransportErrorClass::from_kind(
                            io_error_to_transport_kind(&e),
                        );
                        t.record_error(class);
                    }
                    tracing::warn!(
                        peer = %self.stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "unknown".to_string()),
                        error = %e,
                        "receive loop I/O error, closing connection"
                    );
                    return Err(ReceiveLoopError::Io(e));
                }
            }
        }
    }

    /// Return a snapshot of diagnostic counters from the framing decoder.
    #[must_use]
    pub fn diagnostic_counters(&self) -> ReceiveLoopDiagnostics {
        ReceiveLoopDiagnostics {
            total_bytes_fed: self.decoder.total_bytes_fed(),
            frames_emitted: self.decoder.frames_emitted_count(),
            corrupt_skipped: self.decoder.corrupt_skipped_count(),
            buffered_bytes: self.decoder.buffered_bytes(),
        }
    }

    /// Return a reference to the TCP stream.
    #[must_use]
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Consume the receiver and return the underlying TCP stream.
    #[must_use]
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }

    /// Spawn the receive loop on a tokio task, returning a [`SpawnedReceiver`]
    /// that can be used for lifecycle management (abort on teardown).
    ///
    /// This consumes the `ConnectionReceiver`. The spawned task runs until
    /// TCP EOF or an unrecoverable I/O error.
    #[must_use]
    pub fn spawn(mut self) -> SpawnedReceiver {
        let handle = tokio::spawn(async move {
            if let Err(e) = self.recv_loop().await {
                tracing::warn!(
                    error = %e,
                    "receive loop exited with error"
                );
            }
            // Return TCP stream for potential reuse by caller.
            self.stream
        });
        SpawnedReceiver { handle }
    }

    // ----------------------------------------------------------------
    // Internal helpers
    // ----------------------------------------------------------------

    /// Drain any complete frames remaining in the decoder buffer.
    fn drain_remaining(&mut self) {
        let frames = self.decoder.feed(&[]);
        self.dispatch_frames(frames);
    }

    /// Drain any complete frames remaining in the batch decoder prefix buffer.
    fn drain_remaining_batch(&mut self) {
        if let Some(ref mut batch_dec) = self.recv_batch_decoder {
            let batch = batch_dec.feed(&[]);
            self.dispatch_batch(batch);
        }
    }

    /// Dispatch a batch of decoded frames to the inbound router.
    fn dispatch_frames(&mut self, frames: Vec<FramedMessage>) {
        let msg_count = frames.len();
        for frame in frames {
            let family = match family_id_to_message_family(frame.header.family_id) {
                Some(f) => f,
                None => {
                    tracing::warn!(
                        family_id = frame.header.family_id.0,
                        "unknown message family, dropping frame"
                    );
                    continue;
                }
            };

            // Epoch gate check: reject messages carrying a stale epoch.
            // The epoch is carried in the envelope header's schema_fingerprint_low
            // field (bytes 48..56, u64 LE), repurposed as the transport epoch.
            if let Some(ref gate) = self.epoch_gate {
                let msg_epoch = frame.header.schema_fingerprint_low;
                if let Err(rejected) = gate.check(msg_epoch) {
                    tracing::warn!(
                        family = %family,
                        msg_epoch = msg_epoch,
                        gate_epoch = rejected.current_epoch,
                        "rejecting stale-epoch message"
                    );
                    if let Some(ref t) = self.telemetry {
                        t.record_error(
                            crate::connection_telemetry::TransportErrorClass::ProtocolViolation,
                        );
                    }
                    continue;
                }
            }

            let raw_type = frame.header.type_id.0;
            let channel_id = if raw_type == 0 {
                None
            } else {
                Some(ChannelId::new(raw_type as u16))
            };

            let body = frame.body;
            let payload_len = body.len();

            // Frame-size governance: check inbound frame body length
            // against the per-session recv cap and drop if exceeded.
            if let Some(ref governor) = self.frame_size_governor {
                // Note: session_class is not known at the framing level;
                // we use None here to apply the global recv limit.
                // Per-class overrides are enforced at the send side;
                // the receive side uses the global cap as a coarse gate.
                if let Err(e) = governor.check_recv(None, payload_len) {
                    tracing::warn!(
                        family = %family,
                        payload_len = payload_len,
                        error = %e,
                        "dropping inbound frame that exceeds recv cap"
                    );
                    if let Some(ref t) = self.telemetry {
                        t.record_error(
                            crate::connection_telemetry::TransportErrorClass::ProtocolViolation,
                        );
                    }
                    continue;
                }
            }

            let msg = if let Some(ch) = channel_id {
                DecodedMessage::with_channel_id(family, body, ch)
            } else {
                DecodedMessage::new(family, body)
            };
            let msg = if let Some(session_id) = self.session_id {
                msg.with_session_id(session_id)
            } else {
                msg
            };

            // Record received bytes on the channel table for per-channel accounting.
            if let (Some(ref table), Some(ch)) = (&self.channel_table, channel_id) {
                table
                    .write()
                    .unwrap()
                    .record_bytes_received(ch, payload_len as u64);
            }

            // Receive-window flow control: consume bytes before dispatch.
            // If the window is exhausted, drop the frame (backpressure signal).
            let consumed = if let Some(ref handle) = self.connection_handle {
                handle.receive_window_consume(payload_len as u64).is_ok()
            } else {
                true
            };

            // Inbound window advertisement decode: messages on the HeartbeatAck
            // family with exactly WINDOW_ADVERTISEMENT_FRAME_SIZE bytes of payload
            // may carry a peer window advertisement. Decode and store the peer's
            // available capacity; the outbound send path consults this to throttle sends.
            let is_advertisement = family == crate::envelope::MessageFamily::HeartbeatAck
                && payload_len == crate::flow_control::WINDOW_ADVERTISEMENT_FRAME_SIZE;

            if is_advertisement {
                if let Some(ref handle) = self.connection_handle {
                    if let Some(adv) =
                        crate::flow_control::WindowAdvertisement::decode(&msg.payload)
                    {
                        handle.set_peer_window(adv.window_bytes);
                        tracing::trace!(
                            window_bytes = adv.window_bytes,
                            "stored peer window advertisement"
                        );
                    }
                }
            }

            // Receive-flow credit detection: HeartbeatAck frames with
            // exactly RECEIVE_CREDIT_FRAME_SIZE bytes may carry a
            // ReceiveCredit grant from the peer. Decode and add to the
            // sender-side credit tracker.
            let is_receive_credit = family == crate::envelope::MessageFamily::HeartbeatAck
                && payload_len == RECEIVE_CREDIT_FRAME_SIZE;

            if is_receive_credit {
                if let Some(ref tracker) = self.credit_tracker {
                    if let Some(credit) = ReceiveCredit::decode(&msg.payload) {
                        tracker.add_credits(credit.credits);
                        tracing::trace!(
                            credits = credit.credits,
                            "received credit grant from peer"
                        );
                    }
                }
            }

            if consumed {
                self.dispatch.dispatch_or_warn(msg);

                // Release bytes back after dispatch completes (buffers freed).
                if let Some(ref handle) = self.connection_handle {
                    handle.receive_window_release(payload_len as u64);
                }

                // Record activity on the idle tracker for inbound messages.
                if let Some(ref tracker) = self.idle_tracker {
                    tracker.record_activity();
                }

                // Receive-flow controller: after dispatching a frame,
                // consume bytes from the credit window and issue a
                // credit refresh if the window has drained below the
                // configured threshold.
                if let Some(ref mut ctrl) = self.receive_flow_controller {
                    ctrl.consume(payload_len as u64);
                    let now = std::time::Instant::now();
                    if let Some(credit) = ctrl.needs_refresh(now) {
                        let refresh_frame = credit.encode().to_vec();
                        if let Some(ref tx) = self.credit_refresh_tx {
                            let _ = tx.send(refresh_frame);
                        }
                        ctrl.mark_refreshed(now);
                    }
                }
            } else {
                tracing::debug!(
                    payload_len,
                    "receive window exhausted, dropping inbound frame"
                );
            }
        }
        // Record messages received for telemetry (after dispatching all).
        if let Some(ref t) = self.telemetry {
            for _ in 0..msg_count {
                t.record_message_received();
            }
        }
    }

    /// Dispatch a batch of (MessageFamily, payload) pairs decoded by the
    /// [`RecvBatchDecoder`] to the inbound router.
    ///
    /// Messages dispatched through this path carry no channel ID (the codec
    /// format does not encode channel information) and bypass the epoch gate
    /// check (the codec format does not carry an epoch field).
    fn dispatch_batch(&self, batch: Vec<(MessageFamily, Vec<u8>)>) {
        let msg_count = batch.len();
        for (family, payload) in batch {
            let msg = DecodedMessage::new(family, payload);
            let msg = if let Some(session_id) = self.session_id {
                msg.with_session_id(session_id)
            } else {
                msg
            };

            // Per-channel accounting is not available for batch-decoded
            // messages (no channel ID in the codec format).

            self.dispatch.dispatch_or_warn(msg);

            // Record activity on the idle tracker for inbound messages.
            if let Some(ref tracker) = self.idle_tracker {
                tracker.record_activity();
            }
        }
        // Record messages received for telemetry (after dispatching all).
        if let Some(ref t) = self.telemetry {
            for _ in 0..msg_count {
                t.record_message_received();
            }
        }
    }
}
// SpawnedReceiver
// ---------------------------------------------------------------------------

/// Handle to a spawned receive loop task.
///
/// Obtained via [`ConnectionReceiver::spawn()`]. The contained [`JoinHandle`]
/// can be aborted to tear down the receive loop on connection close.
pub struct SpawnedReceiver {
    /// The tokio task handle for the spawned receive loop.
    pub handle: JoinHandle<TcpStream>,
}

impl SpawnedReceiver {
    /// Abort the spawned receive loop.
    pub fn abort(&self) {
        self.handle.abort();
    }

    /// Check whether the receive loop task has completed.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }
}
// ReceiveLoopDiagnostics
// ---------------------------------------------------------------------------

/// Snapshot of diagnostic counters from a running receive loop.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReceiveLoopDiagnostics {
    /// Total bytes fed into the framing decoder.
    pub total_bytes_fed: u64,
    /// Number of complete frames emitted.
    pub frames_emitted: u64,
    /// Number of corrupt frames skipped during resynchronization.
    pub corrupt_skipped: u64,
    /// Bytes currently buffered in the decoder (partial frame).
    pub buffered_bytes: usize,
}
// ---------------------------------------------------------------------------
// DrainVelocityTracker
// ---------------------------------------------------------------------------

/// Tracks receive-loop drain velocity for peer health scoring (#5885).
///
/// Maintains a moving estimate of messages drained per second from the
/// receive loop's diagnostic counters, sampled on each `feed_health_drain`
/// call.
#[derive(Clone, Debug, Default)]
pub struct DrainVelocityTracker {
    /// Last observed `frames_emitted` value.
    last_frames: u64,
    /// Timestamp of the last observation.
    last_sample: Option<std::time::Instant>,
    /// Current EMA-based drain velocity (messages/s).
    velocity: f64,
}

impl DrainVelocityTracker {
    /// Create a new tracker with zero velocity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_frames: 0,
            last_sample: None,
            velocity: 0.0,
        }
    }

    /// Sample the current diagnostics and update the velocity estimate.
    ///
    /// Call this periodically (e.g., once per batch drain completion or
    /// on a timer) with the current diagnostic counters.
    pub fn sample(&mut self, diag: &ReceiveLoopDiagnostics) {
        let now = std::time::Instant::now();
        let frames = diag.frames_emitted;

        if let Some(prev) = self.last_sample {
            let elapsed = now.duration_since(prev).as_secs_f64();
            if elapsed > 0.0 {
                let instant_rate = (frames - self.last_frames) as f64 / elapsed;
                // EMA with alpha = 0.3 for smoothing
                self.velocity = 0.3_f64.mul_add(instant_rate - self.velocity, self.velocity);
            }
        }

        self.last_frames = frames;
        self.last_sample = Some(now);
    }

    /// Current EMA drain velocity in messages per second.
    #[must_use]
    pub fn velocity(&self) -> f64 {
        self.velocity
    }

    /// Feed the current drain velocity into a health signal sink.
    pub fn feed_health_drain(
        &self,
        sink: &mut dyn crate::peer_health::HealthSignalSink,
        conn_id: crate::connection_registry::ConnectionId,
    ) {
        sink.ingest_signal(
            conn_id,
            crate::peer_health::HealthSignal::DrainVelocity(self.velocity),
        );
    }
}

// ---------------------------------------------------------------------------
// Family ID mapping
// ---------------------------------------------------------------------------

/// Map a [`MessageFamily`] variant to its binary-schema [`SchemaFamilyId`].
///
/// The mapping is: `TRANSPORT_FAMILY_ID_BASE + (family as u8)`.
/// `HelloClose` -> 100, `HeartbeatAck` -> 101, ..., `TransitionHoldResume` -> 109.
#[must_use]
pub fn message_family_to_family_id(family: MessageFamily) -> SchemaFamilyId {
    SchemaFamilyId(TRANSPORT_FAMILY_ID_BASE + family as u64)
}

/// Map a binary-schema [`SchemaFamilyId`] back to a [`MessageFamily`].
///
/// Returns `None` if the family ID is outside the transport range or does
/// not correspond to a known message family.
#[must_use]
pub fn family_id_to_message_family(id: SchemaFamilyId) -> Option<MessageFamily> {
    if id.0 < TRANSPORT_FAMILY_ID_BASE {
        return None;
    }
    let discriminant = (id.0 - TRANSPORT_FAMILY_ID_BASE) as u8;
    MessageFamily::try_from(discriminant).ok()
}

// ---------------------------------------------------------------------------
// Frame construction helpers (for send-side symmetry)
// ---------------------------------------------------------------------------

/// Build a framed message for transmission using the binary-schema framing
/// format.
///
/// Returns the complete wire bytes: 64-byte envelope header followed by
/// the payload.
///
/// The `channel_id` is encoded in the envelope `type_id` field. Pass
/// `ChannelId::default()` (channel 0) for untagged messages.
#[must_use]
pub fn build_frame(family: MessageFamily, channel_id: ChannelId, payload: &[u8]) -> Vec<u8> {
    use tidefs_binary_schema_core::SchemaVersion;

    let family_id = message_family_to_family_id(family);
    let type_id = tidefs_binary_schema_core::SchemaTypeId(channel_id.as_u16() as u64);

    let header = EnvelopeBuilder::new(family_id, type_id, SchemaVersion { major: 1, minor: 0 })
        .build(0, payload.len() as u64);

    let header_bytes = header.encode();
    let mut frame = Vec::with_capacity(header_bytes.len() + payload.len());
    frame.extend_from_slice(&header_bytes);
    frame.extend_from_slice(payload);
    frame
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map a `std::io::Error` to a `TransportErrorKind` for telemetry error-class recording.
///
/// This is used by both the receive loop and the outbound send pipeline to
/// classify I/O errors into the telemetry error taxonomy.
pub fn io_error_to_transport_kind(
    err: &std::io::Error,
) -> crate::error_classification::TransportErrorKind {
    use crate::error_classification::TransportErrorKind;
    match err.kind() {
        std::io::ErrorKind::ConnectionReset => TransportErrorKind::ConnectionReset,
        std::io::ErrorKind::ConnectionRefused => TransportErrorKind::ConnectionRefused,
        std::io::ErrorKind::TimedOut => TransportErrorKind::ConnectionTimeout,
        std::io::ErrorKind::BrokenPipe => TransportErrorKind::ConnectionReset,
        std::io::ErrorKind::UnexpectedEof => TransportErrorKind::ConnectionReset,
        _ => TransportErrorKind::InternalError,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_service_dispatch::{
        ControlServiceDispatchError, ControlServiceDispatchOutcome, ControlServiceFrame,
        ControlServiceHandler, CONTROL_SERVICE_MESSAGE_FAMILY,
    };
    use crate::data_service_dispatch::{
        DataServiceDispatchError, DataServiceDispatchOutcome, DataServiceFrame, DataServiceHandler,
        DATA_SERVICE_MESSAGE_FAMILY,
    };
    use crate::dispatch::MessageDispatch;
    use crate::envelope::MessageFamily;
    use crate::recv_batch::{RecvBatchConfig, RecvBatchDecoder};
    use std::sync::Mutex;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    // -------------------------------------------------------------------
    // Family ID mapping tests
    // -------------------------------------------------------------------

    #[test]
    fn family_id_round_trip_all_members() {
        for family in MessageFamily::all() {
            let id = message_family_to_family_id(family);
            let back = family_id_to_message_family(id).expect("round-trip should succeed");
            assert_eq!(back, family, "round-trip failed for {family}");
        }
    }

    #[test]
    fn family_id_below_base_returns_none() {
        assert!(family_id_to_message_family(SchemaFamilyId(0)).is_none());
        assert!(family_id_to_message_family(SchemaFamilyId(50)).is_none());
        assert!(family_id_to_message_family(SchemaFamilyId(99)).is_none());
    }

    #[test]
    fn family_id_above_range_returns_none() {
        // 110 is above the 100-109 range (only 10 families).
        assert!(family_id_to_message_family(SchemaFamilyId(110)).is_none());
        assert!(family_id_to_message_family(SchemaFamilyId(255)).is_none());
    }

    #[test]
    fn family_id_base_correct() {
        assert_eq!(TRANSPORT_FAMILY_ID_BASE, 100);
        let id = message_family_to_family_id(MessageFamily::HelloClose);
        assert_eq!(id.0, 100);
        let id = message_family_to_family_id(MessageFamily::TransitionHoldResume);
        assert_eq!(id.0, 109);
    }

    // -------------------------------------------------------------------
    // build_frame tests
    // -------------------------------------------------------------------

    #[test]
    fn build_frame_round_trips_through_decoder() {
        let payload = b"hello world";
        let family = MessageFamily::StateTransfer;
        let ch = ChannelId::new(7);

        let frame = build_frame(family, ch, payload);
        let mut decoder = FramingDecoder::new();
        let decoded = decoder.feed(&frame);
        assert_eq!(decoded.len(), 1);

        let msg = &decoded[0];
        let back_family = family_id_to_message_family(msg.header.family_id).unwrap();
        assert_eq!(back_family, family);
        assert_eq!(msg.header.type_id.0, 7);
        assert_eq!(msg.body, payload);
    }

    #[test]
    fn build_frame_zero_channel_untagged() {
        let payload = b"untagged message";
        let family = MessageFamily::HelloClose;
        let ch = ChannelId::default();

        let frame = build_frame(family, ch, payload);
        let mut decoder = FramingDecoder::new();
        let decoded = decoder.feed(&frame);
        assert_eq!(decoded.len(), 1);

        let msg = &decoded[0];
        assert_eq!(msg.header.type_id.0, 0);
        assert_eq!(msg.body, payload);
    }

    #[test]
    fn build_frame_empty_payload() {
        let frame = build_frame(MessageFamily::HeartbeatAck, ChannelId::new(1), &[]);
        let mut decoder = FramingDecoder::new();
        let decoded = decoder.feed(&frame);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].body.len(), 0);
    }

    #[test]
    fn build_frame_max_channel_id() {
        let frame = build_frame(
            MessageFamily::ShadowValidation,
            ChannelId::new(u16::MAX),
            b"data",
        );
        let mut decoder = FramingDecoder::new();
        let decoded = decoder.feed(&frame);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].header.type_id.0, u16::MAX as u64);
    }

    // -------------------------------------------------------------------
    // FramingDecoder: partial-read accumulation tests
    // -------------------------------------------------------------------

    #[test]
    fn decoder_partial_frame_across_multiple_feeds() {
        let payload = vec![0xABu8; 200];
        let frame = build_frame(MessageFamily::StateTransfer, ChannelId::new(3), &payload);
        let mut decoder = FramingDecoder::new();

        // Feed one byte at a time - decoder must accumulate and not panic.
        let mut total_emitted = 0usize;
        for &b in &frame {
            let emitted = decoder.feed(&[b]);
            total_emitted += emitted.len();
        }
        assert_eq!(total_emitted, 1);
        assert_eq!(decoder.frames_emitted_count(), 1);
        assert_eq!(decoder.corrupt_skipped_count(), 0);
    }

    #[test]
    fn decoder_split_mid_header() {
        let payload = vec![0xCDu8; 100];
        let frame = build_frame(
            MessageFamily::PublicationProgress,
            ChannelId::new(7),
            &payload,
        );
        let mut decoder = FramingDecoder::new();
        // Feed only the first 30 bytes of the 64-byte header.
        assert!(decoder.feed(&frame[..30]).is_empty());
        // Feed the rest - one complete frame should emerge.
        let frames = decoder.feed(&frame[30..]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body, payload);
    }

    #[test]
    fn decoder_split_mid_body() {
        let payload = vec![0xEFu8; 200];
        let frame = build_frame(
            MessageFamily::LeaseFenceDeadline,
            ChannelId::new(3),
            &payload,
        );
        let mut decoder = FramingDecoder::new();
        // Feed header + first 50 body bytes.
        let split = 64 + 50;
        assert!(decoder.feed(&frame[..split]).is_empty());
        // Feed the remaining body bytes.
        let frames = decoder.feed(&frame[split..]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body, payload);
    }

    #[test]
    fn decoder_multiple_complete_frames_one_read() {
        let bodies: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8; 64]).collect();
        let mut stream = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            let frame = build_frame(
                MessageFamily::StateTransfer,
                ChannelId::new(i as u16 + 1),
                body,
            );
            stream.extend_from_slice(&frame);
        }
        let mut decoder = FramingDecoder::new();
        let frames = decoder.feed(&stream);
        assert_eq!(frames.len(), 5);
        for (i, f) in frames.iter().enumerate() {
            assert_eq!(f.body, bodies[i]);
            assert_eq!(f.header.type_id.0, i as u64 + 1);
        }
    }

    // -------------------------------------------------------------------
    // Corruption recovery tests
    // -------------------------------------------------------------------

    #[test]
    fn decoder_bad_magic_before_valid_frame() {
        let payload = b"recovered";
        let frame = build_frame(MessageFamily::HelloClose, ChannelId::new(1), payload);
        let mut stream = vec![0u8; 20]; // garbage leading bytes
        stream.extend_from_slice(&frame);
        let mut decoder = FramingDecoder::new();
        let frames = decoder.feed(&stream);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body, payload);
    }

    #[test]
    fn decoder_corrupt_header_then_valid() {
        let payload = b"after-corrupt";
        let frame = build_frame(MessageFamily::ElectionControl, ChannelId::new(99), payload);
        // Fake magic + garbage header bytes, then real frame.
        let mut stream = 0x5346_4256u32.to_le_bytes().to_vec(); // "VBFS" magic
        stream.extend_from_slice(&[0xFFu8; 60]); // corrupt header remainder
        stream.extend_from_slice(&frame);
        let mut decoder = FramingDecoder::new();
        let frames = decoder.feed(&stream);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body, payload);
        assert!(decoder.corrupt_skipped_count() >= 1);
    }

    #[test]
    fn decoder_corrupt_mid_stream() {
        let f1 = build_frame(MessageFamily::StateTransfer, ChannelId::new(1), &[1u8; 10]);
        let f2 = build_frame(
            MessageFamily::ReplicaTransferVerify,
            ChannelId::new(2),
            &[2u8; 20],
        );
        let mut stream = f1.clone();
        // Insert fake magic + garbage between valid frames.
        stream.extend_from_slice(&0x5346_4256u32.to_le_bytes());
        stream.extend_from_slice(&[0xFFu8; 60]);
        stream.extend_from_slice(&f2);
        let mut decoder = FramingDecoder::new();
        let frames = decoder.feed(&stream);
        assert_eq!(frames.len(), 2);
        assert!(decoder.corrupt_skipped_count() >= 1);
    }

    #[test]
    fn decoder_all_zeroes_no_panic() {
        let mut decoder = FramingDecoder::new();
        let frames = decoder.feed(&[0u8; 256]);
        assert!(frames.is_empty());
    }

    #[test]
    fn decoder_reset_clears_state() {
        let frame = build_frame(MessageFamily::HeartbeatAck, ChannelId::new(5), b"hello");
        let mut decoder = FramingDecoder::new();
        assert!(decoder.feed(&frame[..10]).is_empty());
        decoder.reset();
        let frames = decoder.feed(&frame);
        assert_eq!(frames.len(), 1);
    }

    // -------------------------------------------------------------------
    // Diagnostic counters tests
    // -------------------------------------------------------------------

    #[test]
    fn decoder_diagnostic_counters_accurate() {
        let f1 = build_frame(MessageFamily::StateTransfer, ChannelId::new(1), b"hello");
        let f2 = build_frame(
            MessageFamily::ReplicaTransferVerify,
            ChannelId::new(2),
            b"goodbye",
        );
        let mut stream = f1.clone();
        stream.extend_from_slice(&f2);
        let mut decoder = FramingDecoder::new();
        let frames = decoder.feed(&stream);
        assert_eq!(frames.len(), 2);
        assert_eq!(decoder.frames_emitted_count(), 2);
        assert_eq!(decoder.total_bytes_fed(), stream.len() as u64);
        assert_eq!(decoder.buffered_bytes(), 0);
    }

    // -------------------------------------------------------------------
    // Zero-length payload test
    // -------------------------------------------------------------------

    #[test]
    fn decoder_zero_length_frame() {
        let frame = build_frame(MessageFamily::HelloClose, ChannelId::new(1), &[]);
        let mut decoder = FramingDecoder::new();
        let frames = decoder.feed(&frame);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body.len(), 0);
    }

    // -------------------------------------------------------------------
    // ConnectionReceiver unit tests
    // -------------------------------------------------------------------

    #[test]
    fn receive_loop_config_default() {
        let cfg = ReceiveLoopConfig::default();
        assert_eq!(cfg.max_body_bytes, MAX_FRAME_BODY_BYTES);
        assert_eq!(cfg.read_buf_size, DEFAULT_READ_BUF_SIZE);
    }

    #[test]
    fn receive_loop_diagnostics_default_is_zero() {
        let diag = ReceiveLoopDiagnostics::default();
        assert_eq!(diag.total_bytes_fed, 0);
        assert_eq!(diag.frames_emitted, 0);
        assert_eq!(diag.corrupt_skipped, 0);
        assert_eq!(diag.buffered_bytes, 0);
    }

    #[test]
    fn receive_loop_error_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        let e = ReceiveLoopError::Io(io_err);
        assert!(format!("{e}").contains("receive I/O error"));

        let e = ReceiveLoopError::UnknownFamily(999);
        assert!(format!("{e}").contains("999"));
    }

    // -------------------------------------------------------------------
    // Integration test: send frame through TCP, receive and dispatch
    // -------------------------------------------------------------------

    /// A recording handler that stores dispatched messages for test inspection.
    type RecordedDispatch = (MessageFamily, Vec<u8>, Option<ChannelId>);

    struct RecordingHandler {
        log: Mutex<Vec<RecordedDispatch>>,
    }

    impl RecordingHandler {
        fn new() -> Self {
            Self {
                log: Mutex::new(Vec::new()),
            }
        }

        fn log(&self) -> Vec<(MessageFamily, Vec<u8>, Option<ChannelId>)> {
            self.log.lock().unwrap().clone()
        }
    }

    impl crate::dispatch::MessageHandler for RecordingHandler {
        fn handle(&self, msg: DecodedMessage) -> Result<(), crate::dispatch::DispatchError> {
            self.log
                .lock()
                .unwrap()
                .push((msg.family, msg.payload, msg.channel_id));
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingControlServiceHandler {
        seen: Mutex<Vec<(SessionId, ControlServiceFrame)>>,
    }

    impl ControlServiceHandler for RecordingControlServiceHandler {
        fn handle_control_service_frame(
            &self,
            session_id: SessionId,
            frame: ControlServiceFrame,
        ) -> Result<ControlServiceDispatchOutcome, ControlServiceDispatchError> {
            self.seen.lock().unwrap().push((session_id, frame));
            Ok(ControlServiceDispatchOutcome::Consumed)
        }
    }

    struct ConsumedControlReplySink;

    impl ControlServiceReplySink for ConsumedControlReplySink {
        fn send_control_service_reply(
            &self,
            _session_id: SessionId,
            _frame: ControlServiceFrame,
        ) -> Result<(), ControlServiceDispatchError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingDataServiceHandler {
        seen: Mutex<Vec<(SessionId, DataServiceFrame)>>,
    }

    impl DataServiceHandler for RecordingDataServiceHandler {
        fn handle_data_service_frame(
            &self,
            session_id: SessionId,
            frame: DataServiceFrame,
        ) -> Result<DataServiceDispatchOutcome, DataServiceDispatchError> {
            self.seen.lock().unwrap().push((session_id, frame));
            Ok(DataServiceDispatchOutcome::Consumed)
        }
    }

    struct ConsumedDataReplySink;

    impl DataServiceReplySink for ConsumedDataReplySink {
        fn send_data_service_reply(
            &self,
            _session_id: SessionId,
            _frame: DataServiceFrame,
        ) -> Result<(), DataServiceDispatchError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn recv_loop_control_service_dispatch_shares_session_with_data_service() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let session_id = SessionId::new(42);
        let control_frame = ControlServiceFrame::new(0x06, 0x01, b"rpc".to_vec());
        let data_frame = DataServiceFrame::new(0x07, 0x02, b"bulk".to_vec());
        let control_payload = control_frame.encode().expect("encode control frame");
        let data_payload = data_frame.encode().expect("encode data frame");

        let sender = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
            let control = build_frame(
                CONTROL_SERVICE_MESSAGE_FAMILY,
                ChannelId::new(0),
                &control_payload,
            );
            let data = build_frame(
                DATA_SERVICE_MESSAGE_FAMILY,
                ChannelId::new(0),
                &data_payload,
            );
            stream.write_all(&control).await.unwrap();
            stream.write_all(&data).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let message_dispatch = Arc::new(MessageDispatch::new());
        let control_dispatch = ControlServiceDispatch::new();
        let control_handler = Arc::new(RecordingControlServiceHandler::default());
        control_dispatch.register(0x06, control_handler.clone());
        let data_dispatch = DataServiceDispatch::new();
        let data_handler = Arc::new(RecordingDataServiceHandler::default());
        data_dispatch.register(0x07, data_handler.clone());

        let mut receiver = ConnectionReceiver::new(
            server_stream,
            message_dispatch,
            ReceiveLoopConfig::default(),
        )
        .with_data_service_dispatch(session_id, data_dispatch, Arc::new(ConsumedDataReplySink))
        .with_control_service_dispatch(
            session_id,
            control_dispatch,
            Arc::new(ConsumedControlReplySink),
        );

        receiver.recv_loop().await.expect("clean receive EOF");
        sender.await.unwrap();

        assert_eq!(
            control_handler.seen.lock().unwrap().as_slice(),
            &[(session_id, control_frame)]
        );
        assert_eq!(
            data_handler.seen.lock().unwrap().as_slice(),
            &[(session_id, data_frame)]
        );
    }

    #[tokio::test]
    async fn recv_loop_end_to_end_dispatch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Spawn a sender that connects and sends two framed messages.
        let sender = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
            let f1 = build_frame(
                MessageFamily::StateTransfer,
                ChannelId::new(7),
                b"first-message",
            );
            let f2 = build_frame(
                MessageFamily::ReplicaTransferVerify,
                ChannelId::new(3),
                b"second-message",
            );
            tokio::io::AsyncWriteExt::write_all(&mut stream, &f1)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &f2)
                .await
                .unwrap();
            // Shutdown write to signal EOF.
            stream.shutdown().await.unwrap();
        });

        // Accept the connection.
        let (server_stream, _) = listener.accept().await.unwrap();

        // Set up dispatch with test handlers.
        let dispatch = Arc::new(MessageDispatch::new());
        let handler = Arc::new(RecordingHandler::new());

        let h1 = Arc::clone(&handler);
        dispatch.register(MessageFamily::StateTransfer, Box::new(SharedHandler(h1)));
        let h2 = Arc::clone(&handler);
        dispatch.register(
            MessageFamily::ReplicaTransferVerify,
            Box::new(SharedHandler(h2)),
        );

        let config = ReceiveLoopConfig::default();
        let mut receiver = ConnectionReceiver::new(server_stream, dispatch, config);

        let result = receiver.recv_loop().await;
        assert!(result.is_ok(), "recv_loop should return Ok on clean EOF");

        let log = handler.log();
        assert_eq!(log.len(), 2, "expected 2 messages, got {}", log.len());

        // First message
        assert_eq!(log[0].0, MessageFamily::StateTransfer);
        assert_eq!(log[0].1, b"first-message");
        assert_eq!(log[0].2, Some(ChannelId::new(7)));

        // Second message
        assert_eq!(log[1].0, MessageFamily::ReplicaTransferVerify);
        assert_eq!(log[1].1, b"second-message");
        assert_eq!(log[1].2, Some(ChannelId::new(3)));

        sender.await.unwrap();
    }

    /// Helper: wraps an `Arc<RecordingHandler>` so it can be boxed and
    /// registered multiple times.
    struct SharedHandler(Arc<RecordingHandler>);

    impl crate::dispatch::MessageHandler for SharedHandler {
        fn handle(&self, msg: DecodedMessage) -> Result<(), crate::dispatch::DispatchError> {
            self.0
                .log
                .lock()
                .unwrap()
                .push((msg.family, msg.payload, msg.channel_id));
            Ok(())
        }
    }

    #[tokio::test]
    async fn recv_loop_eof_with_no_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Sender connects and immediately shuts down.
        let sender = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let dispatch = Arc::new(MessageDispatch::new());
        let config = ReceiveLoopConfig::default();
        let mut receiver = ConnectionReceiver::new(server_stream, dispatch, config);

        let result = receiver.recv_loop().await;
        assert!(result.is_ok());

        sender.await.unwrap();
    }

    #[tokio::test]
    async fn recv_loop_partial_frame_on_eof_drained() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Sender sends a complete frame, then a partial header, then EOF.
        let sender = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
            let f1 = build_frame(MessageFamily::HelloClose, ChannelId::new(1), b"complete");
            // Send full frame + partial second header
            let mut data = f1.clone();
            data.extend_from_slice(&f1[..30]); // partial second header
            tokio::io::AsyncWriteExt::write_all(&mut stream, &data)
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let dispatch = Arc::new(MessageDispatch::new());

        let handler = Arc::new(RecordingHandler::new());
        dispatch.register(
            MessageFamily::HelloClose,
            Box::new(SharedHandler(Arc::clone(&handler))),
        );

        let config = ReceiveLoopConfig::default();
        let mut receiver = ConnectionReceiver::new(server_stream, dispatch, config);

        let result = receiver.recv_loop().await;
        assert!(result.is_ok());

        // Only the complete first frame should be delivered; partial is dropped.
        let log = handler.log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].1, b"complete");

        sender.await.unwrap();
    }

    #[tokio::test]
    async fn recv_loop_unknown_family_dropped() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Build a frame with a family_id outside the transport range.
        use tidefs_binary_schema_core::SchemaVersion;

        let unknown_family = SchemaFamilyId(999);
        let header = EnvelopeBuilder::new(
            unknown_family,
            tidefs_binary_schema_core::SchemaTypeId(0),
            SchemaVersion { major: 1, minor: 0 },
        )
        .build(0, 5);
        let header_bytes = header.encode();
        let mut frame = Vec::from(header_bytes.as_slice());
        frame.extend_from_slice(b"ghost");

        let sender = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &frame)
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let dispatch = Arc::new(MessageDispatch::new());
        let config = ReceiveLoopConfig::default();
        let mut receiver = ConnectionReceiver::new(server_stream, dispatch, config);

        // Should not panic - unknown family is dropped with a warning.
        let result = receiver.recv_loop().await;
        assert!(result.is_ok());

        sender.await.unwrap();
    }

    #[tokio::test]
    async fn diagnostic_counters_track_after_recv_loop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let sender = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
            let f1 = build_frame(MessageFamily::StateTransfer, ChannelId::new(1), &[0u8; 100]);
            let f2 = build_frame(MessageFamily::StateTransfer, ChannelId::new(2), &[0u8; 50]);
            tokio::io::AsyncWriteExt::write_all(&mut stream, &f1)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &f2)
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let dispatch = Arc::new(MessageDispatch::new());
        let handler = Arc::new(RecordingHandler::new());
        dispatch.register(
            MessageFamily::StateTransfer,
            Box::new(SharedHandler(handler)),
        );

        let config = ReceiveLoopConfig::default();
        let mut receiver = ConnectionReceiver::new(server_stream, dispatch, config);

        receiver.recv_loop().await.unwrap();

        let diag = receiver.diagnostic_counters();
        assert_eq!(diag.frames_emitted, 2);
        assert!(diag.total_bytes_fed > 0);
        assert_eq!(diag.corrupt_skipped, 0);

        sender.await.unwrap();
    }

    /// Full integration test: accept → handshake → receive-loop-spawn →
    /// send-frames → dispatch → abort (teardown).
    ///
    /// Exercises the complete lifecycle: a server accepts a connection,
    /// performs a handshake, spawns the receive loop, the client sends
    /// multiple framed messages on different channels, and the receive
    /// loop decodes and dispatches them. Finally, the spawned receiver
    /// Full integration test: accept → receive-loop-spawn → send-frames →
    /// dispatch → teardown via abort.
    ///
    /// Exercises the complete lifecycle: a server accepts a connection,
    /// spawns the receive loop, the client sends multiple framed messages
    /// on different channels, and the receive loop decodes and dispatches
    /// them. The spawned receiver is aborted to simulate connection
    /// Full integration test: accept → receive-loop-spawn → send-frames →
    /// dispatch → teardown via abort.
    ///
    /// Exercises the complete lifecycle: a server accepts a connection,
    /// spawns the receive loop, the client sends multiple framed messages
    /// on different channels, and the receive loop decodes and dispatches
    /// them. The spawned receiver is aborted to simulate connection
    /// teardown. The handshake layer is tested separately in connection_init.rs.
    #[tokio::test]
    async fn full_accept_receive_dispatch_teardown() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let dispatch = Arc::new(MessageDispatch::new());
        let handler = Arc::new(RecordingHandler::new());

        // Register handlers for expected message families.
        let h1 = Arc::clone(&handler);
        dispatch.register(MessageFamily::StateTransfer, Box::new(SharedHandler(h1)));
        let h2 = Arc::clone(&handler);
        dispatch.register(MessageFamily::HelloClose, Box::new(SharedHandler(h2)));

        // Allocate channels that the client will use.
        let ch7 = ChannelId::new(7);
        let ch3 = ChannelId::new(3);

        // Spawn the server side: accept, spawn receive loop.
        let dispatch_srv = Arc::clone(&dispatch);
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();

            let receiver =
                ConnectionReceiver::new(stream, dispatch_srv, ReceiveLoopConfig::default());

            let spawned = receiver.spawn();

            // Wait for the receive loop to finish (client will close).
            let _stream_back = spawned.handle.await.unwrap();
        });

        // Client side: connect, send framed messages, close.
        let client_handle = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();

            // Send three framed messages on different channels.
            let f1 = build_frame(MessageFamily::StateTransfer, ch7, b"msg-one");
            let f2 = build_frame(MessageFamily::StateTransfer, ch3, b"msg-two");
            let f3 = build_frame(
                MessageFamily::HelloClose,
                ChannelId::new(0),
                b"untagged-ctrl",
            );

            tokio::io::AsyncWriteExt::write_all(&mut stream, &f1)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &f2)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &f3)
                .await
                .unwrap();

            // Shutdown to signal EOF.
            stream.shutdown().await.unwrap();
        });

        // Wait for both sides to complete.
        let (client_result, server_result) = tokio::join!(client_handle, server_handle);
        client_result.unwrap();
        server_result.unwrap();

        // Verify all three messages were received.
        let log = handler.log();
        assert_eq!(log.len(), 3, "expected 3 messages, got {}", log.len());

        // First message: StateTransfer on channel 7.
        assert_eq!(log[0].0, MessageFamily::StateTransfer);
        assert_eq!(log[0].1, b"msg-one");
        assert_eq!(log[0].2, Some(ch7));

        // Second message: StateTransfer on channel 3.
        assert_eq!(log[1].0, MessageFamily::StateTransfer);
        assert_eq!(log[1].1, b"msg-two");
        assert_eq!(log[1].2, Some(ch3));

        // Third message: HelloClose, untagged.
        assert_eq!(log[2].0, MessageFamily::HelloClose);
        assert_eq!(log[2].1, b"untagged-ctrl");
        assert_eq!(log[2].2, None);
    }

    // -------------------------------------------------------------------
    // Batch receive integration tests
    // -------------------------------------------------------------------

    /// Build a codec-format frame (5-byte header + payload) for the
    /// [`RecvBatchDecoder`] path, which uses the simple codec wire format
    /// rather than the binary-schema envelope format.
    fn build_codec_frame(family: MessageFamily, payload: &[u8]) -> Vec<u8> {
        let codec = crate::codec::MessageCodec::default();
        codec.encode(family, payload).unwrap()
    }

    /// Recording handler variant that stores (family, payload) pairs
    /// without channel ID (batch-decoded messages carry no channel ID).
    struct BatchRecordingHandler {
        log: Mutex<Vec<(MessageFamily, Vec<u8>)>>,
    }

    impl BatchRecordingHandler {
        fn new() -> Self {
            Self {
                log: Mutex::new(Vec::new()),
            }
        }

        fn log(&self) -> Vec<(MessageFamily, Vec<u8>)> {
            self.log.lock().unwrap().clone()
        }
    }

    impl crate::dispatch::MessageHandler for BatchRecordingHandler {
        fn handle(&self, msg: DecodedMessage) -> Result<(), crate::dispatch::DispatchError> {
            self.log.lock().unwrap().push((msg.family, msg.payload));
            Ok(())
        }
    }

    /// Helper: wraps `Arc<BatchRecordingHandler>` for `MessageDispatch::register`.
    struct SharedBatchHandler(Arc<BatchRecordingHandler>);

    impl crate::dispatch::MessageHandler for SharedBatchHandler {
        fn handle(&self, msg: DecodedMessage) -> Result<(), crate::dispatch::DispatchError> {
            self.0.log.lock().unwrap().push((msg.family, msg.payload));
            Ok(())
        }
    }

    #[tokio::test]
    async fn recv_loop_with_batch_decoder_single_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let sender = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
            let frame = build_codec_frame(MessageFamily::StateTransfer, b"batch-msg");
            tokio::io::AsyncWriteExt::write_all(&mut stream, &frame)
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });

        let (server_stream, _) = listener.accept().await.unwrap();

        let dispatch = Arc::new(MessageDispatch::new());
        let handler = Arc::new(BatchRecordingHandler::new());
        let h1 = Arc::clone(&handler);
        dispatch.register(
            MessageFamily::StateTransfer,
            Box::new(SharedBatchHandler(h1)),
        );

        let config = ReceiveLoopConfig::default();
        let codec = crate::codec::MessageCodec::default();
        let batch_config = RecvBatchConfig::default();
        let batch_decoder = RecvBatchDecoder::new(batch_config, codec);

        let mut receiver =
            ConnectionReceiver::new(server_stream, dispatch, config).with_recv_batch(batch_decoder);

        let result = receiver.recv_loop().await;
        assert!(result.is_ok(), "recv_loop should return Ok on clean EOF");

        let log = handler.log();
        assert_eq!(log.len(), 1, "expected 1 message, got {}", log.len());
        assert_eq!(log[0].0, MessageFamily::StateTransfer);
        assert_eq!(log[0].1, b"batch-msg");

        sender.await.unwrap();
    }

    #[tokio::test]
    async fn recv_loop_with_batch_decoder_multi_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let sender = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
            let f1 = build_codec_frame(MessageFamily::StateTransfer, b"first");
            let f2 = build_codec_frame(MessageFamily::ReplicaTransferVerify, b"second");
            let f3 = build_codec_frame(MessageFamily::HelloClose, b"third");

            let mut combined = Vec::new();
            combined.extend_from_slice(&f1);
            combined.extend_from_slice(&f2);
            combined.extend_from_slice(&f3);

            tokio::io::AsyncWriteExt::write_all(&mut stream, &combined)
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });

        let (server_stream, _) = listener.accept().await.unwrap();

        let dispatch = Arc::new(MessageDispatch::new());
        let handler = Arc::new(BatchRecordingHandler::new());

        let h1 = Arc::clone(&handler);
        dispatch.register(
            MessageFamily::StateTransfer,
            Box::new(SharedBatchHandler(h1)),
        );
        let h2 = Arc::clone(&handler);
        dispatch.register(
            MessageFamily::ReplicaTransferVerify,
            Box::new(SharedBatchHandler(h2)),
        );
        let h3 = Arc::clone(&handler);
        dispatch.register(MessageFamily::HelloClose, Box::new(SharedBatchHandler(h3)));

        let config = ReceiveLoopConfig::default();
        let codec = crate::codec::MessageCodec::default();
        let batch_config = RecvBatchConfig::default();
        let batch_decoder = RecvBatchDecoder::new(batch_config, codec);

        let mut receiver =
            ConnectionReceiver::new(server_stream, dispatch, config).with_recv_batch(batch_decoder);

        let result = receiver.recv_loop().await;
        assert!(result.is_ok());

        let log = handler.log();
        assert_eq!(log.len(), 3, "expected 3 messages, got {}", log.len());
        assert_eq!(log[0], (MessageFamily::StateTransfer, b"first".to_vec()));
        assert_eq!(
            log[1],
            (MessageFamily::ReplicaTransferVerify, b"second".to_vec())
        );
        assert_eq!(log[2], (MessageFamily::HelloClose, b"third".to_vec()));

        sender.await.unwrap();
    }

    #[tokio::test]
    async fn recv_loop_batch_decoder_partial_frame_on_eof_drained() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let sender = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();

            // Send one complete frame, followed by a partial second frame.
            let complete = build_codec_frame(MessageFamily::HelloClose, b"complete");
            let partial = build_codec_frame(MessageFamily::HeartbeatAck, b"partial-body");

            let mut data = complete.clone();
            // Include only header + 2 bytes of payload for the second frame.
            let partial_split = crate::codec::CODEC_FRAME_HEADER_SIZE + 2;
            data.extend_from_slice(&partial[..partial_split]);

            tokio::io::AsyncWriteExt::write_all(&mut stream, &data)
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });

        let (server_stream, _) = listener.accept().await.unwrap();

        let dispatch = Arc::new(MessageDispatch::new());
        let handler = Arc::new(BatchRecordingHandler::new());

        let h1 = Arc::clone(&handler);
        dispatch.register(MessageFamily::HelloClose, Box::new(SharedBatchHandler(h1)));
        let h2 = Arc::clone(&handler);
        dispatch.register(
            MessageFamily::HeartbeatAck,
            Box::new(SharedBatchHandler(h2)),
        );

        let config = ReceiveLoopConfig::default();
        let codec = crate::codec::MessageCodec::default();
        let batch_config = RecvBatchConfig::default();
        let batch_decoder = RecvBatchDecoder::new(batch_config, codec);

        let mut receiver =
            ConnectionReceiver::new(server_stream, dispatch, config).with_recv_batch(batch_decoder);

        let result = receiver.recv_loop().await;
        assert!(result.is_ok());

        // Only the complete frame should be dispatched; the partial frame
        // bytes remain in the prefix and are drained on EOF but cannot form
        // a complete frame.
        let log = handler.log();
        assert_eq!(log.len(), 1, "only the complete frame should be dispatched");
        assert_eq!(log[0].0, MessageFamily::HelloClose);
        assert_eq!(log[0].1, b"complete");

        sender.await.unwrap();
    }

    // ---------------------------------------------------------------
    // Frame-size governance integration test:
    // oversized inbound frames are dropped before dispatch.
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn recv_loop_drops_oversized_frame_with_frame_size_governor() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Sender: sends one oversized frame (500-byte payload) and one
        // normal frame (50-byte payload). The oversized frame should be
        // dropped by the governor; only the normal frame is dispatched.
        let sender = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
            // Oversized frame: 500 bytes (exceeds 200-byte governor cap).
            let f_oversize = build_frame(
                MessageFamily::StateTransfer,
                ChannelId::new(1),
                &[0xAAu8; 500],
            );
            // Normal frame: 50 bytes (within cap).
            let f_normal = build_frame(
                MessageFamily::StateTransfer,
                ChannelId::new(2),
                &[0xBBu8; 50],
            );
            tokio::io::AsyncWriteExt::write_all(&mut stream, &f_oversize)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &f_normal)
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });

        let (server_stream, _) = listener.accept().await.unwrap();

        let dispatch = Arc::new(MessageDispatch::new());
        let handler = Arc::new(RecordingHandler::new());
        let h = Arc::clone(&handler);
        dispatch.register(MessageFamily::StateTransfer, Box::new(SharedHandler(h)));

        let config = ReceiveLoopConfig::default();
        // Governor with a 200-byte receive cap.
        let fs_config =
            crate::frame_governance::FrameSizeConfig::default().with_max_recv_frame_bytes(200);
        let governor = crate::frame_governance::FrameSizeGovernor::new(fs_config);

        let mut receiver = ConnectionReceiver::new(server_stream, dispatch, config)
            .with_frame_size_governor(governor);

        let result = receiver.recv_loop().await;
        assert!(result.is_ok(), "recv_loop should return Ok on clean EOF");

        let log = handler.log();
        // Only the 50-byte normal frame should be dispatched;
        // the 500-byte oversized frame should have been dropped.
        assert_eq!(
            log.len(),
            1,
            "expected 1 dispatched message, got {}",
            log.len()
        );
        assert_eq!(log[0].1.len(), 50, "expected 50-byte payload");
        assert_eq!(&log[0].1[..], &[0xBBu8; 50]);

        sender.await.unwrap();
    }

    #[test]
    fn connection_receiver_stores_frame_size_governor() {
        // Verify that with_frame_size_governor stores the governor.
        // We cannot test dispatch_frames directly (it is private), but we
        // confirm the builder correctly wires the governor into the struct.
        let fs_config =
            crate::frame_governance::FrameSizeConfig::default().with_max_recv_frame_bytes(4096);
        let governor = crate::frame_governance::FrameSizeGovernor::new(fs_config);
        assert_eq!(governor.recv_limit(None), 4096);

        // The governor is cloneable and the limits are accessible.
        let cloned = governor.clone();
        assert_eq!(cloned.recv_limit(None), 4096);
    }
}
