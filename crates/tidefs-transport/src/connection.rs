//! Transport connection lifecycle state machine managing TCP and Unix domain
//! socket connection establishment, acceptance, state tracking, and graceful
//! drain. Provides the connection substrate for send (#5778) and receive
//! (#5780) paths.
//!
//! ## Connection lifecycle
//!
//! Each connection progresses through a fixed forward-only state machine:
//!
//! ```text
//! Disconnected ──(connect/accept)──▶ Connecting ──(established)──▶ Connected
//!                                                                      │
//!                                                          (drain)     │
//!                                                                      ▼
//!                                                               Draining
//!                                                                      │
//!                                                     (all flushed)    │
//!                                                                      ▼
//!                                                              Disconnected
//! ```
//!
//! - **Disconnected**: No connection exists. Initial state and terminal state
//!   after drain or forced disconnect.
//! - **Connecting**: Outbound connect or inbound accept in progress.
//!   Transitions to Connected on success, or back to Disconnected on failure.
//! - **Connected**: Connection established; can send and receive frames.
//! - **Draining**: Graceful drain in progress; existing in-flight frames
//!   complete, new sends are rejected. Transitions to Disconnected when drain
//!   completes (all outstanding data flushed and acked).
//!
//! Invalid transitions (e.g., Connected→Connecting, Draining→Connected) are
//! rejected with `ConnectionError::InvalidStateTransition`.
//!
//! ## ConnectionManager
//!
//! The [`ConnectionManager`] manages a set of connections keyed by peer
//! [`SocketAddr`]. It provides:
//!
//! - `connect()`: establish an outbound TCP connection with configurable
//!   timeout and retry.
//! - `accept_loop()`: accept inbound connections, validate them, and register
//!   in the connection table.
//! - `disconnect()`: force-close a connection immediately.
//! - `drain()`: initiate graceful drain, allowing in-flight frames to complete
//!   before closing.
//!
//! ## ConnectionHandle
//!
//! [`ConnectionHandle`] provides a safe, checked reference to a managed
//! connection. The handle validates that the connection is in `Connected`
//! state before allowing send/receive operations, returning errors when the
//! connection is in a non-usable state (Connecting, Draining, Disconnected).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};

use crate::channel::{ChannelError, ChannelId, ChannelMultiplexer, SharedChannelTable};
use crate::cross_session_scheduler::CrossSessionScheduler;
use crate::error::TransportError;
use crate::flow_control::WindowAdvertiser;
use crate::idle_timeout::{
    IdleTimeoutConfig, IdleTimeoutController, IdleTimeoutRunner, IdleTracker,
};
use crate::send_concurrency::{SendConcurrencyError, SendConcurrencyLimiter, SendPermit};
use crate::types::SessionId;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// ConnectionState
// ---------------------------------------------------------------------------

use crate::connection_retry::{connect_with_retry, PeerConnectGate};
/// State of a transport connection in the lifecycle state machine.
///
/// Transitions are forward-only:
/// `Disconnected → Connecting → Connected → Draining → Disconnected`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    /// No connection exists. Initial and terminal state.
    Disconnected,
    /// Connection establishment in progress (outbound connect or inbound accept).
    Connecting,
    /// Connection established and usable for send/receive.
    Connected,
    /// Graceful drain in progress; new sends rejected, existing work completes.
    Draining,
}

impl ConnectionState {
    /// Human-readable label for this state.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Draining => "draining",
        }
    }

    /// Whether the connection can accept new send operations.
    pub fn can_send(&self) -> bool {
        matches!(self, Self::Connected)
    }

    /// Whether the connection can accept new receive operations.
    pub fn can_receive(&self) -> bool {
        matches!(self, Self::Connected | Self::Draining)
    }

    /// Whether this is a terminal state (no further transitions possible).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Disconnected)
    }

    /// Validate a transition from this state to `next`. Returns `Ok(())` if
    /// the transition is valid, or an error describing the invalid move.
    pub fn validate_transition(&self, next: Self) -> Result<(), ConnectionError> {
        match (*self, next) {
            // Valid forward transitions
            (Self::Disconnected, Self::Connecting) => Ok(()),
            (Self::Connecting, Self::Connected) => Ok(()),
            (Self::Connecting, Self::Disconnected) => Ok(()), // connect failure
            (Self::Connected, Self::Draining) => Ok(()),
            (Self::Draining, Self::Disconnected) => Ok(()),
            (Self::Connected, Self::Disconnected) => Ok(()), // forced disconnect
            // Self-transitions (no-op, allowed)
            (s, n) if s == n => Ok(()),
            // All other transitions are invalid
            (from, to) => Err(ConnectionError::InvalidStateTransition {
                from,
                to,
                peer: None,
            }),
        }
    }
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ConnectionError
// ---------------------------------------------------------------------------

/// Errors from connection lifecycle operations.
#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("connection to {peer} not found")]
    ConnectionNotFound { peer: String },

    #[error("invalid state transition from {from} to {to}{}", .peer.as_ref().map_or(String::new(), |p| format!(" for peer {p}")))]
    InvalidStateTransition {
        from: ConnectionState,
        to: ConnectionState,
        peer: Option<String>,
    },

    #[error("peer {peer} is already connected")]
    AlreadyConnected { peer: String },

    #[error("peer {peer} is already connecting")]
    AlreadyConnecting { peer: String },

    #[error("max connections ({max}) reached")]
    MaxConnectionsReached { max: usize },

    #[error("I/O error on connection to {peer}: {source}")]
    Io {
        peer: String,
        #[source]
        source: std::io::Error,
    },

    #[error("connect to {peer} timed out after {timeout_ms}ms")]
    ConnectTimeout { peer: String, timeout_ms: u64 },

    #[error("{0}")]
    Other(String),
}

impl From<ConnectionError> for TransportError {
    fn from(err: ConnectionError) -> Self {
        TransportError::Generic(err.to_string())
    }
}

// ---------------------------------------------------------------------------
// ConnectionEntry: per-connection tracked state
// ---------------------------------------------------------------------------

/// Tracked state for a single connection in the manager.
#[allow(dead_code)]
struct ConnectionEntry {
    /// The underlying TCP stream, if connected.
    stream: Option<TcpStream>,
    /// Peer address.
    peer_addr: SocketAddr,
    /// Current state in the lifecycle machine.
    state: ConnectionState,
    /// When the connection entered its current state.
    state_since: Instant,
    /// When the connection was established (set on Connected).
    established_at: Option<Instant>,
    /// Number of in-flight operations (sends not yet acked).
    inflight_count: u64,
    /// Per-connection send-concurrency limiter.
    send_concurrency: Arc<SendConcurrencyLimiter>,
    /// Whether drain has been requested and is pending completion.
    drain_requested: bool,
    /// Per-connection keepalive lifecycle bridge.
    /// `None` when keepalive is disabled (default for single-node mounts).
    pub(crate) keepalive: Option<crate::keepalive::KeepaliveLifecycle>,
    /// Per-connection idle timeout runner.
    /// Spawned when the connection reaches Connected; cancelled on Draining/Disconnected.
    idle_timeout_runner: Option<IdleTimeoutRunner>,
    /// Per-connection receive window for inbound flow control.
    pub(crate) receive_window: crate::flow_control::ReceiveWindow,
    /// Last window advertisement received from the peer (their available buffer capacity).
    /// Updated by inbound advertisement decode in the receive loop; used by the
    /// outbound send path to throttle sends to this peer.
    pub(crate) peer_window_bytes: Option<u64>,
    /// Handle to the spawned window-advertisement background task.
    /// Aborted on disconnect/drain to stop sending advertisements.
    window_advertiser_handle: Option<tokio::task::JoinHandle<()>>,
    /// Cross-session scheduler session identifier. Set when the connection
    /// transitions to Connected and the cross-session scheduler is configured.
    session_id: Option<SessionId>,
}

impl ConnectionEntry {
    fn new_with_keepalive(
        peer_addr: SocketAddr,
        state: ConnectionState,
        max_inflight: usize,
        keepalive_config: Option<crate::config::KeepaliveConfig>,
        receive_window_config: crate::flow_control::ReceiveWindowConfig,
    ) -> Self {
        assert!(max_inflight > 0, "max_inflight must be non-zero");
        let keepalive =
            keepalive_config.map(|kc| crate::keepalive::KeepaliveLifecycle::new(kc.into()));
        Self {
            stream: None,
            peer_addr,
            state,
            state_since: Instant::now(),
            established_at: None,
            inflight_count: 0,
            send_concurrency: Arc::new(SendConcurrencyLimiter::new(max_inflight)),
            drain_requested: false,
            keepalive,
            idle_timeout_runner: None,
            receive_window: crate::flow_control::ReceiveWindow::new(receive_window_config),
            peer_window_bytes: None,
            window_advertiser_handle: None,
            session_id: None,
        }
    }

    /// Cancel the idle timeout runner, if any.
    fn cancel_idle_timeout(&mut self) {
        if let Some(ref mut runner) = self.idle_timeout_runner {
            runner.cancel();
        }
        self.idle_timeout_runner = None;
    }

    /// Cancel the window advertiser task, if running.
    fn cancel_window_advertiser(&mut self) {
        if let Some(handle) = self.window_advertiser_handle.take() {
            handle.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectionHandle: safe access to a managed connection
// ---------------------------------------------------------------------------

/// A checked handle to a managed transport connection.
///
/// The handle validates that the connection is in `Connected` state before
/// allowing send/receive operations. It holds a reference to the manager's
/// internal state, so operations are automatically gated on the connection
/// state machine.
#[derive(Clone)]
pub struct ConnectionHandle {
    /// Peer address for this connection.
    peer_addr: SocketAddr,
    /// Reference to the manager's connection table for state validation.
    /// In production, this would hold an Arc to the manager; for now the
    /// handle carries the peer address and the manager validates on each use.
    manager: Option<Arc<ConnectionManagerInner>>,
    /// Shared channel table for per-channel multiplexing on this connection.
    channel_table: Option<SharedChannelTable>,
    /// When this handle was created.
    #[allow(dead_code)]
    created_at: Instant,
    /// Send-concurrency limiter for this connection.
    send_concurrency: Option<Arc<SendConcurrencyLimiter>>,
}

impl ConnectionHandle {
    /// Create a new handle for a peer connection.
    pub(crate) fn new(
        peer_addr: SocketAddr,
        manager: Arc<ConnectionManagerInner>,
        send_concurrency: Arc<SendConcurrencyLimiter>,
    ) -> Self {
        Self {
            peer_addr,
            manager: Some(manager),
            channel_table: Some(crate::channel::new_shared_channel_table()),
            created_at: Instant::now(),
            send_concurrency: Some(send_concurrency),
        }
    }

    /// Attach a shared channel table for per-channel multiplexing.
    ///
    /// Once attached, `channel_open`, `channel_close`, and `channel_send`
    /// can be used to manage multiplexed channels on this connection.
    pub fn with_channel_table(mut self, table: SharedChannelTable) -> Self {
        self.channel_table = Some(table);
        self
    }

    /// Build a [`ChannelMultiplexer`] for this connection using the
    /// internal channel table and the provided send-queue sender.
    ///
    /// Returns `None` if no channel table is attached (unusual since
    /// a table is auto-created on handle construction).
    ///
    /// # Usage
    ///
    /// ```ignore
    /// let mux = handle.build_channel_multiplexer(send_queue_sender);
    /// let bulk_ch = mux.open_channel()?;
    /// mux.activate_channel(bulk_ch)?;
    /// mux.try_send_on_channel(bulk_ch, payload)?;
    /// ```
    pub fn build_channel_multiplexer<S>(&self, sender: S) -> Option<ChannelMultiplexer<S>> {
        self.channel_table
            .as_ref()
            .map(|t| ChannelMultiplexer::new(t.clone(), sender))
    }

    /// The peer address for this connection.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Whether the underlying connection is in a usable state for sending.
    pub fn can_send(&self) -> bool {
        self.manager.as_ref().is_some_and(|m| {
            if let Ok(guard) = m.connections.try_read() {
                guard
                    .get(&self.peer_addr)
                    .is_some_and(|e| e.state.can_send())
            } else {
                false
            }
        })
    }

    /// Whether the underlying connection is in a usable state for receiving.
    pub fn can_receive(&self) -> bool {
        self.manager.as_ref().is_some_and(|m| {
            if let Ok(guard) = m.connections.try_read() {
                guard
                    .get(&self.peer_addr)
                    .is_some_and(|e| e.state.can_receive())
            } else {
                false
            }
        })
    }

    /// Current state of the connection, if known.
    pub fn state(&self) -> Option<ConnectionState> {
        self.manager.as_ref().and_then(|m| {
            if let Ok(guard) = m.connections.try_read() {
                guard.get(&self.peer_addr).map(|e| e.state)
            } else {
                None
            }
        })
    }

    // ----------------------------------------------------------------

    // ----------------------------------------------------------------
    // Send concurrency limiting
    // ----------------------------------------------------------------

    /// Try to acquire a send permit without waiting.
    ///
    /// Returns `Ok(SendPermit)` if a permit was acquired, or
    /// `Err(SendConcurrencyError::LimitExceeded)` if the in-flight
    /// limit is reached.
    pub fn try_acquire_send_permit(&self) -> Result<SendPermit, SendConcurrencyError> {
        let limiter = self
            .send_concurrency
            .as_ref()
            .ok_or(SendConcurrencyError::ConnectionNotSendable)?;
        limiter.try_acquire()
    }

    /// Acquire a send permit, waiting asynchronously if none is available.
    ///
    /// Increments the permit-wait-count metric.
    pub async fn acquire_send_permit(&self) -> Result<SendPermit, SendConcurrencyError> {
        let limiter = self
            .send_concurrency
            .as_ref()
            .ok_or(SendConcurrencyError::ConnectionNotSendable)?;
        limiter.acquire().await
    }

    /// Access the underlying send-concurrency limiter for metric queries.
    #[must_use]
    pub fn send_concurrency_limiter(&self) -> Option<&Arc<SendConcurrencyLimiter>> {
        self.send_concurrency.as_ref()
    }
    // ----------------------------------------------------------------
    // Channel multiplexing
    // ----------------------------------------------------------------

    /// Open a new multiplexed channel on this connection.
    ///
    /// Returns the allocated [`ChannelId`] in `Opening` state.
    /// Call [`ConnectionHandle::channel_activate`] once the peer acknowledges
    /// the channel to transition it to `Active`.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::AllocatorExhausted`] if all channel IDs are in
    /// use, or an error if no channel table is attached.
    pub fn channel_open(&self) -> Result<ChannelId, ChannelError> {
        let table = self
            .channel_table
            .as_ref()
            .ok_or(ChannelError::AllocatorExhausted)?;
        table.write().unwrap().open()
    }

    /// Transition a channel from `Opening` to `Active`.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::ChannelNotFound`] or
    /// [`ChannelError::InvalidState`].
    pub fn channel_activate(&self, channel_id: ChannelId) -> Result<(), ChannelError> {
        let table = self
            .channel_table
            .as_ref()
            .ok_or(ChannelError::ChannelNotFound(channel_id))?;
        table.write().unwrap().activate(channel_id)
    }

    /// Initiate graceful close of a channel (`Active` → `Closing`).
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::ChannelNotFound`] or
    /// [`ChannelError::ChannelAlreadyClosed`].
    pub fn channel_close(&self, channel_id: ChannelId) -> Result<(), ChannelError> {
        let table = self
            .channel_table
            .as_ref()
            .ok_or(ChannelError::ChannelNotFound(channel_id))?;
        table.write().unwrap().close(channel_id)
    }

    /// Finalize channel close (`Closing` → `Closed`).
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::ChannelNotFound`] or
    /// [`ChannelError::InvalidState`].
    pub fn channel_finalize_close(&self, channel_id: ChannelId) -> Result<(), ChannelError> {
        let table = self
            .channel_table
            .as_ref()
            .ok_or(ChannelError::ChannelNotFound(channel_id))?;
        table.write().unwrap().finalize_close(channel_id)
    }

    /// Force-reset a channel to `Closed` regardless of current state.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::ChannelNotFound`] or
    /// [`ChannelError::ChannelAlreadyClosed`].
    pub fn channel_reset(&self, channel_id: ChannelId) -> Result<(), ChannelError> {
        let table = self
            .channel_table
            .as_ref()
            .ok_or(ChannelError::ChannelNotFound(channel_id))?;
        table.write().unwrap().reset(channel_id)
    }

    /// Validate that a channel is in `Active` state and record bytes sent.
    ///
    /// Returns `Ok(())` if the channel is active and the byte count was
    /// recorded.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::ChannelNotFound`],
    /// [`ChannelError::ChannelAlreadyClosed`], or
    /// [`ChannelError::InvalidState`].
    pub fn channel_send(&self, channel_id: ChannelId, byte_count: u64) -> Result<(), ChannelError> {
        let table = self
            .channel_table
            .as_ref()
            .ok_or(ChannelError::ChannelNotFound(channel_id))?;
        let mut guard = table.write().unwrap();
        if !guard.can_send(channel_id) {
            let state = guard.state(channel_id);
            return match state {
                None => Err(ChannelError::ChannelNotFound(channel_id)),
                Some(crate::channel::ChannelState::Closed) => {
                    Err(ChannelError::ChannelAlreadyClosed(channel_id))
                }
                Some(s) => Err(ChannelError::InvalidState {
                    channel_id,
                    current: s,
                    expected: "Active",
                }),
            };
        }
        guard.record_bytes_sent(channel_id, byte_count);
        Ok(())
    }

    /// Record bytes received on a channel.
    ///
    /// No-op if the channel is not found or no channel table is attached.
    pub fn channel_record_recv(&self, channel_id: ChannelId, byte_count: u64) {
        if let Some(table) = &self.channel_table {
            table
                .write()
                .unwrap()
                .record_bytes_received(channel_id, byte_count);
        }
    }

    /// Return the current state of a channel, if present.
    /// Record that data was received on this connection (proves liveness).
    /// Resets the idle timer in the keepalive state machine.
    pub fn record_activity(&self) {
        if let Some(manager) = &self.manager {
            if let Ok(mut guard) = manager.connections.try_write() {
                if let Some(entry) = guard.get_mut(&self.peer_addr) {
                    if let Some(ref mut k) = entry.keepalive {
                        k.record_activity();
                    }
                }
            }
        }
    }

    /// Record a keepalive pong response for the given sequence number.
    pub fn on_keepalive_pong(&self, seq: u64) {
        if let Some(manager) = &self.manager {
            if let Ok(mut guard) = manager.connections.try_write() {
                if let Some(entry) = guard.get_mut(&self.peer_addr) {
                    if let Some(ref mut k) = entry.keepalive {
                        k.on_pong(seq);
                    }
                }
            }
        }
    }

    pub fn channel_state(&self, channel_id: ChannelId) -> Option<crate::channel::ChannelState> {
        self.channel_table
            .as_ref()
            .and_then(|t| t.read().unwrap().state(channel_id))
    }

    /// Whether a channel table is attached to this handle.
    #[must_use]
    pub fn has_channel_table(&self) -> bool {
        self.channel_table.is_some()
    }
    // ----------------------------------------------------------------
    // Receive-window flow control (inbound buffer advertisement)
    // ----------------------------------------------------------------

    /// Consume bytes from the receive window on inbound message receipt.
    pub fn receive_window_consume(
        &self,
        bytes: u64,
    ) -> Result<(), crate::flow_control::FlowControlError> {
        self.manager.as_ref().map_or(
            Err(crate::flow_control::FlowControlError::WindowExhausted),
            |m| {
                if let Ok(mut guard) = m.connections.try_write() {
                    match guard.get_mut(&self.peer_addr) {
                        Some(entry) => entry.receive_window.consume(bytes),
                        None => Err(crate::flow_control::FlowControlError::WindowExhausted),
                    }
                } else {
                    Err(crate::flow_control::FlowControlError::WindowExhausted)
                }
            },
        )
    }

    /// Release bytes back to the receive window after the application
    /// has finished processing a received message.
    pub fn receive_window_release(&self, bytes: u64) {
        if let Some(manager) = &self.manager {
            if let Ok(mut guard) = manager.connections.try_write() {
                if let Some(entry) = guard.get_mut(&self.peer_addr) {
                    entry.receive_window.release(bytes);
                }
            }
        }
    }

    /// Whether the receive window needs to send a capacity advertisement
    /// to the peer.
    #[must_use]
    pub fn receive_window_needs_advertisement(&self, now: std::time::Instant) -> bool {
        self.manager.as_ref().is_some_and(|m| {
            if let Ok(guard) = m.connections.try_read() {
                guard
                    .get(&self.peer_addr)
                    .is_some_and(|e| e.receive_window.needs_advertisement(now))
            } else {
                false
            }
        })
    }

    /// Record that a window advertisement was sent to the peer.
    pub fn receive_window_mark_advertised(&self, now: std::time::Instant) {
        if let Some(manager) = &self.manager {
            if let Ok(mut guard) = manager.connections.try_write() {
                if let Some(entry) = guard.get_mut(&self.peer_addr) {
                    entry.receive_window.mark_advertised(now);
                }
            }
        }
    }

    /// Get the current available bytes in the receive window.
    #[must_use]
    pub fn receive_window_available(&self) -> Option<u64> {
        self.manager.as_ref().and_then(|m| {
            if let Ok(guard) = m.connections.try_read() {
                guard
                    .get(&self.peer_addr)
                    .map(|e| e.receive_window.available_bytes())
            } else {
                None
            }
        })
    }

    /// Store the peer's advertised receive-window capacity from an inbound
    /// window advertisement. The outbound send path consults this value to
    /// throttle sends and avoid overrunning the peer's receive buffers.
    pub fn set_peer_window(&self, bytes: u64) {
        if let Some(manager) = &self.manager {
            if let Ok(mut guard) = manager.connections.try_write() {
                if let Some(entry) = guard.get_mut(&self.peer_addr) {
                    entry.peer_window_bytes = Some(bytes);
                }
            }
        }
    }

    /// Get the peer's last advertised receive-window capacity, if any.
    #[must_use]
    pub fn peer_window_bytes(&self) -> Option<u64> {
        self.manager.as_ref().and_then(|m| {
            if let Ok(guard) = m.connections.try_read() {
                guard.get(&self.peer_addr).and_then(|e| e.peer_window_bytes)
            } else {
                None
            }
        })
    }
}

impl std::fmt::Debug for ConnectionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionHandle")
            .field("peer_addr", &self.peer_addr)
            .field("state", &self.state())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ConnectionManagerConfig
// ---------------------------------------------------------------------------

/// Configuration for the connection manager.
#[derive(Clone, Debug)]
pub struct ConnectionManagerConfig {
    /// Maximum number of concurrent connections.
    pub max_connections: usize,
    /// Connect timeout duration.
    pub connect_timeout: Duration,
    /// Read timeout for established connections.
    pub read_timeout: Duration,
    /// Drain timeout: how long to wait for in-flight operations to complete
    /// during graceful drain before forcing disconnect.
    pub drain_timeout: Duration,
    /// Maximum connect retries.
    pub max_connect_retries: u32,
    /// Max in-flight (sent but unacknowledged) sends per connection.
    pub max_inflight: usize,
    /// Per-connection keepalive configuration.
    /// `None` disables keepalive (default).
    pub keepalive_config: Option<crate::config::KeepaliveConfig>,
    /// Interval between keepalive tick loop iterations.
    /// Only used when `keepalive_config` is `Some`.
    /// Default: 1 second.
    pub keepalive_tick_interval: Duration,
    /// Optional channel for sending window-advertisement frames.
    /// When set, a WindowAdvertiser background task is spawned for each
    /// connection that reaches Connected.
    pub window_advertisement_tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
    pub receive_window_config: crate::flow_control::ReceiveWindowConfig,
    /// Optional connection pool configuration. When `Some`, the
    /// connection manager uses a shared connection pool to reuse established
    /// TCP connections across transport sessions.
    pub pool_config: Option<crate::connection_pool::PoolConfig>,
    /// Outbound connection retry configuration with backoff and coalescing.
    pub retry_config: crate::connection_retry::RetryConfig,
    /// Optional cross-session scheduler for weighted fair queueing across
    /// active peer sessions. When `Some`, the connection manager registers
    /// sessions on connect/accept and deregisters on disconnect/drain.
    pub cross_session_scheduler: Option<Arc<CrossSessionScheduler>>,
}

impl Default for ConnectionManagerConfig {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            drain_timeout: Duration::from_secs(10),
            max_connect_retries: 3,
            max_inflight: 256,
            keepalive_config: None,
            keepalive_tick_interval: Duration::from_secs(1),
            window_advertisement_tx: None,
            receive_window_config: crate::flow_control::ReceiveWindowConfig::default(),
            pool_config: None,
            retry_config: crate::connection_retry::RetryConfig::default(),
            cross_session_scheduler: None,
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectionManagerInner: shared mutable state
// ---------------------------------------------------------------------------

/// Inner connection table shared between the manager and handles.
pub(crate) struct ConnectionManagerInner {
    /// Connection table keyed by peer SocketAddr.
    connections: RwLock<HashMap<SocketAddr, ConnectionEntry>>,
    /// Manager configuration.
    config: ConnectionManagerConfig,
    /// Transport channel for sending window-advertisement frames toward peers.
    /// Read by spawned WindowAdvertiser background tasks. May be None.
    window_advertisement_tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
    receive_window_config: crate::flow_control::ReceiveWindowConfig,
    /// Bound TCP listener, if any.
    listener: Mutex<Option<TcpListener>>,
    /// Optional shared connection pool for TCP connection reuse.
    connection_pool: Option<crate::connection_pool::TcpConnectionPool>,
    /// Handle to the background pool eviction task, if the pool is enabled.
    _pool_eviction_handle: Option<tokio::task::JoinHandle<()>>,
    /// Per-peer connect attempt coalescing gate.
    connect_gate: Arc<PeerConnectGate>,
    /// Optional cross-session scheduler. When set, sessions are registered
    /// on connect/accept and deregistered on disconnect/drain.
    cross_session_scheduler: Option<Arc<CrossSessionScheduler>>,
    /// Monotonically increasing counter for generating unique session IDs.
    next_session_id: AtomicU64,
}

impl ConnectionManagerInner {
    fn new(config: ConnectionManagerConfig) -> Self {
        let cross_session_scheduler = config.cross_session_scheduler.clone();
        let receive_window_config = config.receive_window_config.clone();
        let adv_tx = config.window_advertisement_tx.clone();
        let (connection_pool, _pool_eviction_handle) =
            if let Some(ref pool_cfg) = config.pool_config {
                let pool = crate::connection_pool::TcpConnectionPool::new(pool_cfg.clone());
                let handle = pool.spawn_eviction_task();
                (Some(pool), Some(handle))
            } else {
                (None, None)
            };
        Self {
            connections: RwLock::new(HashMap::new()),
            config,
            window_advertisement_tx: adv_tx,
            receive_window_config,
            listener: Mutex::new(None),
            connection_pool,
            _pool_eviction_handle,
            connect_gate: Arc::new(PeerConnectGate::new()),
            cross_session_scheduler,
            next_session_id: AtomicU64::new(1),
        }
    }

    /// Spawn the per-connection window-advertisement background task.
    ///
    /// Returns `None` if no `window_advertisement_tx` is configured.
    fn spawn_window_advertiser(
        &self,
        handle: crate::connection::ConnectionHandle,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let adv_tx = self.window_advertisement_tx.as_ref()?;
        let advertiser = WindowAdvertiser::new(handle, adv_tx.clone());
        let poll_interval = std::time::Duration::from_millis(10);
        Some(tokio::spawn(
            crate::flow_control::spawn_window_advertisement_task(advertiser, poll_interval),
        ))
    }
}

// ---------------------------------------------------------------------------
// ConnectionManager
// ---------------------------------------------------------------------------

/// Manages the lifecycle of transport connections.
///
/// Provides `connect()`, `accept_loop()`, `disconnect()`, and `drain()`
/// operations over a set of connections keyed by peer [`SocketAddr`].
///
/// ## Type parameter
///
/// `E` is reserved for future integration with the transport engine
/// (send/receive paths). Currently unused but kept for API compatibility
/// with the planned send (#5778) and receive (#5780) path wiring.
#[derive(Clone)]
pub struct ConnectionManager<E = ()> {
    inner: Arc<ConnectionManagerInner>,
    _engine: std::marker::PhantomData<E>,
}

impl<E> ConnectionManager<E> {
    /// Create a new connection manager with the given configuration.
    pub fn new(config: ConnectionManagerConfig) -> Self {
        Self {
            inner: Arc::new(ConnectionManagerInner::new(config)),
            _engine: std::marker::PhantomData,
        }
    }

    /// Tick the keepalive state machine for all connections.
    ///
    /// Returns a list of peer addresses whose keepalive has declared the
    /// peer dead and should be drained.
    pub async fn tick_keepalive(&self) -> Vec<SocketAddr> {
        let mut dead_peers = Vec::new();
        let mut guard = self.inner.connections.write().await;
        for (peer, entry) in guard.iter_mut() {
            if entry.state == ConnectionState::Connected {
                if let Some(ref mut k) = entry.keepalive {
                    match k.tick() {
                        crate::keepalive::KeepaliveAction::Drain => {
                            // Transition the connection to Draining
                            entry.state = ConnectionState::Draining;
                            entry.state_since = Instant::now();
                            entry.drain_requested = true;
                            dead_peers.push(*peer);
                        }
                        crate::keepalive::KeepaliveAction::SendPing(_seq) => {
                            // Caller should send a keepalive ping frame.
                            // The ping is handled externally via the send path.
                        }
                        crate::keepalive::KeepaliveAction::None => {}
                    }
                }
            }
        }
        dead_peers
    }

    /// Arm idle timeout detection for a connected peer.
    ///
    /// Creates an IdleTimeoutController with the given config and tracker,
    /// wraps it in an IdleTimeoutRunner, and spawns a background task that
    /// triggers drain or disconnect when the idle deadline fires.
    pub async fn arm_idle_timeout(
        &self,
        peer_addr: SocketAddr,
        config: IdleTimeoutConfig,
        tracker: IdleTracker,
    ) where
        E: Send + Sync + 'static,
    {
        let controller = IdleTimeoutController::new(config, tracker);
        let mut runner = IdleTimeoutRunner::with_default_interval(controller);

        let inner_drain = Arc::clone(&self.inner);
        let inner_close = Arc::clone(&self.inner);
        let drain_addr = peer_addr;
        let close_addr = peer_addr;

        runner.spawn(
            move |_idle_duration| {
                let inner = Arc::clone(&inner_drain);
                tokio::spawn(async move {
                    let mgr: ConnectionManager<E> = ConnectionManager {
                        inner,
                        _engine: std::marker::PhantomData,
                    };
                    let _ = mgr.drain(drain_addr).await;
                });
            },
            move |_idle_duration| {
                let inner = Arc::clone(&inner_close);
                tokio::spawn(async move {
                    let mgr: ConnectionManager<E> = ConnectionManager {
                        inner,
                        _engine: std::marker::PhantomData,
                    };
                    let _ = mgr.disconnect(close_addr).await;
                });
            },
            |_idle_duration| {},
        );

        let mut guard = self.inner.connections.write().await;
        if let Some(entry) = guard.get_mut(&peer_addr) {
            entry.cancel_idle_timeout();
            entry.idle_timeout_runner = Some(runner);
        }
    }

    /// Return the connection count.
    pub fn connection_count(&self) -> usize {
        if let Ok(guard) = self.inner.connections.try_read() {
            guard.len()
        } else {
            0
        }
    }

    /// Get a handle for a peer address.
    ///
    /// Returns `None` if no connection entry exists for this peer.
    pub fn handle(&self, peer_addr: SocketAddr) -> Option<ConnectionHandle> {
        if let Ok(guard) = self.inner.connections.try_read() {
            if let Some(entry) = guard.get(&peer_addr) {
                return Some(ConnectionHandle::new(
                    peer_addr,
                    Arc::clone(&self.inner),
                    Arc::clone(&entry.send_concurrency),
                ));
            }
        }
        None
    }

    /// Bind the manager's TCP listener to the given address.
    ///
    /// Must be called before `accept_loop()`.
    pub async fn bind(&self, addr: SocketAddr) -> Result<(), ConnectionError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| ConnectionError::Io {
                peer: addr.to_string(),
                source: e,
            })?;
        let mut guard = self.inner.listener.lock().await;
        *guard = Some(listener);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // connect: establish an outbound connection
    // -----------------------------------------------------------------------

    /// Establish an outbound TCP connection to a peer.
    ///
    /// Registers the connection in the manager's table, progressing through:
    /// `Disconnected → Connecting → Connected`.
    ///
    /// Returns an error if the peer is already connected or connecting,
    /// if the connection table is full, or if connect fails after all retries.
    pub async fn connect(
        &self,
        peer_addr: SocketAddr,
    ) -> Result<ConnectionHandle, ConnectionError> {
        // Insert Connecting state, failing if already present.
        {
            let mut guard = self.inner.connections.write().await;
            if let Some(existing) = guard.get(&peer_addr) {
                match existing.state {
                    ConnectionState::Connected => {
                        return Err(ConnectionError::AlreadyConnected {
                            peer: peer_addr.to_string(),
                        });
                    }
                    ConnectionState::Connecting => {
                        return Err(ConnectionError::AlreadyConnecting {
                            peer: peer_addr.to_string(),
                        });
                    }
                    _ => {}
                }
            }
            if guard.len() >= self.inner.config.max_connections {
                return Err(ConnectionError::MaxConnectionsReached {
                    max: self.inner.config.max_connections,
                });
            }
            guard.insert(
                peer_addr,
                ConnectionEntry::new_with_keepalive(
                    peer_addr,
                    ConnectionState::Connecting,
                    self.inner.config.max_inflight,
                    self.inner.config.keepalive_config.clone(),
                    self.inner.receive_window_config.clone(),
                ),
            );
        }

        // Attempt connect with retry and per-peer coalescing.
        let stream = match connect_with_retry(
            &self.inner.config.retry_config,
            &self.inner.connect_gate,
            self.inner.connection_pool.as_ref(),
            peer_addr,
        )
        .await
        {
            Ok(stream) => stream,
            Err(retry_err) => {
                // Transition back to Disconnected.
                let mut guard = self.inner.connections.write().await;
                if let Some(entry) = guard.get_mut(&peer_addr) {
                    entry.state = ConnectionState::Disconnected;
                    entry.state_since = Instant::now();
                }
                guard.remove(&peer_addr);
                return Err(ConnectionError::Io {
                    peer: peer_addr.to_string(),
                    source: std::io::Error::new(
                        retry_err.last_error_kind,
                        retry_err.last_error_msg.clone(),
                    ),
                });
            }
        };

        // Transition to Connected.
        let mut guard = self.inner.connections.write().await;
        if let Some(entry) = guard.get_mut(&peer_addr) {
            entry.state = ConnectionState::Connected;
            entry.state_since = Instant::now();
            entry.established_at = Some(Instant::now());
            entry.stream = Some(stream);
            if let Some(ref mut k) = entry.keepalive {
                k.on_active();
            }
            // Spawn window advertiser background task.
            let adv_handle = self.inner.spawn_window_advertiser(ConnectionHandle::new(
                peer_addr,
                Arc::clone(&self.inner),
                Arc::clone(&guard.get(&peer_addr).unwrap().send_concurrency),
            ));
            if let Some(e) = guard.get_mut(&peer_addr) {
                e.window_advertiser_handle = adv_handle;
            }
        }
        // Generate a session_id and register with cross-session scheduler if configured.
        let sid_for_reg = if let Some(ref sched) = self.inner.cross_session_scheduler {
            let sid = SessionId(self.inner.next_session_id.fetch_add(1, Ordering::Relaxed));
            // Store the session_id in the entry before dropping the lock.
            if let Some(entry) = guard.get_mut(&peer_addr) {
                entry.session_id = Some(sid);
            }
            let sched = Arc::clone(sched);
            Some((sched, sid, peer_addr))
        } else {
            None
        };
        let limiter = Arc::clone(&guard.get(&peer_addr).unwrap().send_concurrency);
        // Drop the write lock before awaiting.
        drop(guard);
        if let Some((sched, sid, addr)) = sid_for_reg {
            sched.register(sid, addr, None).await;
        }
        Ok(ConnectionHandle::new(
            peer_addr,
            Arc::clone(&self.inner),
            limiter,
        ))
    }
    // -----------------------------------------------------------------------
    // disconnect: force-close a connection
    // -----------------------------------------------------------------------

    /// Force-disconnect a peer connection immediately.
    ///
    /// Drops the underlying stream and transitions the entry to `Disconnected`.
    /// Any in-flight operations will receive errors.
    pub async fn disconnect(&self, peer_addr: SocketAddr) -> Result<(), ConnectionError> {
        let mut guard = self.inner.connections.write().await;
        let sid_to_drop = match guard.get_mut(&peer_addr) {
            Some(entry) => {
                // Cancel idle timeout if running.
                entry.cancel_idle_timeout();
                entry.cancel_window_advertiser();
                // Return the stream to the connection pool if configured.
                if let (Some(pool), Some(stream)) =
                    (self.inner.connection_pool.as_ref(), entry.stream.take())
                {
                    pool.checkin(entry.peer_addr, stream);
                } else {
                    entry.stream = None;
                }
                entry.state = ConnectionState::Disconnected;
                entry.state_since = Instant::now();
                entry.inflight_count = 0;
                let sid = entry.session_id.take();
                guard.remove(&peer_addr);
                sid
            }
            None => {
                return Err(ConnectionError::ConnectionNotFound {
                    peer: peer_addr.to_string(),
                })
            }
        };
        // Drop the write lock before any async scheduler call.
        drop(guard);
        // Deregister from cross-session scheduler if registered.
        if let (Some(sid), Some(ref sched)) = (sid_to_drop, &self.inner.cross_session_scheduler) {
            sched.deregister(sid).await;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // drain: graceful drain
    // -----------------------------------------------------------------------

    /// Initiate graceful drain of a peer connection.
    ///
    /// Transitions the connection to `Draining` state. New sends are rejected.
    /// The connection remains open for existing in-flight frames to complete.
    /// After all in-flight work finishes (or the drain timeout expires), the
    /// connection transitions to `Disconnected`.
    pub async fn drain(&self, peer_addr: SocketAddr) -> Result<(), ConnectionError> {
        // Transition to Draining.
        {
            let mut guard = self.inner.connections.write().await;
            match guard.get_mut(&peer_addr) {
                Some(entry) => {
                    entry
                        .state
                        .validate_transition(ConnectionState::Draining)
                        .map_err(|_e| ConnectionError::InvalidStateTransition {
                            from: entry.state,
                            to: ConnectionState::Draining,
                            peer: Some(peer_addr.to_string()),
                        })?;
                    entry.state = ConnectionState::Draining;
                    entry.state_since = Instant::now();
                    entry.drain_requested = true;
                    // Cancel idle timeout; drain itself handles teardown.
                    entry.cancel_idle_timeout();
                }
                None => {
                    return Err(ConnectionError::ConnectionNotFound {
                        peer: peer_addr.to_string(),
                    });
                }
            }
        }

        // Wait for in-flight operations to complete or timeout.
        let drain_timeout = self.inner.config.drain_timeout;
        let deadline = Instant::now() + drain_timeout;
        loop {
            let inflight = {
                let guard = self.inner.connections.read().await;
                guard.get(&peer_addr).map_or(0, |e| e.inflight_count)
            };

            if inflight == 0 {
                break;
            }

            if Instant::now() >= deadline {
                break;
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Transition to Disconnected and drop stream.
        let sid_to_drop = {
            let mut guard = self.inner.connections.write().await;
            let sid = if let Some(entry) = guard.get_mut(&peer_addr) {
                if let (Some(pool), Some(stream)) =
                    (self.inner.connection_pool.as_ref(), entry.stream.take())
                {
                    pool.checkin(entry.peer_addr, stream);
                } else {
                    entry.stream = None;
                }
                entry.state = ConnectionState::Disconnected;
                entry.state_since = Instant::now();
                entry.inflight_count = 0;
                entry.cancel_idle_timeout();
                entry.session_id.take()
            } else {
                None
            };
            guard.remove(&peer_addr);
            sid
        };
        // Deregister from cross-session scheduler if registered.
        if let (Some(sid), Some(ref sched)) = (sid_to_drop, &self.inner.cross_session_scheduler) {
            sched.deregister(sid).await;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // accept_loop: accept inbound connections
    // -----------------------------------------------------------------------

    /// Accept a single inbound connection on the bound listener.
    ///
    /// Blocks until a connection arrives or the listener is closed.
    /// Registers the accepted connection in the manager's table in `Connected`
    /// state.
    pub async fn accept_one(&self) -> Result<ConnectionHandle, ConnectionError> {
        // Hold the mutex guard across the accept call to keep the listener alive.
        // tokio TcpListener's accept is cancel-safe, and the guard ensures the
        // listener isn't dropped or replaced during accept.
        let listener_guard = self.inner.listener.lock().await;
        let listener = listener_guard.as_ref().ok_or_else(|| {
            ConnectionError::Other("listener not bound; call bind() first".into())
        })?;

        let (stream, peer_addr) = listener.accept().await.map_err(|e| ConnectionError::Io {
            peer: "unknown (accept)".into(),
            source: e,
        })?;
        drop(listener_guard);

        // Note: read_timeout applied via tokio::time::timeout at the caller

        // Register the connection; capture the limiter for the handle.
        // Also generate a session_id for cross-session scheduling if configured.
        let (limiter, opt_reg) = {
            let mut guard = self.inner.connections.write().await;
            if guard.len() >= self.inner.config.max_connections {
                // Drop the accepted connection; capacity exceeded.
                drop(stream);
                return Err(ConnectionError::MaxConnectionsReached {
                    max: self.inner.config.max_connections,
                });
            }
            let mut entry = ConnectionEntry::new_with_keepalive(
                peer_addr,
                ConnectionState::Connected,
                self.inner.config.max_inflight,
                self.inner.config.keepalive_config.clone(),
                self.inner.receive_window_config.clone(),
            );
            entry.stream = Some(stream);
            entry.established_at = Some(Instant::now());
            if let Some(ref mut k) = entry.keepalive {
                k.on_active();
            }
            // Spawn window advertiser before inserting so the handle can be stored.
            let adv_handle = self.inner.spawn_window_advertiser(ConnectionHandle::new(
                peer_addr,
                Arc::clone(&self.inner),
                Arc::clone(&entry.send_concurrency),
            ));
            entry.window_advertiser_handle = adv_handle;
            let limiter = Arc::clone(&entry.send_concurrency);
            // Generate session_id and prepare scheduler registration.
            let opt_reg = if let Some(ref sched) = self.inner.cross_session_scheduler {
                let sid = SessionId(self.inner.next_session_id.fetch_add(1, Ordering::Relaxed));
                entry.session_id = Some(sid);
                Some((Arc::clone(sched), sid, peer_addr))
            } else {
                None
            };
            guard.insert(peer_addr, entry);
            (limiter, opt_reg)
        };

        // Register with cross-session scheduler outside the lock.
        if let Some((sched, sid, addr)) = opt_reg {
            sched.register(sid, addr, None).await;
        }

        Ok(ConnectionHandle::new(
            peer_addr,
            Arc::clone(&self.inner),
            limiter,
        ))
    }

    /// Run the accept loop, calling `on_accept` for each inbound connection.
    ///
    /// This function runs until the listener is closed or an unrecoverable
    /// error occurs. Each accepted connection is registered in the table before
    /// `on_accept` is called.
    pub async fn accept_loop<F>(&self, mut on_accept: F) -> Result<(), ConnectionError>
    where
        F: FnMut(ConnectionHandle),
    {
        loop {
            match self.accept_one().await {
                Ok(handle) => {
                    on_accept(handle);
                }
                Err(ConnectionError::MaxConnectionsReached { .. }) => {
                    // Log and continue; the connection was already dropped.
                    tracing::warn!("accept loop: max connections reached, dropping new connection");
                }
                Err(e) => {
                    // Check if the listener was closed.
                    if e.to_string().contains("closed") || e.to_string().contains("aborted") {
                        return Ok(());
                    }
                    return Err(e);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // In-flight operation tracking (for send/receive integration)
    // -----------------------------------------------------------------------

    /// Mark an in-flight operation started on a peer connection.
    pub async fn inflight_inc(&self, peer_addr: &SocketAddr) -> Result<(), ConnectionError> {
        let mut guard = self.inner.connections.write().await;
        match guard.get_mut(peer_addr) {
            Some(entry) if entry.state.can_send() || entry.state == ConnectionState::Draining => {
                entry.inflight_count += 1;
                Ok(())
            }
            Some(entry) => Err(ConnectionError::InvalidStateTransition {
                from: entry.state,
                to: entry.state,
                peer: Some(peer_addr.to_string()),
            }),
            None => Err(ConnectionError::ConnectionNotFound {
                peer: peer_addr.to_string(),
            }),
        }
    }

    /// Cancel the idle timeout runner for a peer connection, if armed.
    ///
    /// Safe to call even if no idle timeout was configured. This is called
    /// automatically from disconnect and drain; callers only need to invoke
    /// it directly when tearing down a connection outside those paths.
    pub async fn cancel_idle_timeout(&self, peer_addr: SocketAddr) {
        let mut guard = self.inner.connections.write().await;
        if let Some(entry) = guard.get_mut(&peer_addr) {
            entry.cancel_idle_timeout();
            entry.idle_timeout_runner = None;
        }
    }

    /// Mark an in-flight operation completed on a peer connection.
    pub async fn inflight_dec(&self, peer_addr: &SocketAddr) -> Result<(), ConnectionError> {
        let mut guard = self.inner.connections.write().await;
        match guard.get_mut(peer_addr) {
            Some(entry) => {
                entry.inflight_count = entry.inflight_count.saturating_sub(1);
                Ok(())
            }
            None => Err(ConnectionError::ConnectionNotFound {
                peer: peer_addr.to_string(),
            }),
        }
    }

    /// Current state of a peer connection.
    pub async fn state(&self, peer_addr: &SocketAddr) -> Option<ConnectionState> {
        let guard = self.inner.connections.read().await;
        guard.get(peer_addr).map(|e| e.state)
    }

    /// List all connected peer addresses.
    pub async fn connected_peers(&self) -> Vec<SocketAddr> {
        let guard = self.inner.connections.read().await;
        guard
            .iter()
            .filter(|(_, e)| e.state == ConnectionState::Connected)
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// List all peer addresses in any non-terminal state.
    pub async fn active_peers(&self) -> Vec<SocketAddr> {
        let guard = self.inner.connections.read().await;
        guard
            .iter()
            .filter(|(_, e)| !e.state.is_terminal())
            .map(|(addr, _)| *addr)
            .collect()
    }
}

impl ConnectionManager<()> {
    /// Create a new connection manager with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ConnectionManagerConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener as TokioTcpListener;

    /// Helper: find an ephemeral port and return (addr, _guard) where the
    /// _guard holds the port until dropped.
    async fn ephemeral_addr() -> (SocketAddr, TokioTcpListener) {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (addr, listener)
    }

    // -------------------------------------------------------------------
    // ConnectionState tests
    // -------------------------------------------------------------------

    #[test]
    fn test_state_machine_valid_transitions() {
        // Disconnected -> Connecting
        assert!(ConnectionState::Disconnected
            .validate_transition(ConnectionState::Connecting)
            .is_ok());
        // Connecting -> Connected
        assert!(ConnectionState::Connecting
            .validate_transition(ConnectionState::Connected)
            .is_ok());
        // Connecting -> Disconnected (failure path)
        assert!(ConnectionState::Connecting
            .validate_transition(ConnectionState::Disconnected)
            .is_ok());
        // Connected -> Draining
        assert!(ConnectionState::Connected
            .validate_transition(ConnectionState::Draining)
            .is_ok());
        // Connected -> Disconnected (forced disconnect)
        assert!(ConnectionState::Connected
            .validate_transition(ConnectionState::Disconnected)
            .is_ok());
        // Draining -> Disconnected
        assert!(ConnectionState::Draining
            .validate_transition(ConnectionState::Disconnected)
            .is_ok());
        // Self-transitions always ok
        for s in &[
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Draining,
        ] {
            assert!(s.validate_transition(*s).is_ok());
        }
    }

    #[test]
    fn test_state_machine_invalid_transitions() {
        // Connected -> Connecting (cannot go backward)
        assert!(ConnectionState::Connected
            .validate_transition(ConnectionState::Connecting)
            .is_err());
        // Draining -> Connected (cannot go backward)
        assert!(ConnectionState::Draining
            .validate_transition(ConnectionState::Connected)
            .is_err());
        // Draining -> Connecting (cannot go backward)
        assert!(ConnectionState::Draining
            .validate_transition(ConnectionState::Connecting)
            .is_err());
        // Disconnected -> Connected (skip Connecting)
        assert!(ConnectionState::Disconnected
            .validate_transition(ConnectionState::Connected)
            .is_err());
        // Disconnected -> Draining (skip states)
        assert!(ConnectionState::Disconnected
            .validate_transition(ConnectionState::Draining)
            .is_err());
    }

    #[test]
    fn test_state_can_send_and_receive() {
        assert!(!ConnectionState::Disconnected.can_send());
        assert!(!ConnectionState::Disconnected.can_receive());
        assert!(!ConnectionState::Connecting.can_send());
        assert!(!ConnectionState::Connecting.can_receive());
        assert!(ConnectionState::Connected.can_send());
        assert!(ConnectionState::Connected.can_receive());
        assert!(!ConnectionState::Draining.can_send());
        assert!(ConnectionState::Draining.can_receive());
    }

    #[test]
    fn test_state_is_terminal() {
        assert!(ConnectionState::Disconnected.is_terminal());
        assert!(!ConnectionState::Connecting.is_terminal());
        assert!(!ConnectionState::Connected.is_terminal());
        assert!(!ConnectionState::Draining.is_terminal());
    }

    #[test]
    fn test_state_as_str() {
        assert_eq!(ConnectionState::Disconnected.as_str(), "disconnected");
        assert_eq!(ConnectionState::Connecting.as_str(), "connecting");
        assert_eq!(ConnectionState::Connected.as_str(), "connected");
        assert_eq!(ConnectionState::Draining.as_str(), "draining");
    }

    #[test]
    fn test_state_display() {
        assert_eq!(format!("{}", ConnectionState::Connected), "connected");
    }

    // -------------------------------------------------------------------
    // ConnectionManager tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn test_manager_new_and_count() {
        let mgr = ConnectionManager::<()>::with_defaults();
        assert_eq!(mgr.connection_count(), 0);
        assert!(mgr.connected_peers().await.is_empty());
        assert!(mgr.active_peers().await.is_empty());
    }

    #[tokio::test]
    async fn test_connect_disconnect_lifecycle() {
        // Start a simple echo server
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
            // Keep stream alive until client disconnects
            let _ = stream.read(&mut buf).await;
        });

        let mgr = ConnectionManager::<()>::with_defaults();
        let _handle = mgr.connect(server_addr).await.unwrap();
        assert_eq!(mgr.connection_count(), 1);
        assert_eq!(
            mgr.state(&server_addr).await,
            Some(ConnectionState::Connected)
        );

        mgr.disconnect(server_addr).await.unwrap();
        assert_eq!(mgr.connection_count(), 0);
        assert_eq!(mgr.state(&server_addr).await, None);

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_double_connect_rejected() {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let mut buf = [0u8; 256];
                    let _ = stream.read(&mut buf).await;
                }
            }
        });

        let mgr = ConnectionManager::<()>::with_defaults();
        let _handle = mgr.connect(server_addr).await.unwrap();
        // Second connect to same peer should fail
        let result = mgr.connect(server_addr).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("already connected"));

        let _ = mgr.disconnect(server_addr).await;
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_connect_timeout_unreachable() {
        let mgr: ConnectionManager = ConnectionManager::new(ConnectionManagerConfig {
            connect_timeout: Duration::from_millis(100),
            max_connect_retries: 0,
            ..Default::default()
        });

        // 192.0.2.0/24 is TEST-NET-1, should be unreachable
        let bad_addr: SocketAddr = "192.0.2.1:12345".parse().unwrap();
        let result = mgr.connect(bad_addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_to_nonexistent_port() {
        // Bind a listener to find a free port, then close it
        let (addr, _guard) = ephemeral_addr().await;
        drop(_guard); // port is now free but no listener

        let mgr: ConnectionManager = ConnectionManager::new(ConnectionManagerConfig {
            connect_timeout: Duration::from_millis(200),
            max_connect_retries: 0,
            ..Default::default()
        });

        let result = mgr.connect(addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_accept_one() {
        let (addr, _accept_listener) = ephemeral_addr().await;
        drop(_accept_listener);

        let mgr = ConnectionManager::<()>::with_defaults();
        mgr.bind(addr).await.unwrap();

        // Connect from a background task
        let connect_addr = addr;
        let connect_handle =
            tokio::spawn(async move { TcpStream::connect(connect_addr).await.unwrap() });

        let accepted = mgr.accept_one().await.unwrap();
        assert_eq!(accepted.state(), Some(ConnectionState::Connected));
        assert_eq!(mgr.connection_count(), 1);

        let _stream = connect_handle.await.unwrap();
        mgr.disconnect(accepted.peer_addr()).await.unwrap();
    }

    #[tokio::test]
    async fn test_drain_completes() {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
            // Wait for client to close
            let _ = stream.read(&mut buf).await;
        });

        let mgr: ConnectionManager = ConnectionManager::new(ConnectionManagerConfig {
            drain_timeout: Duration::from_secs(2),
            ..Default::default()
        });

        let _handle = mgr.connect(server_addr).await.unwrap();
        assert_eq!(
            mgr.state(&server_addr).await,
            Some(ConnectionState::Connected)
        );

        // Drain should complete since there are no in-flight operations.
        mgr.drain(server_addr).await.unwrap();
        assert_eq!(mgr.state(&server_addr).await, None);
        assert_eq!(mgr.connection_count(), 0);

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_disconnect_nonexistent_fails() {
        let mgr = ConnectionManager::<()>::with_defaults();
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = mgr.disconnect(addr).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_drain_nonexistent_fails() {
        let mgr = ConnectionManager::<()>::with_defaults();
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = mgr.drain(addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_concurrent_connect_disconnect_safety() {
        let mut listeners = Vec::new();
        let mut addrs = Vec::new();
        for _ in 0..3 {
            let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            addrs.push(addr);
            listeners.push(listener);
        }

        let handles: Vec<_> = listeners
            .into_iter()
            .map(|l| {
                tokio::spawn(async move {
                    let (mut stream, _) = l.accept().await.unwrap();
                    let mut buf = [0u8; 256];
                    let _ = stream.read(&mut buf).await;
                })
            })
            .collect();

        let mgr = ConnectionManager::<()>::with_defaults();

        let mut connect_handles = Vec::new();
        for addr in &addrs {
            let mgr = mgr.clone();
            let addr = *addr;
            connect_handles.push(tokio::spawn(async move { mgr.connect(addr).await }));
        }

        for h in connect_handles {
            let result = h.await.unwrap();
            assert!(result.is_ok(), "connect failed: {result:?}");
        }

        assert_eq!(mgr.connection_count(), 3);

        let mut disconnect_handles = Vec::new();
        for addr in &addrs {
            let mgr = mgr.clone();
            let addr = *addr;
            disconnect_handles.push(tokio::spawn(async move { mgr.disconnect(addr).await }));
        }

        for h in disconnect_handles {
            let result = h.await.unwrap();
            assert!(result.is_ok(), "disconnect failed: {result:?}");
        }

        assert_eq!(mgr.connection_count(), 0);

        for h in handles {
            h.abort();
        }
    }

    // -------------------------------------------------------------------
    // ConnectionHandle tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn test_handle_can_send_and_receive() {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf).await;
        });

        let mgr = ConnectionManager::<()>::with_defaults();
        let handle = mgr.connect(server_addr).await.unwrap();

        assert!(handle.can_send());
        assert!(handle.can_receive());
        assert_eq!(handle.state(), Some(ConnectionState::Connected));

        mgr.disconnect(server_addr).await.unwrap();

        assert!(!handle.can_send());
        assert!(!handle.can_receive());
        assert_eq!(handle.state(), None);

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_handle_peer_addr() {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf).await;
        });

        let mgr = ConnectionManager::<()>::with_defaults();
        let handle = mgr.connect(server_addr).await.unwrap();
        assert_eq!(handle.peer_addr(), server_addr);

        mgr.disconnect(server_addr).await.unwrap();
        server_handle.abort();
    }

    // -------------------------------------------------------------------
    // In-flight tracking tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn test_inflight_tracking() {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf).await;
        });

        let mgr = ConnectionManager::<()>::with_defaults();
        let _handle = mgr.connect(server_addr).await.unwrap();

        // Increment in-flight count
        mgr.inflight_inc(&server_addr).await.unwrap();
        mgr.inflight_inc(&server_addr).await.unwrap();
        mgr.inflight_inc(&server_addr).await.unwrap();

        // Decrement
        mgr.inflight_dec(&server_addr).await.unwrap();
        mgr.inflight_dec(&server_addr).await.unwrap();
        mgr.inflight_dec(&server_addr).await.unwrap();

        // Saturating sub test: decrementing below zero should not underflow
        mgr.inflight_dec(&server_addr).await.unwrap();

        mgr.disconnect(server_addr).await.unwrap();
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_inflight_fails_on_disconnected() {
        let mgr = ConnectionManager::<()>::with_defaults();
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(mgr.inflight_inc(&addr).await.is_err());
        assert!(mgr.inflight_dec(&addr).await.is_err());
    }

    // -------------------------------------------------------------------
    // Per-connection send-concurrency isolation tests (#5998)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn test_per_connection_send_concurrency_isolation() {
        // Prove that saturating peer A does not prevent peer B from
        // acquiring a send permit on its own connection.

        // Start two echo servers.
        let l1 = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let l2 = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = l1.local_addr().unwrap();
        let addr_b = l2.local_addr().unwrap();

        let srv_a = tokio::spawn(async move {
            let (mut s, _) = l1.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let _ = s.read(&mut buf).await;
        });
        let srv_b = tokio::spawn(async move {
            let (mut s, _) = l2.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let _ = s.read(&mut buf).await;
        });

        let mgr = ConnectionManager::<()>::new(ConnectionManagerConfig {
            max_inflight: 1,
            ..Default::default()
        });

        let handle_a = mgr.connect(addr_a).await.unwrap();
        let handle_b = mgr.connect(addr_b).await.unwrap();

        // Saturate peer A with the only permit.
        let _permit_a = handle_a.try_acquire_send_permit().unwrap();
        let result = handle_a.try_acquire_send_permit();
        assert!(matches!(
            result,
            Err(crate::send_concurrency::SendConcurrencyError::LimitExceeded { max: 1 })
        ));

        // Peer B must still be able to acquire its own permit.
        let _permit_b = handle_b.try_acquire_send_permit().unwrap();
        let result = handle_b.try_acquire_send_permit();
        assert!(matches!(
            result,
            Err(crate::send_concurrency::SendConcurrencyError::LimitExceeded { max: 1 })
        ));

        drop(_permit_a);
        drop(_permit_b);
        drop(handle_a);
        drop(handle_b);
        mgr.disconnect(addr_a).await.unwrap();
        mgr.disconnect(addr_b).await.unwrap();
        srv_a.abort();
        srv_b.abort();
    }

    #[tokio::test]
    async fn test_send_concurrency_limiter_metrics_per_connection() {
        // Each connection has independent metrics.
        let l1 = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let l2 = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = l1.local_addr().unwrap();
        let addr_b = l2.local_addr().unwrap();

        let srv_a = tokio::spawn(async move {
            let (mut s, _) = l1.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let _ = s.read(&mut buf).await;
        });
        let srv_b = tokio::spawn(async move {
            let (mut s, _) = l2.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let _ = s.read(&mut buf).await;
        });

        let mgr = ConnectionManager::<()>::new(ConnectionManagerConfig {
            max_inflight: 5,
            ..Default::default()
        });

        let handle_a = mgr.connect(addr_a).await.unwrap();
        let handle_b = mgr.connect(addr_b).await.unwrap();

        // Acquire permits on A only.
        let a1 = handle_a.try_acquire_send_permit().unwrap();
        let a2 = handle_a.try_acquire_send_permit().unwrap();

        let limiter_a = handle_a.send_concurrency_limiter().unwrap();
        let limiter_b = handle_b.send_concurrency_limiter().unwrap();

        assert_eq!(limiter_a.in_flight_current(), 2, "peer A in-flight");
        assert_eq!(limiter_b.in_flight_current(), 0, "peer B in-flight");
        assert_eq!(limiter_a.in_flight_high_watermark(), 2);
        assert_eq!(limiter_b.in_flight_high_watermark(), 0);

        drop(a1);
        drop(a2);
        drop(handle_a);
        drop(handle_b);
        mgr.disconnect(addr_a).await.unwrap();
        mgr.disconnect(addr_b).await.unwrap();
        srv_a.abort();
        srv_b.abort();
    }
}
