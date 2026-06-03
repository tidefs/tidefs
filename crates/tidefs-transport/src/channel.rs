//! Transport channel multiplexing: per-connection channel-ID allocation,
//! lifecycle state tracking, and per-channel byte counters.
//!
//! Channels enable concurrent bulk-data and control message streams over a
//! single transport connection. Each channel has an independent lifecycle
//! tracked through a four-state machine: Opening → Active → Closing → Closed.
//!
//! ## Relationship to stream multiplexing
//!
//! [`crate::stream_mux`] handles wire-level framing (magic, sequence numbers,
//! per-stream backpressure). This module provides a lighter channel-ID layer
//! at the transport message level: tagging [`crate::dispatch::DecodedMessage`]
//! with a channel ID so that bulk-data channels and control channels on the
//! same connection deliver messages independently without head-of-line
//! blocking at the message dispatch layer.
//!
//! ## Channel lifecycle
//!
//! ```text
//! Opening ──(activate)──▶ Active ──(close)──▶ Closing ──(finalize)──▶ Closed
//!      │                      │                                    ▲
//!      └──(reset)─────────────┴──(reset)───────────────────────────┘
//! ```
//!
//! - **Opening**: allocated but not yet active; the peer has not acknowledged
//!   the channel open.
//! - **Active**: channel is usable for send/receive.
//! - **Closing**: graceful close initiated; outstanding data may complete.
//! - **Closed**: terminal state; channel cannot be used.

use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;

// ---------------------------------------------------------------------------
// ChannelId
// ---------------------------------------------------------------------------

/// Unique per-connection channel identifier.
///
/// Channel IDs are allocated by [`ChannelAllocator`] starting at 1. ID 0 is
/// reserved (no channel).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct ChannelId(pub u16);

impl ChannelId {
    /// Maximum assignable channel ID.
    pub const MAX: u16 = u16::MAX;

    /// Create a `ChannelId` from a raw u16.
    #[must_use]
    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    /// Return the raw u16 value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ch{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// ChannelAllocator
// ---------------------------------------------------------------------------

/// Allocates unique [`ChannelId`] values per connection.
#[derive(Debug)]
pub struct ChannelAllocator {
    next: u16,
}

impl ChannelAllocator {
    /// Create a new allocator starting at channel ID 1.
    #[must_use]
    pub fn new() -> Self {
        Self { next: 1 }
    }

    /// Allocate the next available channel ID.
    ///
    /// Returns `None` when all 65535 IDs have been allocated (ID 0 is
    /// reserved).
    pub fn allocate(&mut self) -> Option<ChannelId> {
        if self.next == 0 {
            return None;
        }
        let id = ChannelId(self.next);
        self.next = self.next.wrapping_add(1);
        if self.next == 0 {
            // Exhausted; keep at 0 so subsequent calls also return None.
        }
        Some(id)
    }
}

impl Default for ChannelAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ChannelState
// ---------------------------------------------------------------------------

/// Lifecycle state of a multiplexed channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelState {
    /// Allocated but not yet active (peer hasn't acknowledged).
    Opening,
    /// Channel is usable for send/receive.
    Active,
    /// Graceful close initiated; outstanding data may complete.
    Closing,
    /// Terminal state; cannot be used.
    Closed,
}

impl ChannelState {
    /// Human-readable label.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Active => "active",
            Self::Closing => "closing",
            Self::Closed => "closed",
        }
    }

    /// Whether the channel can accept new sends.
    #[must_use]
    pub fn can_send(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether the channel can receive messages.
    #[must_use]
    pub fn can_receive(&self) -> bool {
        matches!(self, Self::Active | Self::Closing)
    }
}

// ---------------------------------------------------------------------------
// ChannelEntry
// ---------------------------------------------------------------------------

/// Per-channel metadata tracked in the [`ChannelTable`].
#[derive(Debug)]
pub struct ChannelEntry {
    /// Current lifecycle state.
    pub state: ChannelState,
    /// Total bytes sent on this channel.
    pub bytes_sent: u64,
    /// Total bytes received on this channel.
    pub bytes_received: u64,
}

impl ChannelEntry {
    fn new() -> Self {
        Self {
            state: ChannelState::Opening,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// ChannelError
// ---------------------------------------------------------------------------

/// Errors from channel operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelError {
    /// The requested channel ID is not present in the table.
    ChannelNotFound(ChannelId),
    /// The channel is in a state that does not permit the requested operation.
    InvalidState {
        channel_id: ChannelId,
        current: ChannelState,
        expected: &'static str,
    },
    /// The channel is already closed (double-close or use-after-close).
    ChannelAlreadyClosed(ChannelId),
    /// The allocator has exhausted all 65535 channel IDs.
    AllocatorExhausted,
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChannelNotFound(id) => write!(f, "channel {id} not found"),
            Self::InvalidState {
                channel_id,
                current,
                expected,
            } => {
                write!(
                    f,
                    "channel {channel_id}: expected {expected}, but state is {current:?}"
                )
            }
            Self::ChannelAlreadyClosed(id) => write!(f, "channel {id} is already closed"),
            Self::AllocatorExhausted => write!(f, "channel ID allocator exhausted"),
        }
    }
}

// ---------------------------------------------------------------------------
// ChannelTable
// ---------------------------------------------------------------------------

/// Tracks open channels and their per-channel state and byte counters for a
/// single connection.
///
/// Wrapped in `Arc<RwLock<ChannelTable>>` for shared concurrent access from
/// multiple [`ConnectionHandle`](crate::connection::ConnectionHandle) clones.
#[derive(Debug)]
pub struct ChannelTable {
    channels: HashMap<ChannelId, ChannelEntry>,
    allocator: ChannelAllocator,
}

impl ChannelTable {
    /// Create a new empty channel table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            allocator: ChannelAllocator::new(),
        }
    }

    // ----------------------------------------------------------------
    // Lifecycle
    // ----------------------------------------------------------------

    /// Allocate a new channel in `Opening` state.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::AllocatorExhausted`] if all 65535 channel IDs
    /// are in use.
    pub fn open(&mut self) -> Result<ChannelId, ChannelError> {
        let id = self
            .allocator
            .allocate()
            .ok_or(ChannelError::AllocatorExhausted)?;
        self.channels.insert(id, ChannelEntry::new());
        Ok(id)
    }

    /// Transition a channel from `Opening` to `Active`.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::ChannelNotFound`] or
    /// [`ChannelError::InvalidState`] if the channel is not in `Opening`.
    pub fn activate(&mut self, channel_id: ChannelId) -> Result<(), ChannelError> {
        let entry = self
            .channels
            .get_mut(&channel_id)
            .ok_or(ChannelError::ChannelNotFound(channel_id))?;
        if entry.state != ChannelState::Opening {
            return Err(ChannelError::InvalidState {
                channel_id,
                current: entry.state,
                expected: "Opening",
            });
        }
        entry.state = ChannelState::Active;
        Ok(())
    }

    /// Initiate graceful close: `Active` → `Closing`.
    ///
    /// If already in `Closing`, transitions to `Closed` (finalize).
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::ChannelNotFound`] or
    /// [`ChannelError::ChannelAlreadyClosed`].
    pub fn close(&mut self, channel_id: ChannelId) -> Result<(), ChannelError> {
        let entry = self
            .channels
            .get_mut(&channel_id)
            .ok_or(ChannelError::ChannelNotFound(channel_id))?;
        match entry.state {
            ChannelState::Closed => {
                return Err(ChannelError::ChannelAlreadyClosed(channel_id));
            }
            ChannelState::Closing => {
                entry.state = ChannelState::Closed;
            }
            _ => {
                entry.state = ChannelState::Closing;
            }
        }
        Ok(())
    }

    /// Finalize a close: `Closing` → `Closed`.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::ChannelNotFound`] or
    /// [`ChannelError::InvalidState`].
    pub fn finalize_close(&mut self, channel_id: ChannelId) -> Result<(), ChannelError> {
        let entry = self
            .channels
            .get_mut(&channel_id)
            .ok_or(ChannelError::ChannelNotFound(channel_id))?;
        if entry.state != ChannelState::Closing {
            return Err(ChannelError::InvalidState {
                channel_id,
                current: entry.state,
                expected: "Closing",
            });
        }
        entry.state = ChannelState::Closed;
        Ok(())
    }

    /// Force-reset a channel to `Closed` regardless of current state.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::ChannelNotFound`] or
    /// [`ChannelError::ChannelAlreadyClosed`].
    pub fn reset(&mut self, channel_id: ChannelId) -> Result<(), ChannelError> {
        let entry = self
            .channels
            .get_mut(&channel_id)
            .ok_or(ChannelError::ChannelNotFound(channel_id))?;
        if entry.state == ChannelState::Closed {
            return Err(ChannelError::ChannelAlreadyClosed(channel_id));
        }
        entry.state = ChannelState::Closed;
        Ok(())
    }

    // ----------------------------------------------------------------
    // State queries
    // ----------------------------------------------------------------

    /// Return the current state of a channel, if present.
    #[must_use]
    pub fn state(&self, channel_id: ChannelId) -> Option<ChannelState> {
        self.channels.get(&channel_id).map(|e| e.state)
    }

    /// Whether the channel is in a state that permits sending.
    #[must_use]
    pub fn can_send(&self, channel_id: ChannelId) -> bool {
        self.channels
            .get(&channel_id)
            .is_some_and(|e| e.state.can_send())
    }

    /// Whether the channel is in a state that permits receiving.
    #[must_use]
    pub fn can_receive(&self, channel_id: ChannelId) -> bool {
        self.channels
            .get(&channel_id)
            .is_some_and(|e| e.state.can_receive())
    }

    /// Return a reference to the channel entry, if present.
    #[must_use]
    pub fn entry(&self, channel_id: ChannelId) -> Option<&ChannelEntry> {
        self.channels.get(&channel_id)
    }

    /// Number of channels currently in the table (any state).
    #[must_use]
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Return all channel IDs currently in `Active` state.
    #[must_use]
    pub fn active_channel_ids(&self) -> Vec<ChannelId> {
        self.channels
            .iter()
            .filter(|(_, e)| e.state == ChannelState::Active)
            .map(|(id, _)| *id)
            .collect()
    }

    // ----------------------------------------------------------------
    // Byte accounting
    // ----------------------------------------------------------------

    /// Record bytes sent on a channel (adds to `bytes_sent` counter).
    ///
    /// No-op if the channel is not found.
    pub fn record_bytes_sent(&mut self, channel_id: ChannelId, n: u64) {
        if let Some(entry) = self.channels.get_mut(&channel_id) {
            entry.bytes_sent = entry.bytes_sent.saturating_add(n);
        }
    }

    /// Record bytes received on a channel (adds to `bytes_received` counter).
    ///
    /// No-op if the channel is not found.
    pub fn record_bytes_received(&mut self, channel_id: ChannelId, n: u64) {
        if let Some(entry) = self.channels.get_mut(&channel_id) {
            entry.bytes_received = entry.bytes_received.saturating_add(n);
        }
    }
}

impl Default for ChannelTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Thread-safe shared channel table wrapper
// ---------------------------------------------------------------------------

/// A shared, thread-safe reference to a [`ChannelTable`].
///
/// Use this type when sharing a single channel table across multiple
/// [`ConnectionHandle`](crate::connection::ConnectionHandle) clones.
pub type SharedChannelTable = std::sync::Arc<RwLock<ChannelTable>>;

/// Create a new shared channel table.
#[must_use]
pub fn new_shared_channel_table() -> SharedChannelTable {
    std::sync::Arc::new(RwLock::new(ChannelTable::new()))
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ChannelEnvelope — tagged message for send/receive paths
// ---------------------------------------------------------------------------

/// A message payload tagged with an optional channel ID for multiplexed
/// transport.
///
/// Upper-layer protocols wrap their payloads in a `ChannelEnvelope` and
/// enqueue them into the per-peer send queue. The receive side extracts
/// the channel ID from the envelope and constructs a
/// [`DecodedMessage`](crate::dispatch::DecodedMessage) with
/// `channel_id` set so subsystem handlers can distinguish bulk-data
/// channels from control channels on the same connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelEnvelope {
    /// The multiplex channel this message belongs to, if any.
    pub channel_id: Option<ChannelId>,
    /// The raw message payload bytes (opaque to the channel layer).
    pub payload: Vec<u8>,
}

impl ChannelEnvelope {
    /// Create an envelope without a channel association.
    #[must_use]
    pub fn new(payload: Vec<u8>) -> Self {
        Self {
            channel_id: None,
            payload,
        }
    }

    /// Create an envelope tagged for a specific channel.
    #[must_use]
    pub fn on_channel(channel_id: ChannelId, payload: Vec<u8>) -> Self {
        Self {
            channel_id: Some(channel_id),
            payload,
        }
    }
}

// ---------------------------------------------------------------------------
// ChannelMultiplexer — lifecycle-gated send/receive bridge
// ---------------------------------------------------------------------------

/// Errors returned by [`ChannelMultiplexer`] operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelMultiplexerError {
    /// A channel lifecycle error (not found, wrong state, exhausted).
    Channel(ChannelError),
    /// The send queue rejected the message (full).
    SendQueueFull,
    /// The send queue is closed (peer removed or shutting down).
    SendQueueClosed,
}

impl fmt::Display for ChannelMultiplexerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel(e) => write!(f, "channel error: {e}"),
            Self::SendQueueFull => write!(f, "send queue is full"),
            Self::SendQueueClosed => write!(f, "send queue is closed"),
        }
    }
}

impl From<ChannelError> for ChannelMultiplexerError {
    fn from(e: ChannelError) -> Self {
        Self::Channel(e)
    }
}

/// Bridges channel lifecycle management and the per-peer send queue.
///
/// `ChannelMultiplexer` enforces channel state before enqueuing messages:
/// only channels in `Active` state can send. It records `bytes_sent` on
/// the channel table and wraps the payload in a [`ChannelEnvelope`] for
/// delivery through the peer send queue.
///
/// # Type parameter
///
/// `S` is the send handle type, typically
/// [`PeerQueueSender`](crate::peer_send_queue::PeerQueueSender)`<ChannelEnvelope>`.
/// The multiplexer is generic over the sender to avoid coupling to a
/// specific queue implementation.
#[derive(Debug)]
pub struct ChannelMultiplexer<S> {
    channel_table: SharedChannelTable,
    sender: S,
}

impl<S> ChannelMultiplexer<S> {
    /// Create a new multiplexer with a given send handle.
    pub fn new(channel_table: SharedChannelTable, sender: S) -> Self {
        Self {
            channel_table,
            sender,
        }
    }

    /// Return a clone of the shared channel table.
    pub fn channel_table(&self) -> SharedChannelTable {
        self.channel_table.clone()
    }

    /// Return a reference to the send handle.
    pub fn sender(&self) -> &S {
        &self.sender
    }

    // ----------------------------------------------------------------
    // Channel lifecycle (delegates to ChannelTable)
    // ----------------------------------------------------------------

    /// Open a new channel in `Opening` state.
    pub fn open_channel(&self) -> Result<ChannelId, ChannelMultiplexerError> {
        Ok(self.channel_table.write().unwrap().open()?)
    }

    /// Transition a channel from `Opening` to `Active`.
    pub fn activate_channel(&self, channel_id: ChannelId) -> Result<(), ChannelMultiplexerError> {
        Ok(self.channel_table.write().unwrap().activate(channel_id)?)
    }

    /// Initiate graceful close of a channel.
    pub fn close_channel(&self, channel_id: ChannelId) -> Result<(), ChannelMultiplexerError> {
        Ok(self.channel_table.write().unwrap().close(channel_id)?)
    }

    /// Finalize a channel close (`Closing` → `Closed`).
    pub fn finalize_channel(&self, channel_id: ChannelId) -> Result<(), ChannelMultiplexerError> {
        Ok(self
            .channel_table
            .write()
            .unwrap()
            .finalize_close(channel_id)?)
    }

    /// Force-reset a channel to `Closed`.
    pub fn reset_channel(&self, channel_id: ChannelId) -> Result<(), ChannelMultiplexerError> {
        Ok(self.channel_table.write().unwrap().reset(channel_id)?)
    }

    /// Return the current state of a channel.
    pub fn channel_state(&self, channel_id: ChannelId) -> Option<ChannelState> {
        self.channel_table.read().unwrap().state(channel_id)
    }

    // ----------------------------------------------------------------
    // Send (lifecycle-gated)
    // ----------------------------------------------------------------

    /// Enqueue a payload on a specific channel.
    ///
    /// Validates that the channel is in `Active` state, records
    /// `bytes_sent`, wraps the payload in a [`ChannelEnvelope`], and
    /// calls `sender.try_send(env)`.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelMultiplexerError::Channel`] if the channel is
    /// not found, not active, or already closed.
    /// Returns [`ChannelMultiplexerError::SendQueueFull`] if the queue
    /// is at capacity.
    /// Returns [`ChannelMultiplexerError::SendQueueClosed`] if the
    /// queue is closed.
    pub fn try_send_on_channel(
        &self,
        channel_id: ChannelId,
        payload: Vec<u8>,
    ) -> Result<(), ChannelMultiplexerError>
    where
        S: ChannelEnvelopeSender,
    {
        let byte_count = payload.len() as u64;
        let envelope = {
            let mut guard = self.channel_table.write().unwrap();
            if !guard.can_send(channel_id) {
                let state = guard.state(channel_id);
                return match state {
                    None => Err(ChannelError::ChannelNotFound(channel_id).into()),
                    Some(ChannelState::Closed) => {
                        Err(ChannelError::ChannelAlreadyClosed(channel_id).into())
                    }
                    Some(s) => Err(ChannelError::InvalidState {
                        channel_id,
                        current: s,
                        expected: "Active",
                    }
                    .into()),
                };
            }
            guard.record_bytes_sent(channel_id, byte_count);
            ChannelEnvelope::on_channel(channel_id, payload)
        };

        self.sender.try_send(envelope).map_err(|e| match e {
            ChannelEnvelopeSendError::Full => ChannelMultiplexerError::SendQueueFull,
            ChannelEnvelopeSendError::Closed => ChannelMultiplexerError::SendQueueClosed,
        })
    }

    /// Enqueue an untagged (connection-wide) message.
    ///
    /// Wraps the payload in a [`ChannelEnvelope`] with `channel_id: None`
    /// and calls `sender.try_send(env)`.
    pub fn try_send_untagged(&self, payload: Vec<u8>) -> Result<(), ChannelMultiplexerError>
    where
        S: ChannelEnvelopeSender,
    {
        let envelope = ChannelEnvelope::new(payload);
        self.sender.try_send(envelope).map_err(|e| match e {
            ChannelEnvelopeSendError::Full => ChannelMultiplexerError::SendQueueFull,
            ChannelEnvelopeSendError::Closed => ChannelMultiplexerError::SendQueueClosed,
        })
    }
}

// ---------------------------------------------------------------------------
// ChannelEnvelopeSender trait — abstracts over send-queue backends
// ---------------------------------------------------------------------------

/// Error from a [`ChannelEnvelopeSender`] `try_send`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelEnvelopeSendError {
    /// The queue is at capacity.
    Full,
    /// The queue is closed.
    Closed,
}

/// Trait for sending [`ChannelEnvelope`] messages through a transport
/// send path.
///
/// Implementors include
/// [`PeerQueueSender`](crate::peer_send_queue::PeerQueueSender)`<ChannelEnvelope>`
/// and mock/spy senders for testing.
pub trait ChannelEnvelopeSender {
    /// Attempt to enqueue a channel envelope without blocking.
    fn try_send(&self, env: ChannelEnvelope) -> Result<(), ChannelEnvelopeSendError>;
}

// ---------------------------------------------------------------------------
// Receive-path bridge: ChannelEnvelope → DecodedMessage
// ---------------------------------------------------------------------------

/// Convert a [`ChannelEnvelope`] from the receive queue into a
/// [`DecodedMessage`](crate::dispatch::DecodedMessage) for dispatch
/// through [`MessageDispatch`](crate::dispatch::MessageDispatch).
///
/// The `family` parameter is the [`MessageFamily`] extracted from the
/// transport frame header or codec layer.
///
/// If the envelope carries a `channel_id`, the resulting
/// [`DecodedMessage`] will have it set, enabling handlers to
/// distinguish bulk-data channels from control channels.
#[must_use]
pub fn envelope_to_decoded_message(
    env: ChannelEnvelope,
    family: crate::envelope::MessageFamily,
) -> crate::dispatch::DecodedMessage {
    match env.channel_id {
        Some(ch) => crate::dispatch::DecodedMessage::with_channel_id(family, env.payload, ch),
        None => {
            let mut msg = crate::dispatch::DecodedMessage::new(family, env.payload);
            msg.channel_id = None;
            msg
        }
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// PeerQueueSender adapter for ChannelEnvelopeSender trait
// ---------------------------------------------------------------------------

use crate::peer_send_queue::{PeerQueueSender, SendError};

impl ChannelEnvelopeSender for PeerQueueSender<ChannelEnvelope> {
    fn try_send(&self, env: ChannelEnvelope) -> Result<(), ChannelEnvelopeSendError> {
        PeerQueueSender::try_send(self, env).map_err(|e| match e {
            SendError::Full => ChannelEnvelopeSendError::Full,
            SendError::Closed => ChannelEnvelopeSendError::Closed,
        })
    }
}

// Tests
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------------------------------------------------------
    // ChannelId
    // ----------------------------------------------------------------

    #[test]
    fn channel_id_new_and_as_u16() {
        let id = ChannelId::new(42);
        assert_eq!(id.as_u16(), 42);
    }

    #[test]
    fn channel_id_display() {
        assert_eq!(format!("{}", ChannelId(7)), "ch7");
    }

    #[test]
    fn channel_id_default_is_zero() {
        assert_eq!(ChannelId::default(), ChannelId(0));
    }

    // ----------------------------------------------------------------
    // ChannelAllocator
    // ----------------------------------------------------------------

    #[test]
    fn allocator_starts_at_one() {
        let mut alloc = ChannelAllocator::new();
        assert_eq!(alloc.allocate(), Some(ChannelId(1)));
    }

    #[test]
    fn allocator_sequential_uniqueness() {
        let mut alloc = ChannelAllocator::new();
        let ids: Vec<_> = (0..100).map(|_| alloc.allocate().unwrap()).collect();
        // All unique
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 100);
        // Sequential from 1
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(id.as_u16(), (i + 1) as u16);
        }
    }

    #[test]
    fn allocator_exhaustion() {
        let mut alloc = ChannelAllocator::new();
        for _ in 1..=65535 {
            assert!(alloc.allocate().is_some());
        }
        // Next should be None (wrapped past 65535)
        assert_eq!(alloc.allocate(), None);
        assert_eq!(alloc.allocate(), None);
    }

    // ----------------------------------------------------------------
    // Channel lifecycles
    // ----------------------------------------------------------------

    #[test]
    fn lifecycle_open_activate_close_finalize() {
        let mut table = ChannelTable::new();
        let id = table.open().unwrap();
        assert_eq!(table.state(id), Some(ChannelState::Opening));

        table.activate(id).unwrap();
        assert_eq!(table.state(id), Some(ChannelState::Active));
        assert!(table.can_send(id));
        assert!(table.can_receive(id));

        table.close(id).unwrap();
        assert_eq!(table.state(id), Some(ChannelState::Closing));
        assert!(!table.can_send(id));
        assert!(table.can_receive(id));

        table.finalize_close(id).unwrap();
        assert_eq!(table.state(id), Some(ChannelState::Closed));
        assert!(!table.can_send(id));
        assert!(!table.can_receive(id));
    }

    #[test]
    fn lifecycle_open_reset() {
        let mut table = ChannelTable::new();
        let id = table.open().unwrap();
        assert_eq!(table.state(id), Some(ChannelState::Opening));

        table.reset(id).unwrap();
        assert_eq!(table.state(id), Some(ChannelState::Closed));
    }

    #[test]
    fn lifecycle_active_reset() {
        let mut table = ChannelTable::new();
        let id = table.open().unwrap();
        table.activate(id).unwrap();
        assert_eq!(table.state(id), Some(ChannelState::Active));

        table.reset(id).unwrap();
        assert_eq!(table.state(id), Some(ChannelState::Closed));
    }

    #[test]
    fn double_close_rejected() {
        let mut table = ChannelTable::new();
        let id = table.open().unwrap();
        table.activate(id).unwrap();

        // First close: Active → Closing
        table.close(id).unwrap();
        assert_eq!(table.state(id), Some(ChannelState::Closing));

        // Second close: Closing → Closed (allowed, acts as finalize)
        table.close(id).unwrap();
        assert_eq!(table.state(id), Some(ChannelState::Closed));

        // Third close: already closed → error
        assert_eq!(table.close(id), Err(ChannelError::ChannelAlreadyClosed(id)));
    }

    #[test]
    fn double_reset_rejected() {
        let mut table = ChannelTable::new();
        let id = table.open().unwrap();

        table.reset(id).unwrap();
        assert_eq!(table.state(id), Some(ChannelState::Closed));

        assert_eq!(table.reset(id), Err(ChannelError::ChannelAlreadyClosed(id)));
    }

    #[test]
    fn activate_wrong_state() {
        let mut table = ChannelTable::new();
        let id = table.open().unwrap();
        table.activate(id).unwrap();
        // Second activate on Active state should fail
        assert!(table.activate(id).is_err());
    }

    #[test]
    fn finalize_close_wrong_state() {
        let mut table = ChannelTable::new();
        let id = table.open().unwrap();
        table.activate(id).unwrap();
        // finalize_close from Active should fail (not Closing)
        assert!(table.finalize_close(id).is_err());
    }

    #[test]
    fn channel_not_found() {
        let mut table = ChannelTable::new();
        let bad_id = ChannelId(999);
        assert_eq!(
            table.activate(bad_id),
            Err(ChannelError::ChannelNotFound(bad_id))
        );
        assert_eq!(
            table.close(bad_id),
            Err(ChannelError::ChannelNotFound(bad_id))
        );
        assert_eq!(
            table.reset(bad_id),
            Err(ChannelError::ChannelNotFound(bad_id))
        );
        assert_eq!(table.state(bad_id), None);
        assert!(!table.can_send(bad_id));
    }

    // ----------------------------------------------------------------
    // Byte counters
    // ----------------------------------------------------------------

    #[test]
    fn byte_counters_initial_zero() {
        let mut table = ChannelTable::new();
        let id = table.open().unwrap();
        let entry = table.entry(id).unwrap();
        assert_eq!(entry.bytes_sent, 0);
        assert_eq!(entry.bytes_received, 0);
    }

    #[test]
    fn byte_counters_record() {
        let mut table = ChannelTable::new();
        let id = table.open().unwrap();
        table.record_bytes_sent(id, 100);
        table.record_bytes_sent(id, 50);
        table.record_bytes_received(id, 200);

        let entry = table.entry(id).unwrap();
        assert_eq!(entry.bytes_sent, 150);
        assert_eq!(entry.bytes_received, 200);
    }

    #[test]
    fn byte_counters_saturating() {
        let mut table = ChannelTable::new();
        let id = table.open().unwrap();
        table.record_bytes_sent(id, u64::MAX);
        table.record_bytes_sent(id, 1);
        assert_eq!(table.entry(id).unwrap().bytes_sent, u64::MAX);
    }

    #[test]
    fn byte_counters_noop_on_missing_channel() {
        let mut table = ChannelTable::new();
        // Should not panic
        table.record_bytes_sent(ChannelId(999), 100);
        table.record_bytes_received(ChannelId(999), 100);
    }

    // ----------------------------------------------------------------
    // Active channel listing
    // ----------------------------------------------------------------

    #[test]
    fn active_channel_ids() {
        let mut table = ChannelTable::new();
        let id1 = table.open().unwrap();
        let id2 = table.open().unwrap();
        let id3 = table.open().unwrap();

        table.activate(id1).unwrap();
        table.activate(id3).unwrap();
        // id2 is still Opening

        let active = table.active_channel_ids();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&id1));
        assert!(active.contains(&id3));
        assert!(!active.contains(&id2));
    }

    #[test]
    fn channel_count() {
        let mut table = ChannelTable::new();
        assert_eq!(table.channel_count(), 0);
        table.open().unwrap();
        assert_eq!(table.channel_count(), 1);
        table.open().unwrap();
        assert_eq!(table.channel_count(), 2);
    }

    // ----------------------------------------------------------------
    // Shared channel table
    // ----------------------------------------------------------------

    #[test]
    fn shared_channel_table_basic() {
        let table = new_shared_channel_table();
        let id = table.write().unwrap().open().unwrap();
        table.write().unwrap().activate(id).unwrap();
        assert_eq!(table.read().unwrap().state(id), Some(ChannelState::Active));
    }

    // ----------------------------------------------------------------
    // ChannelError Display
    // ----------------------------------------------------------------

    #[test]
    fn channel_error_display() {
        let e = ChannelError::ChannelNotFound(ChannelId(5));
        assert!(format!("{e}").contains("ch5"));

        let e = ChannelError::AllocatorExhausted;
        assert!(format!("{e}").contains("exhausted"));

        let e = ChannelError::ChannelAlreadyClosed(ChannelId(3));
        assert!(format!("{e}").contains("ch3"));
    }

    // ----------------------------------------------------------------
    // ChannelEnvelope
    // ----------------------------------------------------------------

    #[test]
    fn envelope_new_no_channel() {
        let env = ChannelEnvelope::new(b"data".to_vec());
        assert_eq!(env.channel_id, None);
        assert_eq!(env.payload, b"data");
    }

    #[test]
    fn envelope_on_channel() {
        let env = ChannelEnvelope::on_channel(ChannelId(42), b"bulk".to_vec());
        assert_eq!(env.channel_id, Some(ChannelId(42)));
        assert_eq!(env.payload, b"bulk");
    }

    #[test]
    fn envelope_channels_are_differentiable() {
        let bulk = ChannelEnvelope::on_channel(ChannelId(1), b"bulk-data".to_vec());
        let ctrl = ChannelEnvelope::on_channel(ChannelId(2), b"ctrl-msg".to_vec());
        assert_ne!(bulk.channel_id, ctrl.channel_id);
        assert_ne!(bulk.payload, ctrl.payload);
    }

    // ----------------------------------------------------------------
    // Integration: channel + send queue + dispatch
    // ----------------------------------------------------------------

    /// Simulates sending interleaved bulk and control messages on two
    /// channels through a send queue, draining them, and verifying
    /// independent per-channel delivery order.
    #[test]
    fn two_channels_independent_delivery() {
        let mut table = ChannelTable::new();
        let bulk_ch = table.open().unwrap();
        let ctrl_ch = table.open().unwrap();
        table.activate(bulk_ch).unwrap();
        table.activate(ctrl_ch).unwrap();

        let mut send_queue: std::collections::VecDeque<ChannelEnvelope> =
            std::collections::VecDeque::new();

        send_queue.push_back(ChannelEnvelope::on_channel(bulk_ch, b"bulk-0".to_vec()));
        send_queue.push_back(ChannelEnvelope::on_channel(ctrl_ch, b"ctrl-0".to_vec()));
        send_queue.push_back(ChannelEnvelope::on_channel(bulk_ch, b"bulk-1".to_vec()));
        send_queue.push_back(ChannelEnvelope::on_channel(bulk_ch, b"bulk-2".to_vec()));
        send_queue.push_back(ChannelEnvelope::on_channel(ctrl_ch, b"ctrl-1".to_vec()));

        let mut bulk_delivered: Vec<Vec<u8>> = Vec::new();
        let mut ctrl_delivered: Vec<Vec<u8>> = Vec::new();

        while let Some(env) = send_queue.pop_front() {
            let payload_len = env.payload.len() as u64;
            match env.channel_id {
                Some(id) if id == bulk_ch => bulk_delivered.push(env.payload),
                Some(id) if id == ctrl_ch => ctrl_delivered.push(env.payload),
                _ => {}
            }
            if let Some(ch) = env.channel_id {
                table.record_bytes_received(ch, payload_len);
            }
        }

        assert_eq!(bulk_delivered.len(), 3);
        assert_eq!(bulk_delivered[0], b"bulk-0");
        assert_eq!(bulk_delivered[1], b"bulk-1");
        assert_eq!(bulk_delivered[2], b"bulk-2");

        assert_eq!(ctrl_delivered.len(), 2);
        assert_eq!(ctrl_delivered[0], b"ctrl-0");
        assert_eq!(ctrl_delivered[1], b"ctrl-1");

        let bulk_entry = table.entry(bulk_ch).unwrap();
        let ctrl_entry = table.entry(ctrl_ch).unwrap();
        assert_eq!(bulk_entry.bytes_received, 18);
        assert_eq!(ctrl_entry.bytes_received, 12);
    }

    /// Closing a channel mid-stream prevents further sends to that
    /// channel but the other channel continues unaffected.
    #[test]
    fn channel_close_isolates_delivery() {
        let mut table = ChannelTable::new();
        let bulk_ch = table.open().unwrap();
        let ctrl_ch = table.open().unwrap();
        table.activate(bulk_ch).unwrap();
        table.activate(ctrl_ch).unwrap();

        table.close(bulk_ch).unwrap();
        assert!(!table.can_send(bulk_ch));
        assert!(table.can_send(ctrl_ch));

        assert!(!table.can_send(bulk_ch));
    }

    /// Messages without a channel ID (channel_id=None) are delivered
    /// alongside channel-tagged messages without interference.
    #[test]
    fn untagged_and_tagged_messages_interleave() {
        let mut table = ChannelTable::new();
        let ch = table.open().unwrap();
        table.activate(ch).unwrap();

        let mut send_queue: std::collections::VecDeque<ChannelEnvelope> =
            std::collections::VecDeque::new();

        send_queue.push_back(ChannelEnvelope::new(b"untagged-0".to_vec()));
        send_queue.push_back(ChannelEnvelope::on_channel(ch, b"tagged-0".to_vec()));
        send_queue.push_back(ChannelEnvelope::new(b"untagged-1".to_vec()));
        send_queue.push_back(ChannelEnvelope::on_channel(ch, b"tagged-1".to_vec()));

        let mut untagged_count = 0;
        let mut tagged_count = 0;
        while let Some(env) = send_queue.pop_front() {
            if env.channel_id.is_some() {
                tagged_count += 1;
            } else {
                untagged_count += 1;
            }
        }
        assert_eq!(untagged_count, 2);
        assert_eq!(tagged_count, 2);
    }

    /// Messages on non-Active channels are rejected by can_send.
    #[test]
    fn invalid_channel_send_rejected() {
        let mut table = ChannelTable::new();
        let ch = table.open().unwrap();
        assert!(!table.can_send(ch));
        table.activate(ch).unwrap();
        assert!(table.can_send(ch));
        table.close(ch).unwrap();
        assert!(!table.can_send(ch));
        table.finalize_close(ch).unwrap();
        assert!(!table.can_send(ch));
    }
    // ChannelMultiplexer integration tests
    // ----------------------------------------------------------------

    /// A mock sender that collects envelopes for test inspection.
    #[derive(Debug, Default)]
    struct MockSender {
        sent: std::cell::RefCell<Vec<ChannelEnvelope>>,
    }

    impl ChannelEnvelopeSender for MockSender {
        fn try_send(&self, env: ChannelEnvelope) -> Result<(), ChannelEnvelopeSendError> {
            self.sent.borrow_mut().push(env);
            Ok(())
        }
    }

    /// Full send-receive cycle: open two channels, send interleaved
    /// messages through ChannelMultiplexer, drain from the mock queue,
    /// convert envelopes to DecodedMessages, verify channel IDs.
    #[test]
    fn multiplexer_full_send_receive_cycle() {
        let table = new_shared_channel_table();
        let mock = MockSender::default();
        let mux = ChannelMultiplexer::new(table.clone(), mock);

        // Open and activate two channels
        let bulk_ch = mux.open_channel().unwrap();
        let ctrl_ch = mux.open_channel().unwrap();
        mux.activate_channel(bulk_ch).unwrap();
        mux.activate_channel(ctrl_ch).unwrap();

        // Send interleaved messages
        mux.try_send_on_channel(bulk_ch, b"bulk-0".to_vec())
            .unwrap();
        mux.try_send_on_channel(ctrl_ch, b"ctrl-0".to_vec())
            .unwrap();
        mux.try_send_on_channel(bulk_ch, b"bulk-1".to_vec())
            .unwrap();
        mux.try_send_untagged(b"global-msg".to_vec()).unwrap();
        mux.try_send_on_channel(ctrl_ch, b"ctrl-1".to_vec())
            .unwrap();

        // Drain mock sender
        let envelopes: Vec<ChannelEnvelope> = mux.sender().sent.borrow_mut().drain(..).collect();
        assert_eq!(envelopes.len(), 5);

        // Convert to DecodedMessages and verify channel IDs
        use crate::envelope::MessageFamily;
        let decoded: Vec<_> = envelopes
            .into_iter()
            .map(|env| envelope_to_decoded_message(env, MessageFamily::StateTransfer))
            .collect();

        assert_eq!(decoded[0].channel_id, Some(bulk_ch));
        assert_eq!(&decoded[0].payload[..], b"bulk-0");
        assert_eq!(decoded[1].channel_id, Some(ctrl_ch));
        assert_eq!(&decoded[1].payload[..], b"ctrl-0");
        assert_eq!(decoded[2].channel_id, Some(bulk_ch));
        assert_eq!(decoded[3].channel_id, None); // untagged
        assert_eq!(&decoded[3].payload[..], b"global-msg");
        assert_eq!(decoded[4].channel_id, Some(ctrl_ch));

        // Byte counters recorded by the multiplexer
        let guard = table.read().unwrap();
        let bulk_entry = guard.entry(bulk_ch).unwrap();
        let ctrl_entry = guard.entry(ctrl_ch).unwrap();
        assert_eq!(bulk_entry.bytes_sent, 12); // "bulk-0" + "bulk-1"
        assert_eq!(ctrl_entry.bytes_sent, 12); // "ctrl-0" + "ctrl-1"
    }

    /// Send on a non-Active channel is rejected by the multiplexer.
    #[test]
    fn multiplexer_rejects_closed_channel() {
        let table = new_shared_channel_table();
        let mock = MockSender::default();
        let mux = ChannelMultiplexer::new(table, mock);

        let ch = mux.open_channel().unwrap();
        // Not yet activated - Opening state
        let result = mux.try_send_on_channel(ch, b"too-early".to_vec());
        assert!(result.is_err());
        match result {
            Err(ChannelMultiplexerError::Channel(ChannelError::InvalidState { .. })) => {}
            other => panic!("expected InvalidState, got {other:?}"),
        }

        // Activate, then close
        mux.activate_channel(ch).unwrap();
        mux.try_send_on_channel(ch, b"ok".to_vec()).unwrap();
        mux.close_channel(ch).unwrap();

        // Closing: no sends allowed
        let result = mux.try_send_on_channel(ch, b"too-late".to_vec());
        assert!(result.is_err());
    }

    /// Opening → Active → Closing → Closed lifecycle through the multiplexer.
    #[test]
    fn multiplexer_lifecycle() {
        let table = new_shared_channel_table();
        let mock = MockSender::default();
        let mux = ChannelMultiplexer::new(table.clone(), mock);

        let ch = mux.open_channel().unwrap();
        assert_eq!(mux.channel_state(ch), Some(ChannelState::Opening));

        mux.activate_channel(ch).unwrap();
        assert_eq!(mux.channel_state(ch), Some(ChannelState::Active));

        mux.close_channel(ch).unwrap();
        assert_eq!(mux.channel_state(ch), Some(ChannelState::Closing));

        mux.finalize_channel(ch).unwrap();
        assert_eq!(mux.channel_state(ch), Some(ChannelState::Closed));
    }

    /// ChannelMultiplexerError Display covers all variants.
    #[test]
    fn multiplexer_error_display() {
        let e = ChannelMultiplexerError::Channel(ChannelError::ChannelNotFound(ChannelId(99)));
        assert!(format!("{e}").contains("ch99"));

        let e = ChannelMultiplexerError::SendQueueFull;
        assert!(format!("{e}").contains("full"));

        let e = ChannelMultiplexerError::SendQueueClosed;
        assert!(format!("{e}").contains("closed"));
    }

    /// envelope_to_decoded_message with a channel ID.
    #[test]
    fn envelope_to_decoded_message_with_channel() {
        let env = ChannelEnvelope::on_channel(ChannelId(7), b"data".to_vec());
        let decoded =
            envelope_to_decoded_message(env, crate::envelope::MessageFamily::StateTransfer);
        assert_eq!(decoded.channel_id, Some(ChannelId(7)));
        assert_eq!(
            decoded.family,
            crate::envelope::MessageFamily::StateTransfer
        );
        assert_eq!(&decoded.payload[..], b"data");
    }

    /// envelope_to_decoded_message without a channel ID.
    #[test]
    fn envelope_to_decoded_message_no_channel() {
        let env = ChannelEnvelope::new(b"global".to_vec());
        let decoded = envelope_to_decoded_message(env, crate::envelope::MessageFamily::HelloClose);
        assert_eq!(decoded.channel_id, None);
        assert_eq!(decoded.family, crate::envelope::MessageFamily::HelloClose);
        assert_eq!(&decoded.payload[..], b"global");
    }
}

// ----------------------------------------------------------------
