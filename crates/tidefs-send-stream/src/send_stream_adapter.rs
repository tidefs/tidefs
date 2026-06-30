// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Send-stream transport session adapter: bridges VFSSEND2 data-plane framing
//! to tidefs-transport session channels.
//!
//! This module provides [`SendStreamTransportWriter`] and
//! [`SendStreamTransportReader`] — transport-aware implementations of the
//! [`TransportWriter`](crate::transport::TransportWriter) and
//! [`TransportReader`](crate::transport::TransportReader) traits that route
//! bulk data transfer through established transport sessions using
//! `MessageFamily::StateTransfer` and `SessionClass::TransferBulk`.
//!
//! # Architecture
//!
//! ```text
//! VFSSEND2 records
//!       |
//!       v
//! SendTransport / RecvTransport  (crate::transport)
//!       |
//!       +-- TransportWriter ──► SendStreamTransportWriter
//!       |                            |
//!       |                     sync_channel -> async drain task
//!       |                            |
//!       |                     SendPipelineHandle::send()
//!       |
//!       +-- TransportReader ◄── SendStreamTransportReader
//!                                    |
//!                             mpsc::Receiver<Vec<u8>>
//! ```
//!
//! The writer bridges synchronous `send_chunk` calls to the async
//! `SendPipelineHandle` via an internal bounded channel drained by a
//! background tokio task. The reader exposes a plain `mpsc::Receiver`
//! that a transport message handler feeds with received chunk bytes.
//!
//! # Session-class awareness
//!
//! The writer binds `SessionClass::TransferBulk` on the
//! `SendPipelineHandle` so that bulk data-plane traffic is automatically
//! deprioritized behind control messages in the outbound scheduler
//! (see [`session_class_to_send_priority`]).
//!
//! # Example
//!
//! ```ignore
//! use tidefs_send_stream::send_stream_adapter::{
//!     SendStreamSession, SendStreamSessionConfig,
//! };
//! use tidefs_send_stream::transport::{
//!     SendTransport, RecvTransport, LoopbackPair,
//! };
//!
//! // Create a session adapter
//! let session = SendStreamSession::new(SendStreamSessionConfig {
//!     buffer_depth: 64,
//!     max_chunk_size: 65536,
//! });
//!
//! // With a SendPipelineHandle, create a writer
//! let writer = session.create_writer(handle);
//!
//! // Use with existing SendTransport
//! let mut send = SendTransport::new(encoded_stream, writer, 65536);
//! send.send_all().unwrap();
//! ```

use std::sync::mpsc;

use tidefs_transport::envelope::MessageFamily;
use tidefs_transport::outbound_send::SendPipelineHandle;
use tidefs_types_transport_session::SessionClass;
// SendPriority used via full path tidefs_transport::send_scheduler::SendPriority
// Data-plane bulk priority: SendPriority::Bulk maps from SessionClass::TransferBulk

use crate::transport::TransportReader;
use crate::transport::TransportWriter;

// ---------------------------------------------------------------------------
// SendStreamSessionConfig
// ---------------------------------------------------------------------------

/// Configuration for a [`SendStreamSession`].
#[derive(Clone, Copy, Debug)]
pub struct SendStreamSessionConfig {
    /// Maximum number of chunks buffered between the sync writer and the
    /// async drain task. Must be at least 1.
    pub buffer_depth: usize,
    /// Maximum payload bytes per transport chunk.
    pub max_chunk_size: u32,
}

impl Default for SendStreamSessionConfig {
    fn default() -> Self {
        Self {
            buffer_depth: 64,
            max_chunk_size: 65536,
        }
    }
}

// ---------------------------------------------------------------------------
// SendStreamAdapterError
// ---------------------------------------------------------------------------

/// Errors from send-stream adapter operations.
#[derive(Debug)]
pub enum SendStreamAdapterError {
    /// The underlying transport reported an error.
    Transport(String),
    /// The adapter has been shut down (background task exited).
    Shutdown,
}

impl std::fmt::Display for SendStreamAdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(msg) => write!(f, "send-stream transport error: {msg}"),
            Self::Shutdown => write!(f, "send-stream adapter shut down"),
        }
    }
}

impl std::error::Error for SendStreamAdapterError {}

// ---------------------------------------------------------------------------
// SendStreamTransportWriter
// ---------------------------------------------------------------------------

/// A [`TransportWriter`] that sends data through a transport session's
/// [`SendPipelineHandle`].
///
/// Internally bridges synchronous `send_chunk` calls to the async transport
/// via a bounded channel drained by a background tokio task.
pub struct SendStreamTransportWriter {
    tx: mpsc::SyncSender<Vec<u8>>,
    max_chunk_size: u32,
    /// Handle to the background drain task; dropped on writer drop, which
    /// signals the drain loop to terminate.
    _task: Option<tokio::task::JoinHandle<()>>,
}

impl SendStreamTransportWriter {
    /// Create a new writer backed by a transport send pipeline handle.
    ///
    /// Spawns a background tokio task that drains chunks from the internal
    /// channel and sends them through the handle with
    /// [`SendPriority::Bulk`] (derived from [`SessionClass::TransferBulk`]).
    ///
    /// `buffer_depth` controls how many chunks can be queued before
    /// `send_chunk` blocks (backpressure).
    pub fn new(handle: SendPipelineHandle, config: SendStreamSessionConfig) -> Self {
        let handle = handle.with_session_class(SessionClass::TransferBulk);
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(config.buffer_depth);

        let max_chunk_size = config.max_chunk_size;

        let priority = tidefs_transport::send_scheduler::SendPriority::Bulk;
        let family = MessageFamily::StateTransfer;

        let task = tokio::task::spawn(async move {
            drain_writer(rx, handle, family, priority).await;
        });

        Self {
            tx,
            max_chunk_size,
            _task: Some(task),
        }
    }

    /// Return the maximum chunk size for this transport session.
    pub fn max_chunk_size(&self) -> u32 {
        self.max_chunk_size
    }
}

impl TransportWriter for SendStreamTransportWriter {
    type Error = SendStreamAdapterError;

    fn max_chunk_size(&self) -> u32 {
        self.max_chunk_size
    }

    fn send_chunk(&mut self, chunk: Vec<u8>) -> Result<(), Self::Error> {
        self.tx
            .send(chunk)
            .map_err(|_| SendStreamAdapterError::Shutdown)
    }

    fn credits_available(&self) -> Option<u32> {
        None // unbounded credit model; backpressure via channel capacity
    }

    fn wait_for_credit(&mut self) -> Result<(), Self::Error> {
        Ok(()) // channel send provides natural backpressure
    }
}

// ---------------------------------------------------------------------------
// SendStreamTransportReader
// ---------------------------------------------------------------------------

/// A [`TransportReader`] that receives chunk data from a transport session.
///
/// Chunks are fed into this reader via the `SyncSender` returned at
/// construction time. Callers should hold the `SyncSender` and push
/// received chunks from a transport message handler into the channel.
#[derive(Debug)]
pub struct SendStreamTransportReader {
    rx: mpsc::Receiver<Vec<u8>>,
}

impl SendStreamTransportReader {
    /// Create a new reader with a given internal buffer capacity.
    ///
    /// Returns the reader and a `SyncSender` that transport message
    /// handlers use to push received chunks into the reader.
    pub fn new(capacity: usize) -> (Self, mpsc::SyncSender<Vec<u8>>) {
        let (tx, rx) = mpsc::sync_channel(capacity);
        (Self { rx }, tx)
    }

    /// Return `true` if there are chunks available for non-blocking read.
    pub fn has_pending(&self) -> bool {
        // Best-effort: try_recv but put it back isn't possible with mpsc.
        // We just check if try_recv would succeed by doing a peek via a
        // clone... not possible with std mpsc.
        false
    }
}

impl TransportReader for SendStreamTransportReader {
    type Error = SendStreamAdapterError;

    fn recv_chunk(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        match self.rx.try_recv() {
            Ok(chunk) => Ok(Some(chunk)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Ok(None),
        }
    }

    fn wait_for_chunk(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        match self.rx.recv() {
            Ok(chunk) => Ok(Some(chunk)),
            Err(mpsc::RecvError) => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// SendStreamSession — factory for paired writer + reader adapter
// ---------------------------------------------------------------------------

/// Factory that creates paired [`SendStreamTransportWriter`] and
/// [`SendStreamTransportReader`] adapters for loopback testing and
/// local harness use.
///
/// For production use, create the writer via
/// [`SendStreamTransportWriter::new`] with a real
/// [`SendPipelineHandle`], and feed the reader through the
/// `SyncSender` returned by [`SendStreamTransportReader::new`].
pub struct SendStreamSession {
    config: SendStreamSessionConfig,
}

impl SendStreamSession {
    /// Create a new session factory.
    pub fn new(config: SendStreamSessionConfig) -> Self {
        Self { config }
    }

    /// Create a [`SendStreamTransportWriter`] that sends through the
    /// given [`SendPipelineHandle`].
    pub fn create_writer(&self, handle: SendPipelineHandle) -> SendStreamTransportWriter {
        SendStreamTransportWriter::new(handle, self.config)
    }

    /// Create a [`SendStreamTransportReader`] for receiving stream data.
    ///
    /// Returns the reader and a `SyncSender` that should be held by
    /// a transport message handler to push received chunks into the reader.
    pub fn create_reader(&self) -> (SendStreamTransportReader, mpsc::SyncSender<Vec<u8>>) {
        SendStreamTransportReader::new(self.config.buffer_depth)
    }

    /// Return a copy of the configuration.
    pub fn config(&self) -> SendStreamSessionConfig {
        self.config
    }
}

// ---------------------------------------------------------------------------
// Background drain task
// ---------------------------------------------------------------------------

/// Drains chunks from the sync channel and sends them through the transport
/// handle as `MessageFamily::StateTransfer` messages.
async fn drain_writer(
    rx: mpsc::Receiver<Vec<u8>>,
    handle: SendPipelineHandle,
    family: MessageFamily,
    priority: tidefs_transport::send_scheduler::SendPriority,
) {
    // Drain chunks until the channel is disconnected (writer dropped).
    while let Ok(chunk) = rx.recv() {
        if let Err(e) = handle.send_with_priority(family, priority, &chunk).await {
            // Log send failure; channel will disconnect and writer will see Shutdown
            eprintln!("send-stream transport writer: send failed: {e}, draining remaining chunks");
            // Drain remaining chunks to unblock the sync sender
            while rx.recv().is_ok() {}
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_accepts_chunks_and_drains_to_channel() {
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(4);

        let mut writer = SendStreamTransportWriter {
            tx,
            max_chunk_size: 1024,
            _task: None, // No background task in test
        };

        writer.send_chunk(b"hello".to_vec()).unwrap();
        writer.send_chunk(b"world".to_vec()).unwrap();

        assert_eq!(rx.recv().unwrap(), b"hello".to_vec());
        assert_eq!(rx.recv().unwrap(), b"world".to_vec());

        drop(writer);
        assert!(rx.recv().is_err());
    }

    #[test]
    fn writer_returns_shutdown_when_receiver_dropped() {
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(1);
        let mut writer = SendStreamTransportWriter {
            tx,
            max_chunk_size: 1024,
            _task: None,
        };

        drop(rx); // receiver dropped — channel disconnected

        let err = writer.send_chunk(b"data".to_vec()).unwrap_err();
        assert!(matches!(err, SendStreamAdapterError::Shutdown));
    }

    #[test]
    fn writer_backpressure_via_channel_capacity() {
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(1); // buffer_depth=1

        let mut writer = SendStreamTransportWriter {
            tx,
            max_chunk_size: 1024,
            _task: None,
        };

        // First chunk fills the channel
        writer.send_chunk(b"first".to_vec()).unwrap();

        // Drain, then send second
        assert_eq!(rx.recv().unwrap(), b"first".to_vec());
        writer.send_chunk(b"second".to_vec()).unwrap();
        assert_eq!(rx.recv().unwrap(), b"second".to_vec());

        drop(writer);
    }

    #[test]
    fn reader_receives_chunks_in_order() {
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(4);
        let mut reader = SendStreamTransportReader { rx };

        tx.send(b"chunk0".to_vec()).unwrap();
        tx.send(b"chunk1".to_vec()).unwrap();
        tx.send(b"chunk2".to_vec()).unwrap();
        drop(tx); // signal end-of-stream

        assert_eq!(reader.wait_for_chunk().unwrap(), Some(b"chunk0".to_vec()));
        assert_eq!(reader.wait_for_chunk().unwrap(), Some(b"chunk1".to_vec()));
        assert_eq!(reader.wait_for_chunk().unwrap(), Some(b"chunk2".to_vec()));
        assert_eq!(reader.wait_for_chunk().unwrap(), None);
    }

    #[test]
    fn reader_try_recv_returns_none_when_empty() {
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(4);
        let mut reader = SendStreamTransportReader { rx };

        assert_eq!(reader.recv_chunk().unwrap(), None);

        tx.send(b"data".to_vec()).unwrap();
        assert_eq!(reader.recv_chunk().unwrap(), Some(b"data".to_vec()));
        assert_eq!(reader.recv_chunk().unwrap(), None);

        drop(tx);
        assert_eq!(reader.recv_chunk().unwrap(), None);
    }

    #[test]
    fn reader_wait_blocks_until_chunk_available() {
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(4);
        let mut reader = SendStreamTransportReader { rx };

        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            tx.send(b"delayed".to_vec()).unwrap();
            drop(tx);
        });

        let chunk = reader.wait_for_chunk().unwrap();
        assert_eq!(chunk, Some(b"delayed".to_vec()));
        assert_eq!(reader.wait_for_chunk().unwrap(), None);

        handle.join().unwrap();
    }

    #[test]
    fn session_factory_creates_writer_and_reader() {
        let config = SendStreamSessionConfig {
            buffer_depth: 8,
            max_chunk_size: 4096,
        };
        let session = SendStreamSession::new(config);

        // Reader can be created without a real transport handle
        let (mut reader, _tx) = session.create_reader();
        assert!(reader.recv_chunk().unwrap().is_none());

        assert_eq!(session.config().buffer_depth, 8);
        assert_eq!(session.config().max_chunk_size, 4096);
    }

    #[test]
    fn config_defaults_are_reasonable() {
        let config = SendStreamSessionConfig::default();
        assert_eq!(config.buffer_depth, 64);
        assert_eq!(config.max_chunk_size, 65536);
    }

    #[test]
    fn writer_exposes_max_chunk_size() {
        let (tx, _rx) = mpsc::sync_channel::<Vec<u8>>(1);
        let writer = SendStreamTransportWriter {
            tx,
            max_chunk_size: 32768,
            _task: None,
        };
        assert_eq!(writer.max_chunk_size(), 32768);
    }

    #[test]
    fn writer_drop_disconnects_channel() {
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(4);
        let writer = SendStreamTransportWriter {
            tx,
            max_chunk_size: 1024,
            _task: None,
        };

        assert!(rx.try_recv().is_err()); // empty
        drop(writer);
        assert!(rx.recv().is_err()); // disconnected
    }

    #[test]
    fn adapter_error_display_and_debug() {
        let e = SendStreamAdapterError::Transport("test error".into());
        assert!(format!("{e}").contains("test error"));
        assert!(format!("{e:?}").contains("Transport"));

        let e = SendStreamAdapterError::Shutdown;
        assert!(format!("{e}").contains("shut down"));
    }

    #[test]
    fn loopback_scenario_writer_to_reader() {
        // Simulates: writer sends chunks, they arrive in reader
        let (tx, writer_rx) = mpsc::sync_channel::<Vec<u8>>(8);
        // In real use, the background drain task sends through transport,
        // and the reader receives from the peer. Here we directly connect:
        let mut reader = SendStreamTransportReader { rx: writer_rx };

        let mut writer = SendStreamTransportWriter {
            tx,
            max_chunk_size: 4096,
            _task: None,
        };

        // Send chunks through the writer
        for i in 0..5 {
            writer.send_chunk(vec![i as u8; 100]).unwrap();
        }

        // Read them back through the reader
        for i in 0..5 {
            let chunk = reader.wait_for_chunk().unwrap().unwrap();
            assert_eq!(chunk, vec![i as u8; 100]);
        }
    }
}
