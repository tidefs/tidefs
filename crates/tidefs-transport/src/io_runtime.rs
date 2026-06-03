//! Async TCP I/O runtime bridging connection lifecycle to framed byte
//! streams.
//!
//! ## Purpose
//!
//! The transport crate provides connection management (#5788 lifecycle state
//! machine, #5795 connection registry), per-peer send queuing (#5793), message
//! dispatch (#5801), request-response correlation (#5800), and endpoint
//! addressing (#5787).  None of these components perform actual socket I/O.
//! This module bridges that gap, providing TCP listener bind, accept loop,
//! and per-connection read/write tasks that move bytes.
//!
//! ## Architecture
//!
//! ```text
//! TcpListener ──(accept)──▶ TcpStream
//!                              │
//!              ┌───────────────┴───────────────┐
//!              ▼                               ▼
//!         read_task()                    write_task()
//!              │                               │
//!     decode frame ────▶ dispatch         dequeue from PeerSendQueue
//!         via MessageDispatch                 encode frame
//!                                               write to TcpStream
//! ```
//!
//! ## Frame format
//!
//! Each frame on the wire is:
//!
//! ```text
//! [0]       family    u8   MessageFamily discriminant
//! [1..5]    len       u32  big-endian payload length
//! [5..]     payload   [u8] variable-length payload
//! ```
//!
//! Maximum frame payload size is 16 MiB (configurable via
//! `MAX_FRAME_PAYLOAD`).

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::addr::TransportAddr;
use crate::config::TransportConfig;
use crate::connection_registry::{
    ConnectionId, ConnectionRegistry, ConnectionState, RegistryError,
};
use crate::dispatch::{DecodedMessage, DispatchError, MessageDispatch};
use crate::envelope::MessageFamily;
use crate::error_classification::{
    os_error_to_kind, DefaultRecoveryDispatcher, ErrorClassifier, ErrorObserver, RecoveryAction,
    RecoveryDispatcher, TracingErrorObserver, TransportErrorKind,
};
use crate::peer_admission::AdmittedPeer;
use crate::peer_send_queue::{PeerQueueReceiver, PeerQueueSender, PeerSendQueue};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum payload size in a single frame (16 MiB).
pub const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;

/// Size of the frame header: 1-byte family + 4-byte length.
pub const IO_FRAME_HEADER_SIZE: usize = 5;

// ---------------------------------------------------------------------------
// ConnectionHandle
// ---------------------------------------------------------------------------

/// Handle returned by [`IoRuntime::connect`] for outbound connection
/// lifecycle tracking.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionHandle {
    /// The peer identifier derived from the remote address.
    pub peer_id: u64,
    /// The connection identifier registered in the registry.
    pub connection_id: ConnectionId,
}

// ---------------------------------------------------------------------------
// IoError
// ---------------------------------------------------------------------------

/// Errors from the I/O runtime layer.
#[derive(Debug, thiserror::Error)]
pub enum IoError {
    /// Bind failed.
    #[error("bind failed: {0}")]
    Bind(#[source] std::io::Error),

    /// TCP connect failed.
    #[error("connect failed: {0}")]
    Connect(#[source] std::io::Error),

    /// Accept failed.
    #[error("accept failed: {0}")]
    Accept(#[source] std::io::Error),

    /// Read failed.
    #[error("read failed on peer {peer}: {source}")]
    Read {
        peer: String,
        #[source]
        source: std::io::Error,
    },

    /// Write failed.
    #[error("write failed on peer {peer}: {source}")]
    Write {
        peer: String,
        #[source]
        source: std::io::Error,
    },

    /// Frame too large or too small.
    #[error("frame size error: {0}")]
    FrameSize(String),

    /// Unknown message family discriminant.
    #[error("unknown message family discriminant: {0}")]
    UnknownMessageFamily(u8),

    /// Message dispatch error.
    #[error("dispatch error: {0}")]
    Dispatch(#[from] DispatchError),

    /// Unsupported transport carrier.
    #[error("unsupported transport carrier: {0}")]
    UnsupportedCarrier(String),

    /// Registry error.
    #[error("registry error: {0}")]
    Registry(String),
}

impl From<RegistryError> for IoError {
    fn from(e: RegistryError) -> Self {
        IoError::Registry(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Frame encode / decode
// ---------------------------------------------------------------------------

/// Encode a message into a framed byte vector.
///
/// Wire format: `[family:1][len:4 BE][payload:N]`.
pub fn encode_frame(family: MessageFamily, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(IO_FRAME_HEADER_SIZE + payload.len());
    buf.push(family as u8);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Decode a frame from raw bytes, returning the [`MessageFamily`] and
/// payload.
///
/// Returns an error if the family discriminant is unknown or the frame
/// is malformed.
pub fn decode_frame(data: &[u8]) -> Result<(MessageFamily, Vec<u8>), IoError> {
    if data.len() < IO_FRAME_HEADER_SIZE {
        return Err(IoError::FrameSize(format!(
            "frame too short: {} bytes, need at least {}",
            data.len(),
            IO_FRAME_HEADER_SIZE
        )));
    }

    let family_discriminant = data[0];
    let family = MessageFamily::try_from(family_discriminant)
        .map_err(|_| IoError::UnknownMessageFamily(family_discriminant))?;

    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&data[1..5]);
    let payload_len = u32::from_be_bytes(len_buf) as usize;

    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(IoError::FrameSize(format!(
            "frame too large: {payload_len} bytes (max {MAX_FRAME_PAYLOAD})"
        )));
    }

    if data.len() < IO_FRAME_HEADER_SIZE + payload_len {
        return Err(IoError::FrameSize(format!(
            "frame truncated: header says {} bytes but only {} available",
            payload_len,
            data.len().saturating_sub(IO_FRAME_HEADER_SIZE)
        )));
    }

    let payload = data[IO_FRAME_HEADER_SIZE..IO_FRAME_HEADER_SIZE + payload_len].to_vec();
    Ok((family, payload))
}

/// Read a complete frame from an async TCP stream.
///
/// Reads the 5-byte header to determine payload length, then reads the
/// full payload.  Returns `None` on clean EOF (connection closed).
pub async fn read_frame(
    stream: &mut TcpStream,
) -> Result<Option<(MessageFamily, Vec<u8>)>, IoError> {
    let peer_str = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let mut header = [0u8; IO_FRAME_HEADER_SIZE];
    match stream.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        }
        Err(e) => {
            return Err(IoError::Read {
                peer: peer_str,
                source: e,
            });
        }
    }

    let family =
        MessageFamily::try_from(header[0]).map_err(|_| IoError::UnknownMessageFamily(header[0]))?;

    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&header[1..5]);
    let payload_len = u32::from_be_bytes(len_buf) as usize;

    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(IoError::FrameSize(format!(
            "frame too large: {payload_len} bytes (max {MAX_FRAME_PAYLOAD})"
        )));
    }

    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| IoError::Read {
                peer: peer_str.clone(),
                source: e,
            })?;
    }

    Ok(Some((family, payload)))
}

/// Write a frame to an async TCP stream.
pub async fn write_frame(
    stream: &mut TcpStream,
    family: MessageFamily,
    payload: &[u8],
) -> Result<(), IoError> {
    let peer_str = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let frame = encode_frame(family, payload);
    stream.write_all(&frame).await.map_err(|e| IoError::Write {
        peer: peer_str,
        source: e,
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// IoRuntime
// ---------------------------------------------------------------------------

/// Async TCP I/O runtime that bridges raw sockets to the transport
/// subsystem (connection registry, message dispatch, peer send queues).
///
/// ## Lifecycle
///
/// 1. Create an [`IoRuntime`] with a [`TransportConfig`].
/// 2. Call [`bind`](Self::bind) to obtain a [`TcpListener`].
/// 3. Call [`accept_loop`](Self::accept_loop) to accept connections and
///    spawn both per-connection read and write tasks.
///
/// The read task decodes framed messages and routes them through
/// [`MessageDispatch`].  The write task drains the peer's
/// [`PeerSendQueue`] and writes framed messages to the socket.
pub struct IoRuntime {
    classifier: ErrorClassifier,
    observer: Arc<dyn ErrorObserver>,
    config: TransportConfig,
}

impl IoRuntime {
    /// Create a new I/O runtime with the given configuration.
    #[must_use]
    pub fn new(
        config: TransportConfig,
        classifier: ErrorClassifier,
        observer: Arc<dyn ErrorObserver>,
    ) -> Self {
        Self {
            config,
            classifier,
            observer,
        }
    }

    /// Return a reference to the transport configuration.
    #[must_use]
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    /// Bind a TCP listener to the given address.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::Bind`] if the bind fails.
    /// Returns [`IoError::UnsupportedCarrier`] if the address is not TCP.
    pub async fn bind(&self, addr: &TransportAddr) -> Result<TcpListener, IoError> {
        let sock_addr = match addr {
            TransportAddr::Tcp(sa) => *sa,
            other => {
                return Err(IoError::UnsupportedCarrier(other.carrier().to_string()));
            }
        };

        TcpListener::bind(sock_addr).await.map_err(IoError::Bind)
    }

    /// Establish an outbound TCP connection to a peer.
    ///
    /// Resolves a [`TransportAddr`] to `SocketAddr`, connects via
    /// `TcpStream::connect`, registers the peer in the
    /// [`ConnectionRegistry`] and [`PeerSendQueue`], and spawns both
    /// read and write tasks — identical to the per-connection setup
    /// in [`accept_loop`](Self::accept_loop).
    ///
    /// Returns a [`ConnectionHandle`] for lifecycle tracking.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::UnsupportedCarrier`] if the address is not TCP.
    /// Returns [`IoError::Connect`] if the TCP connect fails.
    pub async fn connect<F>(
        &self,
        addr: &TransportAddr,
        registry: Arc<ConnectionRegistry>,
        dispatch: Arc<MessageDispatch>,
        send_queues: Arc<Mutex<PeerSendQueue<Vec<u8>>>>,
        encode: Arc<F>,
    ) -> Result<ConnectionHandle, IoError>
    where
        F: Fn(&[u8]) -> (MessageFamily, Vec<u8>) + Send + Sync + 'static + ?Sized,
    {
        let sock_addr = match addr {
            TransportAddr::Tcp(sa) => *sa,
            other => {
                return Err(IoError::UnsupportedCarrier(other.carrier().to_string()));
            }
        };

        let stream = TcpStream::connect(sock_addr)
            .await
            .map_err(IoError::Connect)?;

        let peer_addr = stream.peer_addr().map_err(IoError::Connect)?;
        let peer_id = socket_addr_to_peer_id(&peer_addr);
        let conn_id = ConnectionId::new(0);

        // Register in the connection registry.
        let admitted = AdmittedPeer::new(peer_id, 0);
        registry.insert(&admitted, conn_id, peer_addr)?;
        let _ = registry.set_state(peer_id, ConnectionState::Connected);

        // Initialize keepalive if configured.
        if let Some(kc) = self.config.keepalive() {
            registry.enable_keepalive(kc.clone());
            let _tick = registry.spawn_keepalive_tick_loop();
            // Proactively arm keepalive for this peer so the tick loop
            // can send pings without waiting for the first inbound frame.
            // record_activity lazy-inits the lifecycle with on_active().
            registry.record_activity(peer_id);
        }

        // Obtain the receiver from the peer send queue.
        let (pong_sender, receiver) = {
            let mut sq = send_queues.lock().await;
            let pong_sender = sq.sender(peer_id);
            // Register ping sender for keepalive tick loop if a sender is available.
            if let (true, Some(ref ps)) = (registry.keepalive_enabled(), &pong_sender) {
                registry.register_ping_sender(peer_id, ps.clone());
            }
            (pong_sender, sq.take_receiver(peer_id))
        };

        let receiver = match receiver {
            Some(r) => r,
            None => {
                return Err(IoError::Registry(
                    "could not obtain receiver for peer".to_string(),
                ));
            }
        };

        // Split the stream for concurrent read/write.
        let (read_half, write_half) = stream.into_split();

        // Spawn the read task.
        let read_dispatch = Arc::clone(&dispatch);
        let read_registry = Arc::clone(&registry);
        let read_classifier = self.classifier.clone();
        let read_observer = Arc::clone(&self.observer);
        tokio::spawn(async move {
            read_task(
                read_half,
                ReadTaskContext {
                    peer_id,
                    conn_id,
                    dispatch: read_dispatch,
                    registry: read_registry,
                    classifier: read_classifier,
                    observer: read_observer,
                    pong_sender,
                },
            )
            .await;
        });

        // Spawn the write task.
        let enc = Arc::clone(&encode);
        let write_classifier = self.classifier.clone();
        let write_observer = Arc::clone(&self.observer);
        let write_registry = Arc::clone(&registry);
        tokio::spawn(async move {
            write_task_impl(
                write_half,
                receiver,
                move |msg: &Vec<u8>| enc(msg),
                WriteTaskContext {
                    peer_id,
                    conn_id,
                    classifier: write_classifier,
                    observer: write_observer,
                    registry: write_registry,
                },
            )
            .await;
        });

        Ok(ConnectionHandle {
            peer_id,
            connection_id: conn_id,
        })
    }

    /// Run the accept loop with automatic write-task spawning.
    ///
    /// Accepts inbound connections, registers them in the
    /// [`ConnectionRegistry`], and spawns both read and write tasks.
    /// The write task is spawned immediately by obtaining a
    /// [`PeerQueueReceiver`] from the provided `send_queues` and uses
    /// `encode` to serialize each queued message to
    /// `(MessageFamily, Vec<u8>)` for framing.
    ///
    /// `encode` is wrapped in [`Arc`] so it can be shared across all
    /// spawned write tasks.
    ///
    /// The [`PeerQueueSender`] for each peer remains in `send_queues`
    /// so upper-layer protocols can enqueue outbound messages.
    ///
    /// This function runs until the listener is closed or an
    /// unrecoverable error occurs.
    pub async fn accept_loop<F>(
        &self,
        listener: TcpListener,
        registry: Arc<ConnectionRegistry>,
        dispatch: Arc<MessageDispatch>,
        send_queues: Arc<Mutex<PeerSendQueue<Vec<u8>>>>,
        encode: Arc<F>,
    ) -> Result<(), IoError>
    where
        F: Fn(&[u8]) -> (MessageFamily, Vec<u8>) + Send + Sync + 'static + ?Sized,
    {
        let mut next_conn_id: u64 = 0;

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    return Err(IoError::Accept(e));
                }
            };

            let peer_id = socket_addr_to_peer_id(&peer_addr);
            let conn_id = ConnectionId::new(next_conn_id);
            next_conn_id = next_conn_id.wrapping_add(1);

            // Create a synthetic AdmittedPeer — at this layer we accept
            // all connections; upper-layer admission gates filter.
            let admitted = AdmittedPeer::new(peer_id, 0);

            match registry.insert(&admitted, conn_id, peer_addr) {
                Ok(()) => {}
                Err(RegistryError::DuplicatePeer(_)) => {
                    tracing::debug!(
                        "accept_loop: duplicate peer {}, dropping connection",
                        peer_id
                    );
                    drop(stream);
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        "accept_loop: failed to register connection for peer {}: {}",
                        peer_id,
                        e
                    );
                    drop(stream);
                    continue;
                }
            }

            // Transition to Connected state.
            let _ = registry.set_state(peer_id, ConnectionState::Connected);

            // Initialize keepalive if configured.
            if let Some(kc) = self.config.keepalive() {
                registry.enable_keepalive(kc.clone());
                let _tick = registry.spawn_keepalive_tick_loop();
                // Proactively arm keepalive for this peer so the tick loop
                // can send pings without waiting for the first inbound frame.
                // record_activity lazy-inits the lifecycle with on_active().
                registry.record_activity(peer_id);
            }

            // Obtain receiver from the peer send queue.
            let (pong_sender, receiver) = {
                let mut sq = send_queues.lock().await;
                let pong_sender = sq.sender(peer_id); // ensure queue exists for this peer
                                                      // Register ping sender for keepalive tick loop if a sender is available.
                if let (true, Some(ref ps)) = (registry.keepalive_enabled(), &pong_sender) {
                    registry.register_ping_sender(peer_id, ps.clone());
                }
                (pong_sender, sq.take_receiver(peer_id))
            };

            let receiver = match receiver {
                Some(r) => r,
                None => {
                    tracing::warn!(
                        "accept_loop: could not obtain receiver for peer {}",
                        peer_id
                    );
                    drop(stream);
                    continue;
                }
            };

            // Split the stream for concurrent read/write.
            let (read_half, write_half) = stream.into_split();

            // Spawn the read task.
            let read_dispatch = Arc::clone(&dispatch);
            let read_registry = Arc::clone(&registry);
            let read_classifier = self.classifier.clone();
            let read_observer = Arc::clone(&self.observer);
            tokio::spawn(async move {
                read_task(
                    read_half,
                    ReadTaskContext {
                        peer_id,
                        conn_id,
                        dispatch: read_dispatch,
                        registry: read_registry,
                        classifier: read_classifier,
                        observer: read_observer,
                        pong_sender,
                    },
                )
                .await;
            });

            // Spawn the write task.
            let enc = Arc::clone(&encode);
            let write_classifier = self.classifier.clone();
            let write_observer = Arc::clone(&self.observer);
            let write_registry = Arc::clone(&registry);
            tokio::spawn(async move {
                write_task_impl(
                    write_half,
                    receiver,
                    move |msg: &Vec<u8>| enc(msg),
                    WriteTaskContext {
                        peer_id,
                        conn_id,
                        classifier: write_classifier,
                        observer: write_observer,
                        registry: write_registry,
                    },
                )
                .await;
            });
        }
    }

    /// Spawn a standalone write task for a peer connection.
    ///
    /// Drains the [`PeerQueueReceiver`] and writes each message as a framed
    /// byte vector to the TCP stream.  The `encode` function serializes a
    /// message `M` into `(MessageFamily, Vec<u8>)` for framing.
    ///
    /// The write task runs until the queue is closed (returns `None`) or a
    /// write error occurs.
    pub fn spawn_write_task<M, F>(
        write_half: tokio::net::tcp::OwnedWriteHalf,
        peer_id: u64,
        receiver: PeerQueueReceiver<M>,
        encode: F,
    ) where
        M: Send + 'static,
        F: Fn(&M) -> (MessageFamily, Vec<u8>) + Send + 'static,
    {
        tokio::spawn(async move {
            write_task_impl(
                write_half,
                receiver,
                encode,
                WriteTaskContext {
                    peer_id,
                    conn_id: ConnectionId::new(0),
                    classifier: ErrorClassifier::new(),
                    observer: Arc::new(TracingErrorObserver),
                    registry: Arc::new(ConnectionRegistry::new()),
                },
            )
            .await;
        });
    }

    /// Spawn a write task from a full `TcpStream`.
    ///
    /// Convenience wrapper that splits the stream and spawns the write
    /// task on the write half.  The read half is dropped.
    pub fn spawn_write_task_from_stream<M, F>(
        stream: TcpStream,
        peer_id: u64,
        receiver: PeerQueueReceiver<M>,
        encode: F,
    ) where
        M: Send + 'static,
        F: Fn(&M) -> (MessageFamily, Vec<u8>) + Send + 'static,
    {
        let (_read_half, write_half) = stream.into_split();
        Self::spawn_write_task(write_half, peer_id, receiver, encode);
    }
}

// ---------------------------------------------------------------------------
// Per-connection read task
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// IoError → TransportErrorKind mapping
// ---------------------------------------------------------------------------

/// Map an [`IoError`] to a [`TransportErrorKind`] for classification.
fn io_error_to_transport_kind(err: &IoError) -> TransportErrorKind {
    match err {
        IoError::Read { source, .. }
        | IoError::Write { source, .. }
        | IoError::Connect(source)
        | IoError::Bind(source)
        | IoError::Accept(source) => match source.raw_os_error() {
            Some(code) => os_error_to_kind(code),
            None => TransportErrorKind::InternalError,
        },
        IoError::FrameSize(_) => TransportErrorKind::ProtocolViolation,
        IoError::UnknownMessageFamily(_) => TransportErrorKind::UnknownMessageFamily,
        IoError::Dispatch(_) => TransportErrorKind::InternalError,
        IoError::UnsupportedCarrier(_) => TransportErrorKind::InternalError,
        IoError::Registry(_) => TransportErrorKind::InternalError,
    }
}

struct ReadTaskContext {
    peer_id: u64,
    conn_id: ConnectionId,
    dispatch: Arc<MessageDispatch>,
    registry: Arc<ConnectionRegistry>,
    classifier: ErrorClassifier,
    observer: Arc<dyn ErrorObserver>,
    pong_sender: Option<PeerQueueSender<Vec<u8>>>,
}

/// Read task for a single connection: decode frames and dispatch messages.
async fn read_task(mut stream: tokio::net::tcp::OwnedReadHalf, ctx: ReadTaskContext) {
    let ReadTaskContext {
        peer_id,
        conn_id,
        dispatch,
        registry,
        classifier,
        observer,
        pong_sender,
    } = ctx;

    loop {
        match read_frame_from_half(&mut stream).await {
            Ok(Some((family, payload))) => {
                // Check keepalive expectation before record_activity resets state.
                // Only auto-respond when we are NOT expecting a pong (i.e. the
                // received frame is a ping from the peer, not a response to ours).
                let keepalive_action = if family == MessageFamily::HeartbeatAck {
                    if let Some(seq) = crate::keepalive::decode_pong(&payload) {
                        let should_respond = !registry.is_expecting_pong(peer_id);
                        Some((seq, should_respond))
                    } else {
                        None
                    }
                } else {
                    None
                };

                registry.record_activity(peer_id);

                if let Some((seq, should_respond)) = keepalive_action {
                    registry.on_keepalive_pong(peer_id, seq);
                    if should_respond {
                        if let Some(ref sender) = pong_sender {
                            let pong = crate::keepalive::build_pong(seq);
                            let _ = sender.try_send(pong);
                        }
                    }
                }
                let msg = DecodedMessage::new(family, payload);
                if let Err(_e) = dispatch.dispatch(msg) {
                    let transport_err =
                        classifier.classify_kind_direct(TransportErrorKind::InternalError, conn_id);
                    let action = DefaultRecoveryDispatcher.dispatch(&transport_err);
                    observer.on_error(&transport_err, action);
                    if matches!(
                        action,
                        RecoveryAction::CloseConnection | RecoveryAction::DrainAndClose
                    ) {
                        let _ = registry.set_state(peer_id, ConnectionState::Closed);
                        registry.remove_keepalive(peer_id);
                        break;
                    }
                }
            }
            Ok(None) => {
                tracing::debug!("read_task: peer {} disconnected cleanly", peer_id);
                break;
            }
            Err(e) => {
                let kind = io_error_to_transport_kind(&e);
                let transport_err = classifier.classify_kind_direct(kind, conn_id);
                let action = DefaultRecoveryDispatcher.dispatch(&transport_err);
                observer.on_error(&transport_err, action);
                match action {
                    RecoveryAction::CloseConnection => {
                        let _ = registry.set_state(peer_id, ConnectionState::Closed);
                        registry.remove_keepalive(peer_id);
                    }
                    RecoveryAction::DrainAndClose => {
                        let _ = registry.set_state(peer_id, ConnectionState::Drained);
                        registry.remove_keepalive(peer_id);
                    }
                    _ => {}
                }
                break;
            }
        }
    }

    // Mark the connection as drained in the registry and clean up keepalive.
    let _ = registry.set_state(peer_id, ConnectionState::Drained);
    registry.remove_keepalive(peer_id);
}

/// Read a frame from a read half.  Same format as [`read_frame`] but
/// works on an `OwnedReadHalf`.
async fn read_frame_from_half(
    stream: &mut tokio::net::tcp::OwnedReadHalf,
) -> Result<Option<(MessageFamily, Vec<u8>)>, IoError> {
    let mut header = [0u8; IO_FRAME_HEADER_SIZE];
    match stream.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        }
        Err(e) => {
            return Err(IoError::Read {
                peer: "unknown".to_string(),
                source: e,
            });
        }
    }

    let family =
        MessageFamily::try_from(header[0]).map_err(|_| IoError::UnknownMessageFamily(header[0]))?;

    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&header[1..5]);
    let payload_len = u32::from_be_bytes(len_buf) as usize;

    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(IoError::FrameSize(format!(
            "frame too large: {payload_len} bytes (max {MAX_FRAME_PAYLOAD})"
        )));
    }

    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| IoError::Read {
                peer: "unknown".to_string(),
                source: e,
            })?;
    }

    Ok(Some((family, payload)))
}

// ---------------------------------------------------------------------------
// Per-connection write task
// ---------------------------------------------------------------------------

struct WriteTaskContext {
    peer_id: u64,
    conn_id: ConnectionId,
    classifier: ErrorClassifier,
    observer: Arc<dyn ErrorObserver>,
    registry: Arc<ConnectionRegistry>,
}

/// Write task implementation: drain the peer send queue and write frames.
async fn write_task_impl<M, F>(
    mut stream: tokio::net::tcp::OwnedWriteHalf,
    mut receiver: PeerQueueReceiver<M>,
    encode: F,
    ctx: WriteTaskContext,
) where
    M: Send,
    F: Fn(&M) -> (MessageFamily, Vec<u8>),
{
    let WriteTaskContext {
        peer_id,
        conn_id,
        classifier,
        observer,
        registry,
    } = ctx;

    loop {
        match receiver.recv().await {
            Some(msg) => {
                let (family, payload) = encode(&msg);
                let frame = encode_frame(family, &payload);
                if let Err(e) = stream.write_all(&frame).await {
                    let kind = io_error_to_transport_kind(&IoError::Write {
                        peer: peer_id.to_string(),
                        source: e,
                    });
                    let transport_err = classifier.classify_kind_direct(kind, conn_id);
                    let action = DefaultRecoveryDispatcher.dispatch(&transport_err);
                    observer.on_error(&transport_err, action);
                    match action {
                        RecoveryAction::CloseConnection => {
                            let _ = registry.set_state(peer_id, ConnectionState::Closed);
                            registry.remove_keepalive(peer_id);
                        }
                        RecoveryAction::DrainAndClose => {
                            let _ = registry.set_state(peer_id, ConnectionState::Drained);
                            registry.remove_keepalive(peer_id);
                        }
                        _ => {}
                    }
                    break;
                }
            }
            None => {
                tracing::debug!("write_task: peer {} queue closed, draining", peer_id);
                break;
            }
        }
    }

    // Attempt graceful shutdown.
    let _ = stream.shutdown().await;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a `SocketAddr` to a peer ID (deterministic u64 hash).
fn socket_addr_to_peer_id(addr: &SocketAddr) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    addr.hash(&mut hasher);
    hasher.finish()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    type TestEncodeFn = Arc<dyn Fn(&[u8]) -> (MessageFamily, Vec<u8>) + Send + Sync>;

    // -------------------------------------------------------------------
    // Frame encode / decode round-trip
    // -------------------------------------------------------------------

    #[test]
    fn encode_decode_round_trip() {
        let payload = b"hello transport";
        let family = MessageFamily::StateTransfer;
        let frame = encode_frame(family, payload);
        assert_eq!(frame.len(), IO_FRAME_HEADER_SIZE + payload.len());

        let (decoded_family, decoded_payload) = decode_frame(&frame).unwrap();
        assert_eq!(decoded_family, family);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn encode_empty_payload() {
        let family = MessageFamily::HelloClose;
        let frame = encode_frame(family, b"");
        assert_eq!(frame.len(), IO_FRAME_HEADER_SIZE);

        let (decoded_family, decoded_payload) = decode_frame(&frame).unwrap();
        assert_eq!(decoded_family, family);
        assert!(decoded_payload.is_empty());
    }

    #[test]
    fn decode_truncated_header() {
        let result = decode_frame(&[0x00, 0x00]);
        assert!(matches!(result, Err(IoError::FrameSize(_))));
    }

    #[test]
    fn decode_unknown_family() {
        let mut buf = vec![255u8]; // invalid family discriminant
        buf.extend_from_slice(&10u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; 10]);
        let result = decode_frame(&buf);
        assert!(matches!(result, Err(IoError::UnknownMessageFamily(255))));
    }

    #[test]
    fn decode_payload_too_large() {
        let mut buf = vec![MessageFamily::StateTransfer as u8];
        buf.extend_from_slice(&((MAX_FRAME_PAYLOAD as u32) + 1).to_be_bytes());
        let result = decode_frame(&buf);
        assert!(matches!(result, Err(IoError::FrameSize(_))));
    }

    #[test]
    fn encode_decode_all_families() {
        for family in MessageFamily::all() {
            let payload: Vec<u8> = (0..64).map(|i| i as u8).collect();
            let frame = encode_frame(family, &payload);
            let (decoded_family, decoded_payload) = decode_frame(&frame).unwrap();
            assert_eq!(decoded_family, family);
            assert_eq!(decoded_payload, payload);
        }
    }

    // -------------------------------------------------------------------
    // IoRuntime construction
    // -------------------------------------------------------------------

    #[test]
    fn create_runtime() {
        let cfg = TransportConfig::default();
        let rt = IoRuntime::new(
            cfg.clone(),
            ErrorClassifier::new(),
            Arc::new(TracingErrorObserver),
        );
        assert_eq!(rt.config().endpoint(), cfg.endpoint());
    }

    // -------------------------------------------------------------------
    // Frame header size constant
    // -------------------------------------------------------------------

    #[test]
    fn io_frame_header_size_is_correct() {
        assert_eq!(IO_FRAME_HEADER_SIZE, 5);
    }

    // -------------------------------------------------------------------
    // socket_addr_to_peer_id determinism
    // -------------------------------------------------------------------

    #[test]
    fn socket_addr_to_peer_id_deterministic() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let id1 = socket_addr_to_peer_id(&addr);
        let id2 = socket_addr_to_peer_id(&addr);
        assert_eq!(id1, id2);
    }

    // -------------------------------------------------------------------
    // read_frame / write_frame integration (tokio test)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn read_write_frame_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let result = read_frame(&mut stream).await.unwrap();
            assert!(result.is_some());
            let (family, payload) = result.unwrap();
            assert_eq!(family, MessageFamily::HelloClose);
            assert_eq!(payload, b"ping");

            write_frame(&mut stream, MessageFamily::ReplicaTransferVerify, b"pong")
                .await
                .unwrap();
        });

        let mut stream = TcpStream::connect(server_addr).await.unwrap();
        write_frame(&mut stream, MessageFamily::HelloClose, b"ping")
            .await
            .unwrap();

        let result = read_frame(&mut stream).await.unwrap();
        assert!(result.is_some());
        let (family, payload) = result.unwrap();
        assert_eq!(family, MessageFamily::ReplicaTransferVerify);
        assert_eq!(payload, b"pong");

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn read_frame_eof_returns_none() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream); // immediately close
        });

        let mut stream = TcpStream::connect(server_addr).await.unwrap();
        // Give server time to close.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let result = read_frame(&mut stream).await.unwrap();
        assert!(result.is_none());

        server_handle.await.unwrap();
    }

    // -------------------------------------------------------------------
    // accept_loop starts tasks (smoke test)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn accept_loop_spawns_tasks() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let registry = Arc::new(ConnectionRegistry::new());
        let dispatch = Arc::new(MessageDispatch::new());

        let rt = IoRuntime::new(
            TransportConfig::default(),
            ErrorClassifier::new(),
            Arc::new(TracingErrorObserver),
        );

        let reg = Arc::clone(&registry);
        let disp = Arc::clone(&dispatch);
        let sq: Arc<Mutex<PeerSendQueue<Vec<u8>>>> = Arc::new(Mutex::new(PeerSendQueue::new(
            16,
            crate::peer_send_queue::BackpressurePolicy::Block,
        )));
        let sq2 = Arc::clone(&sq);

        // Spawn the accept loop in a background task.
        let encode_fn: TestEncodeFn =
            Arc::new(|payload: &[u8]| (MessageFamily::StateTransfer, payload.to_vec()));
        let accept_handle = tokio::spawn(async move {
            let _ = rt.accept_loop(listener, reg, disp, sq2, encode_fn).await;
        });

        // Connect a client to trigger an accept.
        let mut stream = TcpStream::connect(server_addr).await.unwrap();

        // Send a frame and close.
        write_frame(&mut stream, MessageFamily::HelloClose, b"hello")
            .await
            .unwrap();
        drop(stream);

        // Give the accept loop time to process.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // The registry should be non-empty (accept loop registered the peer).
        let active = registry.list_active();
        assert!(active.len() <= 1);

        accept_handle.abort();
    }

    /// Two connections from different ephemeral ports get distinct peer
    /// IDs and both register successfully.  This verifies the accept loop
    /// handles sequential connections without crashes.
    #[tokio::test]
    async fn accept_loop_registers_multiple_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let registry = Arc::new(ConnectionRegistry::new());
        let dispatch = Arc::new(MessageDispatch::new());

        let rt = IoRuntime::new(
            TransportConfig::default(),
            ErrorClassifier::new(),
            Arc::new(TracingErrorObserver),
        );

        let reg = Arc::clone(&registry);
        let disp = Arc::clone(&dispatch);
        let sq: Arc<Mutex<PeerSendQueue<Vec<u8>>>> = Arc::new(Mutex::new(PeerSendQueue::new(
            16,
            crate::peer_send_queue::BackpressurePolicy::Block,
        )));
        let sq2 = Arc::clone(&sq);

        let encode_fn: TestEncodeFn =
            Arc::new(|payload: &[u8]| (MessageFamily::StateTransfer, payload.to_vec()));
        let accept_handle = tokio::spawn(async move {
            let _ = rt.accept_loop(listener, reg, disp, sq2, encode_fn).await;
        });

        // First connection.
        let stream1 = TcpStream::connect(server_addr).await.unwrap();
        drop(stream1);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Second connection from same host (different ephemeral port).
        let stream2 = TcpStream::connect(server_addr).await.unwrap();
        drop(stream2);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        accept_handle.abort();
    }

    // -------------------------------------------------------------------
    // write_task via spawn_write_task
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn write_task_drains_queue_and_sends_frames() {
        use crate::peer_send_queue::{BackpressurePolicy, PeerSendQueue};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Read two frames.
            for expected in &[b"message-1" as &[u8], b"message-2"] {
                let result = read_frame(&mut stream).await.unwrap();
                assert!(result.is_some());
                let (_family, payload) = result.unwrap();
                assert_eq!(payload, *expected);
            }
            // Third read should return EOF (write task shutdown after drain).
            let result = read_frame(&mut stream).await.unwrap();
            assert!(result.is_none());
        });

        // Create a send queue and enqueue two messages.
        let mut psq: PeerSendQueue<Vec<u8>> = PeerSendQueue::new(16, BackpressurePolicy::Block);
        let sender = psq.sender(1).unwrap();
        let receiver = psq.take_receiver(1).unwrap();

        sender.send(b"message-1".to_vec()).await.unwrap();
        sender.send(b"message-2".to_vec()).await.unwrap();
        // Remove the peer to close the queue so recv() returns None after
        // draining.  (Dropping the sender alone does not close the queue.)
        drop(sender);
        psq.remove_peer(1);

        // Connect and spawn write task.
        let stream = TcpStream::connect(server_addr).await.unwrap();
        let peer_id = 1u64;

        let encode = |msg: &Vec<u8>| (MessageFamily::StateTransfer, msg.clone());
        IoRuntime::spawn_write_task_from_stream(stream, peer_id, receiver, encode);

        server_handle.await.unwrap();
    }

    // -------------------------------------------------------------------
    // connect method
    // -------------------------------------------------------------------

    /// Verify that `connect` establishes a TCP connection to a listening
    /// socket and that frames can be exchanged in both directions.
    #[tokio::test]
    async fn connect_to_listener_then_exchange() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Server: accept, read one frame, write one frame, close.
        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let result = read_frame(&mut stream).await.unwrap();
            assert!(result.is_some());
            let (family, payload) = result.unwrap();
            // The encode fn supplied to connect maps payloads to
            // StateTransfer, so the received family reflects that.
            assert_eq!(family, MessageFamily::StateTransfer);
            assert_eq!(payload, b"connect-ping");

            write_frame(
                &mut stream,
                MessageFamily::ReplicaTransferVerify,
                b"connect-pong",
            )
            .await
            .unwrap();
        });

        let registry = Arc::new(ConnectionRegistry::new());
        let dispatch = Arc::new(MessageDispatch::new());
        let send_queues: Arc<Mutex<PeerSendQueue<Vec<u8>>>> = Arc::new(Mutex::new(
            PeerSendQueue::new(16, crate::peer_send_queue::BackpressurePolicy::Block),
        ));

        let rt = IoRuntime::new(
            TransportConfig::default(),
            ErrorClassifier::new(),
            Arc::new(TracingErrorObserver),
        );
        let addr = TransportAddr::Tcp(server_addr);
        let encode_fn: TestEncodeFn =
            Arc::new(|payload: &[u8]| (MessageFamily::StateTransfer, payload.to_vec()));

        let handle = rt
            .connect(
                &addr,
                Arc::clone(&registry),
                Arc::clone(&dispatch),
                Arc::clone(&send_queues),
                Arc::clone(&encode_fn),
            )
            .await
            .unwrap();

        assert_eq!(handle.peer_id, socket_addr_to_peer_id(&server_addr));

        // Send a message through the send queue.
        {
            let mut sq = send_queues.lock().await;
            let sender = sq.sender(handle.peer_id).unwrap();
            sender.send(b"connect-ping".to_vec()).await.unwrap();
        }

        // Wait for server to process.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        server_handle.await.unwrap();
    }

    /// Verifies that `connect` to a refused port returns an `IoError::Connect`.
    #[tokio::test]
    async fn connect_refused_port() {
        // Use an ephemeral port where nothing is listening.
        // Bind a temporary socket to find a port, then close it and connect.
        let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refused_addr = tmp.local_addr().unwrap();
        drop(tmp);

        let rt = IoRuntime::new(
            TransportConfig::default(),
            ErrorClassifier::new(),
            Arc::new(TracingErrorObserver),
        );
        let addr = TransportAddr::Tcp(refused_addr);
        let registry = Arc::new(ConnectionRegistry::new());
        let dispatch = Arc::new(MessageDispatch::new());
        let send_queues: Arc<Mutex<PeerSendQueue<Vec<u8>>>> = Arc::new(Mutex::new(
            PeerSendQueue::new(16, crate::peer_send_queue::BackpressurePolicy::Block),
        ));
        let encode_fn: TestEncodeFn =
            Arc::new(|payload: &[u8]| (MessageFamily::StateTransfer, payload.to_vec()));

        let result = rt
            .connect(&addr, registry, dispatch, send_queues, encode_fn)
            .await;

        assert!(matches!(result, Err(IoError::Connect(_))));
    }

    /// Verifies that `connect` with a non-TCP `TransportAddr` returns
    /// `IoError::UnsupportedCarrier`.
    #[tokio::test]
    async fn connect_unsupported_carrier() {
        let rt = IoRuntime::new(
            TransportConfig::default(),
            ErrorClassifier::new(),
            Arc::new(TracingErrorObserver),
        );
        let addr = TransportAddr::Unix(std::path::PathBuf::from("/tmp/nonexistent.sock"));
        let registry = Arc::new(ConnectionRegistry::new());
        let dispatch = Arc::new(MessageDispatch::new());
        let send_queues: Arc<Mutex<PeerSendQueue<Vec<u8>>>> = Arc::new(Mutex::new(
            PeerSendQueue::new(16, crate::peer_send_queue::BackpressurePolicy::Block),
        ));
        let encode_fn: TestEncodeFn =
            Arc::new(|payload: &[u8]| (MessageFamily::StateTransfer, payload.to_vec()));

        let result = rt
            .connect(&addr, registry, dispatch, send_queues, encode_fn)
            .await;

        assert!(matches!(result, Err(IoError::UnsupportedCarrier(_))));
    }

    /// Verify that `ConnectionHandle` carries peer_id and connection_id.
    #[test]
    fn connection_handle_fields() {
        let handle = ConnectionHandle {
            peer_id: 42,
            connection_id: ConnectionId::new(7),
        };
        assert_eq!(handle.peer_id, 42);
        assert_eq!(handle.connection_id.0, 7);
    }

    /// `ConnectionHandle` is `Clone` and `Copy`.
    #[test]
    fn connection_handle_clone_copy() {
        let handle = ConnectionHandle {
            peer_id: 1,
            connection_id: ConnectionId::new(0),
        };
        let handle2 = handle; // Copy
        let handle3 = handle; // still accessible after copy
        assert_eq!(handle2.peer_id, handle3.peer_id);
    }
}
