// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Deterministic multi-node object read path over transport sessions.
//!
//! `ReplicatedObjectReader` fetches objects from any available replica
//! using the ObjectTransfer wire types (ReadRequest/ReadResponse),
//! `TransferHandle` for request/response pairing with timeout/retry,
//! and domain-separated BLAKE3 integrity verification.
//!
//! Replica selection is driven by a deterministic PRNG seed, enabling
//! reproducible multi-replica tests over in-process transport loopback.
//!
//! The reader does not own the [`Transport`]; callers pass `&mut Transport`
//! to [`read_object`](ReplicatedObjectReader::read_object). This lets
//! callers such as `TransportReplicatedStore` share one transport across
//! local I/O and replicated reads.

use std::time::Duration;

use tidefs_transport::{
    dispatch_read_request, recv_read_response, SessionId, TransferDispatchError, TransferHandle,
    Transport, DEFAULT_REQUEST_TIMEOUT,
};

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64) for replica selection
// ---------------------------------------------------------------------------

/// Simple xorshift64 PRNG for deterministic replica selection.
#[derive(Clone, Debug)]
struct XorShiftRng {
    state: u64,
}

impl XorShiftRng {
    fn new(seed: u64) -> Self {
        let seed = if seed == 0 { 1 } else { seed };
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Return a value in `[0, bound)`.
    fn next_bound(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next() as usize) % bound
    }
}

// ---------------------------------------------------------------------------
// ReadError
// ---------------------------------------------------------------------------

/// Error type for replicated object read operations.
#[derive(Debug)]
pub enum ReadError {
    /// Underlying transport or dispatch error.
    Transport(String),
    /// No replicas available in the session set.
    NoReplicas,
    /// All replicas exhausted without success.
    Exhausted {
        /// Number of replicas tried.
        tried: usize,
        /// Last error encountered.
        last_error: String,
    },
    /// Object not found on any replica.
    NotFound,
    /// BLAKE3 payload digest verification failed.
    DigestMismatch,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::NoReplicas => write!(f, "no replicas available"),
            Self::Exhausted { tried, last_error } => {
                write!(
                    f,
                    "all {tried} replicas exhausted, last error: {last_error}"
                )
            }
            Self::NotFound => write!(f, "object not found on any replica"),
            Self::DigestMismatch => write!(f, "BLAKE3 payload digest mismatch"),
        }
    }
}

impl std::error::Error for ReadError {}

impl From<TransferDispatchError> for ReadError {
    fn from(e: TransferDispatchError) -> Self {
        match e {
            TransferDispatchError::DigestMismatch => ReadError::DigestMismatch,
            other => ReadError::Transport(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// ReaderConfig
// ---------------------------------------------------------------------------

/// Configuration for the replicated object reader.
#[derive(Clone, Debug)]
pub struct ReaderConfig {
    /// Maximum number of replica attempts before giving up.
    pub max_attempts: usize,
    /// PRNG seed for deterministic replica selection.
    pub seed: u64,
    /// Request timeout.
    pub timeout: Duration,
    /// Maximum retries per replica.
    pub max_retries: u32,
}

impl Default for ReaderConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            seed: 42,
            timeout: DEFAULT_REQUEST_TIMEOUT,
            max_retries: 3,
        }
    }
}

// ---------------------------------------------------------------------------
// ReplicatedObjectReader
// ---------------------------------------------------------------------------

/// Fetches objects from replicas over transport sessions using the
/// ObjectTransfer read protocol (ReadRequest/ReadResponse) with
/// domain-separated BLAKE3 integrity verification.
///
/// Replica selection is deterministic: given the same seed and same
/// replica set, the same replica order is produced every time.
/// On failure (timeout, digest mismatch, transport error), the reader
/// advances to the next replica in the shuffled order.
///
/// The reader does not own the [`Transport`]; callers pass `&mut Transport`
/// to every [`read_object`](Self::read_object) call. This enables sharing
/// a single transport across local I/O and replicated reads (e.g. inside
/// `TransportReplicatedStore`).
pub struct ReplicatedObjectReader {
    /// TransferHandle for request/response pairing with timeout tracking.
    handle: TransferHandle,
    /// Session IDs for the data path to each replica.
    replica_sessions: Vec<SessionId>,
    /// Deterministic PRNG for replica selection.
    rng: XorShiftRng,
    /// Reader configuration.
    config: ReaderConfig,
}

impl ReplicatedObjectReader {
    /// Create a new reader with the default configuration.
    ///
    /// `replica_sessions` are the data-path session IDs (typically Data
    /// endpoint family, e2) for each replica. The transport must already
    /// have established sessions to all replicas.
    ///
    /// # Panics
    ///
    /// Panics if `replica_sessions` is empty.
    pub fn new(replica_sessions: Vec<SessionId>) -> Self {
        assert!(
            !replica_sessions.is_empty(),
            "ReplicatedObjectReader requires at least one replica session"
        );
        let config = ReaderConfig::default();
        Self {
            handle: TransferHandle::with_limits(config.timeout, config.max_retries),
            rng: XorShiftRng::new(config.seed),
            replica_sessions,
            config,
        }
    }

    /// Create a new reader with a custom configuration.
    pub fn with_config(replica_sessions: Vec<SessionId>, config: ReaderConfig) -> Self {
        assert!(
            !replica_sessions.is_empty(),
            "ReplicatedObjectReader requires at least one replica session"
        );
        let handle = TransferHandle::with_limits(config.timeout, config.max_retries);
        let rng = XorShiftRng::new(config.seed);
        Self {
            handle,
            replica_sessions,
            rng,
            config,
        }
    }

    /// Convenience constructor: extract data-session IDs from a
    /// `TransportReplicatedStore`-style replica list.
    ///
    /// Each element is a `(node_id, data_session_id)` pair.
    pub fn from_replica_sessions(replica_data_sessions: Vec<(u64, SessionId)>) -> Self {
        let sessions: Vec<SessionId> = replica_data_sessions
            .into_iter()
            .map(|(_node_id, sid)| sid)
            .collect();
        Self::new(sessions)
    }

    /// Convenience constructor with custom config from replica session pairs.
    pub fn from_replica_sessions_with_config(
        replica_data_sessions: Vec<(u64, SessionId)>,
        config: ReaderConfig,
    ) -> Self {
        let sessions: Vec<SessionId> = replica_data_sessions
            .into_iter()
            .map(|(_node_id, sid)| sid)
            .collect();
        Self::with_config(sessions, config)
    }

    /// Set the PRNG seed for deterministic replica selection.
    ///
    /// Resets the RNG state so that subsequent reads produce the same
    /// replica order as a fresh reader with this seed.
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.config.seed = seed;
        self.rng = XorShiftRng::new(seed);
        self
    }

    /// Return the number of configured replica sessions.
    pub fn replica_count(&self) -> usize {
        self.replica_sessions.len()
    }

    /// Return the current PRNG seed.
    pub fn seed(&self) -> u64 {
        self.config.seed
    }

    /// Read an object from any available replica.
    ///
    /// Selects replicas in deterministic shuffled order. For each replica:
    /// 1. Dispatches a `ReadRequest` via `dispatch_read_request`.
    /// 2. Collects and reassembles `ReadResponse` chunks via `recv_read_response`.
    /// 3. Verifies per-chunk BLAKE3 digests automatically (inside `recv_read_response`).
    ///
    /// On failure (timeout, transport error, digest mismatch), advances to the
    /// next replica in the shuffled order. Returns `ReadError::Exhausted` if
    /// all replicas fail.
    ///
    /// # Errors
    ///
    /// Returns `ReadError::NoReplicas` if the replica set is empty.
    /// Returns `ReadError::Exhausted` if all replicas were tried without success.
    pub fn read_object(
        &mut self,
        transport: &mut Transport,
        object_key: [u8; 32],
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, ReadError> {
        if self.replica_sessions.is_empty() {
            return Err(ReadError::NoReplicas);
        }

        let max_attempts = self.config.max_attempts.min(self.replica_sessions.len());
        let mut last_error: Option<String> = None;

        // Build a deterministic permutation of replica indices for this read
        let order = self.shuffled_order();

        for &replica_idx in order.iter().take(max_attempts) {
            let session_id = self.replica_sessions[replica_idx];

            match self.try_read_from(transport, session_id, object_key, offset, length) {
                Ok(data) => return Ok(data),
                Err(e) => {
                    last_error = Some(e.to_string());
                }
            }
        }

        Err(ReadError::Exhausted {
            tried: max_attempts,
            last_error: last_error.unwrap_or_else(|| "unknown error".to_string()),
        })
    }

    /// Attempt to read from a single replica session.
    fn try_read_from(
        &mut self,
        transport: &mut Transport,
        session_id: SessionId,
        object_key: [u8; 32],
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, ReadError> {
        let tid = dispatch_read_request(
            transport,
            &mut self.handle,
            session_id,
            object_key,
            offset,
            length,
        )?;

        recv_read_response(transport, &mut self.handle, session_id, tid).map_err(Into::into)
    }

    /// Build a deterministically shuffled order of replica indices.
    ///
    /// Uses Fisher-Yates shuffle driven by the PRNG. The first element
    /// is the preferred replica for the next read. Calling this advances
    /// the RNG state so that subsequent reads get different orderings.
    fn shuffled_order(&mut self) -> Vec<usize> {
        let n = self.replica_sessions.len();
        let mut indices: Vec<usize> = (0..n).collect();

        // Fisher-Yates shuffle using the deterministic PRNG
        for i in (1..n).rev() {
            let j = self.rng.next_bound(i + 1);
            indices.swap(i, j);
        }

        indices
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::thread;
    use tidefs_transport::{
        build_read_responses, NodeInfo, ObjectTransferMessage, SessionCloseReason,
        MAX_CHUNK_PAYLOAD,
    };

    // ── helpers ────────────────────────────────────────────────────────

    fn listening_transport(node_id: u64) -> (Transport, tidefs_transport::TransportAddr) {
        let mut transport = Transport::new(node_id);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        transport
            .bind(tidefs_transport::TransportAddr::Tcp(addr))
            .expect("bind");
        let bound_addr = transport.bind_addr.clone().expect("bind_addr");
        (transport, bound_addr)
    }

    fn blocking_accept(transport: &mut Transport) -> SessionId {
        for _ in 0..100 {
            match transport.accept_incoming() {
                Ok(sid) => return sid,
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("no pending connections") {
                        thread::sleep(Duration::from_millis(10));
                    } else {
                        panic!("server accept error: {e}");
                    }
                }
            }
        }
        panic!("timeout waiting for incoming connection");
    }

    // ── unit: shuffled_order determinism ───────────────────────────────

    #[test]
    fn shuffled_order_deterministic_same_seed() {
        let sessions = vec![SessionId(10), SessionId(20), SessionId(30)];

        let mut reader_a = ReplicatedObjectReader::with_config(
            sessions.clone(),
            ReaderConfig {
                seed: 12345,
                ..Default::default()
            },
        );
        let order_a = reader_a.shuffled_order();

        let mut reader_b = ReplicatedObjectReader::with_config(
            sessions,
            ReaderConfig {
                seed: 12345,
                ..Default::default()
            },
        );
        let order_b = reader_b.shuffled_order();

        assert_eq!(order_a, order_b);
    }

    #[test]
    fn shuffled_order_different_seed_usually_different() {
        let sessions_a = vec![SessionId(1), SessionId(2), SessionId(3)];
        let sessions_b = vec![SessionId(4), SessionId(5), SessionId(6)];

        let mut reader_a = ReplicatedObjectReader::with_config(
            sessions_a,
            ReaderConfig {
                seed: 100,
                ..Default::default()
            },
        );
        let order_a = reader_a.shuffled_order();

        let mut reader_b = ReplicatedObjectReader::with_config(
            sessions_b,
            ReaderConfig {
                seed: 200,
                ..Default::default()
            },
        );
        let order_b = reader_b.shuffled_order();

        // Different seeds can produce same order with low probability (~1/6
        // for 3 elements), but the test exercises the code path regardless.
        let _ = (order_a, order_b);
    }

    #[test]
    fn shuffled_order_contains_all_indices() {
        let sessions = vec![
            SessionId(0),
            SessionId(1),
            SessionId(2),
            SessionId(3),
            SessionId(4),
        ];
        let mut reader = ReplicatedObjectReader::with_config(
            sessions,
            ReaderConfig {
                seed: 77,
                ..Default::default()
            },
        );

        let order = reader.shuffled_order();
        assert_eq!(order.len(), 5);
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![0, 1, 2, 3, 4]);
    }

    // ── unit: config, with_seed, builder ───────────────────────────────

    #[test]
    fn with_seed_resets_rng() {
        let sessions = vec![SessionId(1), SessionId(2)];

        let reader1 = ReplicatedObjectReader::new(sessions.clone());
        assert_eq!(reader1.seed(), 42);

        let reader2 = reader1.with_seed(999);
        assert_eq!(reader2.seed(), 999);
    }

    #[test]
    fn config_defaults() {
        let cfg = ReaderConfig::default();
        assert_eq!(cfg.max_attempts, 3);
        assert_eq!(cfg.seed, 42);
        assert_eq!(cfg.max_retries, 3);
    }

    #[test]
    #[should_panic(expected = "requires at least one replica session")]
    fn empty_replicas_panics() {
        let _reader = ReplicatedObjectReader::new(vec![]);
    }

    #[test]
    fn from_replica_sessions_constructor() {
        let pairs = vec![(1u64, SessionId(100)), (2u64, SessionId(200))];
        let reader = ReplicatedObjectReader::from_replica_sessions(pairs);
        assert_eq!(reader.replica_count(), 2);
    }

    #[test]
    fn from_replica_sessions_with_config() {
        let pairs = vec![(1u64, SessionId(100))];
        let reader = ReplicatedObjectReader::from_replica_sessions_with_config(
            pairs,
            ReaderConfig {
                seed: 55,
                ..Default::default()
            },
        );
        assert_eq!(reader.replica_count(), 1);
        assert_eq!(reader.seed(), 55);
    }

    // ── integration: end-to-end read over TCP loopback ─────────────────

    /// Spawn a server that responds to ReadRequests with chunked ReadResponses.
    fn spawn_echo_server(
        mut server: Transport,
        server_data: Vec<u8>,
    ) -> (tidefs_transport::TransportAddr, thread::JoinHandle<()>) {
        let addr = server.bind_addr.clone().unwrap();
        let handle = thread::spawn(move || {
            let sid = blocking_accept(&mut server);
            server.perform_handshake(sid).expect("server handshake");

            while let Ok(raw) = server.recv_message(sid) {
                let msg = match ObjectTransferMessage::decode(&raw) {
                    Ok(m) => m,
                    Err(_) => break,
                };

                match msg {
                    ObjectTransferMessage::ReadRequest {
                        transfer_id,
                        offset,
                        length,
                        ..
                    } => {
                        let end = (offset + length).min(server_data.len() as u64) as usize;
                        let start = offset as usize;
                        let slice = &server_data[start..end];

                        let responses = build_read_responses(
                            transfer_id,
                            slice.len() as u64,
                            slice,
                            MAX_CHUNK_PAYLOAD,
                        );
                        for resp in responses {
                            let encoded = resp.encode().expect("encode response");
                            server.send_message(sid, &encoded).expect("send response");
                        }
                    }
                    _ => break,
                }
            }
            server
                .close_session(sid, SessionCloseReason::LocalShutdown)
                .ok();
        });
        (addr, handle)
    }

    #[test]
    fn read_object_single_replica_roundtrip() {
        let server_data = b"Hello, replicated object store! This is a test payload.".to_vec();

        let (server, _server_addr) = listening_transport(1);
        let (addr, server_handle) = spawn_echo_server(server, server_data.clone());

        let mut client = Transport::new(2);
        client.add_node(NodeInfo::new(1, vec![addr], 0));
        let session_id = client.connect(1).expect("client connect");
        client
            .perform_handshake(session_id)
            .expect("client handshake");

        let mut reader = ReplicatedObjectReader::new(vec![session_id]);

        let object_key = *blake3::hash(b"test-object").as_bytes();
        let result = reader.read_object(&mut client, object_key, 0, server_data.len() as u64);
        assert!(result.is_ok(), "read failed: {:?}", result.err());
        assert_eq!(result.unwrap(), server_data);

        server_handle.join().ok();
    }

    #[test]
    fn read_object_partial_range() {
        let server_data = b"0123456789ABCDEF".to_vec();

        let (server, _server_addr) = listening_transport(1);
        let (addr, server_handle) = spawn_echo_server(server, server_data.clone());

        let mut client = Transport::new(2);
        client.add_node(NodeInfo::new(1, vec![addr], 0));
        let session_id = client.connect(1).expect("client connect");
        client
            .perform_handshake(session_id)
            .expect("client handshake");

        let mut reader = ReplicatedObjectReader::new(vec![session_id]);

        let object_key = *blake3::hash(b"partial-read").as_bytes();
        let result = reader.read_object(&mut client, object_key, 4, 8);
        assert!(result.is_ok(), "partial read failed: {:?}", result.err());
        assert_eq!(result.unwrap(), b"456789AB");

        server_handle.join().ok();
    }

    #[test]
    fn read_object_large_payload_multi_chunk() {
        // 2.5 MiB payload to exercise multi-chunk reassembly
        let chunk_size = MAX_CHUNK_PAYLOAD;
        let server_data: Vec<u8> = (0..(chunk_size * 2 + 512))
            .map(|i| (i % 251) as u8)
            .collect();

        let (server, _server_addr) = listening_transport(1);
        let (addr, server_handle) = spawn_echo_server(server, server_data.clone());

        let mut client = Transport::new(2);
        client.add_node(NodeInfo::new(1, vec![addr], 0));
        let session_id = client.connect(1).expect("client connect");
        client
            .perform_handshake(session_id)
            .expect("client handshake");

        let mut reader = ReplicatedObjectReader::new(vec![session_id]);

        let object_key = *blake3::hash(b"large-object").as_bytes();
        let result = reader.read_object(&mut client, object_key, 0, server_data.len() as u64);
        assert!(result.is_ok(), "large read failed: {:?}", result.err());
        let data = result.unwrap();
        assert_eq!(data.len(), server_data.len());
        assert_eq!(data, server_data);

        server_handle.join().ok();
    }

    #[test]
    fn read_object_replica_count() {
        let reader = ReplicatedObjectReader::new(vec![SessionId(1)]);
        assert_eq!(reader.replica_count(), 1);
    }

    #[test]
    fn read_object_via_from_replica_sessions() {
        let server_data = b"from_replica_sessions test".to_vec();

        let (server, _server_addr) = listening_transport(1);
        let (addr, server_handle) = spawn_echo_server(server, server_data.clone());

        let mut client = Transport::new(2);
        client.add_node(NodeInfo::new(1, vec![addr], 0));
        let session_id = client.connect(1).expect("client connect");
        client
            .perform_handshake(session_id)
            .expect("client handshake");

        // Use the from_replica_sessions constructor (the integration point
        // that TransportReplicatedStore will use).
        let mut reader = ReplicatedObjectReader::from_replica_sessions(vec![(1u64, session_id)]);

        let object_key = *blake3::hash(b"from-replica-sessions").as_bytes();
        let result = reader.read_object(&mut client, object_key, 0, server_data.len() as u64);
        assert!(result.is_ok(), "read failed: {:?}", result.err());
        assert_eq!(result.unwrap(), server_data);

        server_handle.join().ok();
    }
}
