// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use crate::addr::TransportAddr;
use ed25519_dalek::Keypair;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tidefs_auth::{self, verify_mutual_attestation, HelloMessage, HelloResponse, NodeKeyStore};

use crate::backend::{ConnectionLike, TransportBackend, TransportBackendKind};
use crate::carrier_selection::CarrierDisclosure;
use crate::chunk_shipper::ChunkShipper;
use crate::compression::CompressionConfig;
use crate::connect_lifecycle::{
    ConnectConfig, ConnectLifecycle, LifecycleChangeCallbackRef, SessionLifecycle,
};
use crate::epoch_barrier::EpochBarrier;
use crate::error::TransportError;
use crate::fragmentation::FragmentReassembler;
use crate::fragmentation::{decode_fragment, fragment_message, is_fragment, DEFAULT_MTU};
use crate::message_priority::MessagePriority;
use crate::message_priority::{QueuedMessage, SendCancelHandle};
use crate::send_backpressure::{SendCapacity, SendCapacitySet, SendWatermarkConfig};
use crate::send_buffer::BackpressurePolicy;
use crate::send_concurrency::SendConcurrencyLimiter;
use crate::session::{PeerSessionInfo, Session, SessionCloseReason, SessionState};
use crate::session::{SessionStatsSnapshot, TransportStats};
use crate::session_cohort::{NodeInfo, SessionCohortGraph};
use crate::session_reconnector::SessionReconnector;
use crate::tcp::TcpTransport;
#[cfg(feature = "tdma")]
use crate::tdma_gate::TdmaSendGate;
use crate::types::{CohortMembership, FamilyVersion, HlcTimestamp, NodeIdentityPublic, SessionId};
use crate::unreachable_peer::UnreachablePeerCallbackRef;
use crate::SendGate;
use tidefs_types_transport_session::{
    DrainResultClass, EndpointFamily, TransportClosureReceipt, TransportClosureReceiptId,
    TransportSessionId,
};
use tracing;

const RDMA_RUNTIME_FALLBACK_PERMANENT_LOSS: &str = "permanent RDMA carrier loss";
const RDMA_RUNTIME_FALLBACK_RECONNECT_EXHAUSTED: &str = "reconnect exhausted";
const RDMA_RUNTIME_FALLBACK_PERMANENT_LOSS_REFUSED: &str =
    "enforce carrier policy: runtime RDMA fallback to TCP refused after permanent carrier loss";
const RDMA_RUNTIME_FALLBACK_RECONNECT_EXHAUSTED_REFUSED: &str =
    "enforce carrier policy: runtime RDMA fallback to TCP refused after reconnect exhaustion";
// ---------------------------------------------------------------------------
// Connection: wraps the transport backend connection with metadata
// ---------------------------------------------------------------------------

/// Wraps a transport backend connection (TCP or RDMA) with peer address,
/// endpoint family, and activity-tracking metadata.
pub struct Connection {
    /// The underlying connection (TCP or RDMA)
    pub conn: Box<dyn ConnectionLike>,
    /// Peer address
    pub peer_addr: TransportAddr,
    /// Endpoint family for this connection (e0..e3 per P8-01 §4).
    pub endpoint_family: EndpointFamily,
    /// When the connection was established
    pub established_at: Instant,
    /// Last activity timestamp
    pub last_activity: Instant,
}

impl Connection {
    /// Create a new `Connection` wrapping a transport backend connection.
    ///
    /// Sets `established_at` and `last_activity` to the current time.
    pub fn new(
        conn: Box<dyn ConnectionLike>,
        peer_addr: TransportAddr,
        endpoint_family: EndpointFamily,
    ) -> Self {
        let now = Instant::now();
        Self {
            conn,
            peer_addr,
            endpoint_family,
            established_at: now,
            last_activity: now,
        }
    }

    /// Whether this connection has been idle longer than the given duration.
    #[must_use]
    pub fn is_idle(&self, idle_timeout: Duration) -> bool {
        self.last_activity.elapsed() > idle_timeout
    }
}

// ---------------------------------------------------------------------------
// ConnectionPool: manage outgoing connections
// ---------------------------------------------------------------------------

/// Manages a pool of outgoing connections indexed by (peer address, endpoint family).
/// Supports connection pruning based on idle timeout.
pub struct ConnectionPool {
    /// Outgoing connections: (peer_addr, EndpointFamily) → Connection
    pub connections: BTreeMap<(TransportAddr, EndpointFamily), Connection>,
    /// Maximum connections to any single peer
    pub max_per_peer: usize,
    /// Connection idle timeout
    pub idle_timeout: Duration,
}

impl ConnectionPool {
    #[must_use]
    /// Create a new connection pool with per-peer and idle limits.
    pub fn new(max_per_peer: usize, idle_timeout: Duration) -> Self {
        Self {
            connections: BTreeMap::new(),
            max_per_peer,
            idle_timeout,
        }
    }

    /// Prune idle connections.
    pub fn prune_idle(&mut self) -> Vec<(TransportAddr, EndpointFamily)> {
        let idle: Vec<(TransportAddr, EndpointFamily)> = self
            .connections
            .iter()
            .filter(|(_, conn)| conn.is_idle(self.idle_timeout))
            .map(|((addr, ep), _)| (addr.clone(), *ep))
            .collect();

        for key in &idle {
            self.connections.remove(key);
        }
        idle
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new(4, Duration::from_secs(300))
    }
}

// ---------------------------------------------------------------------------
// DataPathCarrierSummary: per-carrier data-plane statistics
// ---------------------------------------------------------------------------

/// Aggregated carrier counts for active transport data-plane sessions
/// and chunk shippers. Used for carrier-disclosure validation: operators
/// can observe whether cluster data paths are using RDMA, TCP fallback,
/// or another backend.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataPathCarrierSummary {
    /// Number of active sessions using the RDMA carrier.
    pub rdma_sessions: usize,
    /// Number of active sessions using plain TCP.
    pub tcp_sessions: usize,
    /// Number of active sessions using TLS over TCP.
    pub tls_sessions: usize,
    /// Number of chunk shippers using the RDMA carrier.
    pub rdma_shippers: usize,
    /// Number of chunk shippers using plain TCP.
    pub tcp_shippers: usize,
    /// Number of chunk shippers using TLS over TCP.
    pub tls_shippers: usize,
}

impl DataPathCarrierSummary {
    /// Total active data-path sessions across all carriers.
    #[must_use]
    pub fn total_sessions(&self) -> usize {
        self.rdma_sessions + self.tcp_sessions + self.tls_sessions
    }

    /// Total active chunk shippers across all carriers.
    #[must_use]
    pub fn total_shippers(&self) -> usize {
        self.rdma_shippers + self.tcp_shippers + self.tls_shippers
    }

    /// Whether any data-plane session currently uses RDMA.
    #[must_use]
    pub fn has_rdma(&self) -> bool {
        self.rdma_sessions > 0 || self.rdma_shippers > 0
    }

    /// Dominant carrier kind for data-plane sessions.
    ///
    /// Returns `Rdma` when at least one session uses RDMA;
    /// otherwise `Tls` when at least one session uses TLS;
    /// otherwise `Tcp`.
    #[must_use]
    pub fn dominant_carrier(&self) -> TransportBackendKind {
        if self.rdma_sessions > 0 {
            TransportBackendKind::Rdma
        } else if self.tls_sessions > 0 {
            TransportBackendKind::Tls
        } else {
            TransportBackendKind::Tcp
        }
    }

    /// Active carrier disclosure name for runtime validation.
    ///
    /// Returns `"rdma"` when any data-plane session or shipper uses RDMA;
    /// `"tls"` when all active sessions/shippers use TLS;
    /// `"tcp"` when all active sessions/shippers use TCP;
    /// `"none"` when no data-plane sessions or shippers are active.
    ///
    /// This is the preferred method for health-check and stats disclosure
    /// because it never returns a carrier name when no sessions are
    /// live (unlike [`dominant_carrier`], which defaults to `Tcp`).
    #[must_use]
    pub fn disclosure_carrier_name(&self) -> &'static str {
        if self.has_rdma() {
            "rdma"
        } else if self.tls_sessions > 0 || self.tls_shippers > 0 {
            "tls"
        } else if self.total_sessions() > 0 || self.total_shippers() > 0 {
            "tcp"
        } else {
            "none"
        }
    }
}

// ---------------------------------------------------------------------------
// Transport: the main orchestrator
// ---------------------------------------------------------------------------

/// The Transport layer manages connections, sessions, and chunk shipping.
/// It binds TCP listeners, accepts connections, establishes sessions,
/// and feeds messages to the EnvelopeRouter (#894).
///
/// ## Endpoint lifecycle
///
/// The [`Transport`] orchestrates the full endpoint lifecycle for every active
/// session. Each node participates as one or more endpoints drawn from the four
/// P8-01 endpoint families (`LocalEmbed`, `Control`, `Data`, `Shadow`).
///
/// The canonical lifecycle, managed by `Transport`:
///
/// 1. **Listen & bind** — `bind()` opens a TCP listener on a local address.
///    The bound address becomes the local endpoint for incoming connections.
///
/// 2. **Node registration** — `add_node()` registers a peer with its addresses,
///    endpoint family, and cohort memberships in the [`SessionCohortGraph`].
///
/// 3. **Session open (connect)** — `connect()` selects an endpoint family for
///    the target peer, creates a new [`Session`] in `Unconnected` state, opens
///    a TCP connection, and performs mutual attestation.
///
/// 4. **Handshake & bind** — `perform_handshake()` exchanges identities,
///    protocol family versions, and endpoint family; transitions the session
///    to `Established`.
///
/// 5. **Cohort attach & lane admission** — the session cohort graph enforces
///    that sessions only attach to declared [`CohortClass`](tidefs_types_transport_session::CohortClass) values (k0–k7).
///    Lane budgets are admitted per the endpoint family and cohort class.
///
/// 6. **Envelope flow** — `send_envelope()` and `recv_envelope()` exchange
///    framed messages with sequence tracking and ack floors.
///
/// 7. **Drain & close** — `close_session()` transitions the session to
///    `Closed` with a [`SessionCloseReason`], removes the session from
///    active connections, the cohort graph, and the shipper pool.
///
/// ### Endpoint family invariants enforced by Transport
///
/// - Every session opened through `connect()` has exactly one endpoint family,
///   set during construction and propagated through the handshake.
/// - A session's `endpoint_family` field determines which session classes,
///   lane classes, and cohort classes are legal for that session (per P8-01
///   pair-graph rules).
/// - [`Connection`] wraps the underlying socket with its endpoint family,
///   enabling per-endpoint-family accounting and idle pruning.
/// - The [`ConnectionPool`] indexes outgoing connections by
///   `(peer_addr, EndpointFamily)`, ensuring each endpoint family maintains
///   its own connection pool with per-peer connection caps.
pub struct Transport {
    /// TCP transport backend
    backend: Box<dyn TransportBackend>,

    /// Backend kind (Tcp, Tls, Rdma) for backend-specific error handling,
    /// reconnect decisions, and resource cleanup.
    pub backend_kind: TransportBackendKind,

    /// Carrier policy for fail-closed RDMA enforcement (#6672).
    /// Defaults to [`CarrierPolicy::Prefer`]; set to [`CarrierPolicy::Enforce`]
    /// to fail closed when an RDMA claim cannot be satisfied.
    pub carrier_policy: crate::carrier_selection::CarrierPolicy,

    /// Active sessions
    pub sessions: BTreeMap<SessionId, Arc<std::sync::Mutex<Session>>>,

    /// Active I/O connections per session (the actual TCP/RDMA connections).
    /// Sessions in Established state have an entry here for frame I/O.
    pub active_connections: BTreeMap<SessionId, Box<dyn ConnectionLike>>,

    /// Session cohort graph
    pub cohort_graph: SessionCohortGraph,

    /// Connection pool (outgoing connections)
    pub pool: ConnectionPool,

    /// Protocol families and versions this node supports (declared during handshake).
    pub supported_families: Vec<FamilyVersion>,

    /// Local node's public identity (sent during handshake).
    pub local_identity: Option<NodeIdentityPublic>,

    /// Chunk shipper per session
    pub shippers: BTreeMap<SessionId, ChunkShipper>,

    /// Per-session drain handles for membership-eviction completion tracking.
    /// Keyed by SessionId; populated when a drain handle is attached via
    /// [`set_session_drain_handle`](Self::set_session_drain_handle).
    pub session_drain_handles: BTreeMap<SessionId, Arc<crate::session_drain::SessionDrainHandle>>,

    /// Authoritative close receipts keyed by session ID.
    ///
    /// This is a TFR-017 reduction: it makes transport lifecycle closure
    /// evidence observable inside the runtime. It is not a placement,
    /// rebuild, or distributed recovery receipt authority.
    pub session_closure_receipts: BTreeMap<SessionId, TransportClosureReceipt>,

    /// Local node ID
    pub local_node_id: u64,

    /// Ed25519 signing keypair for session attestation (mutual challenge-response).
    /// When Some, perform_handshake() executes full mutual-attestation exchange.
    pub attestation_key: Option<Keypair>,

    /// Auth-crate NodeIdentity matching attestation_key.
    pub attestation_identity: Option<tidefs_auth::NodeIdentity>,

    /// Registry of known peer identities for attestation verification.
    pub known_identities: NodeKeyStore,

    /// Permit first-session bootstrap by registering the peer identity sent in
    /// the basic transport handshake before the mutual-attestation exchange.
    ///
    /// This is intended for early cluster bootstrap where membership has not
    /// yet published a key roster. It is disabled by default; configured
    /// trust anchors still use [`with_known_identities`](Self::with_known_identities).
    pub attestation_bootstrap_from_handshake: bool,

    /// Current membership epoch for attestation epoch negotiation.
    pub epoch: u64,
    /// Epoch barrier for fencing messages by membership epoch.
    pub epoch_barrier: Option<EpochBarrier>,

    /// Bind address
    pub bind_addr: Option<TransportAddr>,

    /// Local endpoint family (e0..e3 per P8-01 §4).
    pub endpoint_family: EndpointFamily,

    /// Per-session response tracker configuration.
    /// Used to auto-create trackers when sessions reach Established.
    response_tracker_config: crate::config::ResponseTrackerConfig,

    /// Maximum Transmission Unit for message fragmentation.
    /// Messages larger than this will be fragmented on send.
    pub mtu: usize,

    /// Optional callback invoked when a peer session's reconnection is
    /// exhausted, indicating the peer is permanently unreachable.
    /// Set via [`set_unreachable_peer_callback`](Self::set_unreachable_peer_callback).
    pub unreachable_peer_callback: UnreachablePeerCallbackRef,
    /// Fragment reassembler for incoming fragmented messages.
    pub fragment_reassembler: FragmentReassembler,
    /// Session reconnector for automatic reconnection with exponential backoff.
    pub session_reconnector: Option<SessionReconnector>,
    /// Graceful drain configuration for session queue-flushing before close.
    pub graceful_drain_config: crate::session_drain::GracefulDrainConfig,
    /// Peer-level drain coordinator for aggregating per-session drain completion.
    pub peer_drain_coordinator: crate::peer_drain_coordinator::PeerDrainCoordinator,
    /// Set of sessions currently undergoing graceful drain.
    pub draining_sessions: BTreeMap<SessionId, std::time::Instant>,
    /// Per-session connect-lifecycle trackers keyed by SessionId.
    /// Created in `connect()`, updated in `perform_handshake()` and
    /// `close_session()`.
    pub connect_lifecycles: BTreeMap<SessionId, ConnectLifecycle>,
    /// Default connect-timeout configuration applied to new sessions.
    pub connect_config: ConnectConfig,
    /// Optional global callback invoked on every session lifecycle transition.
    /// Individual `ConnectLifecycle` instances may also carry their own callback.
    pub lifecycle_callback: Option<LifecycleChangeCallbackRef>,
    /// Optional TDMA transmit gate for time-division send scheduling.
    #[cfg(feature = "tdma")]
    pub tdma_gate: Option<TdmaSendGate>,
    /// Optional outbound membership roster send gate.
    /// When set, every send is checked against the gate and rejected
    /// with TransportError::PeerNotInRoster if the peer is not in
    /// the current committed roster.
    pub send_gate: Option<std::sync::Arc<dyn SendGate>>,

    /// Optional per-peer capability advertisements from membership for
    /// carrier selection during outbound session establishment.
    /// Keyed by peer node id (MemberId as u64).
    pub peer_capabilities: BTreeMap<u64, tidefs_membership_types::capabilities::PeerCapabilities>,

    /// Per-peer carrier selection disclosures, populated during
    /// [`connect`](Self::connect) when peer capabilities are consulted.
    /// Keyed by peer node id (MemberId as u64).
    pub carrier_disclosures: BTreeMap<u64, crate::carrier_selection::CarrierDisclosure>,

    /// Optional send-concurrency limiter that caps in-flight sends across
    /// all sessions. When set via [`set_send_concurrency_limit`], every
    /// call to [`send_message`] / [`send_priority`] acquires a permit
    /// before writing to the wire, returning [`TransportError::SendConcurrencyLimitExceeded`]
    /// when the limit is reached.
    ///
    /// This closes B5 (Transport Flow Control Not Wired) by gating the
    /// production send dispatch path with a configurable concurrency cap.
    pub send_concurrency: Option<Arc<SendConcurrencyLimiter>>,
}

impl Transport {
    #[must_use]
    /// Create a new Transport using the default TCP backend.
    pub fn new(local_node_id: u64) -> Self {
        let backend = Box::new(TcpTransport::default());
        Self {
            backend_kind: TransportBackendKind::Tcp,
            carrier_policy: crate::carrier_selection::CarrierPolicy::Prefer,
            backend,
            sessions: BTreeMap::new(),
            active_connections: BTreeMap::new(),
            cohort_graph: SessionCohortGraph::new(),
            pool: ConnectionPool::default(),
            supported_families: Vec::new(),
            local_identity: None,
            shippers: BTreeMap::new(),
            session_drain_handles: BTreeMap::new(),
            session_closure_receipts: BTreeMap::new(),
            local_node_id,
            attestation_key: None,
            attestation_identity: None,
            known_identities: NodeKeyStore::new(),
            attestation_bootstrap_from_handshake: false,
            bind_addr: None,
            epoch: 0,
            epoch_barrier: None,
            endpoint_family: EndpointFamily::LocalEmbed,
            response_tracker_config: crate::config::ResponseTrackerConfig::default(),
            mtu: DEFAULT_MTU,
            unreachable_peer_callback: None,
            fragment_reassembler: FragmentReassembler::default(),
            session_reconnector: None,
            graceful_drain_config: crate::session_drain::GracefulDrainConfig::default(),
            peer_drain_coordinator: crate::peer_drain_coordinator::PeerDrainCoordinator::new(),
            draining_sessions: BTreeMap::new(),
            connect_lifecycles: BTreeMap::new(),
            connect_config: ConnectConfig::default(),
            lifecycle_callback: None,
            #[cfg(feature = "tdma")]
            tdma_gate: None,
            send_gate: None,
            peer_capabilities: BTreeMap::new(),
            carrier_disclosures: BTreeMap::new(),
            send_concurrency: None,
        }
    }

    /// Set the endpoint family for this transport instance.
    pub fn set_endpoint_family(&mut self, family: EndpointFamily) {
        self.endpoint_family = family;
    }

    /// Attach an outbound membership roster send gate.
    ///
    /// When set, every call to send_message checks the gate before
    /// writing frames. Sends to peers not in the committed roster are
    /// rejected with TransportError::PeerNotInRoster.
    ///
    /// Set to None to disable send gating.
    pub fn set_send_gate(&mut self, gate: Option<std::sync::Arc<dyn SendGate>>) {
        self.send_gate = gate;
    }

    /// Register a callback to be invoked when a peer session's reconnection
    /// attempts are exhausted, indicating the peer is permanently unreachable.
    ///
    /// The callback is invoked at most once per exhaustion event. When multiple
    /// sessions to the same peer exist, the callback may be invoked once per
    /// session exhaustion; implementations must be idempotent.
    pub fn set_unreachable_peer_callback(
        &mut self,
        callback: std::sync::Arc<dyn crate::unreachable_peer::UnreachablePeerCallback>,
    ) {
        self.unreachable_peer_callback = Some(callback);
    }

    /// Set the per-session response tracker configuration.
    ///
    /// This config is used to auto-create response trackers when sessions
    /// reach []. Existing sessions are unaffected;
    /// only newly-established sessions will use the new config.
    pub fn set_response_tracker_config(&mut self, cfg: crate::config::ResponseTrackerConfig) {
        self.response_tracker_config = cfg;
    }

    /// Override the per-session in-flight request concurrency limit.
    ///
    /// When `max` is `Some(n)`, the session will reject
    /// [`send_tracked_request`](Self::send_tracked_request) calls once `n`
    /// requests are already in-flight, returning
    /// [`TransportError::RequestLimitExceeded`].  When `max` is `None`,
    /// the limit is removed (unlimited in-flight requests — use with care).
    ///
    /// This affects an already-established session and takes effect
    /// immediately for future registrations; already-in-flight requests
    /// are not preempted.
    pub async fn set_max_in_flight_requests(
        &self,
        session_id: SessionId,
        max: Option<usize>,
    ) -> Result<(), TransportError> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or(TransportError::SessionNotFound { session_id })?;
        let tracker = {
            let session = session
                .lock()
                .map_err(|e| TransportError::Generic(format!("session lock poisoned: {e}")))?;
            session
                .response_tracker
                .clone()
                .ok_or_else(|| TransportError::Generic("session has no response tracker".into()))?
        };
        tracker.set_max_in_flight(max).await;
        Ok(())
    }

    /// Set the default connect-timeout configuration for new sessions.
    ///
    /// Existing sessions are unaffected; only newly-established sessions
    /// (via [`connect`](Self::connect) or [`accept_incoming`](Self::accept_incoming))
    /// will use the new config.
    ///
    /// Register per-peer capability advertisements from membership for
    /// carrier selection during outbound session establishment.
    ///
    /// When capabilities are registered, [](Self::connect) consults
    /// them to select the best mutually-supported transport carrier.
    /// When a peer has no entry, the default backend kind is used unchanged.
    pub fn set_peer_capabilities(
        &mut self,
        caps: BTreeMap<u64, tidefs_membership_types::capabilities::PeerCapabilities>,
    ) {
        self.peer_capabilities = caps;
    }

    /// Return the carrier selection disclosure for a peer, if one was produced
    /// during the last [`connect`](Self::connect) call for that peer.
    ///
    /// Returns `None` when no peer capabilities were registered for the peer
    /// at connection time, or when no connection has been attempted yet.
    #[must_use]
    pub fn carrier_disclosure(
        &self,
        peer_id: u64,
    ) -> Option<&crate::carrier_selection::CarrierDisclosure> {
        self.carrier_disclosures.get(&peer_id)
    }

    /// Configure an optional send-concurrency limit that gates every
    /// outbound send through [`send_message`] / [`send_priority`].
    ///
    /// When set, each send acquires a non-blocking permit before writing
    /// to the wire. If the in-flight limit is reached, the send returns
    /// [`TransportError::SendConcurrencyLimitExceeded`] instead of
    /// blocking. Pass `0` or call [`clear_send_concurrency_limit`] to
    /// remove the limiter.
    ///
    /// Default: `None` (no concurrency limit).
    pub fn set_send_concurrency_limit(&mut self, max_inflight: usize) {
        if max_inflight == 0 {
            self.send_concurrency = None;
        } else {
            self.send_concurrency = Some(Arc::new(SendConcurrencyLimiter::new(max_inflight)));
        }
    }

    /// Remove the send-concurrency limiter, allowing unbounded in-flight
    /// sends.
    pub fn clear_send_concurrency_limit(&mut self) {
        self.send_concurrency = None;
    }

    pub fn set_connect_config(&mut self, cfg: ConnectConfig) {
        self.connect_config = cfg;
    }

    /// Return the current default connect configuration.
    #[must_use]
    pub fn connect_config(&self) -> &ConnectConfig {
        &self.connect_config
    }

    /// Register a global callback to be invoked on every session lifecycle
    /// transition (Connecting → Ready → Dead).
    ///
    /// New sessions created after this call inherit the callback automatically.
    /// Existing sessions are unaffected.
    pub fn set_lifecycle_callback(&mut self, callback: LifecycleChangeCallbackRef) {
        self.lifecycle_callback = Some(callback);
    }

    /// Configure message batching for an existing session.
    ///
    /// When enabled, subsequent [`batched_send`](Self::batched_send) calls
    /// accumulate messages in a per-session batcher instead of writing each
    /// message immediately. Call [`flush_batches`](Self::flush_batches)
    /// periodically to drain accumulated messages.
    ///
    /// When disabled (default), [`batched_send`](Self::batched_send) falls
    /// through to immediate send via [`send_priority`](Self::send_priority).
    pub fn set_batch_config(
        &mut self,
        session_id: SessionId,
        config: crate::message_batcher::BatchConfig,
    ) -> Result<(), TransportError> {
        if let Some(session) = self.sessions.get(&session_id) {
            if let Ok(mut s) = session.lock() {
                s.configure_batching(config);
                return Ok(());
            }
            return Err(TransportError::Generic("session lock poisoned".into()));
        }
        Err(TransportError::Generic(format!(
            "no session for session_id {session_id}"
        )))
    }

    /// Configure per-session outbound compression.
    ///
    /// Enables compression on the send path for the given session using
    /// the specified algorithm and threshold. The compressed output is
    /// prefixed with a wire marker so the peer can auto-detect and
    /// decompress without relying on matching local configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the session does not exist or the lock is poisoned.
    pub fn set_compression_config(
        &mut self,
        session_id: SessionId,
        config: CompressionConfig,
    ) -> Result<(), TransportError> {
        if let Some(session) = self.sessions.get(&session_id) {
            if let Ok(mut s) = session.lock() {
                s.set_compression(config);
                return Ok(());
            }
            return Err(TransportError::Generic("session lock poisoned".into()));
        }
        Err(TransportError::Generic(format!(
            "no session for session_id {session_id}"
        )))
    }

    /// Disable outbound compression for a session.
    ///
    /// # Errors
    ///
    /// Returns an error if the session does not exist or the lock is poisoned.
    pub fn disable_compression(&mut self, session_id: SessionId) -> Result<(), TransportError> {
        if let Some(session) = self.sessions.get(&session_id) {
            if let Ok(mut s) = session.lock() {
                s.disable_compression();
                return Ok(());
            }
            return Err(TransportError::Generic("session lock poisoned".into()));
        }
        Err(TransportError::Generic(format!(
            "no session for session_id {session_id}"
        )))
    }

    /// Enable or disable non-blocking I/O on all connections.
    ///
    /// When enabled, [`Self::recv_message`] and [`Self::recv_envelope`] return
    /// [`TransportError::WouldBlock`] instead of blocking when no data is available.
    /// This is propagated to the backend and all active+future connections.
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), TransportError> {
        self.backend.set_nonblocking(nonblocking)?;
        for conn in self.active_connections.values_mut() {
            conn.set_nonblocking(nonblocking)?;
        }
        Ok(())
    }

    #[must_use]
    /// Create a new Transport with a custom backend (e.g. RDMA).
    pub fn with_backend(local_node_id: u64, backend: Box<dyn TransportBackend>) -> Self {
        let kind = backend.backend_kind();
        Self {
            backend,
            backend_kind: kind,
            carrier_policy: crate::carrier_selection::CarrierPolicy::Prefer,
            sessions: BTreeMap::new(),
            active_connections: BTreeMap::new(),
            cohort_graph: SessionCohortGraph::new(),
            pool: ConnectionPool::default(),
            supported_families: Vec::new(),
            local_identity: None,
            shippers: BTreeMap::new(),
            session_drain_handles: BTreeMap::new(),
            session_closure_receipts: BTreeMap::new(),
            local_node_id,
            attestation_key: None,
            attestation_identity: None,
            known_identities: NodeKeyStore::new(),
            attestation_bootstrap_from_handshake: false,
            bind_addr: None,
            epoch: 0,
            epoch_barrier: None,
            endpoint_family: EndpointFamily::LocalEmbed,
            response_tracker_config: crate::config::ResponseTrackerConfig::default(),
            mtu: DEFAULT_MTU,
            unreachable_peer_callback: None,
            fragment_reassembler: FragmentReassembler::default(),
            session_reconnector: None,
            graceful_drain_config: crate::session_drain::GracefulDrainConfig::default(),
            peer_drain_coordinator: crate::peer_drain_coordinator::PeerDrainCoordinator::new(),
            draining_sessions: BTreeMap::new(),
            connect_lifecycles: BTreeMap::new(),
            connect_config: ConnectConfig::default(),
            lifecycle_callback: None,
            #[cfg(feature = "tdma")]
            tdma_gate: None,
            send_gate: None,
            peer_capabilities: BTreeMap::new(),
            carrier_disclosures: BTreeMap::new(),
            send_concurrency: None,
        }
    }

    /// Create a Transport with an RDMA verbs backend.
    ///
    /// Falls back to TCP if no RDMA device is available on this host.
    /// Uses the given `connect_timeout` for TCP control-channel connections
    /// during QP handshake.
    pub fn with_rdma_backend(
        local_node_id: u64,
        connect_timeout: Duration,
    ) -> Result<Self, TransportError> {
        let backend = crate::rdma::RdmaTransport::new(connect_timeout)?;
        Ok(Self::with_backend(local_node_id, Box::new(backend)))
    }

    /// Create a Transport with an RDMA backend, falling back to TCP
    /// when RDMA is unavailable.
    #[must_use]
    pub fn with_rdma_or_tcp(local_node_id: u64, connect_timeout: Duration) -> Self {
        match crate::rdma::RdmaTransport::new(connect_timeout) {
            Ok(backend) => Self::with_backend(local_node_id, Box::new(backend)),
            Err(_) => Self::new(local_node_id),
        }
    }

    /// Set the carrier policy for this transport.
    ///
    /// Controls whether carrier selection silently falls back to TCP
    /// (`Prefer`, default) or fails closed (`Enforce`) when the configured
    /// backend (e.g. RDMA) cannot be satisfied.  Implements the "fail closed
    /// on silent TCP fallback when an RDMA claim is being made" requirement
    /// from #6672.
    #[must_use]
    pub fn with_carrier_policy(mut self, policy: crate::carrier_selection::CarrierPolicy) -> Self {
        self.carrier_policy = policy;
        self
    }

    fn check_runtime_rdma_fallback_policy(
        &mut self,
        session_id: SessionId,
        peer_node: u64,
        reason: &'static str,
        refusal_detail: &'static str,
    ) -> Result<(), TransportError> {
        self.carrier_policy
            .check_runtime_fallback(
                TransportBackendKind::Rdma,
                TransportBackendKind::Tcp,
                refusal_detail,
            )
            .map_err(|e| {
                let disclosure = CarrierDisclosure::from_runtime_fallback_refusal(
                    TransportBackendKind::Rdma,
                    reason,
                    self.carrier_policy,
                );
                tracing::error!(peer = peer_node, session_id = %session_id, "{}", disclosure);
                self.carrier_disclosures.insert(peer_node, disclosure);
                TransportError::Generic(format!("session {session_id}: {e}"))
            })
    }

    /// Configure this transport for Ed25519 mutual attestation.
    /// Both the keypair and identity should come from tidefs_auth::NodeIdentity::generate().
    #[must_use]
    pub fn with_attestation(
        mut self,
        keypair: Keypair,
        identity: tidefs_auth::NodeIdentity,
    ) -> Self {
        self.attestation_key = Some(keypair);
        self.attestation_identity = Some(identity.clone());
        self.local_identity = Some(identity.clone());
        // Register our own identity so the peer can verify us.
        let _ = self.known_identities.register(identity);
        self
    }

    /// Generate and configure an ephemeral Ed25519 identity for this transport.
    ///
    /// This enables attestation for non-LocalEmbed endpoint families without
    /// requiring the caller to directly depend on `tidefs-auth`.
    ///
    /// # Errors
    ///
    /// Returns an error if identity generation fails.
    pub fn configure_generated_attestation(
        &mut self,
        bootstrap_from_handshake: bool,
    ) -> Result<(), TransportError> {
        let (identity, keypair) = tidefs_auth::NodeIdentity::generate(self.local_node_id)
            .map_err(|e| TransportError::Generic(format!("generate attestation identity: {e}")))?;
        self.attestation_key = Some(keypair);
        self.attestation_identity = Some(identity.clone());
        self.local_identity = Some(identity.clone());
        self.known_identities
            .register(identity)
            .map_err(|e| TransportError::Generic(format!("register local identity: {e}")))?;
        self.attestation_bootstrap_from_handshake = bootstrap_from_handshake;
        Ok(())
    }

    /// Enable or disable handshake-provided peer identity bootstrap.
    ///
    /// When enabled, non-LocalEmbed sessions may register a peer identity from
    /// the basic transport handshake before the attestation exchange. Existing
    /// configured identities still verify through the normal key store path.
    pub fn set_attestation_bootstrap_from_handshake(&mut self, enabled: bool) {
        self.attestation_bootstrap_from_handshake = enabled;
    }

    /// Pre-populate the known-identity registry (bootstrap trust anchors).
    #[must_use]
    pub fn with_known_identities(mut self, store: NodeKeyStore) -> Self {
        self.known_identities = store;
        self
    }

    /// Set the membership epoch for attestation negotiation.
    #[must_use]
    pub fn with_epoch(mut self, epoch: u64) -> Self {
        self.epoch = epoch;
        self
    }

    /// Attach a SessionReconnector for automatic reconnection with
    /// exponential backoff on transient session failures.
    #[must_use]
    pub fn with_session_reconnector(mut self, reconnector: SessionReconnector) -> Self {
        self.session_reconnector = Some(reconnector);
        self
    }

    /// Set the graceful drain configuration for session queue-flushing.
    ///
    /// When [`drain_session_gracefully`](Self::drain_session_gracefully) is called,
    /// this config governs the deadline, poll interval, and new-send rejection
    /// behavior.
    #[must_use]
    pub fn with_graceful_drain_config(
        mut self,
        config: crate::session_drain::GracefulDrainConfig,
    ) -> Self {
        self.graceful_drain_config = config;
        self
    }

    /// Start listening and accepting connections.
    pub fn bind(&mut self, addr: TransportAddr) -> Result<(), TransportError> {
        self.backend.bind(addr)?;
        self.bind_addr = self.backend.local_addr();
        Ok(())
    }

    /// Add a node to the cohort graph.
    pub fn add_node(&mut self, info: NodeInfo) {
        self.cohort_graph.add_node(info);
    }

    /// Accept a single incoming TCP connection, create an inbound session,
    /// and return the session ID.
    ///
    /// The caller must call `perform_handshake` to complete the handshake
    /// and transition the session to Established.
    pub fn accept_incoming(&mut self) -> Result<SessionId, TransportError> {
        let (conn, peer_addr) = self.backend.accept()?;

        // Create an inbound session (peer identity not yet known)
        let session_id = self.cohort_graph.next_session_id();
        let mut session = Session::new(
            session_id,
            self.local_node_id,
            0,
            peer_addr,
            self.endpoint_family,
            self.backend_kind,
        );

        session
            .transition(SessionState::Connecting {
                started_at: HlcTimestamp::default(),
            })
            .map_err(|e| TransportError::Generic(e.to_string()))?;

        // Attach per-priority capacity signals for external backpressure
        // queries (e.g. rebuild throttling against foreground I/O).
        {
            let cs = SendCapacitySet::new(&SendWatermarkConfig::default());
            session.set_capacity_set(cs);
        }

        let session = Arc::new(std::sync::Mutex::new(session));
        self.sessions.insert(session_id, Arc::clone(&session));

        // Store the connection for frame I/O
        self.active_connections.insert(session_id, conn);

        // Create per-session connect-lifecycle tracker with the configured
        // connect timeout.  The lifecycle starts in Connecting and will be
        // advanced to Ready by perform_handshake() on success, or to Dead
        // by close_session() / timeout enforcement.
        let mut lifecycle = ConnectLifecycle::new(
            session_id.0,
            0, /* unknown peer on accept */
            Instant::now(),
            self.connect_config.clone(),
        );
        if let Some(ref cb) = self.lifecycle_callback {
            lifecycle.set_lifecycle_callback(Arc::clone(cb));
        }
        self.connect_lifecycles.insert(session_id, lifecycle);

        Ok(session_id)
    }

    /// Establish a session to a peer (outgoing).
    ///
    /// When per-peer capability advertisements have been registered via
    /// [](Self::set_peer_capabilities), this method
    /// consults them to select the best mutually-supported transport carrier.
    /// Otherwise the transport's default  is used unchanged.
    pub fn connect(&mut self, peer_node_id: u64) -> Result<SessionId, TransportError> {
        let peer = self
            .cohort_graph
            .nodes
            .get(&peer_node_id)
            .cloned()
            .ok_or(TransportError::PeerNotFound { peer: peer_node_id })?;

        if !self.cohort_graph.can_establish_session(self.local_node_id) {
            return Err(TransportError::MaxSessionsReached {
                max: 100,
                peer: peer_node_id,
            });
        }

        // Carrier selection: consult peer capabilities when available.
        let (session_backend_kind, maybe_disclosure) = self
            .peer_capabilities
            .get(&peer_node_id)
            .map(|caps| {
                let result = crate::carrier_selection::CarrierSelector::new(self.backend_kind)
                    .with_policy(self.carrier_policy)
                    .select(caps.transport_carriers)?;
                let disclosure = crate::carrier_selection::CarrierDisclosure::from_selection(
                    result,
                    self.backend_kind,
                    caps.transport_carriers,
                );
                Ok::<_, crate::carrier_selection::CarrierSelectionError>((
                    result.backend_kind,
                    Some(disclosure),
                ))
            })
            .transpose()
            .map_err(|e| TransportError::Generic(format!("carrier selection failed: {e}")))?
            .unwrap_or((self.backend_kind, None));

        // Store and log the disclosure when peer capabilities were consulted.
        if let Some(ref disclosure) = maybe_disclosure {
            tracing::info!(peer = peer_node_id, "{}", disclosure,);
            if let Some(ref mismatch) = disclosure.mismatch {
                tracing::warn!(peer = peer_node_id, "{}", mismatch,);
            }
            self.carrier_disclosures
                .insert(peer_node_id, disclosure.clone());
        }

        // Connect via backend
        let conn = self.backend.connect(&peer)?;
        let peer_addr = peer
            .addresses
            .first()
            .cloned()
            .unwrap_or_else(|| TransportAddr::Tcp("0.0.0.0:0".parse().unwrap()));

        // Create session
        let session_id = self.cohort_graph.next_session_id();
        let mut session = Session::new(
            session_id,
            self.local_node_id,
            peer_node_id,
            peer_addr.clone(),
            self.endpoint_family,
            session_backend_kind,
        );

        // Transition: Unconnected → Connecting
        session
            .transition(SessionState::Connecting {
                started_at: HlcTimestamp::default(),
            })
            .map_err(|e| TransportError::Generic(e.to_string()))?;

        // Attach per-priority capacity signals for external backpressure
        // queries (e.g. rebuild throttling against foreground I/O).
        {
            let cs = SendCapacitySet::new(&SendWatermarkConfig::default());
            session.set_capacity_set(cs);
        }

        // Insert session
        let session = Arc::new(std::sync::Mutex::new(session));
        self.sessions.insert(session_id, Arc::clone(&session));
        self.cohort_graph.sessions.insert(
            (
                self.local_node_id,
                peer_node_id,
                self.endpoint_family as u32,
            ),
            Session::new(
                session_id,
                self.local_node_id,
                peer_node_id,
                peer_addr,
                self.endpoint_family,
                session_backend_kind,
            ),
        );

        // Store the connection for frame I/O
        self.active_connections.insert(session_id, conn);

        // Create chunk shipper for this session
        let shipper = ChunkShipper::new(session_id, session_backend_kind);
        self.shippers.insert(session_id, shipper);

        // Create per-session connect-lifecycle tracker with the configured
        // connect timeout.  The lifecycle starts in Connecting and will be
        // advanced to Ready by perform_handshake() on success, or to Dead
        // by close_session() / timeout enforcement.
        let mut lifecycle = ConnectLifecycle::new(
            session_id.0,
            peer_node_id,
            Instant::now(),
            self.connect_config.clone(),
        );
        if let Some(ref cb) = self.lifecycle_callback {
            lifecycle.set_lifecycle_callback(Arc::clone(cb));
        }
        self.connect_lifecycles.insert(session_id, lifecycle);

        Ok(session_id)
    }

    /// Perform a real session handshake: exchange node identities and negotiate
    /// protocol versions over the active connection. On success, the session
    /// transitions to Established.
    ///
    /// Must be called after `connect()` or `accept_incoming()`.
    pub fn perform_handshake(&mut self, session_id: SessionId) -> Result<(), TransportError> {
        // Determine initiator vs responder before the basic HandshakeMessage
        // exchange overwrites peer_node.  connect() sets peer_node to the
        // known peer id; accept_incoming() leaves it at 0 (unknown).
        let (is_initiator, endpoint_family) = {
            let session = self
                .sessions
                .get(&session_id)
                .ok_or(TransportError::SessionNotFound { session_id })?;
            let mut session = session
                .lock()
                .map_err(|e| TransportError::Generic(format!("session lock poisoned: {e}")))?;
            let is_initiator = session.peer_node != 0;
            let endpoint_family = session.endpoint_family;

            // Transition: Connecting -> Handshaking
            session
                .transition(SessionState::Handshaking {
                    started_at: HlcTimestamp::default(),
                })
                .map_err(|e| TransportError::Generic(e.to_string()))?;
            (is_initiator, endpoint_family)
        }; // session lock dropped here

        // ────────────────────────────────────────────────────────────────
        // Attestation gating: non-LocalEmbed endpoints MUST attest. The
        // initiator already knows its requested endpoint family, while an
        // acceptor only learns the peer's requested family after the basic
        // transport handshake below.
        // ────────────────────────────────────────────────────────────────
        let local_requires_attestation = !matches!(endpoint_family, EndpointFamily::LocalEmbed);

        if is_initiator && local_requires_attestation && self.attestation_key.is_none() {
            self.close_session(session_id, SessionCloseReason::AuthFailed)?;
            return Err(TransportError::HandshakeFailed {
                session_id,
                reason: format!(
                    "attestation required for {endpoint_family:?} endpoint but no attestation key configured"
                ),
            });
        }

        // Get the active connection
        let conn = self
            .active_connections
            .get_mut(&session_id)
            .ok_or_else(|| {
                TransportError::Generic(format!("no active connection for session {session_id}"))
            })?;

        // Build our local identity
        let local_id = self.local_identity.clone().unwrap_or_else(|| {
            tidefs_auth::NodeIdentity::generate(self.local_node_id)
                .expect("generate node identity")
                .0
        });

        // Serialize and send our identity + supported families
        let local_handshake = HandshakeMessage {
            identity: local_id.clone(),
            families: self.supported_families.clone(),
            endpoint_family: self.endpoint_family as u32,
            epoch: self.epoch,
            mtu: self.mtu as u32,
            feature_flags: crate::session_handshake::DEFAULT_FEATURE_FLAGS,
        };

        let local_bytes = bincode::serialize(&local_handshake)
            .map_err(|e| TransportError::Generic(format!("handshake serialize failed: {e}")))?;

        conn.write_frame(&local_bytes)?;

        // Read peer's identity + families
        let peer_bytes = conn.read_frame()?;

        let peer_handshake: HandshakeMessage = bincode::deserialize(&peer_bytes)
            .map_err(|e| TransportError::Generic(format!("handshake deserialize failed: {e}")))?;

        // Negotiate MTU: use the minimum of both sides
        let negotiated_mtu = (self.mtu as u32).min(peer_handshake.mtu).max(512) as usize;
        self.mtu = negotiated_mtu;

        // Negotiate feature flags: intersection of local and peer bits.
        let negotiated_feature_flags = local_handshake.feature_flags & peer_handshake.feature_flags;

        let peer_endpoint = match peer_handshake.endpoint_family {
            0 => EndpointFamily::LocalEmbed,
            1 => EndpointFamily::Control,
            2 => EndpointFamily::Data,
            3 => EndpointFamily::Shadow,
            other => {
                return Err(TransportError::Generic(format!(
                    "unknown endpoint family: {other}"
                )))
            }
        };
        let peer_requires_attestation = !matches!(peer_endpoint, EndpointFamily::LocalEmbed);
        let requires_attestation = local_requires_attestation || peer_requires_attestation;

        if requires_attestation && self.attestation_key.is_none() {
            self.close_session(session_id, SessionCloseReason::AuthFailed)?;
            return Err(TransportError::HandshakeFailed {
                session_id,
                reason: format!(
                    "attestation required for local {endpoint_family:?} / peer {peer_endpoint:?} endpoint but no attestation key configured"
                ),
            });
        }

        if requires_attestation && self.attestation_bootstrap_from_handshake {
            self.known_identities
                .register(peer_handshake.identity.clone())
                .map_err(|e| TransportError::Generic(format!("bootstrap peer identity: {e}")))?;
        }

        // Store peer info (re-lock the session)
        let peer_node_id = peer_handshake.identity.node_id;
        {
            let session = self
                .sessions
                .get(&session_id)
                .ok_or(TransportError::SessionNotFound { session_id })?;
            let mut session = session
                .lock()
                .map_err(|e| TransportError::Generic(format!("session lock poisoned: {e}")))?;
            session.peer_node = peer_node_id;
            session.peer_info = Some(PeerSessionInfo {
                node_id: peer_node_id,
                identity: peer_handshake.identity.clone(),
                supported_families: peer_handshake.families.clone(),
                cohort_membership: CohortMembership::new(Vec::new(), 0),
                endpoint_family: peer_endpoint,
                hlc_offset: 0,
                peer_epoch: peer_handshake.epoch,
            });
            session.current_epoch = self.epoch;
        } // session lock dropped

        // Update the cohort graph with the peer's node id
        if !self.cohort_graph.nodes.contains_key(&peer_node_id) {
            let peer_addr = {
                let s = self.sessions.get(&session_id).unwrap().lock().unwrap();
                s.peer_addr.clone()
            };
            self.cohort_graph
                .add_node(NodeInfo::new(peer_node_id, vec![peer_addr], 0));
        }

        // ------------------------------------------------------------------
        // Mutual attestation handshake.
        // ------------------------------------------------------------------
        if requires_attestation {
            let attestation_key = self.attestation_key.as_ref().ok_or_else(|| {
                TransportError::Generic("attestation key missing after attestation gate".into())
            })?;
            // Use the registered attestation identity (set via with_attestation)
            // so the peer can verify us against known_identities.
            let our_identity = self
                .attestation_identity
                .clone()
                .unwrap_or_else(|| local_id.clone());

            if is_initiator {
                // ── Initiator: send HelloMessage, receive HelloResponse ──
                let hello = HelloMessage::new(
                    our_identity,
                    attestation_key,
                    vec![1],
                    tidefs_auth::SessionClass::FullMesh,
                    self.epoch,
                );

                let hello_bytes = bincode::serialize(&hello).map_err(|e| {
                    TransportError::Generic(format!("attestation hello serialize failed: {e}"))
                })?;
                conn.write_frame(&hello_bytes)?;

                let resp_bytes = conn.read_frame()?;
                let hello_resp: HelloResponse = bincode::deserialize(&resp_bytes).map_err(|e| {
                    TransportError::Generic(format!("attestation response deserialize failed: {e}"))
                })?;

                let nonce = hello.client_nonce;
                match verify_mutual_attestation(
                    &nonce,
                    &hello_resp.server_nonce,
                    &hello,
                    &hello_resp,
                    &self.known_identities,
                ) {
                    Ok(result) => {
                        // Register peer identity
                        self.known_identities
                            .register(result.peer_identity.clone())
                            .map_err(|e| {
                                TransportError::Generic(format!("register peer identity: {e}"))
                            })?;

                        // Update session peer identity with verified identity
                        let session = self.sessions.get(&session_id).unwrap();
                        let mut session = session.lock().map_err(|e| {
                            TransportError::Generic(format!("session lock poisoned: {e}"))
                        })?;
                        if let Some(ref mut info) = session.peer_info {
                            info.identity = result.peer_identity;
                        }
                    }
                    Err(e) => {
                        self.close_session(session_id, SessionCloseReason::AuthFailed)?;
                        return Err(TransportError::HandshakeFailed {
                            session_id,
                            reason: format!("mutual attestation failed: {e}"),
                        });
                    }
                }
            } else {
                // ── Responder: receive HelloMessage, send HelloResponse ──
                let hello_bytes = conn.read_frame()?;
                let hello: HelloMessage = bincode::deserialize(&hello_bytes).map_err(|e| {
                    TransportError::Generic(format!("attestation hello deserialize failed: {e}"))
                })?;

                // Verify the initiator before responding
                hello.verify().map_err(|e| {
                    TransportError::Generic(format!("attestation hello verify failed: {e}"))
                })?;
                hello.client_identity.verify_self_signature().map_err(|e| {
                    TransportError::Generic(format!("attestation peer self-signature failed: {e}"))
                })?;
                if !self
                    .known_identities
                    .contains(hello.client_identity.node_id)
                {
                    self.close_session(session_id, SessionCloseReason::AuthFailed)?;
                    return Err(TransportError::HandshakeFailed {
                        session_id,
                        reason: format!(
                            "peer node {} not in known identities",
                            hello.client_identity.node_id
                        ),
                    });
                }
                if hello.proposed_epoch != self.epoch {
                    self.close_session(session_id, SessionCloseReason::AuthFailed)?;
                    return Err(TransportError::HandshakeFailed {
                        session_id,
                        reason: format!(
                            "epoch mismatch: client proposed {}, local {}",
                            hello.proposed_epoch, self.epoch
                        ),
                    });
                }

                // Build and send response
                let session_id_u64 = session_id.0;
                let hello_resp = HelloResponse::new(
                    our_identity,
                    attestation_key,
                    hello.client_nonce,
                    1, // accepted protocol version
                    tidefs_auth::SessionClass::FullMesh,
                    session_id_u64,
                    self.epoch,
                );

                let resp_bytes = bincode::serialize(&hello_resp).map_err(|e| {
                    TransportError::Generic(format!("attestation response serialize failed: {e}"))
                })?;
                conn.write_frame(&resp_bytes)?;

                // Register the verified peer identity
                self.known_identities
                    .register(hello.client_identity.clone())
                    .map_err(|e| TransportError::Generic(format!("register peer identity: {e}")))?;

                // Update session peer identity with verified identity
                let session = self.sessions.get(&session_id).unwrap();
                let mut session = session
                    .lock()
                    .map_err(|e| TransportError::Generic(format!("session lock poisoned: {e}")))?;
                if let Some(ref mut info) = session.peer_info {
                    info.identity = hello.client_identity;
                }
            }
        }

        // Transition: Handshaking -> Established
        let session = self.sessions.get(&session_id).unwrap();
        let mut session = session
            .lock()
            .map_err(|e| TransportError::Generic(format!("session lock poisoned: {e}")))?;

        session
            .transition(SessionState::Established {
                since: HlcTimestamp::default(),
            })
            .map_err(|e| TransportError::Generic(e.to_string()))?;

        // Wire negotiated feature flags into the session rollback gate.
        session.rollback_gate = Some(crate::rollback_compat::RollingUpgradeGate::from_raw(
            negotiated_feature_flags,
        ));

        // Create the per-session response tracker if not already attached.
        let cfg = &self.response_tracker_config.clone();
        session.set_response_tracker(cfg.max_pending, cfg.default_timeout, cfg.reap_interval);
        drop(session); // release lock before accessing self.connect_lifecycles

        // Advance the connect lifecycle to Ready now that the session is
        // fully established and can carry messages.
        if let Some(lifecycle) = self.connect_lifecycles.get_mut(&session_id) {
            let _ = lifecycle.transition(SessionLifecycle::Ready, Instant::now());
        }

        Ok(())
    }

    /// Ensure a session has a response tracker, creating one from config
    /// if it doesn't already exist.
    fn ensure_response_tracker(&self, session: &mut crate::session::Session) {
        if session.response_tracker.is_some() {
            return;
        }
        let cfg = &self.response_tracker_config;
        session.set_response_tracker(cfg.max_pending, cfg.default_timeout, cfg.reap_interval);
    }

    /// Send a tracked request on an established session.
    ///
    /// Registers a new in-flight request in the session's response tracker,
    /// frames the payload with a correlation header, and transmits the
    /// framed bytes via [](Self::send_message).
    ///
    /// Returns a [] that will receive the
    /// response (or a timeout error) when the peer replies or the tracker's
    /// background reaper expires the entry.
    ///
    /// # Errors
    ///
    /// Returns [] if the session isn't found, isn't
    /// established, or the send fails.
    pub async fn send_tracked_request(
        &mut self,
        session_id: SessionId,
        payload: &[u8],
    ) -> Result<
        tokio::sync::oneshot::Receiver<Result<Vec<u8>, crate::request_response::CorrelationError>>,
        TransportError,
    > {
        // Register the request and get a correlation ID + receiver.
        let needs_tracker = {
            let session = self
                .sessions
                .get(&session_id)
                .ok_or(TransportError::SessionNotFound { session_id })?;
            let session = session
                .lock()
                .map_err(|e| TransportError::Generic(format!("session lock poisoned: {e}")))?;
            session.response_tracker.is_none()
        };

        if needs_tracker {
            let session = self
                .sessions
                .get(&session_id)
                .ok_or(TransportError::SessionNotFound { session_id })?;
            let mut session = session
                .lock()
                .map_err(|e| TransportError::Generic(format!("session lock poisoned: {e}")))?;
            self.ensure_response_tracker(&mut session);
        }

        let tracker = {
            let session = self
                .sessions
                .get(&session_id)
                .ok_or(TransportError::SessionNotFound { session_id })?;
            let session = session
                .lock()
                .map_err(|e| TransportError::Generic(format!("session lock poisoned: {e}")))?;
            session.response_tracker.clone().ok_or_else(|| {
                TransportError::Generic("response tracker not available on session".into())
            })?
        };

        let (correlation_id, rx) = tracker
            .register_request()
            .await
            .map_err(|e| TransportError::Generic(format!("register_request: {e}")))?;

        // Frame the payload with the correlation header.
        let framed = crate::correlation_frame::encode_correlation_request(correlation_id, payload);

        // Send via the standard send path.
        self.send_message(session_id, &framed)?;

        Ok(rx)
    }

    /// Try to deliver an inbound message to the session's response tracker.
    ///
    /// If the message starts with a valid correlation header and carries
    /// a response (not a request), it delivers the payload to the waiting
    /// caller and returns . Otherwise returns  (the caller
    /// should process the message through normal dispatch).
    ///
    /// This is a non-blocking check: it peeks at the first
    /// [] bytes and only acquires the session lock
    /// when a response frame is detected.
    pub async fn try_deliver_correlation_response(
        &self,
        session_id: SessionId,
        data: &[u8],
    ) -> bool {
        if !crate::correlation_frame::has_correlation_header(data) {
            return false;
        }

        let decoded = match crate::correlation_frame::decode_correlation_frame(data) {
            Ok(decoded) => decoded,
            Err(_) => return false,
        };

        match decoded {
            crate::correlation_frame::CorrelationFrameKind::Request { .. } => {
                // Requests are dispatched normally; not delivered here.
                false
            }
            crate::correlation_frame::CorrelationFrameKind::Response {
                correlation_id,
                payload,
            } => {
                let tracker = {
                    let session = match self.sessions.get(&session_id) {
                        Some(s) => s,
                        None => return false,
                    };
                    let session = match session.lock() {
                        Ok(s) => s,
                        Err(_) => return false,
                    };
                    match session.response_tracker.clone() {
                        Some(tracker) => tracker,
                        None => return false,
                    }
                };
                matches!(
                    tracker.deliver_response(correlation_id, payload).await,
                    Ok(())
                )
            }
        }
    }

    /// Send a message frame on an established session.
    /// Send a message on an established session.
    ///
    /// If the payload exceeds the session MTU, the message is automatically
    /// fragmented using [`fragment_message`] and each fragment is sent
    /// individually. The receiver's [`FragmentReassembler`] reconstructs
    /// the original payload before dispatch.
    ///
    /// Fragments are sent as raw frames and do not carry per-message
    /// authentication; integrity for large payloads is deferred
    /// Send a message on an established session, enqueued at Data priority
    /// for backward compatibility. Messages go through the per-session priority
    /// queue and are written to the connection after draining Control messages
    /// ahead of Data messages.
    ///
    /// Callers that need explicit priority should use [`send_priority`](Self::send_priority)
    /// to classify control-plane messages (`MessagePriority::Control`) separately
    /// from data-plane messages (`MessagePriority::Data`).
    ///
    /// ## Backward compatibility
    ///
    /// Existing callers that use `send_message` continue to work unchanged:
    /// their messages are enqueued at `Data` priority and written after any
    /// pending `Control` messages in the same session's priority queue.
    pub fn send_message(
        &mut self,
        session_id: SessionId,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        self.send_priority(session_id, payload, MessagePriority::Data)
    }

    /// Send a message on an established session with explicit priority.
    ///
    /// Messages are enqueued into the session's per-priority sub-queues:
    /// `Control` messages bypass queued `Data` messages within the same
    /// session, preventing head-of-line blocking of time-sensitive control
    /// traffic during bulk data transfers.
    ///
    /// The Control queue has a bounded depth (default 16 messages); enqueue
    /// beyond this limit returns `TransportError::Generic` with the
    /// `MessagePriorityError::ControlQueueFull` detail.
    pub fn send_priority(
        &mut self,
        session_id: SessionId,
        payload: &[u8],
        priority: MessagePriority,
    ) -> Result<(), TransportError> {
        #[cfg(feature = "tdma")]
        if let Some(ref gate) = self.tdma_gate {
            gate.check_transmit_window(session_id)?;
        }

        if !self.sessions.contains_key(&session_id) {
            self.record_send_err(session_id);
            return Err(TransportError::SessionNotFound { session_id });
        }

        // Outbound membership roster send-gate: reject sends to peers
        // not in the current committed roster.
        if let Some(ref gate) = self.send_gate {
            if let Some(session) = self.sessions.get(&session_id) {
                if let Ok(s) = session.lock() {
                    let peer_id: crate::circuit_breaker::PeerId = s.peer_node;
                    if !gate.can_send_to(peer_id) {
                        self.record_send_err(session_id);
                        return Err(TransportError::PeerNotInRoster {
                            peer_id,
                            session_id,
                        });
                    }
                }
            }
        }

        // Reject new sends if this session is undergoing graceful drain
        // and reject_new_sends is configured.
        if self.graceful_drain_config.reject_new_sends && self.is_session_draining(session_id) {
            self.record_send_err(session_id);
            return Err(TransportError::SessionInWrongState {
                session_id,
                expected: "not draining",
                actual: "draining",
            });
        }
        // Send-buffer admission with backpressure policy enforcement.
        let needed = payload.len() as u64;
        if let Some(session) = self.sessions.get(&session_id) {
            if let Ok(mut s) = session.lock() {
                if s.send_buffer.is_shutdown() {
                    self.record_send_err(session_id);
                    return Err(TransportError::SendBufferShutdown { session_id });
                }

                let policy = s.send_buffer_config().backpressure_policy;

                if s.send_buffer.remaining_capacity() < needed {
                    match policy {
                        BackpressurePolicy::Error => {
                            self.record_send_err(session_id);
                            return Err(TransportError::SendBufferFull {
                                session_id,
                                capacity: s.send_buffer.max_memory(),
                                needed,
                            });
                        }
                        BackpressurePolicy::Block => {
                            s.send_buffer_stats_mut()
                                .blocks
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            self.record_send_err(session_id);
                            return Err(TransportError::SendBufferFull {
                                session_id,
                                capacity: s.send_buffer.max_memory(),
                                needed,
                            });
                        }
                        BackpressurePolicy::DropOldest => {
                            // Evict oldest Data-plane messages from the priority
                            // queue until enough send-buffer capacity is freed.
                            let mut evicted = 0u64;
                            while s.send_buffer.remaining_capacity() < needed {
                                // Pop oldest Data message from priority queue.
                                let popped = s.pop_oldest_data_message();
                                match popped {
                                    Some(evicted_msg) => {
                                        let freed = evicted_msg.payload.len() as u64;
                                        s.send_buffer.drop_oldest();
                                        evicted += 1;
                                        tracing::warn!(
                                            session_id = %session_id,
                                            freed_bytes = freed,
                                            "send buffer full: evicting oldest Data message under DropOldest policy"
                                        );
                                    }
                                    None => {
                                        // No more Data messages to evict;
                                        // fall through to error.
                                        if evicted > 0 {
                                            s.send_buffer_stats_mut().rejected.fetch_add(
                                                evicted,
                                                std::sync::atomic::Ordering::Relaxed,
                                            );
                                        }
                                        self.record_send_err(session_id);
                                        return Err(TransportError::SendBufferFull {
                                            session_id,
                                            capacity: s.send_buffer.max_memory(),
                                            needed,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                self.record_send_err(session_id);
                return Err(TransportError::Generic("session lock poisoned".into()));
            }
        } else {
            self.record_send_err(session_id);
            return Err(TransportError::SessionNotFound { session_id });
        }

        // Enqueue the payload into the session's priority queue and track
        // bytes in the send buffer.
        if let Some(session) = self.sessions.get(&session_id) {
            if let Ok(mut s) = session.lock() {
                // Rolling upgrade gate: if peer did not negotiate priority
                // queuing, demote all messages to Data (FIFO) to avoid
                // head-of-line blocking from features the peer lacks.
                let priority = match &s.rollback_gate {
                    Some(gate)
                        if gate.forbids(
                            crate::rollback_compat::NodeFeatureFlags::PRIORITY_QUEUING,
                        ) =>
                    {
                        crate::message_priority::MessagePriority::Data
                    }
                    _ => priority,
                };
                s.message_priority_queue
                    .enqueue(QueuedMessage::new(payload.to_vec()), priority)
                    .map_err(|e| TransportError::Generic(format!("message priority queue: {e}")))?;
                // Track bytes in the send buffer.
                let _ = s.try_enqueue_send(bytes::Bytes::from(payload.to_vec()));
            }
        }

        // Drain the priority queue: Control messages first, then Data.
        let result = self.flush_priority_queue(session_id);
        if result.is_err() {
            self.record_send_err(session_id);
        }
        result
    }
    /// Send a message on an established session with explicit priority,
    /// returning a [`SendCancelHandle`] that the caller can use to discard
    /// the message before it reaches the wire.
    ///
    /// This is identical to [`send_priority`] except it returns a token
    /// instead of `()`. The message is enqueued into the session's
    /// per-priority sub-queues and immediately flushed (unless batching
    /// is enabled).
    ///
    /// Call [`cancel_message`] (or [`SendCancelHandle::cancel`]) with the
    /// returned token to discard the message before it is sent. After the
    /// message has been dequeued and written to the wire, `cancel` returns
    /// `false`.
    pub fn send_with_cancel(
        &mut self,
        session_id: SessionId,
        payload: &[u8],
        priority: MessagePriority,
    ) -> Result<SendCancelHandle, TransportError> {
        #[cfg(feature = "tdma")]
        if let Some(ref gate) = self.tdma_gate {
            gate.check_transmit_window(session_id)?;
        }

        // Outbound membership roster send-gate.
        if let Some(ref gate) = self.send_gate {
            if let Some(session) = self.sessions.get(&session_id) {
                if let Ok(s) = session.lock() {
                    let peer_id: crate::circuit_breaker::PeerId = s.peer_node;
                    if !gate.can_send_to(peer_id) {
                        self.record_send_err(session_id);
                        return Err(TransportError::PeerNotInRoster {
                            peer_id,
                            session_id,
                        });
                    }
                }
            }
        }

        // Reject new sends if this session is undergoing graceful drain.
        if self.graceful_drain_config.reject_new_sends && self.is_session_draining(session_id) {
            self.record_send_err(session_id);
            return Err(TransportError::SessionInWrongState {
                session_id,
                expected: "not draining",
                actual: "draining",
            });
        }

        // Send-buffer admission with backpressure.
        let needed = payload.len() as u64;
        if let Some(session) = self.sessions.get(&session_id) {
            if let Ok(mut s) = session.lock() {
                if s.send_buffer.is_shutdown() {
                    self.record_send_err(session_id);
                    return Err(TransportError::SendBufferShutdown { session_id });
                }

                let policy = s.send_buffer_config().backpressure_policy;

                if s.send_buffer.remaining_capacity() < needed {
                    match policy {
                        BackpressurePolicy::Error => {
                            self.record_send_err(session_id);
                            return Err(TransportError::SendBufferFull {
                                session_id,
                                capacity: s.send_buffer.max_memory(),
                                needed,
                            });
                        }
                        BackpressurePolicy::Block => {
                            s.send_buffer_stats_mut()
                                .blocks
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            self.record_send_err(session_id);
                            return Err(TransportError::SendBufferFull {
                                session_id,
                                capacity: s.send_buffer.max_memory(),
                                needed,
                            });
                        }
                        BackpressurePolicy::DropOldest => {
                            let mut evicted = 0u64;
                            while s.send_buffer.remaining_capacity() < needed {
                                let popped = s.pop_oldest_data_message();
                                match popped {
                                    Some(evicted_msg) => {
                                        let freed = evicted_msg.payload.len() as u64;
                                        s.send_buffer.drop_oldest();
                                        evicted += 1;
                                        tracing::warn!(
                                            session_id = %session_id,
                                            freed_bytes = freed,
                                            "send buffer full: evicting oldest Data message under DropOldest policy"
                                        );
                                    }
                                    None => {
                                        if evicted > 0 {
                                            s.send_buffer_stats_mut().rejected.fetch_add(
                                                evicted,
                                                std::sync::atomic::Ordering::Relaxed,
                                            );
                                        }
                                        self.record_send_err(session_id);
                                        return Err(TransportError::SendBufferFull {
                                            session_id,
                                            capacity: s.send_buffer.max_memory(),
                                            needed,
                                        });
                                    }
                                }
                            }
                            let _ = evicted;
                        }
                    }
                }
            } else {
                return Err(TransportError::Generic("session lock poisoned".into()));
            }
        } else {
            return Err(TransportError::Generic(format!(
                "no session for session_id {session_id}"
            )));
        }

        // Enqueue as a cancelable message and return the token.
        let token = {
            if let Some(session) = self.sessions.get(&session_id) {
                if let Ok(mut s) = session.lock() {
                    let (qmsg, token) = QueuedMessage::new_cancelable(payload.to_vec());
                    s.message_priority_queue
                        .enqueue(qmsg, priority)
                        .map_err(|e| {
                            TransportError::Generic(format!("message priority queue: {e}"))
                        })?;
                    let _ = s.try_enqueue_send(bytes::Bytes::from(payload.to_vec()));
                    token
                } else {
                    return Err(TransportError::Generic("session lock poisoned".into()));
                }
            } else {
                return Err(TransportError::Generic(format!(
                    "no session for session_id {session_id}"
                )));
            }
        };

        // Drain the priority queue.
        let result = self.flush_priority_queue(session_id);
        if result.is_err() {
            self.record_send_err(session_id);
        }
        Ok(token)
    }

    /// Cancel a previously queued outbound message.
    ///
    /// Returns `true` if the message was still queued and has been discarded.
    /// Returns `false` if the message was already sent, already cancelled, or
    /// the token does not refer to a known message.
    ///
    /// This is a convenience wrapper around [`SendCancelHandle::cancel`].
    /// Callers may also call `token.cancel()` directly without going through
    /// `Transport`.
    pub fn cancel_message(&self, token: &SendCancelHandle) -> bool {
        token.cancel()
    }

    /// Enqueue a message for batched send on an established session.
    ///
    /// When batch is enabled on the session (via
    /// [`Session::configure_batching`]), the message is enqueued into
    /// the session's priority queue but is **not** immediately flushed.
    /// Call [`flush_batches`](Self::flush_batches) to drain accumulated
    /// messages through the batch coalescer onto the wire.
    ///
    /// When batching is disabled (default), this falls through to
    /// [`send_priority`](Self::send_priority) for immediate delivery.
    pub fn batched_send(
        &mut self,
        session_id: SessionId,
        payload: &[u8],
        priority: MessagePriority,
    ) -> Result<(), TransportError> {
        #[cfg(feature = "tdma")]
        if let Some(ref gate) = self.tdma_gate {
            gate.check_transmit_window(session_id)?;
        }

        // Check whether batching is enabled on this session.
        let batching_enabled = {
            if let Some(session) = self.sessions.get(&session_id) {
                if let Ok(s) = session.lock() {
                    s.batch_config.enabled
                } else {
                    false
                }
            } else {
                return Err(TransportError::Generic(format!(
                    "no session for session_id {session_id}"
                )));
            }
        };

        if !batching_enabled {
            // Fall through to immediate send.
            return self.send_priority(session_id, payload, priority);
        }

        // Send-buffer admission check.
        {
            if let Some(session) = self.sessions.get(&session_id) {
                if let Ok(s) = session.lock() {
                    let needed = payload.len() as u64;
                    if s.send_buffer.remaining_capacity() < needed {
                        if s.send_buffer.is_shutdown() {
                            return Err(TransportError::SendBufferShutdown { session_id });
                        }
                        return Err(TransportError::SendBufferFull {
                            session_id,
                            capacity: s.send_buffer.max_memory(),
                            needed,
                        });
                    }
                }
            }
        }

        // Enqueue into the session's priority queue (preserves Control/Data
        // ordering), but do NOT flush — batching accumulates messages.
        {
            if let Some(session) = self.sessions.get(&session_id) {
                if let Ok(mut s) = session.lock() {
                    // Rolling upgrade gate: if peer did not negotiate priority
                    // queuing, demote all messages to Data (FIFO) to avoid
                    // head-of-line blocking from features the peer lacks.
                    let priority = match &s.rollback_gate {
                        Some(gate)
                            if gate.forbids(
                                crate::rollback_compat::NodeFeatureFlags::PRIORITY_QUEUING,
                            ) =>
                        {
                            crate::message_priority::MessagePriority::Data
                        }
                        _ => priority,
                    };
                    s.message_priority_queue
                        .enqueue(QueuedMessage::new(payload.to_vec()), priority)
                        .map_err(|e| {
                            TransportError::Generic(format!("message priority queue: {e}"))
                        })?;
                }
            }
        }

        Ok(())
    }

    /// Flush accumulated batches for a session.
    ///
    /// Drains the session's priority queue through the message batcher
    /// and writes each resulting batch as a single wire frame.
    /// Call this periodically (e.g., from a background tick) or explicitly
    /// before session teardown / epoch transitions to ensure queued
    /// messages are delivered.
    ///
    /// When batching is disabled this is a no-op (the priority queue is
    /// already drained by each [`send_priority`] call).
    pub fn flush_batches(&mut self, session_id: SessionId) -> Result<(), TransportError> {
        // Phase 1: drain priority queue through batcher under the lock,
        // collecting any triggered batches.
        let batches: Vec<crate::message_batcher::MessageBatch> = {
            if let Some(session) = self.sessions.get(&session_id) {
                if let Ok(mut s) = session.lock() {
                    if !s.batch_config.enabled {
                        return Ok(());
                    }

                    let peer = s.peer_node;

                    // Drain priority queue (Control-first ordering preserved).
                    // Skip entries whose cancellation token has been marked cancelled.
                    let mut msgs = Vec::new();
                    while let Some(qmsg) = s.message_priority_queue.dequeue() {
                        if !qmsg.mark_sent() {
                            continue;
                        }
                        msgs.push(qmsg.payload);
                    }

                    // Feed each message through the batcher.
                    let mut collected = Vec::new();
                    for msg in msgs {
                        if let Some(batch) = s.message_batcher.enqueue(peer, msg) {
                            collected.push(batch);
                        }
                    }

                    // Drain deadline-based batches still in the batcher.
                    collected.extend(s.message_batcher.drain_ready().into_iter().map(|(_, b)| b));

                    collected
                } else {
                    return Err(TransportError::Generic("session lock poisoned".into()));
                }
            } else {
                return Err(TransportError::Generic(format!(
                    "no session for session_id {session_id}"
                )));
            }
        };

        // Phase 2: write all batches without holding the session lock.
        for batch in batches {
            let encoded = batch.encode();
            self.write_payload_to_session(session_id, &encoded, MessagePriority::Data)?;
        }

        Ok(())
    }

    /// Drain all pending messages from the session's priority queue,
    /// writing each through the payload-to-connection pipeline.
    ///
    /// Control messages are drained before Data messages (head-of-line
    /// bypass). This method is called automatically by [`send_priority`]
    /// and [`send_message`]; callers that enqueue messages externally
    /// (e.g., via direct queue access) can call this to flush.
    fn flush_priority_queue(&mut self, session_id: SessionId) -> Result<(), TransportError> {
        // Collect all pending messages from the priority queue (Control first).
        // Collect all pending messages from the priority queue (Control first).
        // Skip any entries whose cancellation token has been marked cancelled.
        let messages: Vec<(Vec<u8>, MessagePriority)> = {
            if let Some(session) = self.sessions.get(&session_id) {
                if let Ok(mut s) = session.lock() {
                    let mut msgs = Vec::new();
                    while let Some((qmsg, pri)) = s.message_priority_queue.dequeue_with_priority() {
                        // Check cancellation before sending — if cancelled, skip.
                        if !qmsg.mark_sent() {
                            continue;
                        }
                        msgs.push((qmsg.payload, pri));
                    }
                    msgs
                } else {
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        };

        for (msg, pri) in &messages {
            self.write_payload_to_session(session_id, msg, *pri)?;
        }

        // Release send-buffer capacity for all written messages.
        if let Some(session) = self.sessions.get(&session_id) {
            if let Ok(mut s) = session.lock() {
                for _ in &messages {
                    let _ = s.dequeue_send();
                }
            }
        }

        Ok(())
    }

    /// Write a single payload to the session's active connection,
    /// applying epoch-barrier stamping, fragmentation, HLC advancement,
    /// and encryption.
    fn write_payload_to_session(
        &mut self,
        session_id: SessionId,
        payload: &[u8],
        priority: MessagePriority,
    ) -> Result<(), TransportError> {
        // Send-concurrency gate: acquire a non-blocking permit before
        // writing to the wire. When the in-flight limit is reached,
        // the send is rejected with SendConcurrencyLimitExceeded.
        // This closes B5 (Transport Flow Control Not Wired).
        let _send_permit = if let Some(ref limiter) = self.send_concurrency {
            match limiter.try_acquire() {
                Ok(permit) => Some(permit),
                Err(crate::send_concurrency::SendConcurrencyError::LimitExceeded { max }) => {
                    self.record_send_err(session_id);
                    return Err(TransportError::SendConcurrencyLimitExceeded { max, session_id });
                }
                Err(_) => {
                    // Shutdown or ConnectionNotSendable — permit not available.
                    // Treat as exceeded for simplicity.
                    self.record_send_err(session_id);
                    return Err(TransportError::SendConcurrencyLimitExceeded {
                        max: 0,
                        session_id,
                    });
                }
            }
        } else {
            None
        };

        // Per-session compression: compress payload before wire transforms.
        // Compression sits above epoch-barrier stamping, fragmentation, and
        // encryption so that all downstream transforms operate on compressed
        // bytes.
        let compressed_payload;
        let payload: &[u8] = if let Some(session) = self.sessions.get(&session_id) {
            if let Ok(mut s) = session.lock() {
                compressed_payload = s.compress_outbound(payload);
                &compressed_payload
            } else {
                payload
            }
        } else {
            payload
        };

        // Epoch-barrier stamping: wrap payload with epoch + seq + BLAKE3 digest.
        let stamped_payload;
        let payload: &[u8] = if let Some(ref mut barrier) = self.epoch_barrier {
            let stamped = barrier.stamp(payload.to_vec());
            stamped_payload = stamped.encode();
            &stamped_payload
        } else {
            payload
        };

        // If payload exceeds MTU, fragment and send each fragment.
        if payload.len() > self.mtu {
            let msg_id = self.fragment_reassembler.next_message_id();
            let fragments = fragment_message(msg_id, payload, self.mtu, 0);
            let conn = self
                .active_connections
                .get_mut(&session_id)
                .ok_or_else(|| {
                    TransportError::Generic(format!(
                        "no active connection for session {session_id}"
                    ))
                })?;
            // Advance session HLC once per logical message.
            if let Some(session) = self.sessions.get(&session_id) {
                if let Ok(mut s) = session.lock() {
                    s.on_send(payload.len() as u64, priority);
                }
            }
            for frag in &fragments {
                conn.write_frame(frag)?;
            }
            return Ok(());
        }

        let conn = self
            .active_connections
            .get_mut(&session_id)
            .ok_or_else(|| {
                TransportError::Generic(format!("no active connection for session {session_id}"))
            })?;

        // Advance session HLC on send.
        if let Some(session) = self.sessions.get(&session_id) {
            if let Ok(mut s) = session.lock() {
                s.on_send(payload.len() as u64, priority);
            }
        }

        // Per-session ChaCha20-Poly1305 encryption.
        let has_ciphers = self
            .sessions
            .get(&session_id)
            .and_then(|s| s.lock().ok().map(|s| s.has_ciphers()))
            .unwrap_or(false);

        if has_ciphers {
            let encrypted = self
                .sessions
                .get(&session_id)
                .and_then(|s| s.lock().ok())
                .and_then(|mut s| s.seal_message(payload).ok())
                .ok_or_else(|| TransportError::Generic("encryption failed".into()))?;

            conn.write_frame(&encrypted)
        } else {
            conn.write_frame(payload)
        }
    }

    /// Receive a message frame on an established session.
    ///
    /// When non-blocking I/O is enabled (via [`Self::set_nonblocking`]),
    /// returns [`TransportError::WouldBlock`] if no data is available.
    ///
    /// If the received frame is a fragment (identified by the `VFRG` magic),
    /// or if a fragment reassembly is already in progress, this method
    /// reads additional frames until the reassembled message is complete
    /// or a [`TransportError::WouldBlock`] occurs. Fragmentation is
    /// transparent to callers — a fragmented message is reassembled
    /// before being returned.
    fn recv_message_inner(&mut self, session_id: SessionId) -> Result<Vec<u8>, TransportError> {
        let conn = self
            .active_connections
            .get_mut(&session_id)
            .ok_or_else(|| {
                TransportError::Generic(format!("no active connection for session {session_id}"))
            })?;

        // If a fragment reassembly is in progress, continue reading
        // fragments rather than starting a new top-level frame.
        if self.fragment_reassembler.pending_count() > 0 {
            return self.recv_fragment_loop(session_id);
        }

        let raw_frame = conn.read_frame()?;

        match self.decode_received_frame(session_id, raw_frame)? {
            Some(payload) => Ok(payload),
            None => self.recv_fragment_loop(session_id),
        }
    }

    /// Decode one raw connection frame for an already established session.
    ///
    /// This is used by servers that need to read from the underlying connection
    /// outside a shared transport mutex, then re-enter the transport only for
    /// session accounting and payload transforms.
    pub fn decode_received_frame(
        &mut self,
        session_id: SessionId,
        raw_frame: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        if is_fragment(&raw_frame) {
            let (header, frag_payload) = decode_fragment(&raw_frame)
                .map_err(|e| TransportError::Generic(format!("fragment decode: {e}")))?;

            if let Some(session) = self.sessions.get(&session_id) {
                if let Ok(mut s) = session.lock() {
                    s.on_recv(None, raw_frame.len() as u64, None);
                }
            }

            let maybe_complete = self
                .fragment_reassembler
                .feed(&header, frag_payload)
                .map_err(|e| TransportError::Generic(format!("fragment reassembly: {e}")))?;

            return match maybe_complete {
                Some(reassembled) => {
                    let unwrapped = self.apply_epoch_barrier_recv(reassembled)?;
                    Ok(Some(
                        self.decompress_received_payload(session_id, unwrapped)?,
                    ))
                }
                None => {
                    self.fragment_reassembler.evict_expired();
                    Ok(None)
                }
            };
        }

        if let Some(session) = self.sessions.get(&session_id) {
            if let Ok(mut s) = session.lock() {
                s.on_recv(None, raw_frame.len() as u64, None);
            }
        }

        let has_ciphers = self
            .sessions
            .get(&session_id)
            .and_then(|s| s.lock().ok().map(|s| s.has_ciphers()))
            .unwrap_or(false);

        let frame = if has_ciphers {
            self.sessions
                .get(&session_id)
                .and_then(|s| s.lock().ok())
                .and_then(|mut s| s.open_message(&raw_frame).ok())
                .unwrap_or(raw_frame)
        } else {
            raw_frame
        };

        let unwrapped = self.apply_epoch_barrier_recv(frame)?;
        Ok(Some(
            self.decompress_received_payload(session_id, unwrapped)?,
        ))
    }

    fn decompress_received_payload(
        &mut self,
        session_id: SessionId,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, TransportError> {
        if let Some(session) = self.sessions.get(&session_id) {
            if let Ok(mut s) = session.lock() {
                return s
                    .decompress_inbound(&payload)
                    .map_err(|e| TransportError::Generic(format!("decompression failed: {e}")));
            }
        }
        Ok(payload)
    }

    /// Receive a message frame on an established session.
    ///
    /// Record receive errors on the session statistics before propagating.
    pub fn recv_message(&mut self, session_id: SessionId) -> Result<Vec<u8>, TransportError> {
        let result = self.recv_message_inner(session_id);
        if result.is_err() {
            self.record_recv_err(session_id);
        }
        result
    }

    /// Apply the epoch barrier to a received raw message payload.
    /// If no barrier is configured, passes through unchanged.
    fn apply_epoch_barrier_recv(&mut self, raw: Vec<u8>) -> Result<Vec<u8>, TransportError> {
        if let Some(ref mut barrier) = self.epoch_barrier {
            match barrier.verify_raw_and_unwrap(&raw) {
                Ok(Some(payload)) => Ok(payload),
                Ok(None) => Ok(Vec::new()),
                Err(e) => Err(TransportError::Generic(format!("epoch barrier: {e}"))),
            }
        } else {
            Ok(raw)
        }
    }
    /// Send a typed envelope and payload on an established session.
    /// Internal helper: continue reading fragments until reassembly completes.
    ///
    /// When non-blocking I/O is enabled, returns [`TransportError::WouldBlock`]
    /// if the next fragment has not arrived yet. The caller must retry
    /// `recv_message` to resume reassembly.
    fn recv_fragment_loop(&mut self, session_id: SessionId) -> Result<Vec<u8>, TransportError> {
        let conn = self
            .active_connections
            .get_mut(&session_id)
            .ok_or_else(|| {
                TransportError::Generic(format!("no active connection for session {session_id}"))
            })?;

        loop {
            // Check if reassembly completed from a previously-fed fragment
            if self.fragment_reassembler.pending_count() == 0 {
                // Should not happen — caller checks before entering loop
                return Err(TransportError::Generic(
                    "fragment loop entered with no pending reassembly".into(),
                ));
            }

            // Try to read the next fragment frame
            let next_frame = match conn.read_frame() {
                Ok(frame) => frame,
                Err(TransportError::WouldBlock(_)) => {
                    return Err(TransportError::WouldBlock(
                        "waiting for next fragment".into(),
                    ));
                }
                Err(e) => return Err(e),
            };

            if !is_fragment(&next_frame) {
                return Err(TransportError::Generic(
                    "expected fragment, got non-fragment frame during reassembly".into(),
                ));
            }

            let (next_header, next_payload) = decode_fragment(&next_frame)
                .map_err(|e| TransportError::Generic(format!("fragment decode: {e}")))?;

            // Advance session HLC on receive (once per fragment)
            if let Some(session) = self.sessions.get(&session_id) {
                if let Ok(mut s) = session.lock() {
                    s.on_recv(None, next_frame.len() as u64, None);
                }
            }

            let maybe_complete = self
                .fragment_reassembler
                .feed(&next_header, next_payload)
                .map_err(|e| TransportError::Generic(format!("fragment reassembly: {e}")))?;

            match maybe_complete {
                Some(reassembled) => {
                    let unwrapped = self.apply_epoch_barrier_recv(reassembled)?;
                    // Per-session decompression for reassembled fragmented messages.
                    if let Some(session) = self.sessions.get(&session_id) {
                        if let Ok(mut s) = session.lock() {
                            return s.decompress_inbound(&unwrapped).map_err(|e| {
                                TransportError::Generic(format!(
                                    "decompression failed after reassembly: {e}"
                                ))
                            });
                        }
                    }
                    return Ok(unwrapped);
                }
                None => {
                    self.fragment_reassembler.evict_expired();
                    // Loop around to read the next fragment
                }
            }
        }
    }

    /// The envelope is encoded into a binary frame and transmitted.
    pub fn send_envelope(
        &mut self,

        envelope: &mut crate::envelope::TransportEnvelope,

        payload: &[u8],
    ) -> Result<(), TransportError> {
        let frame = envelope.encode(payload);

        let conn = self
            .active_connections
            .get_mut(&envelope.session_id)
            .ok_or_else(|| {
                TransportError::Generic(format!(
                    "no active connection for session {}",
                    envelope.session_id
                ))
            })?;

        conn.write_frame(&frame)
    }

    /// Receive a typed envelope and payload on an established session.
    ///
    /// Decodes the binary frame into a `TransportEnvelope` and its payload.
    /// When non-blocking I/O is enabled (via [`Self::set_nonblocking`]),
    /// returns [`TransportError::WouldBlock`] if no data is available.
    pub fn recv_envelope(
        &mut self,

        session_id: SessionId,
    ) -> Result<(crate::envelope::TransportEnvelope, Vec<u8>), TransportError> {
        let conn = self
            .active_connections
            .get_mut(&session_id)
            .ok_or_else(|| {
                TransportError::Generic(format!("no active connection for session {session_id}"))
            })?;

        let frame = conn.read_frame()?;

        crate::envelope::TransportEnvelope::decode(&frame)
            .map_err(|e| TransportError::Generic(format!("envelope decode failed: {e}")))
    }

    /// Return a [`SendCapacity`] handle for the Data lane of a given session.
    ///
    /// This provides external consumers (e.g. rebuild throttle,
    /// background scrub) with a transport backpressure signal they can
    /// use to yield when foreground I/O is congested.
    ///
    /// Returns `None` if the session is not found or has no capacity set
    /// configured.
    #[must_use]
    pub fn session_data_lane_capacity(&self, session_id: SessionId) -> Option<SendCapacity> {
        self.sessions
            .get(&session_id)
            .and_then(|s| s.lock().ok())
            .and_then(|guard| guard.data_lane_capacity())
    }

    /// Store a session drain handle keyed by session ID.
    ///
    /// The handle is later drained in [`close_session`](Self::close_session)
    /// when the close reason is [`SessionCloseReason::PeerRemoved`].
    pub fn set_session_drain_handle(
        &mut self,
        session_id: SessionId,
        handle: Arc<crate::session_drain::SessionDrainHandle>,
    ) {
        self.session_drain_handles.insert(session_id, handle);
    }

    /// Remove and return the drain handle for a session, if present.
    ///
    /// The caller is responsible for draining the handle if the session
    /// is being evicted.
    pub fn take_session_drain_handle(
        &mut self,
        session_id: SessionId,
    ) -> Option<Arc<crate::session_drain::SessionDrainHandle>> {
        self.session_drain_handles.remove(&session_id)
    }

    /// Return a reference to the drain handle for a session, if present.
    #[must_use]
    pub fn session_drain_handle(
        &self,
        session_id: SessionId,
    ) -> Option<&Arc<crate::session_drain::SessionDrainHandle>> {
        self.session_drain_handles.get(&session_id)
    }

    /// Return the authoritative close receipt for a session, if one exists.
    #[must_use]
    pub fn session_closure_receipt(
        &self,
        session_id: SessionId,
    ) -> Option<&TransportClosureReceipt> {
        self.session_closure_receipts.get(&session_id)
    }

    /// Return all authoritative close receipts recorded by this transport.
    #[must_use]
    pub fn session_closure_receipts(&self) -> &BTreeMap<SessionId, TransportClosureReceipt> {
        &self.session_closure_receipts
    }

    fn record_session_closure_receipt(
        &mut self,
        session_id: SessionId,
        reason: SessionCloseReason,
        last_seq_acked: u64,
        drain_result_class: DrainResultClass,
    ) -> &TransportClosureReceipt {
        let receipt = Self::build_session_closure_receipt(
            session_id,
            reason,
            last_seq_acked,
            drain_result_class,
        );
        self.session_closure_receipts
            .entry(session_id)
            .or_insert(receipt)
    }

    fn build_session_closure_receipt(
        session_id: SessionId,
        reason: SessionCloseReason,
        last_seq_acked: u64,
        drain_result_class: DrainResultClass,
    ) -> TransportClosureReceipt {
        let digest = Self::session_closure_receipt_digest(
            session_id,
            reason,
            last_seq_acked,
            drain_result_class,
        );
        TransportClosureReceipt {
            receipt_id: TransportClosureReceiptId::new(digest),
            session_ref: TransportSessionId::new(session_id.0),
            closure_class: reason.closure_class(),
            trigger_ref: reason.trigger_ref(),
            last_seq_acked,
            drain_result_class,
            successor_session_ref: None,
            preserved_artifact_refs: Vec::new(),
            digest,
        }
    }

    fn session_closure_receipt_digest(
        session_id: SessionId,
        reason: SessionCloseReason,
        last_seq_acked: u64,
        drain_result_class: DrainResultClass,
    ) -> u64 {
        let model_reason = reason.to_type_model() as u32;
        let closure_class = reason.closure_class() as u32;
        let drain_result_class = drain_result_class as u32;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tidefs.transport.session.close_receipt.v1");
        hasher.update(&session_id.0.to_le_bytes());
        hasher.update(&model_reason.to_le_bytes());
        hasher.update(&closure_class.to_le_bytes());
        hasher.update(&drain_result_class.to_le_bytes());
        hasher.update(&last_seq_acked.to_le_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest.as_bytes()[..8]);
        u64::from_le_bytes(bytes)
    }

    /// Drain the per-session drain handle for a session being evicted.
    ///
    /// This resolves all pending [`DrainToken`](crate::session_drain::DrainToken)s
    /// with the given error and rejects new tracked sends.  Called by the
    /// membership layer when [`SessionPolicy::Drain`] is issued for a peer
    /// before the eventual [`close_session`](Self::close_session) teardown.
    ///
    /// Returns the drained handle if one was registered for this session,
    /// or `None` if no handle was attached.
    pub fn drain_session(
        &mut self,
        session_id: SessionId,
        error: crate::session_drain::DrainError,
    ) -> Option<Arc<crate::session_drain::SessionDrainHandle>> {
        // Fail all pending response-tracked requests so callers unblock
        // promptly when the session is being drained before eviction.
        if let Some(session) = self.sessions.get(&session_id) {
            if let Ok(s) = session.lock() {
                let rt = s.response_tracker.clone();
                drop(s);
                if let Some(ref tracker) = rt {
                    let tracker = tracker.clone();
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        handle.spawn(async move {
                            tracker.fail_all_pending().await;
                        });
                    }
                }
            }
        }

        let dh = self.session_drain_handles.remove(&session_id)?;
        dh.drain(error);
        Some(dh)
    }

    /// Gracefully drain a session: flush all queued outbound messages
    /// before closing, bounded by the configured deadline.
    ///
    /// On return, the priority queue is either empty ([`DrainOutcome::Completed`])
    /// or the deadline expired with messages remaining
    /// ([`DrainOutcome::DeadlineExpired`]).
    ///
    /// Returns [`DrainOutcome::AlreadyClosed`] immediately if the session is
    /// already in `Closed` state.
    ///
    /// While draining, if [`GracefulDrainConfig::reject_new_sends`] is `true`,
    /// new sends to this session return an error.  Callers can check
    /// [`is_session_draining`](Self::is_session_draining) before sending.
    pub fn drain_session_gracefully(
        &mut self,
        session_id: SessionId,
    ) -> Result<crate::session_drain::DrainOutcome, TransportError> {
        use crate::session_drain::DrainOutcome;

        // Check if session exists and is not already closed.
        let session = self
            .sessions
            .get(&session_id)
            .cloned()
            .ok_or(TransportError::SessionNotFound { session_id })?;

        {
            let s = session
                .lock()
                .map_err(|e| TransportError::Generic(format!("session lock poisoned: {e}")))?;
            if s.is_closed() {
                let reason = match &s.state {
                    SessionState::Closed { reason } => *reason,
                    _ => unreachable!("is_closed returned true for a non-closed state"),
                };
                let last_seq_acked = s.last_recv_seq().0;
                drop(s);
                self.record_session_closure_receipt(
                    session_id,
                    reason,
                    last_seq_acked,
                    reason.drain_result_class(),
                );
                return Ok(DrainOutcome::AlreadyClosed);
            }
        }

        // Mark the session as draining.
        let deadline = std::time::Instant::now() + self.graceful_drain_config.deadline;
        self.draining_sessions.insert(session_id, deadline);

        // Capture initial dequeued count before polling so we report
        // accurate drained-message counts even when the I/O path flushes
        // messages between loop iterations.
        let initial_total = {
            let s = session
                .lock()
                .map_err(|e| TransportError::Generic(format!("session lock poisoned: {e}")))?;
            s.message_priority_queue.total_dequeued()
        };

        // Poll the priority queue until empty or deadline, releasing the
        // session lock between checks so the I/O path can flush queued messages.
        let poll_interval = self.graceful_drain_config.poll_interval;
        let (outcome, remaining) = {
            let mut remaining: u64;
            loop {
                remaining = {
                    let s = session.lock().map_err(|e| {
                        TransportError::Generic(format!("session lock poisoned: {e}"))
                    })?;
                    s.message_priority_queue.len() as u64
                };

                if remaining == 0 {
                    break (
                        DrainOutcome::Completed {
                            messages_drained: 0,
                        },
                        0,
                    );
                }

                if std::time::Instant::now() >= deadline {
                    break (
                        DrainOutcome::DeadlineExpired {
                            messages_remaining: remaining,
                        },
                        remaining,
                    );
                }

                std::thread::sleep(poll_interval.min(Duration::from_millis(1)));
            }
        };

        // Compute the accurate drained count from the pre-loop baseline.
        let outcome = if remaining == 0 {
            let final_total = {
                let s = session
                    .lock()
                    .map_err(|e| TransportError::Generic(format!("session lock poisoned: {e}")))?;
                s.message_priority_queue.total_dequeued()
            };
            let messages_drained = final_total.saturating_sub(initial_total);
            DrainOutcome::Completed { messages_drained }
        } else {
            outcome
        };
        // Always remove from draining set on exit.
        self.draining_sessions.remove(&session_id);

        match outcome {
            DrainOutcome::Completed { .. } => {
                if let Err(e) = self.close_session(session_id, SessionCloseReason::LocalShutdown) {
                    tracing::warn!(
                        session_id = %session_id,
                        error = %e,
                        "graceful drain completed but close_session failed"
                    );
                }
            }
            DrainOutcome::DeadlineExpired { .. } => {
                if let Err(e) = self.close_session_with_drain_result(
                    session_id,
                    SessionCloseReason::TransportError,
                    DrainResultClass::StalledTimeout,
                ) {
                    tracing::warn!(
                        session_id = %session_id,
                        error = %e,
                        "graceful drain deadline expired but close_session failed"
                    );
                }
            }
            DrainOutcome::AlreadyClosed => {}
        }

        Ok(outcome)
    }

    /// Return `true` if the session is currently undergoing a graceful drain.
    ///
    /// Callers can use this to decide whether to enqueue new sends or wait
    /// for the drain to complete.
    #[must_use]
    pub fn is_session_draining(&self, session_id: SessionId) -> bool {
        self.draining_sessions.contains_key(&session_id)
    }

    /// Drain all sessions to the given peer.
    ///
    /// Gathers every active, non-closed session where [`Session::peer_node`]
    /// matches `member_id`, initiates graceful drain on each, and returns a
    /// [`PeerDrainHandle`](crate::peer_drain_coordinator::PeerDrainHandle)
    /// that resolves when all sessions are drained or the deadline expires.
    ///
    /// Returns [`PeerDrainError::DrainAlreadyInProgress`] if a drain is already
    /// active for this peer.
    ///
    /// After the handle resolves, call
    /// [`PeerDrainCoordinator::finish_peer_drain`]
    /// to release the coordinator slot for this peer.
    pub fn drain_peer_sessions(
        &mut self,
        member_id: tidefs_membership_epoch::MemberId,
    ) -> Result<
        crate::peer_drain_coordinator::PeerDrainHandle,
        crate::peer_drain_coordinator::PeerDrainError,
    > {
        // Gather session IDs for this peer (active, not closed).

        let session_ids: Vec<SessionId> = self
            .sessions
            .iter()
            .filter_map(|(sid, s)| {
                let s = s.lock().ok()?;

                if s.peer_node == member_id.0 && !s.is_closed() {
                    Some(*sid)
                } else {
                    None
                }
            })
            .collect();

        let (handle, driver) = self.peer_drain_coordinator.begin_peer_drain(
            member_id,
            &session_ids,
            self.graceful_drain_config.deadline,
        )?;

        // Initiate graceful drain on each session and signal completion.

        for &sid in &session_ids {
            match self.drain_session_gracefully(sid) {
                Ok(_) => driver.complete_session(sid),

                Err(e) => {
                    tracing::warn!(

                        session_id = %sid,

                        error = %e,

                        "drain_peer_sessions: drain_session_gracefully failed for session; marking complete anyway"

                    );

                    driver.complete_session(sid);
                }
            }
        }

        Ok(handle)
    }

    /// Close a session and record its authoritative TFR-017 closure receipt.
    pub fn close_session(
        &mut self,
        session_id: SessionId,
        reason: SessionCloseReason,
    ) -> Result<(), TransportError> {
        self.close_session_with_drain_result(session_id, reason, reason.drain_result_class())
    }

    fn close_session_with_drain_result(
        &mut self,
        session_id: SessionId,
        reason: SessionCloseReason,
        drain_result_class: DrainResultClass,
    ) -> Result<(), TransportError> {
        // Drain pending tokens on eviction before touching session state.
        // Must happen first to avoid borrow conflicts with sessions.get().
        if reason == SessionCloseReason::PeerRemoved {
            self.drain_session(session_id, crate::session_drain::DrainError::Evicted);
        }

        let session = self
            .sessions
            .get(&session_id)
            .cloned()
            .ok_or(TransportError::SessionNotFound { session_id })?;

        let mut session = session
            .lock()
            .map_err(|e| TransportError::Generic(format!("session lock poisoned: {e}")))?;

        if session.is_closed() {
            let existing_reason = match &session.state {
                SessionState::Closed { reason } => *reason,
                _ => unreachable!("is_closed returned true for a non-closed state"),
            };
            let last_seq_acked = session.last_recv_seq().0;
            drop(session);
            self.record_session_closure_receipt(
                session_id,
                existing_reason,
                last_seq_acked,
                existing_reason.drain_result_class(),
            );
            return Ok(());
        }

        // RDMA carrier: if the backend is RDMA, log the degrade before closing.
        // The active connection close handles transport-level teardown;
        // memory-region deregistration is the caller's responsibility (pin law P4-04).
        if self.backend_kind.is_rdma() {
            tracing::warn!(
                "closing RDMA session {}: reason={:?}; RDMA memory regions must be
                 deregistered by the pin/loan owner per P4-04",
                session_id,
                reason
            );
        }
        // Close the active connection
        if let Some(mut conn) = self.active_connections.remove(&session_id) {
            conn.close();
        }

        // Abort the background timeout-reaping task so it doesn't leak
        // when the session is removed from the session map.
        session.abort_response_timeout_task();

        // Fail all pending response-tracked requests on session close so
        // callers unblock promptly instead of waiting for timeout expiry.
        if let Some(ref tracker) = session.response_tracker {
            let tracker = tracker.clone();
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    tracker.fail_all_pending().await;
                });
            }
        }

        session
            .transition(SessionState::Closed { reason })
            .map_err(|e| TransportError::Generic(e.to_string()))?;

        let peer_node = session.peer_node;
        let last_seq_acked = session.last_recv_seq().0;
        drop(session);

        self.record_session_closure_receipt(session_id, reason, last_seq_acked, drain_result_class);

        // Consult the session reconnector on transport-level failures.
        // Transient failures (network blips, peer restart) should trigger
        // automatic reconnection with exponential backoff rather than
        // immediate escalation to membership unreachability.
        if let Some(ref reconnector) = self.session_reconnector {
            let should_reconnect = matches!(
                reason,
                SessionCloseReason::TransportError | SessionCloseReason::RdmaCarrierLost
            );
            if should_reconnect {
                let member_id = tidefs_membership_epoch::MemberId::new(peer_node);
                let action = reconnector.on_session_failed(member_id);
                match action {
                    crate::session_reconnector::ReconnectAction::ReconnectAfter {
                        delay,
                        attempt,
                    } => {
                        tracing::info!(
                            "session {} (peer {}): scheduling reconnect attempt {} after {:?}",
                            session_id,
                            peer_node,
                            attempt,
                            delay
                        );
                    }
                    crate::session_reconnector::ReconnectAction::PermanentFailure {
                        reason: fail_reason,
                    } => {
                        tracing::warn!(
                            "session {} (peer {}): reconnection permanently failed: {}",
                            session_id,
                            peer_node,
                            fail_reason
                        );
                    }
                }
            }
        }

        // Advance the connect lifecycle to Ready now that the session is
        // fully established and can carry messages.
        if let Some(lifecycle) = self.connect_lifecycles.get_mut(&session_id) {
            let _ = lifecycle.transition(SessionLifecycle::Ready, Instant::now());
        }

        // Transition the connect lifecycle to Dead on session close.
        if let Some(lifecycle) = self.connect_lifecycles.get_mut(&session_id) {
            lifecycle.force_dead();
        }

        Ok(())
    }

    /// Reconnect a session after connection loss.
    pub fn reconnect(&mut self, session_id: SessionId) -> Result<(), TransportError> {
        let session = self
            .sessions
            .get(&session_id)
            .cloned()
            .ok_or(TransportError::SessionNotFound { session_id })?;

        let mut session = session
            .lock()
            .map_err(|e| TransportError::Generic(format!("session lock poisoned: {e}")))?;

        let backoff = session.reconnect.next_backoff();
        let attempt = session.reconnect.attempt;

        if session.reconnect.is_exhausted() {
            // Notify the membership layer that the peer is unreachable
            // so it can trigger automated departure via LeaveCoordinator.
            let peer_node = session.peer_node;
            drop(session);
            if let Some(ref cb) = self.unreachable_peer_callback {
                cb.on_peer_unreachable(peer_node);
            }
            return Err(TransportError::Generic(format!(
                "session {session_id}: reconnection exhausted after {attempt} attempts"
            )));
        }

        // When the RDMA carrier is permanently lost and we are still on
        // an RDMA backend, attempt TCP fallback immediately (do not wait
        // for the attempt >= 3 threshold).  This avoids useless RDMA
        // reconnect attempts while still providing a recovery path.
        if session.is_carrier_lost() && self.backend_kind.is_rdma() {
            let peer_node = session.peer_node;
            self.check_runtime_rdma_fallback_policy(
                session_id,
                peer_node,
                RDMA_RUNTIME_FALLBACK_PERMANENT_LOSS,
                RDMA_RUNTIME_FALLBACK_PERMANENT_LOSS_REFUSED,
            )?;
            session
                .handle_rdma_degraded(RDMA_RUNTIME_FALLBACK_PERMANENT_LOSS)
                .map_err(|e| TransportError::Generic(e.to_string()))?;
            session.fallback_to_tcp();

            // Record the carrier fallback disclosure for operator observability.
            // This ensures the runtime validation never claims RDMA when TCP
            // fallback has occurred (per OW-308).
            {
                let peer_node = session.peer_node;
                let disclosure = CarrierDisclosure::from_runtime_fallback(
                    TransportBackendKind::Rdma,
                    RDMA_RUNTIME_FALLBACK_PERMANENT_LOSS,
                    self.carrier_policy,
                );
                tracing::info!(peer = peer_node, "{}", disclosure);
                self.carrier_disclosures.insert(peer_node, disclosure);
            }

            tracing::warn!(
                session_id = %session_id,
                attempt = %session.reconnect.attempt,
                "RDMA carrier permanently lost; falling back to TCP per OW-308"
            );

            // Reset attempt counter and proceed with TCP reconnection.
            session.reconnect.reset();
            let backoff = session.reconnect.next_backoff();
            let attempt = session.reconnect.attempt;

            session
                .transition(SessionState::Reconnecting {
                    attempt,
                    since: HlcTimestamp::default(),
                    backoff,
                })
                .map_err(|e| TransportError::Generic(e.to_string()))?;

            session
                .transition(SessionState::Connecting {
                    started_at: HlcTimestamp::default(),
                })
                .map_err(|e| TransportError::Generic(e.to_string()))?;

            session
                .transition(SessionState::Handshaking {
                    started_at: HlcTimestamp::default(),
                })
                .map_err(|e| TransportError::Generic(e.to_string()))?;

            session
                .transition(SessionState::Established {
                    since: HlcTimestamp::default(),
                })
                .map_err(|e| TransportError::Generic(e.to_string()))?;

            tracing::info!(
                session_id = %session_id,
                "RDMA session re-established via TCP fallback after permanent carrier loss"
            );
            return Ok(());
        }

        // Reconnect gate: refuse reconnection for any carrier-lost session
        // per P8-01 resume law §7 (carrier_lost on an RDMA backend blocks reconnects; TCP fallback clears carrier_lost, allowing normal TCP reconnection).
        if session.is_carrier_lost() && self.backend_kind.is_rdma() {
            let reason = format!(
                "session {session_id}: carrier lost on RDMA backend, reconnection refused (TCP fallback required)"
            );
            tracing::error!("reconnect gate refused: {reason}");
            return Err(TransportError::Generic(reason));
        }

        // RDMA carrier: if the backend is RDMA and reconnection has exceeded
        // a threshold, degrade the RDMA carrier and attempt TCP fallback
        // per OW-308. The session must be in Established state for degradation.
        if self.backend_kind.is_rdma() && session.reconnect.attempt >= 3 {
            let peer_node = session.peer_node;
            self.check_runtime_rdma_fallback_policy(
                session_id,
                peer_node,
                RDMA_RUNTIME_FALLBACK_RECONNECT_EXHAUSTED,
                RDMA_RUNTIME_FALLBACK_RECONNECT_EXHAUSTED_REFUSED,
            )?;
            session
                .handle_rdma_degraded(RDMA_RUNTIME_FALLBACK_RECONNECT_EXHAUSTED)
                .map_err(|e| TransportError::Generic(e.to_string()))?;
            session.fallback_to_tcp();

            // Record the carrier fallback disclosure for operator observability
            // (per OW-308).
            {
                let peer_node = session.peer_node;
                let disclosure = CarrierDisclosure::from_runtime_fallback(
                    TransportBackendKind::Rdma,
                    RDMA_RUNTIME_FALLBACK_RECONNECT_EXHAUSTED,
                    self.carrier_policy,
                );
                tracing::info!(peer = peer_node, "{}", disclosure);
                self.carrier_disclosures.insert(peer_node, disclosure);
            }

            tracing::warn!(
                session_id = %session_id,
                attempt = %session.reconnect.attempt,
                "RDMA session degraded to TCP fallback per OW-308; RDMA reconnect attempts exhausted"
            );

            // Attempt TCP reconnection: reset attempt counter and proceed
            // with the standard TCP reconnection flow below.
            // The session is now in Degraded state with TCP fallback active.
            session.reconnect.reset();
            let backoff = session.reconnect.next_backoff();
            let attempt = session.reconnect.attempt;

            session
                .transition(SessionState::Reconnecting {
                    attempt,
                    since: HlcTimestamp::default(),
                    backoff,
                })
                .map_err(|e| TransportError::Generic(e.to_string()))?;

            session
                .transition(SessionState::Connecting {
                    started_at: HlcTimestamp::default(),
                })
                .map_err(|e| TransportError::Generic(e.to_string()))?;

            session
                .transition(SessionState::Handshaking {
                    started_at: HlcTimestamp::default(),
                })
                .map_err(|e| TransportError::Generic(e.to_string()))?;

            session
                .transition(SessionState::Established {
                    since: HlcTimestamp::default(),
                })
                .map_err(|e| TransportError::Generic(e.to_string()))?;

            tracing::info!(
                session_id = %session_id,
                "RDMA session re-established via TCP fallback after carrier degradation"
            );
            return Ok(());
        }

        session
            .transition(SessionState::Reconnecting {
                attempt,
                since: HlcTimestamp::default(),
                backoff,
            })
            .map_err(|e| TransportError::Generic(e.to_string()))?;

        // Simulate reconnection: transition back through connecting → handshaking → established
        // In production, this would actually reconnect via the backend.
        session
            .transition(SessionState::Connecting {
                started_at: HlcTimestamp::default(),
            })
            .map_err(|e| TransportError::Generic(e.to_string()))?;

        session
            .transition(SessionState::Handshaking {
                started_at: HlcTimestamp::default(),
            })
            .map_err(|e| TransportError::Generic(e.to_string()))?;

        session
            .transition(SessionState::Established {
                since: HlcTimestamp::default(),
            })
            .map_err(|e| TransportError::Generic(e.to_string()))?;

        session.reconnect.reset();

        Ok(())
    }

    /// Look up a session by peer address and close it.
    ///
    /// Iterates the session table to find a session whose peer_addr
    /// matches addr, then calls close_session with the given reason.
    /// Returns Ok(()) if the session was found and closed, or
    /// TransportError::SessionNotFound if no session matches the address.
    pub fn close_session_by_addr(
        &mut self,
        addr: SocketAddr,
        reason: SessionCloseReason,
    ) -> Result<(), TransportError> {
        let tcp_addr = TransportAddr::Tcp(addr);
        let session_id = {
            let mut found = None;
            for (sid, session_arc) in &self.sessions {
                let session = session_arc
                    .lock()
                    .map_err(|e| TransportError::Generic(format!("session lock poisoned: {e}")))?;
                if session.peer_addr == tcp_addr {
                    found = Some(*sid);
                }
            }
            found
        };
        match session_id {
            Some(sid) => self.close_session(sid, reason),
            None => Err(TransportError::SessionNotFound {
                session_id: SessionId(0),
            }),
        }
    }

    /// Return the peer node ID for a session, if the session exists
    /// and its peer_node has been set by a completed handshake.
    ///
    /// Returns `None` if the session is not found, or if the session
    /// was accepted but has not yet completed the handshake
    /// (peer_node is 0 for pre-handshake inbound sessions).
    pub fn peer_node(&self, session_id: SessionId) -> Option<u64> {
        let session = self.sessions.get(&session_id)?;
        let s = session.lock().ok()?;
        if s.peer_node == 0 {
            None
        } else {
            Some(s.peer_node)
        }
    }

    /// Return the socket address of a session's peer endpoint.
    ///
    /// Returns `None` if the session is not found or if the peer
    /// address is not a TCP endpoint.
    pub fn session_addr(&self, session_id: SessionId) -> Option<SocketAddr> {
        let session = self.sessions.get(&session_id)?;
        let s = session.lock().ok()?;
        match s.peer_addr {
            TransportAddr::Tcp(addr) => Some(addr),
            _ => None,
        }
    }

    /// Return the transport backend kind for an active session.
    ///
    /// Returns `None` when the session is not found. The backend kind
    /// is carrier-stable: a session created with `Rdma` that later falls
    /// back to TCP will have its `backend_kind` demoted to `Tcp` by the
    /// session's carrier-lost handler.
    #[must_use]
    pub fn session_backend_kind(&self, session_id: SessionId) -> Option<TransportBackendKind> {
        let session = self.sessions.get(&session_id)?;
        let s = session.lock().ok()?;
        Some(s.backend_kind)
    }

    /// Return the current connect lifecycle phase for a session.
    ///
    /// Returns `None` if no lifecycle tracker exists for the session
    /// (e.g., session created before lifecycle tracking was added).
    #[must_use]
    pub fn session_lifecycle(&self, session_id: SessionId) -> Option<SessionLifecycle> {
        self.connect_lifecycles
            .get(&session_id)
            .map(|lc| lc.current())
    }

    /// Return a summary of data-path carriers for active sessions.
    ///
    /// Aggregates per-session `backend_kind` into per-carrier session counts.
    #[must_use]
    pub fn data_path_carrier_summary(&self) -> DataPathCarrierSummary {
        let mut summary = DataPathCarrierSummary::default();
        for session in self.sessions.values() {
            if let Ok(s) = session.lock() {
                match s.backend_kind {
                    TransportBackendKind::Rdma => summary.rdma_sessions += 1,
                    TransportBackendKind::Tls => summary.tls_sessions += 1,
                    TransportBackendKind::Tcp => summary.tcp_sessions += 1,
                }
            }
        }
        // Also count shippers per carrier
        for shipper in self.shippers.values() {
            match shipper.backend_kind {
                TransportBackendKind::Rdma => summary.rdma_shippers += 1,
                TransportBackendKind::Tls => summary.tls_shippers += 1,
                TransportBackendKind::Tcp => summary.tcp_shippers += 1,
            }
        }
        summary
    }

    /// Get or create the chunk shipper for a session.
    #[must_use]
    pub fn shipper(&self, session_id: SessionId) -> Option<&ChunkShipper> {
        self.shippers.get(&session_id)
    }

    /// Get a mutable chunk shipper.
    pub fn shipper_mut(&mut self, session_id: SessionId) -> Option<&mut ChunkShipper> {
        self.shippers.get_mut(&session_id)
    }

    /// Periodic maintenance: prune idle connections, retry reconnections.
    pub fn maintain(&mut self) {
        // Clean up closed sessions
        let closed_ids: Vec<SessionId> = self
            .sessions
            .iter()
            .filter_map(|(sid, session_arc)| {
                session_arc.lock().ok().and_then(|session| {
                    if matches!(session.state, SessionState::Closed { .. }) {
                        Some(*sid)
                    } else {
                        None
                    }
                })
            })
            .collect();

        for session_id in closed_ids {
            self.active_connections.remove(&session_id);
            self.sessions.remove(&session_id);
            self.shippers.remove(&session_id);
        }

        // Prune idle connections
        self.pool.prune_idle();

        // Check for sessions needing reconnection
        let reconnecting_ids: Vec<SessionId> = self
            .sessions
            .iter()
            .filter_map(|(session_id, session_arc)| {
                session_arc.lock().ok().and_then(|session| {
                    if matches!(session.state, SessionState::Reconnecting { .. }) {
                        Some(*session_id)
                    } else {
                        None
                    }
                })
            })
            .collect();

        for session_id in reconnecting_ids {
            let _ = self.reconnect(session_id);
        }
    }
    // ── Session operational statistics ──────────────────────────────────

    /// Return a point-in-time snapshot of operational statistics for a
    /// single session, or `None` if the session does not exist.
    pub fn session_stats(&self, session_id: SessionId) -> Option<SessionStatsSnapshot> {
        let session = self.sessions.get(&session_id)?;
        let s = session.lock().ok()?;
        Some(s.stats())
    }

    /// Return aggregate statistics across all known sessions.
    pub fn all_stats(&self) -> TransportStats {
        let mut agg = TransportStats::new();
        for (sid, session) in &self.sessions {
            if let Ok(s) = session.lock() {
                agg.sessions.insert(*sid, s.stats());
            }
        }
        agg
    }

    /// Reset all statistics counters for a single session.
    ///
    /// Returns `true` if the session was found and its stats were reset.
    pub fn reset_session_stats(&mut self, session_id: SessionId) -> bool {
        let Some(session) = self.sessions.get(&session_id) else {
            return false;
        };
        let Ok(mut s) = session.lock() else {
            return false;
        };
        s.reset_stats();
        true
    }

    /// Record a send-side error on a session's statistics.
    ///
    /// This is a best-effort call: if the session lock is poisoned,
    /// already held by an error path, or the session does not exist,
    /// the error is silently ignored.
    fn record_send_err(&self, session_id: SessionId) {
        if let Some(session) = self.sessions.get(&session_id) {
            if let Ok(s) = session.try_lock() {
                s.stats_ref().record_send_error();
            }
        }
    }

    /// Record a receive-side error on a session's statistics.
    ///
    /// This is a best-effort call: if the session lock is poisoned or
    /// the session does not exist, the error is silently ignored.
    fn record_recv_err(&self, session_id: SessionId) {
        if let Some(session) = self.sessions.get(&session_id) {
            if let Ok(s) = session.lock() {
                s.stats_ref().record_recv_error();
            }
        }
    }
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport")
            .field("local_node", &self.local_node_id)
            .field("bind_addr", &self.bind_addr)
            .field("sessions", &self.sessions.len())
            .field("shippers", &self.shippers.len())
            .field("pool_connections", &self.pool.connections.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Handshake wire message
// ---------------------------------------------------------------------------

/// Message exchanged during session handshake.
/// Serialized with bincode and sent as a single frame.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct HandshakeMessage {
    /// Sender's public identity.
    pub identity: NodeIdentityPublic,
    /// Protocol families and versions the sender supports.
    pub families: Vec<FamilyVersion>,
    /// Endpoint family (e0..e3 per P8-01 §4), serialized as u32.
    pub endpoint_family: u32,
    pub epoch: u64,
    /// Maximum transmission unit in bytes (advertised by sender).
    pub mtu: u32,
    /// Feature flags advertised by sender for rolling upgrade compatibility.
    pub feature_flags: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carrier_selection::{CarrierPolicy, CarrierSelectionFallback};
    use crate::session_cohort::NodeInfo;
    use crate::session_drain::{DrainOutcome, GracefulDrainConfig};
    use tidefs_types_transport_session::{ClosureClass, CohortClass};

    use crate::ReconnectState;
    use std::net::TcpListener;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::thread;

    fn make_established_session_with_backend(
        sid: SessionId,
        backend_kind: TransportBackendKind,
    ) -> Session {
        let mut session = Session::new(
            sid,
            1,
            2,
            TransportAddr::Tcp("127.0.0.1:9001".parse().unwrap()),
            EndpointFamily::LocalEmbed,
            backend_kind,
        );
        for state in [
            SessionState::Connecting {
                started_at: HlcTimestamp::default(),
            },
            SessionState::Handshaking {
                started_at: HlcTimestamp::default(),
            },
            SessionState::Bound {
                since: HlcTimestamp::default(),
            },
            SessionState::CohortAttached {
                since: HlcTimestamp::default(),
            },
            SessionState::Established {
                since: HlcTimestamp::default(),
            },
        ] {
            session.transition(state).unwrap();
        }
        session
    }

    fn make_established_session(sid: SessionId) -> Session {
        make_established_session_with_backend(sid, TransportBackendKind::Tcp)
    }

    fn insert_established_session(t: &mut Transport, sid: SessionId) {
        t.sessions.insert(
            sid,
            Arc::new(std::sync::Mutex::new(make_established_session(sid))),
        );
    }

    fn insert_established_rdma_session(t: &mut Transport, sid: SessionId) {
        t.sessions.insert(
            sid,
            Arc::new(std::sync::Mutex::new(
                make_established_session_with_backend(sid, TransportBackendKind::Rdma),
            )),
        );
    }

    #[test]
    fn test_transport_create() {
        let transport = Transport::new(1);
        assert_eq!(transport.local_node_id, 1);
        assert_eq!(transport.sessions.len(), 0);
    }

    #[test]
    fn test_add_node() {
        let mut transport = Transport::new(0);
        let addr = crate::TransportAddr::Tcp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9000,
        ));
        let node = NodeInfo::new(1, vec![addr], 0);
        transport.add_node(node);
        assert_eq!(transport.cohort_graph.nodes.len(), 1);
    }

    #[test]
    fn test_cohort_graph_targeted_peers_full_mesh() {
        let mut graph = SessionCohortGraph::new();
        for i in 1..=5 {
            let addr = crate::TransportAddr::Tcp(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, i as u8)),
                9000,
            ));
            graph.add_node(NodeInfo::new(i as u64, vec![addr], i as u64 % 2));
        }
        // With 5 nodes, full mesh: node 1 should connect to 2,3,4,5
        let peers = graph.targeted_peers(1);
        assert_eq!(peers.len(), 4);
        assert!(peers.contains(&2));
        assert!(peers.contains(&5));
    }

    #[test]
    fn test_session_state_transitions() {
        let mut session = Session::new(
            SessionId::new(1),
            0,
            1,
            TransportAddr::Tcp("127.0.0.1:9001".parse().unwrap()),
            EndpointFamily::LocalEmbed,
            TransportBackendKind::Tcp,
        );
        assert!(matches!(session.state, SessionState::Unconnected));

        session
            .transition(SessionState::Connecting {
                started_at: HlcTimestamp::default(),
            })
            .unwrap();
        assert!(matches!(session.state, SessionState::Connecting { .. }));

        session
            .transition(SessionState::Handshaking {
                started_at: HlcTimestamp::default(),
            })
            .unwrap();
        assert!(matches!(session.state, SessionState::Handshaking { .. }));

        session
            .transition(SessionState::Established {
                since: HlcTimestamp::default(),
            })
            .unwrap();
        assert!(session.is_established());
    }

    #[test]
    fn test_session_close() {
        let mut session = Session::new(
            SessionId::new(1),
            0,
            1,
            TransportAddr::Tcp("127.0.0.1:9001".parse().unwrap()),
            EndpointFamily::LocalEmbed,
            TransportBackendKind::Tcp,
        );
        session
            .transition(SessionState::Closed {
                reason: SessionCloseReason::LocalShutdown,
            })
            .unwrap();
        assert!(session.is_closed());
    }

    #[test]
    fn test_lane_demux_write_read() {
        let mut demux = crate::lane_demux::LaneDemux::new();

        // Write messages to different lanes
        let result = demux.write(crate::lane_demux::LaneClass::Control, b"hello".to_vec());
        assert_eq!(result, crate::lane_demux::WriteResult::Queued);

        let result = demux.write(crate::lane_demux::LaneClass::Background, b"world".to_vec());
        assert_eq!(result, crate::lane_demux::WriteResult::Queued);

        // Control lane should be read first (higher priority)
        let next = demux.next_to_send();
        assert!(next.is_some());
        let (lane, msg) = next.unwrap();
        assert_eq!(lane, crate::lane_demux::LaneClass::Control);
        assert_eq!(msg, b"hello");

        // Then Background
        let next = demux.next_to_send();
        assert!(next.is_some());
        let (lane, msg) = next.unwrap();
        assert_eq!(lane, crate::lane_demux::LaneClass::Background);
        assert_eq!(msg, b"world");

        // Empty
        assert!(demux.next_to_send().is_none());
    }

    #[test]
    fn test_lane_demux_backpressure() {
        let mut demux = crate::lane_demux::LaneDemux::new();

        // Lower high watermark to trigger backpressure quickly
        // We can't easily mutate the backpressure settings from outside,
        // but we can fill the buffer with large messages.
        let big_msg = vec![0u8; 128 * 1024]; // 128KB per message
        let mut paused = false;
        for _ in 0..200 {
            let result = demux.write(crate::lane_demux::LaneClass::Background, big_msg.clone());
            if matches!(result, crate::lane_demux::WriteResult::Paused { .. }) {
                paused = true;
                break;
            }
        }
        assert!(paused, "Expected backpressure to trigger");
        assert!(demux.is_paused(crate::lane_demux::LaneClass::Background));

        // Resume the lane
        demux.resume(crate::lane_demux::LaneClass::Background);
        assert!(!demux.is_paused(crate::lane_demux::LaneClass::Background));
    }

    #[test]
    fn test_chunk_shipper_send_complete() {
        let shipper = &mut ChunkShipper::new(SessionId::new(1), TransportBackendKind::Tcp);
        let chunk_id = crate::types::ChunkId::new(42);
        let result = shipper.send_chunk(chunk_id, 1024);
        assert!(result.is_ok());
        let transfer_id = result.unwrap();

        let transfer = shipper.get(transfer_id);
        assert!(transfer.is_some());
        let t = transfer.unwrap();
        assert_eq!(t.chunk_id, chunk_id);
        assert_eq!(t.total_bytes, 1024);
        assert!(matches!(
            t.state,
            crate::chunk_shipper::ChunkTransferState::Queued
        ));

        // Complete the transfer
        let digest = crate::types::Hash::new([0u8; 32]);
        shipper.complete(transfer_id, digest).unwrap();

        let t = shipper.get(transfer_id).unwrap();
        assert!(matches!(
            t.state,
            crate::chunk_shipper::ChunkTransferState::Complete { .. }
        ));
    }

    #[test]
    fn test_chunk_shipper_max_concurrent() {
        let mut shipper = ChunkShipper::new(SessionId::new(1), TransportBackendKind::Tcp);
        shipper.max_concurrent = 2;

        assert!(shipper
            .send_chunk(crate::types::ChunkId::new(1), 100)
            .is_ok());
        assert!(shipper
            .send_chunk(crate::types::ChunkId::new(2), 200)
            .is_ok());
        // Third should fail
        assert!(shipper
            .send_chunk(crate::types::ChunkId::new(3), 300)
            .is_err());
    }

    #[test]
    fn test_reconnect_exponential_backoff() {
        let mut state = ReconnectState::new();
        let d1 = state.next_backoff();
        let d2 = state.next_backoff();
        let d3 = state.next_backoff();

        // Each backoff should be roughly double the previous
        assert!(d2 > d1);
        assert!(d3 > d2);

        // Reset
        state.reset();
        assert_eq!(state.attempt, 0);
    }

    #[test]
    fn rdma_permanent_carrier_loss_prefer_falls_back_to_tcp() {
        let sid = SessionId::new(41);
        let mut transport = Transport::new(1).with_carrier_policy(CarrierPolicy::Prefer);
        transport.backend_kind = TransportBackendKind::Rdma;
        insert_established_rdma_session(&mut transport, sid);
        {
            let session = transport.sessions.get(&sid).unwrap();
            session.lock().unwrap().carrier_lost = true;
        }

        transport.reconnect(sid).expect("prefer should fall back");

        let session = transport.sessions.get(&sid).unwrap().lock().unwrap();
        assert_eq!(session.backend_kind, TransportBackendKind::Tcp);
        assert!(!session.carrier_lost);
        assert!(matches!(session.state, SessionState::Established { .. }));
        drop(session);

        let disclosure = transport
            .carrier_disclosure(2)
            .expect("runtime fallback disclosure");
        assert_eq!(disclosure.selected_backend, TransportBackendKind::Tcp);
        assert_eq!(disclosure.policy, Some(CarrierPolicy::Prefer));
        assert!(matches!(
            disclosure.fallback,
            CarrierSelectionFallback::Fallback {
                requested: "rdma",
                reason: RDMA_RUNTIME_FALLBACK_PERMANENT_LOSS,
            }
        ));
    }

    #[test]
    fn rdma_permanent_carrier_loss_enforce_fails_closed() {
        let sid = SessionId::new(42);
        let mut transport = Transport::new(1).with_carrier_policy(CarrierPolicy::Enforce);
        transport.backend_kind = TransportBackendKind::Rdma;
        insert_established_rdma_session(&mut transport, sid);
        {
            let session = transport.sessions.get(&sid).unwrap();
            session.lock().unwrap().carrier_lost = true;
        }

        let err = transport
            .reconnect(sid)
            .expect_err("enforce must refuse TCP fallback");
        let err = err.to_string();
        assert!(err.contains("carrier policy violation"));
        assert!(err.contains("runtime RDMA fallback to TCP refused"));

        let session = transport.sessions.get(&sid).unwrap().lock().unwrap();
        assert_eq!(session.backend_kind, TransportBackendKind::Rdma);
        assert!(session.carrier_lost);
        assert!(matches!(session.state, SessionState::Established { .. }));
        drop(session);

        let disclosure = transport
            .carrier_disclosure(2)
            .expect("runtime refusal disclosure");
        assert_eq!(disclosure.selected_backend, TransportBackendKind::Rdma);
        assert_eq!(disclosure.policy, Some(CarrierPolicy::Enforce));
        assert!(matches!(
            disclosure.fallback,
            CarrierSelectionFallback::Refused {
                requested: "rdma",
                reason: RDMA_RUNTIME_FALLBACK_PERMANENT_LOSS,
            }
        ));
    }

    #[test]
    fn rdma_reconnect_exhausted_prefer_falls_back_to_tcp() {
        let sid = SessionId::new(43);
        let mut transport = Transport::new(1).with_carrier_policy(CarrierPolicy::Prefer);
        transport.backend_kind = TransportBackendKind::Rdma;
        insert_established_rdma_session(&mut transport, sid);
        {
            let session = transport.sessions.get(&sid).unwrap();
            session.lock().unwrap().reconnect.attempt = 2;
        }

        transport.reconnect(sid).expect("prefer should fall back");

        let session = transport.sessions.get(&sid).unwrap().lock().unwrap();
        assert_eq!(session.backend_kind, TransportBackendKind::Tcp);
        assert!(matches!(session.state, SessionState::Established { .. }));
        drop(session);

        let disclosure = transport
            .carrier_disclosure(2)
            .expect("runtime fallback disclosure");
        assert_eq!(disclosure.selected_backend, TransportBackendKind::Tcp);
        assert_eq!(disclosure.policy, Some(CarrierPolicy::Prefer));
        assert!(matches!(
            disclosure.fallback,
            CarrierSelectionFallback::Fallback {
                requested: "rdma",
                reason: RDMA_RUNTIME_FALLBACK_RECONNECT_EXHAUSTED,
            }
        ));
    }

    #[test]
    fn rdma_reconnect_exhausted_enforce_fails_closed() {
        let sid = SessionId::new(44);
        let mut transport = Transport::new(1).with_carrier_policy(CarrierPolicy::Enforce);
        transport.backend_kind = TransportBackendKind::Rdma;
        insert_established_rdma_session(&mut transport, sid);
        {
            let session = transport.sessions.get(&sid).unwrap();
            session.lock().unwrap().reconnect.attempt = 2;
        }

        let err = transport
            .reconnect(sid)
            .expect_err("enforce must refuse TCP fallback");
        let err = err.to_string();
        assert!(err.contains("carrier policy violation"));
        assert!(err.contains("runtime RDMA fallback to TCP refused"));

        let session = transport.sessions.get(&sid).unwrap().lock().unwrap();
        assert_eq!(session.backend_kind, TransportBackendKind::Rdma);
        assert!(matches!(session.state, SessionState::Established { .. }));
        drop(session);

        let disclosure = transport
            .carrier_disclosure(2)
            .expect("runtime refusal disclosure");
        assert_eq!(disclosure.selected_backend, TransportBackendKind::Rdma);
        assert_eq!(disclosure.policy, Some(CarrierPolicy::Enforce));
        assert!(matches!(
            disclosure.fallback,
            CarrierSelectionFallback::Refused {
                requested: "rdma",
                reason: RDMA_RUNTIME_FALLBACK_RECONNECT_EXHAUSTED,
            }
        ));
    }

    #[test]
    fn test_cohort_based_targeting() {
        let mut graph = SessionCohortGraph::new();

        // Nodes 1-3 share PeerPair cohort
        graph.add_node(NodeInfo::with_cohorts(
            1,
            vec![TransportAddr::Tcp("127.0.0.1:9000".parse().unwrap())],
            0,
            vec![CohortClass::PeerPair],
        ));
        graph.add_node(NodeInfo::with_cohorts(
            2,
            vec![TransportAddr::Tcp("127.0.0.2:9000".parse().unwrap())],
            0,
            vec![CohortClass::PeerPair],
        ));
        graph.add_node(NodeInfo::with_cohorts(
            3,
            vec![TransportAddr::Tcp("127.0.0.3:9000".parse().unwrap())],
            0,
            vec![CohortClass::PeerPair],
        ));
        // Node 4 is only in ReplicaSet — no shared cohort with nodes 1-3
        graph.add_node(NodeInfo::with_cohorts(
            4,
            vec![TransportAddr::Tcp("127.0.0.4:9000".parse().unwrap())],
            1,
            vec![CohortClass::ReplicaSet],
        ));

        // Node 1 sees nodes 2 and 3 (shared PeerPair), but not 4
        let peers = graph.targeted_peers(1);
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&2));
        assert!(peers.contains(&3));
        assert!(!peers.contains(&4));

        // Node 4 sees no one (no shared cohorts)
        assert!(graph.targeted_peers(4).is_empty());
    }

    #[test]
    fn test_cohort_multiple_memberships() {
        let mut graph = SessionCohortGraph::new();

        // Node 1: PeerPair + AuthorityDomainControl
        graph.add_node(NodeInfo::with_cohorts(
            1,
            vec![TransportAddr::Tcp("127.0.0.1:9000".parse().unwrap())],
            0,
            vec![CohortClass::PeerPair, CohortClass::AuthorityDomainControl],
        ));
        // Node 2: PeerPair only
        graph.add_node(NodeInfo::with_cohorts(
            2,
            vec![TransportAddr::Tcp("127.0.0.2:9000".parse().unwrap())],
            0,
            vec![CohortClass::PeerPair],
        ));
        // Node 3: AuthorityDomainControl only
        graph.add_node(NodeInfo::with_cohorts(
            3,
            vec![TransportAddr::Tcp("127.0.0.3:9000".parse().unwrap())],
            1,
            vec![CohortClass::AuthorityDomainControl],
        ));
        // Node 4: TransitionStage (no overlap)
        graph.add_node(NodeInfo::with_cohorts(
            4,
            vec![TransportAddr::Tcp("127.0.0.4:9000".parse().unwrap())],
            2,
            vec![CohortClass::TransitionStage],
        ));

        // Node 1 sees nodes 2 (PeerPair) and 3 (AuthorityDomainControl)
        let peers = graph.targeted_peers(1);
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&2));
        assert!(peers.contains(&3));

        // Node 2 sees only node 1 (shared PeerPair)
        assert_eq!(graph.targeted_peers(2), vec![1]);

        // Node 3 sees only node 1 (shared AuthorityDomainControl)
        assert_eq!(graph.targeted_peers(3), vec![1]);
    }

    #[test]
    fn test_session_invalid_transition() {
        let mut session = Session::new(
            SessionId::new(1),
            0,
            1,
            TransportAddr::Tcp("127.0.0.1:9001".parse().unwrap()),
            EndpointFamily::LocalEmbed,
            TransportBackendKind::Tcp,
        );

        // Cannot jump from Unconnected directly to Established
        let result = session.transition(SessionState::Established {
            since: HlcTimestamp::default(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_connection_pool_prune() {
        let mut pool = ConnectionPool::new(2, Duration::from_secs(0)); // immediate timeout
                                                                       // Connections can't be created without a real TcpStream, but we can test state
        assert_eq!(pool.connections.len(), 0);
        let pruned = pool.prune_idle();
        assert!(pruned.is_empty());
    }

    /// Integration test: TCP loopback transport with connect, handshake,
    /// message exchange, and session close.
    #[test]
    fn test_transport_tcp_loopback_connect_handshake_message() {
        // Bind a TCP listener on a random port
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let server_addr = listener.local_addr().expect("local_addr");

        // Server thread: accept connection, handshake, exchange message, close
        let server_handle = thread::spawn(move || {
            let (stream, _peer) = listener.accept().expect("accept");
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

            use std::io::{Read, Write};
            let mut s = stream;

            // Send server identity (handshake outbound)
            let server_id = tidefs_auth::NodeIdentity::generate(2).expect("generate").0;
            let hs = HandshakeMessage {
                epoch: 0,
                identity: server_id,
                families: Vec::new(),
                endpoint_family: 0,
                mtu: 65536,
                feature_flags: 0,
            };
            let bytes = bincode::serialize(&hs).expect("serialize");

            let len = bytes.len() as u32;
            s.write_all(&len.to_be_bytes()).expect("write len");
            s.write_all(&bytes).expect("write payload");
            s.flush().expect("flush");

            // Read client identity (handshake inbound)
            let mut len_buf = [0u8; 4];
            s.read_exact(&mut len_buf).expect("read len");
            let peer_len = u32::from_be_bytes(len_buf) as usize;
            let mut peer_bytes = vec![0u8; peer_len];
            s.read_exact(&mut peer_bytes).expect("read payload");
            let _peer_hs: HandshakeMessage =
                bincode::deserialize(&peer_bytes).expect("deserialize");

            // Read a message from the client
            let mut len_buf = [0u8; 4];
            s.read_exact(&mut len_buf).expect("read msg len");
            let msg_len = u32::from_be_bytes(len_buf) as usize;
            let mut msg_bytes = vec![0u8; msg_len];
            s.read_exact(&mut msg_bytes).expect("read msg");
            assert_eq!(msg_bytes, b"hello from node 1");

            // Send a reply
            let reply = b"hello from node 2";
            let reply_len = reply.len() as u32;
            s.write_all(&reply_len.to_be_bytes())
                .expect("write reply len");
            s.write_all(reply).expect("write reply");
            s.flush().expect("flush");
        });

        // Client: connect, perform handshake, exchange messages
        let server_ip = server_addr.ip();
        let server_port = server_addr.port();

        let mut client = Transport::new(1);
        client.local_identity = Some(tidefs_auth::NodeIdentity::generate(1).expect("generate").0);

        let node = NodeInfo::new(
            2,
            vec![crate::TransportAddr::Tcp(SocketAddr::new(
                server_ip,
                server_port,
            ))],
            0,
        );
        client.add_node(node);

        let session_id = client.connect(2).expect("connect");
        client.perform_handshake(session_id).expect("handshake");

        // Verify peer info populated
        {
            let session = client.sessions.get(&session_id).unwrap().lock().unwrap();
            assert!(session.is_established());
            assert!(session.peer_info.is_some());
            assert_eq!(session.peer_info.as_ref().unwrap().node_id, 2);
        }

        // Send a message
        client
            .send_message(session_id, b"hello from node 1")
            .expect("send");

        // Receive reply
        let reply = client.recv_message(session_id).expect("recv");
        assert_eq!(reply, b"hello from node 2");

        // Clean up session
        client
            .close_session(session_id, SessionCloseReason::LocalShutdown)
            .expect("close");

        server_handle.join().expect("server thread");
    }

    /// Verify that send_message fails on a closed session.
    #[test]
    fn test_send_message_on_closed_session_fails() {
        let mut transport = Transport::new(1);
        transport.local_identity =
            Some(tidefs_auth::NodeIdentity::generate(1).expect("generate").0);

        // Set up a listener and connect
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let server_addr = listener.local_addr().expect("local_addr");

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            use std::io::Write;
            let mut s = stream;
            // Send handshake
            let hs = HandshakeMessage {
                epoch: 0,
                identity: tidefs_auth::NodeIdentity::generate(2).expect("generate").0,
                families: Vec::new(),
                endpoint_family: 0,
                mtu: 65536,
                feature_flags: 0,
            };
            let bytes = bincode::serialize(&hs).expect("serialize");
            let len = bytes.len() as u32;
            s.write_all(&len.to_be_bytes()).expect("write");
            s.write_all(&bytes).expect("write");
            s.flush().expect("flush");

            // Read client handshake
            let mut lb = [0u8; 4];
            use std::io::Read;
            s.read_exact(&mut lb).ok();
        });

        let node = NodeInfo::new(
            2,
            vec![crate::TransportAddr::Tcp(SocketAddr::new(
                server_addr.ip(),
                server_addr.port(),
            ))],
            0,
        );
        transport.add_node(node);

        let sid = transport.connect(2).expect("connect");
        transport.perform_handshake(sid).expect("handshake");
        transport
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .expect("close");

        // Attempting to send on a closed session should fail
        let result = transport.send_message(sid, b"should fail");
        assert!(result.is_err());

        server_handle.join().expect("server thread");
    }

    /// Integration test: send_envelope/recv_envelope roundtrip over TCP loopback.
    #[test]
    fn test_send_recv_envelope_tcp_loopback() {
        use crate::envelope::{MessageFamily, SequenceTracker, TransportEnvelope, VisibilityClass};
        use crate::lane_demux::LaneClass;
        use crate::session_cohort::TransportCohortId;
        use crate::types::Hash;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let server_addr = listener.local_addr().expect("local_addr");

        let server_handle = thread::spawn(move || {
            let (stream, _peer) = listener.accept().expect("accept");
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
            use std::io::{Read, Write};
            let mut s = stream;

            // Send handshake
            let hs = HandshakeMessage {
                epoch: 0,
                identity: tidefs_auth::NodeIdentity::generate(2).expect("generate").0,
                families: Vec::new(),
                endpoint_family: 0,
                mtu: 65536,
                feature_flags: 0,
            };
            let bytes = bincode::serialize(&hs).expect("serialize");
            let len = bytes.len() as u32;
            s.write_all(&len.to_be_bytes()).expect("write len");
            s.write_all(&bytes).expect("write payload");
            s.flush().expect("flush");

            // Read client handshake
            let mut len_buf = [0u8; 4];
            s.read_exact(&mut len_buf).expect("read len");
            let peer_len = u32::from_be_bytes(len_buf) as usize;
            let mut peer_bytes = vec![0u8; peer_len];
            s.read_exact(&mut peer_bytes).expect("read payload");

            // Read an envelope frame from the client
            let mut len_buf = [0u8; 4];
            s.read_exact(&mut len_buf).expect("read env len");
            let env_len = u32::from_be_bytes(len_buf) as usize;
            let mut env_bytes = vec![0u8; env_len];
            s.read_exact(&mut env_bytes).expect("read env payload");
            let (env, payload) = TransportEnvelope::decode(&env_bytes).expect("decode envelope");

            assert_eq!(env.message_family, MessageFamily::StateTransfer);
            assert_eq!(env.lane_class, LaneClass::Demand);
            assert_eq!(env.sequence_number, 0); // first seq from SequenceTracker
            assert_eq!(payload, b"envelope test payload");

            // Send a reply envelope
            let mut reply_env = TransportEnvelope::new(
                SessionId::new(2),
                TransportCohortId::new(env.cohort_id.0),
                LaneClass::Demand,
                MessageFamily::StateTransfer,
                5,
                env.sequence_number, // ack the client's seq
                vec![Hash([0x42u8; 32])],
                VisibilityClass::Internal,
            );
            let reply_payload = b"envelope reply from node 2";
            let reply_frame = reply_env.encode(reply_payload);
            let reply_len = reply_frame.len() as u32;
            s.write_all(&reply_len.to_be_bytes())
                .expect("write reply len");
            s.write_all(&reply_frame).expect("write reply");
            s.flush().expect("flush");
        });

        // Client side
        let mut client = Transport::new(1);
        client.local_identity = Some(tidefs_auth::NodeIdentity::generate(1).expect("generate").0);

        let node = NodeInfo::new(
            2,
            vec![crate::TransportAddr::Tcp(SocketAddr::new(
                server_addr.ip(),
                server_addr.port(),
            ))],
            0,
        );
        client.add_node(node);

        let session_id = client.connect(2).expect("connect");
        client.perform_handshake(session_id).expect("handshake");

        let mut tracker = SequenceTracker::new();
        let seq = tracker.next_sequence(LaneClass::Demand);

        let mut env = TransportEnvelope::new(
            session_id,
            TransportCohortId::new(1),
            LaneClass::Demand,
            MessageFamily::StateTransfer,
            seq,
            tracker.ack_floor(LaneClass::Demand),
            vec![Hash([0xCCu8; 32]), Hash([0xDDu8; 32])],
            VisibilityClass::Public,
        );
        let payload = b"envelope test payload";

        client
            .send_envelope(&mut env, payload)
            .expect("send_envelope");

        let (reply_env, reply_payload) = client.recv_envelope(session_id).expect("recv_envelope");

        assert_eq!(reply_env.message_family, MessageFamily::StateTransfer);
        assert_eq!(reply_env.sequence_number, 5);
        assert_eq!(reply_env.ack_floor, 0); // they acked our seq 0
        assert_eq!(reply_env.anchor_refs.len(), 1);
        assert_eq!(reply_env.anchor_refs[0], Hash([0x42u8; 32]));
        assert_eq!(reply_env.visibility_class, VisibilityClass::Internal);
        assert_eq!(reply_payload, b"envelope reply from node 2");

        // Verify our envelope's payload digest is zero-filled (BLAKE3 removed)
        assert_eq!(env.payload_digest().0, [0u8; 32]);

        client
            .close_session(session_id, SessionCloseReason::LocalShutdown)
            .expect("close");
        server_handle.join().expect("server thread");
    }

    /// Envelope decode fails gracefully on garbage data.
    #[test]
    fn test_recv_envelope_rejects_garbage() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let server_addr = listener.local_addr().expect("local_addr");

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            use std::io::Write;
            let mut s = stream;
            // Send handshake
            let hs = HandshakeMessage {
                epoch: 0,
                identity: tidefs_auth::NodeIdentity::generate(2).expect("generate").0,
                families: Vec::new(),
                endpoint_family: 0,
                mtu: 65536,
                feature_flags: 0,
            };
            let bytes = bincode::serialize(&hs).expect("serialize");
            let len = bytes.len() as u32;
            s.write_all(&len.to_be_bytes()).expect("write");
            s.write_all(&bytes).expect("write");
            s.flush().expect("flush");

            // Read client handshake
            let mut lb = [0u8; 4];
            use std::io::Read;
            s.read_exact(&mut lb).ok();

            // Send garbage as a "frame" (not a valid envelope)
            let garbage = b"totally not an envelope";
            let glen = garbage.len() as u32;
            s.write_all(&glen.to_be_bytes()).expect("write garbage len");
            s.write_all(garbage).expect("write garbage");
            s.flush().expect("flush");
        });

        let mut client = Transport::new(1);
        client.local_identity = Some(tidefs_auth::NodeIdentity::generate(1).expect("generate").0);
        let node = NodeInfo::new(
            2,
            vec![crate::TransportAddr::Tcp(SocketAddr::new(
                server_addr.ip(),
                server_addr.port(),
            ))],
            0,
        );
        client.add_node(node);
        let sid = client.connect(2).expect("connect");
        client.perform_handshake(sid).expect("handshake");

        let result = client.recv_envelope(sid);
        assert!(result.is_err(), "recv_envelope should reject garbage data");

        client
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .expect("close");
        server_handle.join().expect("server thread");
    }

    /// Verify that endpoint family is serialized during handshake and
    /// correctly deserialized by the peer (P8-01 §4.2 endpoint propagation).
    #[test]
    fn test_endpoint_family_propagates_through_handshake() {
        for family in [
            EndpointFamily::LocalEmbed,
            EndpointFamily::Data,
            EndpointFamily::Shadow,
        ] {
            let hs = HandshakeMessage {
                epoch: 0,
                endpoint_family: family as u32,
                identity: tidefs_auth::NodeIdentity::generate(42).expect("generate").0,
                families: vec![],
                mtu: 65536,
                feature_flags: 0,
            };
            let bytes = bincode::serialize(&hs).unwrap();
            let peer_hs: HandshakeMessage = bincode::deserialize(&bytes).unwrap();
            let peer_family = match peer_hs.endpoint_family {
                0 => EndpointFamily::LocalEmbed,
                1 => EndpointFamily::Control,
                2 => EndpointFamily::Data,
                3 => EndpointFamily::Shadow,
                _ => panic!("unexpected"),
            };
            assert_eq!(peer_family, family);
        }
    }
    /// Integration test: send a 64 KiB message over a 1 KiB MTU transport
    /// and verify byte-identical reassembly on the receive side using
    /// Transport on both ends.
    #[test]
    fn test_fragmentation_large_payload_over_small_mtu_tcp_loopback() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let server_addr = listener.local_addr().expect("local_addr");

        // Server thread: accept, handshake, receive fragmented message, echo back
        let server_handle = std::thread::spawn(move || {
            let (stream, _peer) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .ok();
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(10)))
                .ok();

            use std::io::{Read, Write};
            let mut s = stream;

            // Handshake outbound (server -> client)
            let server_id = tidefs_auth::NodeIdentity::generate(2).expect("generate").0;
            let hs = HandshakeMessage {
                epoch: 0,
                identity: server_id,
                families: Vec::new(),
                endpoint_family: 0,
                mtu: 65536,
                feature_flags: 0,
            };
            let bytes = bincode::serialize(&hs).expect("serialize");
            let len = bytes.len() as u32;
            s.write_all(&len.to_be_bytes()).expect("write len");
            s.write_all(&bytes).expect("write payload");
            s.flush().expect("flush");

            // Handshake inbound (client -> server)
            let mut len_buf = [0u8; 4];
            s.read_exact(&mut len_buf).expect("read len");
            let peer_len = u32::from_be_bytes(len_buf) as usize;
            let mut peer_bytes = vec![0u8; peer_len];
            s.read_exact(&mut peer_bytes).expect("read payload");
            let _peer_hs: HandshakeMessage =
                bincode::deserialize(&peer_bytes).expect("deserialize");

            // Read fragment frames until we have the full message
            let mut reassembled = Vec::new();
            for _ in 0..128 {
                let mut len_buf = [0u8; 4];
                if s.read_exact(&mut len_buf).is_err() {
                    break;
                }
                let frame_len = u32::from_be_bytes(len_buf) as usize;
                if frame_len == 0 || frame_len > 65536 {
                    break;
                }
                let mut frame = vec![0u8; frame_len];
                s.read_exact(&mut frame).expect("read frame");

                if is_fragment(&frame) {
                    let (header, payload) = decode_fragment(&frame).expect("decode fragment");

                    reassembled.extend_from_slice(&payload);
                    if header.is_last() {
                        break;
                    }
                } else {
                    // Non-fragment — treat as complete message
                    reassembled = frame;
                    break;
                }
            }

            // Echo the reassembled payload back as a single non-fragment frame
            let reply_len = reassembled.len() as u32;
            s.write_all(&reply_len.to_be_bytes())
                .expect("write reply len");
            s.write_all(&reassembled).expect("write reply");
            s.flush().expect("flush");
        });

        // Client: uses Transport with 1 KiB MTU
        let server_ip = server_addr.ip();
        let server_port = server_addr.port();

        let mut client = Transport::new(1);
        client.local_identity = Some(tidefs_auth::NodeIdentity::generate(1).expect("generate").0);
        client.mtu = 1024;

        let node = NodeInfo::new(
            2,
            vec![crate::TransportAddr::Tcp(std::net::SocketAddr::new(
                server_ip,
                server_port,
            ))],
            0,
        );
        client.add_node(node);

        let session_id = client.connect(2).expect("connect");
        client.perform_handshake(session_id).expect("handshake");

        // MTU negotiated to minimum of (1024, 65536) = 1024
        assert_eq!(client.mtu, 1024);

        // Send a 64 KiB payload — Transport fragments it automatically
        let large_payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
        client
            .send_message(session_id, &large_payload)
            .expect("send large message");

        // Receive the server's echo — comes back as a single non-fragment frame
        let reply = client.recv_message(session_id).expect("recv reply");

        // Verify byte-identical roundtrip
        assert_eq!(reply.len(), large_payload.len(), "payload length mismatch");
        assert_eq!(reply, large_payload, "payload content mismatch");

        client
            .close_session(session_id, SessionCloseReason::LocalShutdown)
            .expect("close");

        server_handle.join().expect("server thread");
    }

    /// Loopback attestation: two Transports complete the full Ed25519 mutual
    /// attestation handshake (initiator + responder) and both reach Established.
    /// Covers: key-not-consumed, responder path, gate for non-LocalEmbed.
    #[test]
    fn test_transport_loopback_mutual_attestation() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        // Generate identities and keypairs for both nodes
        let (identity1, keypair1) =
            tidefs_auth::NodeIdentity::generate(1).expect("generate node 1 identity");
        let (identity2, keypair2) =
            tidefs_auth::NodeIdentity::generate(2).expect("generate node 2 identity");

        // Pre-populate known-identity registries so each peer can verify the other.
        let mut known1 = NodeKeyStore::new();
        known1
            .register(identity1.clone())
            .expect("register self node 1");
        known1
            .register(identity2.clone())
            .expect("register peer node 2");
        let mut known2 = NodeKeyStore::new();
        known2
            .register(identity2.clone())
            .expect("register self node 2");
        known2
            .register(identity1.clone())
            .expect("register peer node 1");

        // Server (node 2): attestation-configured Data endpoint.
        // TcpTransport::bind() sets the listener nonblocking, so accept_incoming()
        // must be polled in a loop.
        let mut server = Transport::new(2)
            .with_attestation(keypair2, identity2)
            .with_known_identities(known2);
        server.set_endpoint_family(EndpointFamily::Data);
        server
            .bind(crate::TransportAddr::Tcp(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                0,
            )))
            .expect("server bind");
        let server_port = match server.bind_addr.as_ref().unwrap() {
            crate::TransportAddr::Tcp(sa) => sa.port(),
            _ => panic!("expected TCP bind address"),
        };

        // Wrap server in a Mutex so the accept thread can call &mut methods
        let server = std::sync::Arc::new(std::sync::Mutex::new(server));

        // Client (node 1): attestation-configured Data endpoint
        let mut client = Transport::new(1)
            .with_attestation(keypair1, identity1)
            .with_known_identities(known1);
        client.set_endpoint_family(EndpointFamily::Data);
        client.add_node(NodeInfo::new(
            2,
            vec![crate::TransportAddr::Tcp(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                server_port,
            ))],
            0,
        ));

        // Spawn server thread: poll accept_incoming() until client connects.
        let server_clone = std::sync::Arc::clone(&server);
        let server_handle = std::thread::spawn(move || {
            // Poll accept with 50ms intervals; give up after 10s.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let sid = loop {
                match server_clone.lock().unwrap().accept_incoming() {
                    Ok(sid) => break sid,
                    Err(TransportError::Generic(ref msg))
                        if msg.contains("no pending connections") =>
                    {
                        if std::time::Instant::now() > deadline {
                            panic!("server accept timed out");
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    Err(e) => panic!("server accept failed: {e:?}"),
                }
            };
            server_clone
                .lock()
                .unwrap()
                .perform_handshake(sid)
                .expect("server handshake");

            let s = server_clone.lock().unwrap();
            let session = s.sessions.get(&sid).unwrap().lock().unwrap();
            assert!(session.is_established(), "server session not established");
            let peer = session.peer_info.as_ref().unwrap();
            assert_eq!(peer.node_id, 1, "server peer should be node 1");
        });

        // Client connects and performs handshake
        let client_sid = client.connect(2).expect("client connect");
        client
            .perform_handshake(client_sid)
            .expect("client handshake");

        {
            let session = client.sessions.get(&client_sid).unwrap().lock().unwrap();
            assert!(session.is_established(), "client session not established");
            let peer = session.peer_info.as_ref().unwrap();
            assert_eq!(peer.node_id, 2, "client peer should be node 2");
        }

        // Clean up
        client
            .close_session(client_sid, SessionCloseReason::LocalShutdown)
            .expect("client close");
        server_handle.join().expect("server thread");
    }

    /// Non-LocalEmbed endpoint without attestation key is refused.
    #[test]
    fn test_transport_data_endpoint_rejects_missing_attestation() {
        let mut transport = Transport::new(42);
        transport.set_endpoint_family(EndpointFamily::Data);

        // Create a fake session that looks like it came from connect()
        // (peer_node != 0 so is_initiator is true)
        let sid = transport.cohort_graph.next_session_id();
        let mut session = Session::new(
            sid,
            42,
            99,
            crate::TransportAddr::Tcp("127.0.0.1:1".parse().unwrap()),
            EndpointFamily::Data,
            TransportBackendKind::Tcp,
        );
        session.peer_node = 99;
        session.state = SessionState::Connecting {
            started_at: HlcTimestamp::default(),
        };
        let session = std::sync::Arc::new(std::sync::Mutex::new(session));
        transport.sessions.insert(sid, session);

        // No active connection — the gating check happens before I/O,
        // so lack of connection is fine (the error we want comes first).
        let result = transport.perform_handshake(sid);
        assert!(
            result.is_err(),
            "should reject non-LocalEmbed without attestation key"
        );
        let err = result.unwrap_err();
        let err = format!("{err:?}");
        assert!(
            err.contains("attestation required"),
            "expected attestation-required error, got: {err}"
        );
    }
    // ---- graceful drain config ----

    #[test]
    fn graceful_drain_config_defaults() {
        let cfg = GracefulDrainConfig::default();
        assert_eq!(cfg.deadline, Duration::from_secs(5));
        assert_eq!(cfg.poll_interval, Duration::from_millis(10));
        assert!(cfg.reject_new_sends);
    }

    // ---- graceful drain config: builder ----

    #[test]
    fn with_graceful_drain_config_sets_fields() {
        let cfg =
            GracefulDrainConfig::new(Duration::from_secs(3), Duration::from_millis(50), false);
        let t = Transport::new(1).with_graceful_drain_config(cfg.clone());
        assert_eq!(t.graceful_drain_config, cfg);
    }

    // ---- graceful drain: session not found ----

    #[test]
    fn graceful_drain_nonexistent_session_errors() {
        let mut t = Transport::new(1);
        let sid = SessionId::new(99999);
        let result = t.drain_session_gracefully(sid);
        assert!(result.is_err());
    }

    // ---- graceful drain: already closed ----

    #[test]
    fn graceful_drain_already_closed_returns_already_closed() {
        let mut t = Transport::new(1);
        let sid = SessionId::new(1);
        let mut session = Session::new(
            sid,
            1,
            2,
            TransportAddr::Tcp("127.0.0.1:9001".parse().unwrap()),
            EndpointFamily::LocalEmbed,
            TransportBackendKind::Tcp,
        );
        session
            .transition(SessionState::Connecting {
                started_at: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Handshaking {
                started_at: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Bound {
                since: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::CohortAttached {
                since: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Established {
                since: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Closed {
                reason: SessionCloseReason::LocalShutdown,
            })
            .unwrap();

        t.sessions
            .insert(sid, Arc::new(std::sync::Mutex::new(session)));

        let outcome = t.drain_session_gracefully(sid).unwrap();
        assert_eq!(outcome, DrainOutcome::AlreadyClosed);
        let receipt = t
            .session_closure_receipt(sid)
            .expect("already-closed drain must preserve closure receipt evidence");
        assert_eq!(receipt.closure_class, ClosureClass::CleanDrain);
        assert_eq!(receipt.drain_result_class, DrainResultClass::Complete);
        assert_eq!(receipt.last_seq_acked, 0);
    }

    // ---- graceful drain: empty queue returns completed ----

    #[test]
    fn graceful_drain_empty_queue_returns_completed() {
        let mut t = Transport::new(1);
        let sid = SessionId::new(1);
        let mut session = Session::new(
            sid,
            1,
            2,
            TransportAddr::Tcp("127.0.0.1:9001".parse().unwrap()),
            EndpointFamily::LocalEmbed,
            TransportBackendKind::Tcp,
        );
        session
            .transition(SessionState::Connecting {
                started_at: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Handshaking {
                started_at: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Bound {
                since: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::CohortAttached {
                since: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Established {
                since: HlcTimestamp::default(),
            })
            .unwrap();

        t.sessions
            .insert(sid, Arc::new(std::sync::Mutex::new(session)));

        let outcome = t.drain_session_gracefully(sid).unwrap();
        assert_eq!(
            outcome,
            DrainOutcome::Completed {
                messages_drained: 0
            }
        );
        assert!(!t.is_session_draining(sid));
        let receipt = t
            .session_closure_receipt(sid)
            .expect("completed drain must record a close receipt");
        assert_eq!(receipt.closure_class, ClosureClass::CleanDrain);
        assert_eq!(receipt.drain_result_class, DrainResultClass::Complete);
        // Verify the session was closed by the completed drain.
        let s = t.sessions.get(&sid).unwrap().lock().unwrap();
        assert!(
            s.is_closed(),
            "session should be closed after completed drain"
        );
    }

    // ---- graceful drain: nonempty queue with zero deadline returns expired ----

    #[test]
    fn graceful_drain_nonempty_queue_deadline_expired() {
        let mut t = Transport::new(1);
        t.graceful_drain_config =
            GracefulDrainConfig::new(Duration::from_nanos(1), Duration::from_millis(1), false);

        let sid = SessionId::new(1);
        let mut session = Session::new(
            sid,
            1,
            2,
            TransportAddr::Tcp("127.0.0.1:9001".parse().unwrap()),
            EndpointFamily::LocalEmbed,
            TransportBackendKind::Tcp,
        );
        session
            .message_priority_queue
            .enqueue(QueuedMessage::new(b"hello".to_vec()), MessagePriority::Data)
            .unwrap();

        session
            .transition(SessionState::Connecting {
                started_at: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Handshaking {
                started_at: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Bound {
                since: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::CohortAttached {
                since: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Established {
                since: HlcTimestamp::default(),
            })
            .unwrap();

        t.sessions
            .insert(sid, Arc::new(std::sync::Mutex::new(session)));

        let outcome = t.drain_session_gracefully(sid).unwrap();
        assert_eq!(
            outcome,
            DrainOutcome::DeadlineExpired {
                messages_remaining: 1
            }
        );
        assert!(!t.is_session_draining(sid));
        let receipt = t
            .session_closure_receipt(sid)
            .expect("deadline-expired drain must record a close receipt");
        assert_eq!(receipt.closure_class, ClosureClass::ForcedClose);
        assert_eq!(receipt.drain_result_class, DrainResultClass::StalledTimeout);
        assert_eq!(
            receipt.trigger_ref,
            SessionCloseReason::TransportError.trigger_ref()
        );
        let s = t.sessions.get(&sid).unwrap().lock().unwrap();
        assert!(
            s.is_closed(),
            "stalled drain should force-close the session"
        );
    }

    // ---- graceful drain: completed drain closes session state ----

    #[test]
    fn graceful_drain_completed_closes_session() {
        let mut t = Transport::new(1);
        let sid = SessionId::new(1);
        let mut session = Session::new(
            sid,
            1,
            2,
            TransportAddr::Tcp("127.0.0.1:9001".parse().unwrap()),
            EndpointFamily::LocalEmbed,
            TransportBackendKind::Tcp,
        );
        for state in [
            SessionState::Connecting {
                started_at: HlcTimestamp::default(),
            },
            SessionState::Handshaking {
                started_at: HlcTimestamp::default(),
            },
            SessionState::Bound {
                since: HlcTimestamp::default(),
            },
            SessionState::CohortAttached {
                since: HlcTimestamp::default(),
            },
            SessionState::Established {
                since: HlcTimestamp::default(),
            },
        ] {
            session.transition(state).unwrap();
        }
        t.sessions
            .insert(sid, Arc::new(std::sync::Mutex::new(session)));
        let outcome = t.drain_session_gracefully(sid).unwrap();
        assert_eq!(
            outcome,
            DrainOutcome::Completed {
                messages_drained: 0
            }
        );
        assert!(!t.is_session_draining(sid));
        let s = t.sessions.get(&sid).unwrap().lock().unwrap();
        assert!(
            s.is_closed(),
            "session should be in Closed state after completed drain"
        );
    }

    #[test]
    fn close_session_records_receipt_for_each_public_reason() {
        let cases = [
            (
                SessionCloseReason::AuthFailed,
                ClosureClass::RefusedPolicy,
                DrainResultClass::Force,
            ),
            (
                SessionCloseReason::ProtocolVersionMismatch,
                ClosureClass::RefusedPolicy,
                DrainResultClass::Force,
            ),
            (
                SessionCloseReason::LocalShutdown,
                ClosureClass::CleanDrain,
                DrainResultClass::Complete,
            ),
            (
                SessionCloseReason::PeerRemoved,
                ClosureClass::ForcedClose,
                DrainResultClass::Force,
            ),
            (
                SessionCloseReason::TransportError,
                ClosureClass::ForcedClose,
                DrainResultClass::Force,
            ),
            (
                SessionCloseReason::RdmaCarrierLost,
                ClosureClass::ForcedClose,
                DrainResultClass::Force,
            ),
            (
                SessionCloseReason::RdmaRegistrationFailure,
                ClosureClass::ForcedClose,
                DrainResultClass::Force,
            ),
        ];

        for (idx, (reason, closure_class, drain_result_class)) in cases.into_iter().enumerate() {
            let mut t = Transport::new(1);
            let sid = SessionId::new(idx as u64 + 1000);
            insert_established_session(&mut t, sid);

            t.close_session(sid, reason).unwrap();

            let receipt = t
                .session_closure_receipt(sid)
                .expect("close_session must record a closure receipt");
            assert_eq!(receipt.closure_class, closure_class);
            assert_eq!(receipt.drain_result_class, drain_result_class);
            assert_eq!(receipt.trigger_ref, reason.trigger_ref());
            assert_eq!(receipt.last_seq_acked, 0);
        }
    }

    #[test]
    fn transport_error_close_receipt_records_last_acknowledged_sequence() {
        let mut t = Transport::new(1);
        let sid = SessionId::new(2000);
        let mut session = make_established_session(sid);
        for seq in 1..=3 {
            assert_eq!(
                session.accept_recv_seq(crate::session::MessageSequenceNumber(seq)),
                crate::session::SeqReceiveOutcome::Accepted
            );
        }
        t.sessions
            .insert(sid, Arc::new(std::sync::Mutex::new(session)));

        t.close_session(sid, SessionCloseReason::TransportError)
            .unwrap();

        let receipt = t
            .session_closure_receipt(sid)
            .expect("transport-error close must record a closure receipt");
        assert_eq!(receipt.last_seq_acked, 3);
        assert_eq!(receipt.closure_class, ClosureClass::ForcedClose);
        assert_eq!(receipt.drain_result_class, DrainResultClass::Force);
    }

    #[test]
    fn already_closed_close_keeps_observable_receipt() {
        let mut t = Transport::new(1);
        let sid = SessionId::new(2001);
        insert_established_session(&mut t, sid);

        t.close_session(sid, SessionCloseReason::LocalShutdown)
            .unwrap();
        let first_receipt = t
            .session_closure_receipt(sid)
            .expect("first close must record a closure receipt")
            .clone();

        t.close_session(sid, SessionCloseReason::TransportError)
            .unwrap();

        assert_eq!(t.session_closure_receipts().len(), 1);
        let receipt = t
            .session_closure_receipt(sid)
            .expect("already-closed close must keep closure receipt evidence");
        assert_eq!(receipt, &first_receipt);
        assert_eq!(receipt.closure_class, ClosureClass::CleanDrain);
        assert_eq!(
            receipt.trigger_ref,
            SessionCloseReason::LocalShutdown.trigger_ref()
        );
    }

    // ---- graceful drain: is_session_draining tracking ----

    #[test]
    fn is_session_draining_false_when_not_draining() {
        let t = Transport::new(1);
        assert!(!t.is_session_draining(SessionId::new(1)));
    }

    // ---- graceful drain: sends rejected when reject_new_sends=true ----

    #[test]
    fn sends_rejected_when_draining_and_reject_new_sends_true() {
        let mut t = Transport::new(1);
        t.graceful_drain_config =
            GracefulDrainConfig::new(Duration::from_secs(10), Duration::from_millis(1), true);

        let sid = SessionId::new(1);
        let mut session = Session::new(
            sid,
            1,
            2,
            TransportAddr::Tcp("127.0.0.1:9001".parse().unwrap()),
            EndpointFamily::LocalEmbed,
            TransportBackendKind::Tcp,
        );
        session
            .transition(SessionState::Connecting {
                started_at: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Handshaking {
                started_at: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Bound {
                since: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::CohortAttached {
                since: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Established {
                since: HlcTimestamp::default(),
            })
            .unwrap();

        t.sessions
            .insert(sid, Arc::new(std::sync::Mutex::new(session)));

        t.draining_sessions
            .insert(sid, std::time::Instant::now() + Duration::from_secs(10));

        let result = t.send_message(sid, b"test");
        assert!(result.is_err());
    }

    // ---- graceful drain: sends allowed when reject_new_sends=false ----

    #[test]
    fn sends_allowed_when_reject_new_sends_false() {
        let mut t = Transport::new(1);
        t.graceful_drain_config =
            GracefulDrainConfig::new(Duration::from_secs(10), Duration::from_millis(1), false);

        let sid = SessionId::new(1);
        let mut session = Session::new(
            sid,
            1,
            2,
            TransportAddr::Tcp("127.0.0.1:9001".parse().unwrap()),
            EndpointFamily::LocalEmbed,
            TransportBackendKind::Tcp,
        );
        session
            .transition(SessionState::Connecting {
                started_at: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Handshaking {
                started_at: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Bound {
                since: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::CohortAttached {
                since: HlcTimestamp::default(),
            })
            .unwrap();
        session
            .transition(SessionState::Established {
                since: HlcTimestamp::default(),
            })
            .unwrap();

        t.sessions
            .insert(sid, Arc::new(std::sync::Mutex::new(session)));

        t.draining_sessions
            .insert(sid, std::time::Instant::now() + Duration::from_secs(10));

        let result = t.send_message(sid, b"test");
        if let Err(ref e) = result {
            let err_str = format!("{e:?}");
            assert!(
                !err_str.contains("draining"),
                "expected non-draining error, got: {err_str}"
            );
        }
    }
}

// -----------------------------------------------------------------------
// TDMA send-gate integration tests
// -----------------------------------------------------------------------

#[cfg(feature = "tdma")]
#[test]
fn tdma_gate_blocks_unregistered_session() {
    let mut transport = Transport::new(1);
    let gate = crate::tdma_gate::TdmaSendGate::new(
        4,
        std::time::Duration::from_millis(100),
        std::time::Duration::from_millis(10),
        std::time::Duration::from_millis(50),
    )
    .expect("valid gate config");
    transport.tdma_gate = Some(gate);

    let sid = SessionId::new(42);
    let result = transport.send_message(sid, b"hello");
    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = format!("{err:?}");
    assert!(
        err_msg.contains("not registered for TDMA gating"),
        "expected TDMA gating error, got: {err_msg}"
    );
}

#[cfg(feature = "tdma")]
#[test]
fn tdma_gate_recognizes_registered_session() {
    let mut transport = Transport::new(1);
    let mut gate = crate::tdma_gate::TdmaSendGate::new(
        4,
        std::time::Duration::from_millis(100),
        std::time::Duration::from_millis(10),
        std::time::Duration::from_millis(50),
    )
    .expect("valid gate config");

    let sid = SessionId::new(1);
    gate.register_session(sid, 42, std::time::Duration::ZERO);
    transport.tdma_gate = Some(gate);

    let result = transport.send_message(sid, b"hello");
    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = format!("{err:?}");
    assert!(
        !err_msg.contains("not registered for TDMA gating"),
        "registered session should not get unregistered error: {err_msg}"
    );
}
#[test]
fn tdma_gate_none_does_not_block_send() {
    let mut transport = Transport::new(1);
    // No gate set — should proceed past the gate check and fail on
    // connection lookup, NOT on TDMA.
    let sid = SessionId::new(99);
    let session = Session::new(
        sid,
        1,
        2,
        TransportAddr::Tcp("127.0.0.1:9901".parse().unwrap()),
        EndpointFamily::LocalEmbed,
        TransportBackendKind::Tcp,
    );
    transport
        .sessions
        .insert(sid, Arc::new(std::sync::Mutex::new(session)));

    let result = transport.send_message(sid, b"hello");
    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = format!("{err:?}");
    assert!(
        err_msg.contains("no active connection"),
        "expected connection error without gate, got: {err_msg}"
    );
}

#[test]
fn send_message_missing_session_fails() {
    let mut transport = Transport::new(1);
    let sid = SessionId::new(199);

    let result = transport.send_message(sid, b"hello");
    assert!(matches!(
        result,
        Err(TransportError::SessionNotFound { session_id }) if session_id == sid
    ));
}

// ── Session drain handle integration tests ────────────────────────────

#[tokio::test]
async fn session_drain_handle_store_and_retrieve() {
    let mut t = Transport::new(1);
    let sid = SessionId::new(100);
    let handle = Arc::new(crate::session_drain::SessionDrainHandle::with_defaults());

    // Initially no handle.
    assert!(t.session_drain_handle(sid).is_none());

    // Store and retrieve.
    t.set_session_drain_handle(sid, Arc::clone(&handle));
    assert!(t.session_drain_handle(sid).is_some());

    // Take removes it.
    let taken = t.take_session_drain_handle(sid);
    assert!(taken.is_some());
    assert!(t.session_drain_handle(sid).is_none());
}

#[tokio::test]
async fn session_drain_eviction_drains_handle() {
    use crate::session_drain::DrainError;

    let mut t = Transport::new(1);
    let sid = SessionId::new(101);
    let handle = Arc::new(crate::session_drain::SessionDrainHandle::with_defaults());

    // Create a pending token.
    let token = handle.send_with_token().unwrap();
    t.set_session_drain_handle(sid, Arc::clone(&handle));

    // Create a session and insert it.
    let session = Arc::new(std::sync::Mutex::new(Session::new(
        sid,
        1,
        2,
        TransportAddr::Tcp("127.0.0.1:9001".parse().unwrap()),
        EndpointFamily::LocalEmbed,
        TransportBackendKind::Tcp,
    )));
    t.sessions.insert(sid, session);

    // Close with PeerRemoved.
    t.close_session(sid, SessionCloseReason::PeerRemoved)
        .unwrap();

    // Drain handle should be resolved.
    assert!(handle.is_draining());
    let result = token.wait().await;
    assert_eq!(result, Err(DrainError::Evicted));

    // Handle should be removed from transport.
    assert!(t.session_drain_handle(sid).is_none());
}

#[tokio::test]
async fn session_drain_localshutdown_does_not_drain() {
    let mut t = Transport::new(1);
    let sid = SessionId::new(102);
    let handle = Arc::new(crate::session_drain::SessionDrainHandle::with_defaults());

    // Create a pending token.
    let token = handle.send_with_token().unwrap();
    assert_eq!(handle.in_flight_count(), 1);
    t.set_session_drain_handle(sid, Arc::clone(&handle));

    // Create a session and insert it.
    let session = Arc::new(std::sync::Mutex::new(Session::new(
        sid,
        1,
        2,
        TransportAddr::Tcp("127.0.0.1:9001".parse().unwrap()),
        EndpointFamily::LocalEmbed,
        TransportBackendKind::Tcp,
    )));
    t.sessions.insert(sid, session);

    // Close with LocalShutdown (non-eviction).
    t.close_session(sid, SessionCloseReason::LocalShutdown)
        .unwrap();

    // Drain handle should NOT be drained - token still pending.
    assert!(!handle.is_draining());
    assert_eq!(handle.in_flight_count(), 1);

    // Token can be completed manually.
    handle.complete(Ok(()));
    assert_eq!(token.wait().await, Ok(()));
}

#[tokio::test]
async fn session_drain_multiple_tokens_resolved_on_eviction() {
    use crate::session_drain::DrainError;

    let mut t = Transport::new(1);
    let sid = SessionId::new(103);
    let handle = Arc::new(crate::session_drain::SessionDrainHandle::with_defaults());

    let mut tokens = Vec::new();
    for _ in 0..8 {
        tokens.push(handle.send_with_token().unwrap());
    }
    t.set_session_drain_handle(sid, Arc::clone(&handle));

    let session = Arc::new(std::sync::Mutex::new(Session::new(
        sid,
        1,
        2,
        TransportAddr::Tcp("127.0.0.1:9001".parse().unwrap()),
        EndpointFamily::LocalEmbed,
        TransportBackendKind::Tcp,
    )));
    t.sessions.insert(sid, session);

    t.close_session(sid, SessionCloseReason::PeerRemoved)
        .unwrap();

    for token in tokens {
        assert_eq!(token.wait().await, Err(DrainError::Evicted));
    }
    assert_eq!(handle.in_flight_count(), 0);
}

#[test]
fn drain_session_returns_none_when_no_handle() {
    use crate::session_drain::DrainError;
    let mut t = Transport::new(1);
    let sid = SessionId::new(200);
    let result = t.drain_session(sid, DrainError::Evicted);
    assert!(result.is_none());
}

#[tokio::test]
async fn drain_session_drains_and_returns_handle() {
    use crate::session_drain::DrainError;

    let mut t = Transport::new(1);
    let sid = SessionId::new(201);
    let handle = Arc::new(crate::session_drain::SessionDrainHandle::with_defaults());

    let token = handle.send_with_token().unwrap();
    t.set_session_drain_handle(sid, Arc::clone(&handle));

    // drain_session should drain and return the handle.
    let returned = t.drain_session(sid, DrainError::Evicted);
    assert!(returned.is_some());
    assert!(handle.is_draining());

    let result = token.wait().await;
    assert_eq!(result, Err(DrainError::Evicted));

    // Handle is now removed; second call returns None.
    let second = t.drain_session(sid, DrainError::Evicted);
    assert!(second.is_none());
}

#[tokio::test]
async fn drain_session_then_close_session_is_safe() {
    use crate::session_drain::DrainError;

    let mut t = Transport::new(1);
    let sid = SessionId::new(202);
    let handle = Arc::new(crate::session_drain::SessionDrainHandle::with_defaults());

    let mut token = handle.send_with_token().unwrap();
    t.set_session_drain_handle(sid, Arc::clone(&handle));

    // Create a session and insert it.
    let session = Arc::new(std::sync::Mutex::new(Session::new(
        sid,
        1,
        2,
        TransportAddr::Tcp("127.0.0.1:9001".parse().unwrap()),
        EndpointFamily::LocalEmbed,
        TransportBackendKind::Tcp,
    )));
    t.sessions.insert(sid, session);

    // Phase 1: drain_session (called on SessionPolicy::Drain).
    let returned = t.drain_session(sid, DrainError::Evicted);
    assert!(returned.is_some());
    assert_eq!(token.try_wait(), Some(Err(DrainError::Evicted)));

    // Phase 2: close_session (called on SessionPolicy::Close / PeerRemoved).
    // Because drain_session already removed the handle, close_session's
    // PeerRemoved drain is a no-op (handle not found). This is safe.
    let result = t.close_session(sid, SessionCloseReason::PeerRemoved);
    assert!(result.is_ok());
}

// ------------------------------------------------------------------
// Outbound send-gate tests (#6181)
// ------------------------------------------------------------------

/// A test send gate that rejects all sends to peer 99.
#[allow(dead_code)]
struct TestSendGate {
    blocked: std::collections::BTreeSet<u64>,
}

impl TestSendGate {
    #[allow(dead_code)]
    fn new() -> Self {
        let mut blocked = std::collections::BTreeSet::new();
        blocked.insert(99);
        Self { blocked }
    }
}

impl SendGate for TestSendGate {
    fn can_send_to(&self, peer_id: crate::circuit_breaker::PeerId) -> bool {
        !self.blocked.contains(&peer_id)
    }
}

impl std::fmt::Debug for TestSendGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestSendGate").finish()
    }
}

#[test]
fn send_gate_accepts_roster_member() {
    let mut t = Transport::new(1);
    let sid = SessionId::new(301);

    let session = Arc::new(std::sync::Mutex::new(Session::new(
        sid,
        1,
        42,
        TransportAddr::Tcp("127.0.0.1:9101".parse().unwrap()),
        EndpointFamily::LocalEmbed,
        TransportBackendKind::Tcp,
    )));
    t.sessions.insert(sid, session);

    t.set_send_gate(Some(Arc::new(TestSendGate::new())));

    let result = t.send_message(sid, b"test");
    if let Err(TransportError::PeerNotInRoster { .. }) = result {
        panic!("peer 42 should not be blocked by the gate");
    }
}

#[test]
fn send_gate_rejects_non_roster_peer() {
    let mut t = Transport::new(1);
    let sid = SessionId::new(302);

    let session = Arc::new(std::sync::Mutex::new(Session::new(
        sid,
        1,
        99,
        TransportAddr::Tcp("127.0.0.1:9102".parse().unwrap()),
        EndpointFamily::LocalEmbed,
        TransportBackendKind::Tcp,
    )));
    t.sessions.insert(sid, session);

    t.set_send_gate(Some(Arc::new(TestSendGate::new())));

    let result = t.send_message(sid, b"should be rejected");
    match result {
        Err(TransportError::PeerNotInRoster {
            peer_id,
            session_id,
        }) => {
            assert_eq!(peer_id, 99);
            assert_eq!(session_id, sid);
        }
        other => panic!("expected PeerNotInRoster for peer 99, got: {other:?}"),
    }
}

#[test]
fn send_gate_none_allows_all_sends() {
    let mut t = Transport::new(1);
    let sid = SessionId::new(303);

    let session = Arc::new(std::sync::Mutex::new(Session::new(
        sid,
        1,
        99,
        TransportAddr::Tcp("127.0.0.1:9103".parse().unwrap()),
        EndpointFamily::LocalEmbed,
        TransportBackendKind::Tcp,
    )));
    t.sessions.insert(sid, session);

    t.set_send_gate(None);

    let result = t.send_message(sid, b"test");
    if let Err(TransportError::PeerNotInRoster { .. }) = result {
        panic!("no gate set, should not reject on roster");
    }
}

#[test]
fn set_send_gate_stores_and_replaces() {
    let mut t = Transport::new(1);
    let sid = SessionId::new(304);

    let session = Arc::new(std::sync::Mutex::new(Session::new(
        sid,
        1,
        99,
        TransportAddr::Tcp("127.0.0.1:9104".parse().unwrap()),
        EndpointFamily::LocalEmbed,
        TransportBackendKind::Tcp,
    )));
    t.sessions.insert(sid, session);

    t.set_send_gate(Some(Arc::new(TestSendGate::new())));
    let result = t.send_message(sid, b"x");
    assert!(matches!(
        result,
        Err(TransportError::PeerNotInRoster { .. })
    ));

    t.set_send_gate(None);
    let result = t.send_message(sid, b"x");
    if let Err(TransportError::PeerNotInRoster { .. }) = result {
        panic!("gate removed, should not reject");
    }
}

// ── DataPathCarrierSummary::disclosure_carrier_name ──────────────

#[test]
fn disclosure_carrier_name_rdma_when_rdma_sessions_present() {
    let s = DataPathCarrierSummary {
        rdma_sessions: 1,
        ..Default::default()
    };
    assert_eq!(s.disclosure_carrier_name(), "rdma");
}

#[test]
fn disclosure_carrier_name_tcp_when_only_tcp_sessions() {
    let s = DataPathCarrierSummary {
        tcp_sessions: 2,
        ..Default::default()
    };
    assert_eq!(s.disclosure_carrier_name(), "tcp");
}

#[test]
fn disclosure_carrier_name_tls_when_only_tls() {
    let s = DataPathCarrierSummary {
        tls_sessions: 1,
        ..Default::default()
    };
    assert_eq!(s.disclosure_carrier_name(), "tls");
}

#[test]
fn disclosure_carrier_name_none_when_no_sessions() {
    let s = DataPathCarrierSummary::default();
    assert_eq!(s.disclosure_carrier_name(), "none");
}

#[test]
fn disclosure_carrier_name_rdma_priority_over_tcp() {
    let s = DataPathCarrierSummary {
        rdma_sessions: 1,
        tcp_sessions: 5,
        ..Default::default()
    };
    assert_eq!(s.disclosure_carrier_name(), "rdma");
}

#[test]
fn disclosure_carrier_name_rdma_shipper_counts() {
    let s = DataPathCarrierSummary {
        rdma_shippers: 1,
        ..Default::default()
    };
    assert_eq!(s.disclosure_carrier_name(), "rdma");
}

#[test]
fn disclosure_carrier_name_tcp_shipper_no_sessions() {
    let s = DataPathCarrierSummary {
        tcp_shippers: 3,
        ..Default::default()
    };
    assert_eq!(s.disclosure_carrier_name(), "tcp");
}
