// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Clustered mounted-filesystem client over authenticated inline VFS_RPC.
//!
//! The public connector authenticates the configured Pool lease authority,
//! observes the current writer/epoch/fence without receiving a lease token,
//! selects that node from an exact provisioned endpoint/identity map, and
//! requires the owner-issued preface to match the observation.
//! If one inline request loses its transport before the response arrives, the
//! client opens one fresh mutually authenticated session and replays the exact
//! request and operation ID only when the full owner authority is unchanged.
//! Any Pool, dataset, writer, term, or epoch movement fails closed.

use std::collections::{hash_map::RandomState, BTreeMap};
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tidefs_auth::{NodeKeyStore, NodePrivateCredential, NodePublicIdentity};
use tidefs_transport::{
    EndpointFamily, NodeInfo, SessionCloseReason, SessionId, SessionState, TcpTransport, Transport,
    TransportAddr, TransportError, TransportSessionSet,
};
use tidefs_types_vfs_core::{
    DirHandleId, EngineDirHandle, EngineFileHandle, Errno, FileHandleId, InodeId, RequestCtx,
};
use tidefs_vfs_engine::operation as engine_op;
use tidefs_vfs_engine::{VfsDispatch, VfsOperation, VfsResponse};
use tidefs_vfs_rpc::transport_adapter::{
    decode_session_authority_frame, VfsRpcEnvelopeContext, VfsRpcInboundFrame,
    VfsRpcSessionAuthority, VfsRpcSessionAuthorityError, VfsRpcTransportAdapter,
    VfsRpcTransportAdapterConfig,
};
use tidefs_vfs_rpc::{
    DatasetId, InlineOrBulk, OpId, PeerId, VfsRpcClient, VfsRpcCredentials, VfsRpcHandle,
    VfsRpcHandleType, VfsRpcRequest, VfsRpcRequestPayload, VfsRpcResponse, VfsRpcResponsePayload,
    DEFAULT_INLINE_THRESHOLD,
};

use crate::cluster_pool_owner_observer::{observe_pool_owner, AuthenticatedPoolOwnerObservation};

const CLIENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CLIENT_AUTHORITY_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_RETRY_INTERVAL: Duration = Duration::from_millis(1);
const CLIENT_RECONNECT_ATTEMPTS: usize = 1;

/// Provisioned VFS_RPC endpoint and exact public identity for one candidate.
#[derive(Clone, Debug)]
pub struct ClusterVfsRpcOwnerCandidate {
    /// Provisioned TCP endpoint for this exact node identity.
    pub addr: SocketAddr,
    /// Exact public identity required at the endpoint.
    pub identity: NodePublicIdentity,
}

impl ClusterVfsRpcOwnerCandidate {
    #[must_use]
    pub const fn new(addr: SocketAddr, identity: NodePublicIdentity) -> Self {
        Self { addr, identity }
    }
}

/// Operator-provisioned inputs for authenticated owner discovery.
///
/// The candidate list provisions connectivity and trust only. The lease
/// authority observation, not list ordering or a direct caller choice,
/// selects the current owner, epoch, and writer-fence generation.
#[derive(Debug)]
pub struct ClusterVfsRpcClientConfig {
    authority_addr: SocketAddr,
    expected_pool_guid: [u8; 16],
    local_credential: NodePrivateCredential,
    trusted_authority_identity: NodePublicIdentity,
    owner_candidates: Vec<ClusterVfsRpcOwnerCandidate>,
    authority_lost: Arc<AtomicBool>,
}

impl ClusterVfsRpcClientConfig {
    #[must_use]
    pub fn new(
        authority_addr: SocketAddr,
        expected_pool_guid: [u8; 16],
        local_credential: NodePrivateCredential,
        trusted_authority_identity: NodePublicIdentity,
        owner_candidates: Vec<ClusterVfsRpcOwnerCandidate>,
    ) -> Self {
        Self {
            authority_addr,
            expected_pool_guid,
            local_credential,
            trusted_authority_identity,
            owner_candidates,
            authority_lost: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Install the terminal signal owned by the clustered FUSE mount.
    #[must_use]
    pub fn with_authority_loss_signal(mut self, authority_lost: Arc<AtomicBool>) -> Self {
        self.authority_lost = authority_lost;
        self
    }
}

/// Construction or explicit-teardown failure at the authenticated client
/// boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClusterVfsRpcClientError {
    NonControlTransport,
    MissingSession(SessionId),
    SessionLockPoisoned(SessionId),
    SessionNotEstablished(SessionId),
    NonControlSession(SessionId),
    LocalNodeMismatch {
        transport_node: u64,
        session_node: u64,
    },
    WrongPeer {
        expected_writer: u64,
        authenticated_peer: u64,
    },
    WrongPool {
        expected: [u8; 16],
        found: [u8; 16],
    },
    ExpectedPoolGuidZero,
    MissingOwnerCandidates,
    InvalidOwnerCandidate(u64),
    DuplicateOwnerCandidate(u64),
    ConflictingNodeIdentity(u64),
    OwnerObservation(String),
    ObservedOwnerNotProvisioned(u64),
    ObservedAuthorityMismatch {
        observed_owner: u64,
        observed_term: u64,
        observed_epoch: u64,
        preface_owner: u64,
        preface_term: u64,
        preface_epoch: u64,
    },
    Credential(String),
    TrustStore(String),
    Transport(String),
    EpochMoved {
        authenticated_peer: u64,
        attempted_epoch: u64,
        required_epoch: u64,
    },
    MissingActiveConnection(SessionId),
    UnauthenticatedSession(SessionId),
    ConfigureNonblocking(String),
    AuthorityTimeout(SessionId),
    AuthorityTransport(String),
    MalformedAuthority(VfsRpcSessionAuthorityError),
    AuthorityDeadlineExpired {
        remaining_ms: u64,
    },
    AuthorityDeadlineOverflow {
        remaining_ms: u64,
    },
    CloseFailed(String),
}

impl fmt::Display for ClusterVfsRpcClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonControlTransport => write!(f, "cluster VFS_RPC requires a Control transport"),
            Self::MissingSession(session) => {
                write!(f, "cluster VFS_RPC session {session} does not exist")
            }
            Self::SessionLockPoisoned(session) => {
                write!(f, "cluster VFS_RPC session {session} lock is poisoned")
            }
            Self::SessionNotEstablished(session) => {
                write!(f, "cluster VFS_RPC session {session} is not established")
            }
            Self::NonControlSession(session) => {
                write!(f, "cluster VFS_RPC session {session} is not a Control session")
            }
            Self::LocalNodeMismatch {
                transport_node,
                session_node,
            } => write!(
                f,
                "cluster VFS_RPC local-node mismatch: transport {transport_node}, session {session_node}"
            ),
            Self::WrongPeer {
                expected_writer,
                authenticated_peer,
            } => write!(
                f,
                "cluster VFS_RPC authenticated peer {authenticated_peer} is not admitted writer {expected_writer}"
            ),
            Self::WrongPool { expected, found } => write!(
                f,
                "cluster VFS_RPC owner Pool GUID {found:02x?} does not match expected {expected:02x?}"
            ),
            Self::ExpectedPoolGuidZero => {
                write!(f, "cluster VFS_RPC expected Pool GUID must be nonzero")
            }
            Self::MissingOwnerCandidates => {
                write!(f, "cluster VFS_RPC requires at least one provisioned owner candidate")
            }
            Self::InvalidOwnerCandidate(node) => write!(
                f,
                "cluster VFS_RPC provisioned candidate has invalid node ID {node}"
            ),
            Self::DuplicateOwnerCandidate(node) => write!(
                f,
                "cluster VFS_RPC has more than one provisioned candidate for node {node}"
            ),
            Self::ConflictingNodeIdentity(node) => write!(
                f,
                "cluster VFS_RPC has conflicting provisioned identities for node {node}"
            ),
            Self::OwnerObservation(error) => {
                write!(f, "observe current Pool owner: {error}")
            }
            Self::ObservedOwnerNotProvisioned(node) => write!(
                f,
                "Pool lease authority selected owner node {node}, but no exact VFS_RPC candidate is provisioned"
            ),
            Self::ObservedAuthorityMismatch {
                observed_owner,
                observed_term,
                observed_epoch,
                preface_owner,
                preface_term,
                preface_epoch,
            } => write!(
                f,
                "cluster VFS_RPC owner preface {preface_owner}/{preface_term}/{preface_epoch} does not match lease-authority observation {observed_owner}/{observed_term}/{observed_epoch}"
            ),
            Self::Credential(error) => {
                write!(f, "load cluster VFS_RPC client credential: {error}")
            }
            Self::TrustStore(error) => {
                write!(f, "configure cluster VFS_RPC trust: {error}")
            }
            Self::Transport(error) => write!(f, "connect cluster VFS_RPC owner: {error}"),
            Self::EpochMoved {
                authenticated_peer,
                attempted_epoch,
                required_epoch,
            } => write!(
                f,
                "cluster VFS_RPC owner {authenticated_peer} moved from authenticated epoch {attempted_epoch} to {required_epoch} before the exact retry"
            ),
            Self::MissingActiveConnection(session) => write!(
                f,
                "cluster VFS_RPC session {session} has no active transport connection"
            ),
            Self::UnauthenticatedSession(session) => write!(
                f,
                "cluster VFS_RPC session {session} lacks authenticated confidentiality"
            ),
            Self::ConfigureNonblocking(error) => {
                write!(f, "configure bounded cluster VFS_RPC receive: {error}")
            }
            Self::AuthorityTimeout(session) => write!(
                f,
                "cluster VFS_RPC session {session} timed out waiting for owner authority"
            ),
            Self::AuthorityTransport(error) => {
                write!(f, "receive cluster VFS_RPC owner authority: {error}")
            }
            Self::MalformedAuthority(error) => {
                write!(f, "refuse cluster VFS_RPC owner authority: {error}")
            }
            Self::AuthorityDeadlineExpired { remaining_ms } => write!(
                f,
                "cluster VFS_RPC owner authority expired during authenticated observation of its {remaining_ms}ms remaining lifetime"
            ),
            Self::AuthorityDeadlineOverflow { remaining_ms } => write!(
                f,
                "cluster VFS_RPC owner authority lifetime {remaining_ms}ms exceeds the local monotonic clock"
            ),
            Self::CloseFailed(error) => write!(f, "close cluster VFS_RPC client: {error}"),
        }
    }
}

impl std::error::Error for ClusterVfsRpcClientError {}

/// Synchronous dispatch client installed behind [`FuseVfsAdapter`].
///
/// [`FuseVfsAdapter`]: crate::fuse_vfs_adapter::FuseVfsAdapter
#[derive(Clone)]
pub struct ClusterVfsRpcClient {
    state: Arc<Mutex<ClientState>>,
    authority_lost: Arc<AtomicBool>,
}

impl ClusterVfsRpcClient {
    /// Discover and connect to the current authority-selected Pool owner.
    pub fn connect(config: ClusterVfsRpcClientConfig) -> Result<Self, ClusterVfsRpcClientError> {
        if config.expected_pool_guid == [0; 16] {
            return Err(ClusterVfsRpcClientError::ExpectedPoolGuidZero);
        }
        validate_client_config(&config)?;
        let observation = observe_pool_owner(
            config.authority_addr,
            config.expected_pool_guid,
            &config.local_credential,
            &config.trusted_authority_identity,
        )
        .map_err(ClusterVfsRpcClientError::OwnerObservation)?;
        let owner = owner_candidate(&config, observation.owner_node_id)?;
        let observation_remaining = observation.remaining();
        if observation_remaining.is_zero() {
            return Err(ClusterVfsRpcClientError::AuthorityDeadlineExpired { remaining_ms: 0 });
        }
        let authority_observation_started = Instant::now();
        let (mut transport, session_id) = connect_transport(
            &config,
            owner,
            observation.membership_epoch,
            observation_remaining.min(CLIENT_AUTHORITY_TIMEOUT),
        )?;
        match transport.perform_handshake(session_id) {
            Ok(()) => Self::from_authenticated_transport(
                transport,
                session_id,
                config.expected_pool_guid,
                Some(config),
                authority_observation_started,
                Some(observation),
            ),
            Err(TransportError::AttestedEpochMismatch {
                authenticated_peer,
                proposed_epoch,
                required_epoch,
                ..
            }) => Err(ClusterVfsRpcClientError::EpochMoved {
                authenticated_peer,
                attempted_epoch: proposed_epoch,
                required_epoch,
            }),
            Err(error) => Err(ClusterVfsRpcClientError::Transport(error.to_string())),
        }
    }

    /// Consume an already-authenticated Control transport/session and derive
    /// request authority from its owner-issued preface.
    pub fn new(
        transport: Transport,
        session_id: SessionId,
        expected_pool_guid: [u8; 16],
    ) -> Result<Self, ClusterVfsRpcClientError> {
        Self::from_authenticated_transport(
            transport,
            session_id,
            expected_pool_guid,
            None,
            Instant::now(),
            None,
        )
    }

    fn from_authenticated_transport(
        mut transport: Transport,
        session_id: SessionId,
        expected_pool_guid: [u8; 16],
        reconnect_config: Option<ClusterVfsRpcClientConfig>,
        authority_observation_started: Instant,
        expected_observation: Option<AuthenticatedPoolOwnerObservation>,
    ) -> Result<Self, ClusterVfsRpcClientError> {
        let authenticated_peer = validate_construction_session(&transport, session_id)?;
        transport
            .set_nonblocking(true)
            .map_err(|error| ClusterVfsRpcClientError::ConfigureNonblocking(error.to_string()))?;
        let authority = receive_session_authority(
            &mut transport,
            session_id,
            Instant::now() + CLIENT_AUTHORITY_TIMEOUT,
        )?;
        authority
            .validate_for_client(expected_pool_guid, authenticated_peer)
            .map_err(map_session_authority_error)?;
        if let Some(observation) = expected_observation {
            if observation.pool_guid != expected_pool_guid
                || observation.owner_node_id != authority.writer_node()
                || observation.owner_node_id != authenticated_peer
                || observation.membership_epoch != authority.epoch()
                || observation.write_fence_generation != authority.term()
            {
                return Err(ClusterVfsRpcClientError::ObservedAuthorityMismatch {
                    observed_owner: observation.owner_node_id,
                    observed_term: observation.write_fence_generation,
                    observed_epoch: observation.membership_epoch,
                    preface_owner: authority.writer_node(),
                    preface_term: authority.term(),
                    preface_epoch: authority.epoch(),
                });
            }
            if observation.remaining().is_zero() {
                return Err(ClusterVfsRpcClientError::AuthorityDeadlineExpired { remaining_ms: 0 });
            }
        }
        let (mut authority_valid_until, mut next_authority_refresh) =
            authority_schedule(authority_observation_started, authority)?;
        if let Some(observation) = expected_observation {
            authority_valid_until = authority_valid_until.min(observation.valid_until);
            let now = Instant::now();
            let remaining = authority_valid_until.saturating_duration_since(now);
            if remaining.is_zero() {
                return Err(ClusterVfsRpcClientError::AuthorityDeadlineExpired {
                    remaining_ms: authority.lease_remaining_ms(),
                });
            }
            next_authority_refresh = now.checked_add(remaining / 2).unwrap_or(now);
        }

        let writer = authority.writer_node();
        let dataset_id = authority.dataset_id();
        let local_node = transport.local_node_id;
        let authority_lost = reconnect_config
            .as_ref()
            .map(|config| Arc::clone(&config.authority_lost))
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
        let mut sessions = TransportSessionSet::new();
        sessions.add_binding_with_epoch(writer, session_id, authority.epoch());
        sessions.mark_healthy(session_id);

        Ok(Self {
            authority_lost: Arc::clone(&authority_lost),
            state: Arc::new(Mutex::new(ClientState {
                transport,
                session_id,
                local_node,
                writer,
                dataset_id,
                rpc: VfsRpcClient::new_with_initial_op_id(
                    writer,
                    dataset_id,
                    authority.term(),
                    authority.epoch(),
                    randomized_operation_id(local_node, authority),
                    1,
                    Duration::from_millis(250),
                ),
                adapter: VfsRpcTransportAdapter::new(
                    VfsRpcTransportAdapterConfig {
                        request_timeout: CLIENT_REQUEST_TIMEOUT,
                        ..VfsRpcTransportAdapterConfig::default()
                    },
                    sessions,
                ),
                next_sequence: 0,
                files: BTreeMap::new(),
                directories: BTreeMap::new(),
                closed: false,
                authority,
                authority_valid_until,
                next_authority_refresh,
                reconnect_config,
                authority_lost,
            })),
        })
    }

    /// Refresh or expire the authenticated owner authority without requiring
    /// a filesystem request from the mounted frontend.
    pub fn poll_authority(&self) -> Result<(), Errno> {
        let Ok(mut state) = self.state.lock() else {
            self.authority_lost.store(true, Ordering::Release);
            return Err(Errno::ESTALE);
        };
        state.poll_authority()
    }

    /// Time until the next authority refresh or terminal deadline check.
    #[must_use]
    pub fn authority_poll_wait(&self) -> Duration {
        match self.state.lock() {
            Ok(state) => state.authority_poll_wait(),
            Err(_) => {
                self.authority_lost.store(true, Ordering::Release);
                Duration::ZERO
            }
        }
    }

    /// Close the client session before the owner/Pool lifecycle is torn down.
    pub fn close(&self) -> Result<(), ClusterVfsRpcClientError> {
        let mut state = self.state.lock().map_err(|_| {
            self.authority_lost.store(true, Ordering::Release);
            ClusterVfsRpcClientError::SessionLockPoisoned(SessionId::new(0))
        })?;
        state.close().map_err(|error| {
            ClusterVfsRpcClientError::CloseFailed(format!("session {}: {error}", state.session_id))
        })
    }
}

fn validate_client_config(
    config: &ClusterVfsRpcClientConfig,
) -> Result<(), ClusterVfsRpcClientError> {
    if config.owner_candidates.is_empty() {
        return Err(ClusterVfsRpcClientError::MissingOwnerCandidates);
    }
    let local_identity = config.local_credential.public_identity().into_identity();
    let mut identities = vec![
        &local_identity,
        config.trusted_authority_identity.identity(),
    ];
    let mut candidate_nodes = std::collections::BTreeSet::new();
    for candidate in &config.owner_candidates {
        let node = candidate.identity.node_id();
        if node == 0 {
            return Err(ClusterVfsRpcClientError::InvalidOwnerCandidate(node));
        }
        if !candidate_nodes.insert(node) {
            return Err(ClusterVfsRpcClientError::DuplicateOwnerCandidate(node));
        }
        identities.push(candidate.identity.identity());
    }
    for (index, left) in identities.iter().enumerate() {
        for right in &identities[index + 1..] {
            if left.node_id == right.node_id && left != right {
                return Err(ClusterVfsRpcClientError::ConflictingNodeIdentity(
                    left.node_id,
                ));
            }
        }
    }
    Ok(())
}

fn owner_candidate(
    config: &ClusterVfsRpcClientConfig,
    owner_node_id: u64,
) -> Result<&ClusterVfsRpcOwnerCandidate, ClusterVfsRpcClientError> {
    config
        .owner_candidates
        .iter()
        .find(|candidate| candidate.identity.node_id() == owner_node_id)
        .ok_or(ClusterVfsRpcClientError::ObservedOwnerNotProvisioned(
            owner_node_id,
        ))
}

fn connect_transport(
    config: &ClusterVfsRpcClientConfig,
    owner: &ClusterVfsRpcOwnerCandidate,
    epoch: u64,
    timeout: Duration,
) -> Result<(Transport, SessionId), ClusterVfsRpcClientError> {
    let local_node = config.local_credential.node_id();
    let owner_node = owner.identity.node_id();
    let local_identity = config.local_credential.public_identity().into_identity();
    let mut known_identities = NodeKeyStore::new();
    known_identities
        .register(local_identity.clone())
        .map_err(|error| ClusterVfsRpcClientError::TrustStore(error.to_string()))?;
    known_identities
        .register(owner.identity.identity().clone())
        .map_err(|error| ClusterVfsRpcClientError::TrustStore(error.to_string()))?;
    let local_keypair = config
        .local_credential
        .keypair()
        .map_err(|error| ClusterVfsRpcClientError::Credential(error.to_string()))?;
    let mut transport =
        Transport::with_backend(local_node, Box::new(TcpTransport::new(timeout, timeout)))
            .with_attestation(local_keypair, local_identity)
            .with_known_identities(known_identities)
            .with_epoch(epoch);
    transport.set_endpoint_family(EndpointFamily::Control);
    transport.set_attestation_bootstrap_from_handshake(false);
    transport.add_node(NodeInfo::new(
        owner_node,
        vec![TransportAddr::Tcp(owner.addr)],
        epoch,
    ));
    let session_id = transport
        .connect(owner_node)
        .map_err(|error| ClusterVfsRpcClientError::Transport(error.to_string()))?;
    Ok((transport, session_id))
}

fn randomized_operation_id(local_node: u64, authority: VfsRpcSessionAuthority) -> OpId {
    let randomized = RandomState::new();
    let mut attempt = 0_u64;
    loop {
        let mut hasher = randomized.build_hasher();
        hasher.write(b"tidefs-vfs-rpc-op-incarnation-v1");
        hasher.write_u64(local_node);
        hasher.write_u64(authority.writer_node());
        hasher.write(&authority.dataset_id().0.to_le_bytes());
        hasher.write_u64(authority.term());
        hasher.write_u64(authority.epoch());
        hasher.write_u64(attempt);
        let op_id = hasher.finish();
        if op_id != 0 {
            return OpId(op_id);
        }
        attempt = attempt.wrapping_add(1);
    }
}

fn authority_schedule(
    observation_started: Instant,
    authority: VfsRpcSessionAuthority,
) -> Result<(Instant, Instant), ClusterVfsRpcClientError> {
    let remaining_ms = authority.lease_remaining_ms();
    let valid_until = observation_started
        .checked_add(Duration::from_millis(remaining_ms))
        .ok_or(ClusterVfsRpcClientError::AuthorityDeadlineOverflow { remaining_ms })?;
    let now = Instant::now();
    let remaining = valid_until.saturating_duration_since(now);
    if remaining.is_zero() {
        return Err(ClusterVfsRpcClientError::AuthorityDeadlineExpired { remaining_ms });
    }
    let next_refresh = now.checked_add(remaining / 2).unwrap_or(now);
    Ok((valid_until, next_refresh))
}

impl VfsDispatch for ClusterVfsRpcClient {
    fn dispatch(&self, operation: VfsOperation) -> Result<VfsResponse, Errno> {
        let Ok(mut state) = self.state.lock() else {
            self.authority_lost.store(true, Ordering::Release);
            return Err(Errno::ESTALE);
        };
        state.dispatch(operation)
    }
}

#[derive(Clone)]
struct FileHandleRecord {
    local: EngineFileHandle,
    remote: VfsRpcHandle,
    credentials: VfsRpcCredentials,
}

#[derive(Clone)]
struct DirHandleRecord {
    local: EngineDirHandle,
    remote: VfsRpcHandle,
    credentials: VfsRpcCredentials,
}

struct ClientState {
    transport: Transport,
    session_id: SessionId,
    local_node: u64,
    writer: u64,
    dataset_id: DatasetId,
    rpc: VfsRpcClient,
    adapter: VfsRpcTransportAdapter,
    next_sequence: u64,
    files: BTreeMap<FileHandleId, FileHandleRecord>,
    directories: BTreeMap<DirHandleId, DirHandleRecord>,
    closed: bool,
    authority: VfsRpcSessionAuthority,
    authority_valid_until: Instant,
    next_authority_refresh: Instant,
    reconnect_config: Option<ClusterVfsRpcClientConfig>,
    authority_lost: Arc<AtomicBool>,
}

impl ClientState {
    fn dispatch(&mut self, operation: VfsOperation) -> Result<VfsResponse, Errno> {
        if self.authority_lost.load(Ordering::Acquire) {
            return Err(Errno::ESTALE);
        }
        self.ensure_authority_live()?;
        use engine_op::{
            GetRootInodeResponse, InodeAttrResponse, OpenDirResponse, OpenResponse,
            ReadDirResponse, ReadResponse, StatFsResponse, UnitResponse, WriteResponse,
        };

        match operation {
            VfsOperation::GetRootInode(request) => {
                let payload = self.call(
                    VfsRpcRequestPayload::GetRoot,
                    credentials(self.local_node, &request.ctx),
                )?;
                match payload {
                    VfsRpcResponsePayload::RootInode(inode) if inode.get() != 0 => {
                        Ok(VfsResponse::GetRootInode(GetRootInodeResponse { inode }))
                    }
                    _ => Err(Errno::EPROTO),
                }
            }
            VfsOperation::Lookup(request) => {
                let payload = self.call(
                    VfsRpcRequestPayload::Lookup {
                        parent: request.parent,
                        name: request.name,
                    },
                    credentials(self.local_node, &request.ctx),
                )?;
                match payload {
                    VfsRpcResponsePayload::Lookup { inode, attr }
                        if inode == attr.inode_id && inode.get() != 0 =>
                    {
                        Ok(VfsResponse::InodeAttr(InodeAttrResponse { attr }))
                    }
                    _ => Err(Errno::EPROTO),
                }
            }
            VfsOperation::GetAttr(request) => {
                if let Some(handle) = request.handle.as_ref() {
                    self.resolve_file(handle)?;
                }
                let payload = self.call(
                    VfsRpcRequestPayload::Getattr {
                        inode: request.inode,
                    },
                    credentials(self.local_node, &request.ctx),
                )?;
                match payload {
                    VfsRpcResponsePayload::Attr(attr) if attr.inode_id == request.inode => {
                        Ok(VfsResponse::InodeAttr(InodeAttrResponse { attr }))
                    }
                    _ => Err(Errno::EPROTO),
                }
            }
            VfsOperation::Create(request) => self.create(
                request.parent,
                request.name,
                request.mode,
                request.flags,
                request.ctx,
            ),
            VfsOperation::Mkdir(request) => {
                let payload = self.call(
                    VfsRpcRequestPayload::Mkdir {
                        parent: request.parent,
                        name: request.name,
                        mode: request.mode,
                    },
                    credentials(self.local_node, &request.ctx),
                )?;
                match payload {
                    VfsRpcResponsePayload::Attr(attr) if attr.inode_id.get() != 0 => {
                        Ok(VfsResponse::InodeAttr(InodeAttrResponse { attr }))
                    }
                    _ => Err(Errno::EPROTO),
                }
            }
            VfsOperation::Unlink(request) => {
                let payload = self.call(
                    VfsRpcRequestPayload::Unlink {
                        parent: request.parent,
                        name: request.name,
                    },
                    credentials(self.local_node, &request.ctx),
                )?;
                expect_empty(payload)?;
                Ok(VfsResponse::Unit(UnitResponse))
            }
            VfsOperation::Rmdir(request) => {
                let payload = self.call(
                    VfsRpcRequestPayload::Rmdir {
                        parent: request.parent,
                        name: request.name,
                    },
                    credentials(self.local_node, &request.ctx),
                )?;
                expect_empty(payload)?;
                Ok(VfsResponse::Unit(UnitResponse))
            }
            VfsOperation::Rename(request) => {
                let payload = self.call(
                    VfsRpcRequestPayload::Rename {
                        old_parent: request.old_parent,
                        old_name: request.old_name,
                        new_parent: request.new_parent,
                        new_name: request.new_name,
                        flags: request.flags,
                    },
                    credentials(self.local_node, &request.ctx),
                )?;
                expect_empty(payload)?;
                Ok(VfsResponse::Unit(UnitResponse))
            }
            VfsOperation::Link(request) => {
                let payload = self.call(
                    VfsRpcRequestPayload::Link {
                        inode: request.target,
                        new_parent: request.new_parent,
                        new_name: request.new_name,
                    },
                    credentials(self.local_node, &request.ctx),
                )?;
                match payload {
                    VfsRpcResponsePayload::Attr(attr) if attr.inode_id == request.target => {
                        Ok(VfsResponse::InodeAttr(InodeAttrResponse { attr }))
                    }
                    _ => Err(Errno::EPROTO),
                }
            }
            VfsOperation::Open(request) => {
                let caller = credentials(self.local_node, &request.ctx);
                let payload = self.call(
                    VfsRpcRequestPayload::Open {
                        inode: request.inode,
                        flags: request.flags,
                        lock_owner: 0,
                    },
                    caller.clone(),
                )?;
                match payload {
                    VfsRpcResponsePayload::FileHandle(remote) if remote.inode == request.inode => {
                        let local = self.register_file(remote, request.flags, caller)?;
                        Ok(VfsResponse::Open(OpenResponse { fh: local }))
                    }
                    _ => Err(Errno::EPROTO),
                }
            }
            VfsOperation::Read(request) => {
                if request.size as usize > DEFAULT_INLINE_THRESHOLD {
                    return Err(Errno::EOPNOTSUPP);
                }
                let remote = self.resolve_file(&request.fh)?.remote.clone();
                let payload = self.call(
                    VfsRpcRequestPayload::Read {
                        handle: remote,
                        offset: request.offset,
                        length: u64::from(request.size),
                    },
                    credentials(self.local_node, &request.ctx),
                )?;
                match payload {
                    VfsRpcResponsePayload::Data(InlineOrBulk::Inline(data))
                        if data.len() <= request.size as usize =>
                    {
                        Ok(VfsResponse::Read(ReadResponse { data }))
                    }
                    VfsRpcResponsePayload::Data(InlineOrBulk::Bulk { .. }) => {
                        Err(Errno::EOPNOTSUPP)
                    }
                    _ => Err(Errno::EPROTO),
                }
            }
            VfsOperation::Write(request) => {
                if request.data.len() > DEFAULT_INLINE_THRESHOLD {
                    return Err(Errno::EOPNOTSUPP);
                }
                let remote = self.resolve_file(&request.fh)?.remote.clone();
                let expected = request.data.len();
                let payload = self.call(
                    VfsRpcRequestPayload::Write {
                        handle: remote,
                        offset: request.offset,
                        data: InlineOrBulk::Inline(request.data),
                    },
                    credentials(self.local_node, &request.ctx),
                )?;
                match payload {
                    VfsRpcResponsePayload::BytesWritten(written)
                        if written <= expected as u64 && written <= u64::from(u32::MAX) =>
                    {
                        Ok(VfsResponse::Write(WriteResponse {
                            written: written as u32,
                        }))
                    }
                    _ => Err(Errno::EPROTO),
                }
            }
            VfsOperation::Flush(request) => {
                let remote = self.resolve_file(&request.fh)?.remote.clone();
                let payload = self.call(
                    VfsRpcRequestPayload::Flush {
                        handle: remote,
                        lock_owner: request.fh.lock_owner,
                    },
                    credentials(self.local_node, &request.ctx),
                )?;
                expect_empty(payload)?;
                Ok(VfsResponse::Unit(UnitResponse))
            }
            VfsOperation::Fsync(request) => {
                let remote = self.resolve_file(&request.fh)?.remote.clone();
                let payload = self.call(
                    VfsRpcRequestPayload::Fsync {
                        handle: remote,
                        datasync: request.datasync,
                    },
                    credentials(self.local_node, &request.ctx),
                )?;
                expect_empty(payload)?;
                Ok(VfsResponse::Unit(UnitResponse))
            }
            VfsOperation::Release(request) => {
                let record = self.resolve_file(&request.fh)?.clone();
                let payload = self.call(
                    VfsRpcRequestPayload::Release {
                        handle: record.remote,
                        flags: request.fh.open_flags,
                    },
                    record.credentials,
                )?;
                expect_empty(payload)?;
                self.files.remove(&request.fh.fh_id);
                Ok(VfsResponse::Unit(UnitResponse))
            }
            VfsOperation::StatFs(request) => {
                let payload = self.call(
                    VfsRpcRequestPayload::Statfs {
                        inode: request.inode,
                    },
                    credentials(self.local_node, &request.ctx),
                )?;
                match payload {
                    VfsRpcResponsePayload::Statfs(stat) => {
                        Ok(VfsResponse::StatFs(StatFsResponse { stat }))
                    }
                    _ => Err(Errno::EPROTO),
                }
            }
            VfsOperation::OpenDir(request) => {
                let caller = credentials(self.local_node, &request.ctx);
                let payload = self.call(
                    VfsRpcRequestPayload::Opendir {
                        inode: request.inode,
                    },
                    caller.clone(),
                )?;
                match payload {
                    VfsRpcResponsePayload::DirHandle(remote) if remote.inode == request.inode => {
                        let local = self.register_dir(remote, caller)?;
                        Ok(VfsResponse::OpenDir(OpenDirResponse { dh: local }))
                    }
                    _ => Err(Errno::EPROTO),
                }
            }
            VfsOperation::ReadDir(request) => {
                let remote = self.resolve_dir(&request.dh)?.remote.clone();
                let payload = self.call(
                    VfsRpcRequestPayload::Readdir {
                        handle: remote,
                        offset: request.offset,
                        max_entries: u32::MAX,
                    },
                    credentials(self.local_node, &request.ctx),
                )?;
                match payload {
                    VfsRpcResponsePayload::DirEntries(entries) => {
                        Ok(VfsResponse::ReadDir(ReadDirResponse {
                            entries,
                            has_more: false,
                        }))
                    }
                    _ => Err(Errno::EPROTO),
                }
            }
            VfsOperation::ReleaseDir(request) => {
                let record = self.resolve_dir(&request.dh)?.clone();
                let payload = self.call(
                    VfsRpcRequestPayload::Releasedir {
                        handle: record.remote,
                    },
                    record.credentials,
                )?;
                expect_empty(payload)?;
                self.directories.remove(&request.dh.dh_id);
                Ok(VfsResponse::Unit(UnitResponse))
            }
            _ => Ok(VfsResponse::Err(Errno::ENOSYS)),
        }
    }

    fn create(
        &mut self,
        parent: InodeId,
        name: Vec<u8>,
        mode: u32,
        flags: u32,
        ctx: RequestCtx,
    ) -> Result<VfsResponse, Errno> {
        let caller = credentials(self.local_node, &ctx);
        let payload = self.call(
            VfsRpcRequestPayload::Create {
                parent,
                name,
                mode,
                flags,
            },
            caller.clone(),
        )?;
        match payload {
            VfsRpcResponsePayload::Created {
                inode,
                attr,
                handle,
            } if inode == attr.inode_id && inode == handle.inode => {
                let fh = self.register_file(handle, flags, caller)?;
                Ok(VfsResponse::Create(engine_op::CreateResponse { attr, fh }))
            }
            _ => Err(Errno::EPROTO),
        }
    }

    fn call(
        &mut self,
        payload: VfsRpcRequestPayload,
        credentials: VfsRpcCredentials,
    ) -> Result<VfsRpcResponsePayload, Errno> {
        if self.authority_lost.load(Ordering::Acquire) {
            return Err(Errno::ESTALE);
        }
        self.ensure_authority_live()?;
        if self.closed {
            return Err(Errno::ESTALE);
        }
        if let Err(error) = self.validate_live_session() {
            if self.reconnect_config.is_none() {
                return Err(error);
            }
            self.reconnect_exact()?;
        }
        let now = Instant::now();
        let request = self
            .rpc
            .begin_request(now, 0, payload, Some(credentials))
            .map_err(|_| Errno::EPROTO)?;
        let op_id = request.header.op_id;
        let result = self.call_pending(&request).and_then(response_payload);
        if self.rpc.abandon_request(op_id).is_some() {
            if self.authority_lost.load(Ordering::Acquire) {
                self.retire_adapter();
            } else {
                self.reset_adapter_for_current_session();
            }
        }
        result
    }

    fn call_pending(&mut self, request: &VfsRpcRequest) -> Result<VfsRpcResponse, Errno> {
        let mut reconnect_attempts = 0;

        'transmit: loop {
            if let Err(error) = self.send_pending(request) {
                if error.reconnectable && reconnect_attempts < CLIENT_RECONNECT_ATTEMPTS {
                    self.reconnect_exact()?;
                    reconnect_attempts += 1;
                    continue;
                }
                return Err(error.errno);
            }

            let deadline =
                (Instant::now() + CLIENT_REQUEST_TIMEOUT).min(self.authority_valid_until);
            loop {
                let (envelope, payload) = match self.transport.recv_envelope(self.session_id) {
                    Ok(frame) => frame,
                    Err(TransportError::WouldBlock(_)) if Instant::now() < deadline => {
                        thread::sleep(CLIENT_RETRY_INTERVAL);
                        continue;
                    }
                    Err(TransportError::WouldBlock(_)) => {
                        if reconnect_attempts < CLIENT_RECONNECT_ATTEMPTS {
                            self.reconnect_exact()?;
                            reconnect_attempts += 1;
                            continue 'transmit;
                        }
                        return Err(Errno::EIO);
                    }
                    Err(error) => {
                        let failure = classify_transport_error(error);
                        if failure.reconnectable && reconnect_attempts < CLIENT_RECONNECT_ATTEMPTS {
                            self.reconnect_exact()?;
                            reconnect_attempts += 1;
                            continue 'transmit;
                        }
                        return Err(failure.errno);
                    }
                };
                let received_at = Instant::now();
                self.ensure_authority_live()?;
                let inbound = self
                    .adapter
                    .unwrap_inbound(received_at, self.session_id, &envelope, &payload)
                    .map_err(|error| error.errno())?;
                let VfsRpcInboundFrame::Response { response, .. } = inbound else {
                    return Err(Errno::EPROTO);
                };
                self.rpc
                    .complete_response(received_at, &response)
                    .map_err(|_| Errno::EPROTO)?;
                return Ok(response);
            }
        }
    }

    fn send_pending(&mut self, request: &VfsRpcRequest) -> Result<(), TransportFailure> {
        let now = Instant::now();
        let context = VfsRpcEnvelopeContext {
            sequence_number: self.next_sequence,
            ..VfsRpcEnvelopeContext::default()
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        let mut outbound = self
            .adapter
            .begin_request(PeerId(self.writer), request, now, context)
            .map_err(|error| TransportFailure {
                errno: error.errno(),
                reconnectable: error.is_retryable(),
            })?;
        self.transport
            .send_envelope(&mut outbound.envelope, &outbound.payload)
            .map_err(classify_transport_error)
    }

    fn reconnect_exact(&mut self) -> Result<(), Errno> {
        self.ensure_authority_live()?;
        let config = self.reconnect_config.as_ref().ok_or(Errno::EIO)?;
        let remaining = self
            .authority_valid_until
            .saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            self.fence_authority_loss();
            return Err(Errno::ESTALE);
        }
        let observation_started = Instant::now();
        let owner = owner_candidate(config, self.writer).map_err(|_| Errno::ESTALE)?;
        let (mut replacement, replacement_session) = connect_transport(
            config,
            owner,
            self.authority.epoch(),
            remaining.min(CLIENT_AUTHORITY_TIMEOUT),
        )
        .map_err(|_| Errno::EIO)?;
        match replacement.perform_handshake(replacement_session) {
            Ok(()) => {}
            Err(TransportError::AttestedEpochMismatch { .. }) => {
                let _ = replacement
                    .close_session(replacement_session, SessionCloseReason::TransportError);
                self.fence_authority_loss();
                return Err(Errno::ESTALE);
            }
            Err(_) => return Err(Errno::EIO),
        }
        let authenticated_peer = validate_construction_session(&replacement, replacement_session)
            .map_err(|_| Errno::EIO)?;
        replacement.set_nonblocking(true).map_err(|_| Errno::EIO)?;
        let authority_receive_deadline = self
            .authority_valid_until
            .min(Instant::now() + CLIENT_AUTHORITY_TIMEOUT);
        let replacement_authority = receive_session_authority(
            &mut replacement,
            replacement_session,
            authority_receive_deadline,
        )
        .map_err(|_| Errno::EIO)?;
        if replacement_authority
            .validate_for_client(config.expected_pool_guid, authenticated_peer)
            .is_err()
            || !replacement_authority.same_owner_incarnation(&self.authority)
        {
            let _ =
                replacement.close_session(replacement_session, SessionCloseReason::TransportError);
            self.fence_authority_loss();
            return Err(Errno::ESTALE);
        }
        let (authority_valid_until, next_authority_refresh) =
            match authority_schedule(observation_started, replacement_authority) {
                Ok(schedule) => schedule,
                Err(_) => {
                    let _ = replacement
                        .close_session(replacement_session, SessionCloseReason::TransportError);
                    self.fence_authority_loss();
                    return Err(Errno::ESTALE);
                }
            };

        let old_session = self.session_id;
        let mut old_transport = std::mem::replace(&mut self.transport, replacement);
        self.session_id = replacement_session;
        self.next_sequence = 0;
        self.closed = false;
        self.authority = replacement_authority;
        self.authority_valid_until = authority_valid_until;
        self.next_authority_refresh = next_authority_refresh;
        self.reset_adapter_for_current_session();
        let _ = old_transport.close_session(old_session, SessionCloseReason::TransportError);
        Ok(())
    }

    fn ensure_authority_live(&mut self) -> Result<(), Errno> {
        if Instant::now() < self.authority_valid_until {
            return Ok(());
        }
        self.fence_authority_loss();
        Err(Errno::ESTALE)
    }

    fn poll_authority(&mut self) -> Result<(), Errno> {
        if self.authority_lost.load(Ordering::Acquire) || self.closed {
            return Err(Errno::ESTALE);
        }
        self.ensure_authority_live()?;
        let now = Instant::now();
        if now < self.next_authority_refresh {
            return Ok(());
        }

        let remaining = self.authority_valid_until.saturating_duration_since(now);
        self.next_authority_refresh = now.checked_add(remaining / 2).unwrap_or(now);
        match self.reconnect_exact() {
            Ok(()) => Ok(()),
            Err(Errno::ESTALE) => Err(Errno::ESTALE),
            Err(_) if Instant::now() >= self.authority_valid_until => {
                self.fence_authority_loss();
                Err(Errno::ESTALE)
            }
            Err(_) => Ok(()),
        }
    }

    fn authority_poll_wait(&self) -> Duration {
        if self.authority_lost.load(Ordering::Acquire) || self.closed {
            return Duration::ZERO;
        }
        let next_check = self.next_authority_refresh.min(self.authority_valid_until);
        next_check.saturating_duration_since(Instant::now())
    }

    fn fence_authority_loss(&mut self) {
        let _ = self
            .transport
            .close_session(self.session_id, SessionCloseReason::TransportError);
        self.files.clear();
        self.directories.clear();
        self.retire_adapter();
        self.closed = true;
        self.authority_lost.store(true, Ordering::Release);
    }

    fn retire_adapter(&mut self) {
        self.adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig {
                request_timeout: CLIENT_REQUEST_TIMEOUT,
                ..VfsRpcTransportAdapterConfig::default()
            },
            TransportSessionSet::new(),
        );
    }

    fn reset_adapter_for_current_session(&mut self) {
        let mut sessions = TransportSessionSet::new();
        sessions.add_binding_with_epoch(self.writer, self.session_id, self.authority.epoch());
        sessions.mark_healthy(self.session_id);
        self.adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig {
                request_timeout: CLIENT_REQUEST_TIMEOUT,
                ..VfsRpcTransportAdapterConfig::default()
            },
            sessions,
        );
    }

    fn register_file(
        &mut self,
        remote: VfsRpcHandle,
        open_flags: u32,
        credentials: VfsRpcCredentials,
    ) -> Result<EngineFileHandle, Errno> {
        self.validate_remote_handle(&remote, VfsRpcHandleType::File)?;
        let local = remote.as_file_handle(open_flags, 0);
        if self.files.contains_key(&local.fh_id) {
            return Err(Errno::EPROTO);
        }
        self.files.insert(
            local.fh_id,
            FileHandleRecord {
                local,
                remote,
                credentials,
            },
        );
        Ok(local)
    }

    fn register_dir(
        &mut self,
        remote: VfsRpcHandle,
        credentials: VfsRpcCredentials,
    ) -> Result<EngineDirHandle, Errno> {
        self.validate_remote_handle(&remote, VfsRpcHandleType::Dir)?;
        let local = remote.as_dir_handle();
        if self.directories.contains_key(&local.dh_id) {
            return Err(Errno::EPROTO);
        }
        self.directories.insert(
            local.dh_id,
            DirHandleRecord {
                local,
                remote,
                credentials,
            },
        );
        Ok(local)
    }

    fn resolve_file(&self, local: &EngineFileHandle) -> Result<&FileHandleRecord, Errno> {
        let record = self.files.get(&local.fh_id).ok_or(Errno::EBADF)?;
        if record.local.inode_id != local.inode_id
            || record.local.open_flags != local.open_flags
            || record.remote.inode != local.inode_id
            || record.remote.handle_cookie != local.fh_id.get()
        {
            return Err(Errno::ESTALE);
        }
        self.validate_remote_handle(&record.remote, VfsRpcHandleType::File)?;
        Ok(record)
    }

    fn resolve_dir(&self, local: &EngineDirHandle) -> Result<&DirHandleRecord, Errno> {
        let record = self.directories.get(&local.dh_id).ok_or(Errno::EBADF)?;
        if record.local != *local
            || record.remote.inode != local.inode_id
            || record.remote.handle_cookie != local.dh_id.get()
        {
            return Err(Errno::ESTALE);
        }
        self.validate_remote_handle(&record.remote, VfsRpcHandleType::Dir)?;
        Ok(record)
    }

    fn validate_remote_handle(
        &self,
        handle: &VfsRpcHandle,
        expected_type: VfsRpcHandleType,
    ) -> Result<(), Errno> {
        if handle.handle_type != expected_type
            || handle.dataset_id != self.dataset_id
            || handle.writer_node != self.writer
            || handle.inode.get() == 0
            || handle.handle_cookie == 0
        {
            return Err(Errno::ESTALE);
        }
        Ok(())
    }

    fn validate_live_session(&self) -> Result<(), Errno> {
        validate_active_session(
            &self.transport,
            self.session_id,
            self.local_node,
            self.writer,
        )
        .map_err(|_| Errno::ESTALE)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.transport
            .close_session(self.session_id, SessionCloseReason::LocalShutdown)
    }
}

impl Drop for ClientState {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn validate_construction_session(
    transport: &Transport,
    session_id: SessionId,
) -> Result<u64, ClusterVfsRpcClientError> {
    if transport.endpoint_family != EndpointFamily::Control {
        return Err(ClusterVfsRpcClientError::NonControlTransport);
    }
    authenticated_session_peer(transport, session_id, transport.local_node_id)
}

fn validate_active_session(
    transport: &Transport,
    session_id: SessionId,
    local_node: u64,
    expected_writer: u64,
) -> Result<(), ClusterVfsRpcClientError> {
    let authenticated_peer = authenticated_session_peer(transport, session_id, local_node)?;
    if authenticated_peer != expected_writer {
        return Err(ClusterVfsRpcClientError::WrongPeer {
            expected_writer,
            authenticated_peer,
        });
    }
    Ok(())
}

fn authenticated_session_peer(
    transport: &Transport,
    session_id: SessionId,
    local_node: u64,
) -> Result<u64, ClusterVfsRpcClientError> {
    let session = transport
        .sessions
        .get(&session_id)
        .ok_or(ClusterVfsRpcClientError::MissingSession(session_id))?
        .lock()
        .map_err(|_| ClusterVfsRpcClientError::SessionLockPoisoned(session_id))?;
    if !matches!(session.state, SessionState::Established { .. }) {
        return Err(ClusterVfsRpcClientError::SessionNotEstablished(session_id));
    }
    if session.endpoint_family != EndpointFamily::Control {
        return Err(ClusterVfsRpcClientError::NonControlSession(session_id));
    }
    if session.local_node != local_node {
        return Err(ClusterVfsRpcClientError::LocalNodeMismatch {
            transport_node: local_node,
            session_node: session.local_node,
        });
    }
    let authenticated_peer = session.peer_node;
    drop(session);
    if !transport.active_connections.contains_key(&session_id) {
        return Err(ClusterVfsRpcClientError::MissingActiveConnection(
            session_id,
        ));
    }
    if !transport.session_has_authenticated_confidentiality(session_id) {
        return Err(ClusterVfsRpcClientError::UnauthenticatedSession(session_id));
    }
    Ok(authenticated_peer)
}

fn receive_session_authority(
    transport: &mut Transport,
    session_id: SessionId,
    deadline: Instant,
) -> Result<tidefs_vfs_rpc::transport_adapter::VfsRpcSessionAuthority, ClusterVfsRpcClientError> {
    loop {
        match transport.recv_envelope(session_id) {
            Ok((envelope, payload)) => {
                return decode_session_authority_frame(&envelope, &payload)
                    .map_err(map_session_authority_error);
            }
            Err(TransportError::WouldBlock(_)) if Instant::now() < deadline => {
                thread::sleep(CLIENT_RETRY_INTERVAL);
            }
            Err(TransportError::WouldBlock(_)) => {
                return Err(ClusterVfsRpcClientError::AuthorityTimeout(session_id));
            }
            Err(error) => {
                return Err(ClusterVfsRpcClientError::AuthorityTransport(
                    error.to_string(),
                ));
            }
        }
    }
}

fn map_session_authority_error(error: VfsRpcSessionAuthorityError) -> ClusterVfsRpcClientError {
    match error {
        VfsRpcSessionAuthorityError::WrongPoolGuid { expected, found } => {
            ClusterVfsRpcClientError::WrongPool { expected, found }
        }
        VfsRpcSessionAuthorityError::WrongWriter {
            expected,
            authenticated_peer,
        } => ClusterVfsRpcClientError::WrongPeer {
            expected_writer: expected,
            authenticated_peer,
        },
        VfsRpcSessionAuthorityError::ZeroExpectedPoolGuid => {
            ClusterVfsRpcClientError::ExpectedPoolGuidZero
        }
        other => ClusterVfsRpcClientError::MalformedAuthority(other),
    }
}

fn credentials(local_node: u64, ctx: &RequestCtx) -> VfsRpcCredentials {
    VfsRpcCredentials {
        peer_id: PeerId(local_node),
        auth_tag: [0; 16],
        uid: ctx.uid,
        gid: ctx.gid,
        pid: ctx.pid,
        umask: ctx.umask,
        groups: ctx.groups.clone(),
    }
}

fn response_payload(response: VfsRpcResponse) -> Result<VfsRpcResponsePayload, Errno> {
    if response.header.errno.is_error() {
        return Err(response.header.errno);
    }
    Ok(response.payload)
}

fn expect_empty(payload: VfsRpcResponsePayload) -> Result<(), Errno> {
    match payload {
        VfsRpcResponsePayload::Empty => Ok(()),
        _ => Err(Errno::EPROTO),
    }
}

#[derive(Clone, Copy)]
struct TransportFailure {
    errno: Errno,
    reconnectable: bool,
}

fn classify_transport_error(error: TransportError) -> TransportFailure {
    let reconnectable = matches!(
        &error,
        TransportError::SessionNotFound { .. }
            | TransportError::SessionInWrongState { .. }
            | TransportError::Io { .. }
            | TransportError::SendBufferShutdown { .. }
            | TransportError::Generic(_)
    );
    let errno = match error {
        TransportError::WouldBlock(_) | TransportError::SendBufferFull { .. } => Errno::EAGAIN,
        TransportError::SessionNotFound { .. }
        | TransportError::SessionInWrongState { .. }
        | TransportError::SendBufferShutdown { .. } => Errno::ESTALE,
        _ => Errno::EIO,
    };
    TransportFailure {
        errno,
        reconnectable,
    }
}
