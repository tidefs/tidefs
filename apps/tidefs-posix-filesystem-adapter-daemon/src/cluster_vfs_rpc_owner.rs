// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pool-owner VFS_RPC service over the authenticated Control transport.
//!
//! This service owns only inline VFS_RPC dispatch. It deliberately refuses
//! BULK descriptors until a same-session production BULK consumer owns their
//! completion and cancellation lifecycle.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tidefs_auth::{NodeKeyStore, NodePrivateCredential, NodePublicIdentity};
use tidefs_transport::{
    EndpointFamily, SessionCloseReason, SessionId, Transport, TransportAddr, TransportError,
    TransportSessionSet,
};
use tidefs_vfs_engine::dispatch::VfsEngineDispatchBridge;
use tidefs_vfs_engine::{VfsDispatch, VfsOperation, VfsResponse};
use tidefs_vfs_rpc::transport_adapter::{
    VfsRpcEnvelopeContext, VfsRpcFrameDirection, VfsRpcInboundFrame, VfsRpcSessionAuthority,
    VfsRpcTransportAdapter, VfsRpcTransportAdapterConfig, VfsRpcTransportAdapterError,
};
use tidefs_vfs_rpc::vfs_engine_bridge::{VfsEngineBridge, VfsEngineBridgeWriter};
use tidefs_vfs_rpc::{DatasetId, PeerId, VfsRpcResponse};

use crate::live_owner::LiveOwnerEngine;

const OWNER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const NO_PENDING_CONNECTIONS: &str = "no pending connections";

struct PoolBackedEngineDispatch {
    engine: LiveOwnerEngine,
}

impl VfsDispatch for PoolBackedEngineDispatch {
    fn dispatch(
        &self,
        operation: VfsOperation,
    ) -> Result<VfsResponse, tidefs_types_vfs_core::Errno> {
        let engine = self
            .engine
            .lock()
            .map_err(|_| tidefs_types_vfs_core::Errno::EIO)?;
        VfsEngineDispatchBridge::new(engine.as_ref()).dispatch(operation)
    }
}

/// Lease-derived mutation fence shared with the renewal worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClusterVfsRpcWriterFence {
    pub writer_node: u64,
    pub term: u64,
    pub epoch: u64,
}

impl ClusterVfsRpcWriterFence {
    #[must_use]
    pub const fn new(writer_node: u64, term: u64, epoch: u64) -> Self {
        Self {
            writer_node,
            term,
            epoch,
        }
    }

    fn bridge_writer(self, dataset_id: DatasetId) -> VfsEngineBridgeWriter {
        VfsEngineBridgeWriter::new(self.writer_node, dataset_id, self.term, self.epoch)
    }
}

/// Configuration for one Pool-backed owner-side VFS_RPC service.
pub struct ClusterVfsRpcOwnerConfig {
    bind_addr: SocketAddr,
    local_owner_node: u64,
    local_credential: Arc<NodePrivateCredential>,
    trusted_peer_identities: Vec<NodePublicIdentity>,
    pool_guid: [u8; 16],
    dataset_id: DatasetId,
    writer_fence: Arc<Mutex<ClusterVfsRpcWriterFence>>,
    engine: LiveOwnerEngine,
    shutdown: Arc<AtomicBool>,
}

impl ClusterVfsRpcOwnerConfig {
    #[must_use]
    pub fn new(
        bind_addr: SocketAddr,
        local_owner_node: u64,
        local_credential: Arc<NodePrivateCredential>,
        trusted_peer_identities: Vec<NodePublicIdentity>,
        pool_guid: [u8; 16],
        dataset_id: DatasetId,
        writer_fence: Arc<Mutex<ClusterVfsRpcWriterFence>>,
        engine: LiveOwnerEngine,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            bind_addr,
            local_owner_node,
            local_credential,
            trusted_peer_identities,
            pool_guid,
            dataset_id,
            writer_fence,
            engine,
            shutdown,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.local_owner_node == 0 {
            return Err("cluster VFS_RPC owner node must be nonzero".to_string());
        }
        if self.local_credential.node_id() != self.local_owner_node {
            return Err(format!(
                "cluster VFS_RPC local credential names node {}, expected owner node {}",
                self.local_credential.node_id(),
                self.local_owner_node
            ));
        }
        if self.trusted_peer_identities.is_empty() {
            return Err("cluster VFS_RPC requires at least one trusted peer identity".to_string());
        }
        let mut peer_nodes = BTreeSet::new();
        for identity in &self.trusted_peer_identities {
            let peer_node = identity.node_id();
            if peer_node == 0 {
                return Err("cluster VFS_RPC trusted peer node must be nonzero".to_string());
            }
            if !peer_nodes.insert(peer_node) {
                return Err(format!(
                    "cluster VFS_RPC has more than one trusted identity for node {peer_node}"
                ));
            }
            if self.local_owner_node == peer_node {
                return Err(format!(
                    "cluster VFS_RPC trusted peer node {peer_node} conflicts with the local owner node"
                ));
            }
        }
        self.local_credential
            .keypair()
            .map_err(|error| format!("cluster VFS_RPC local credential is invalid: {error}"))?;
        if self.pool_guid == [0; 16] {
            return Err("cluster VFS_RPC Pool GUID must be nonzero".to_string());
        }
        if self.dataset_id.0 == 0 {
            return Err("cluster VFS_RPC dataset identity must be nonzero".to_string());
        }
        self.current_writer_fence()?;
        Ok(())
    }

    fn current_writer_fence(&self) -> Result<ClusterVfsRpcWriterFence, String> {
        let fence = *self
            .writer_fence
            .lock()
            .map_err(|_| "cluster VFS_RPC writer fence lock is poisoned".to_string())?;
        if fence.writer_node != self.local_owner_node || fence.term == 0 || fence.epoch == 0 {
            return Err(
                "cluster VFS_RPC writer fence must name the local owner with nonzero term and epoch"
                    .to_string(),
            );
        }
        Ok(fence)
    }

    fn trusted_peer_nodes(&self) -> BTreeSet<u64> {
        self.trusted_peer_identities
            .iter()
            .map(NodePublicIdentity::node_id)
            .collect()
    }
}

/// Running owner service. Dropping the handle stops and joins its thread.
pub struct ClusterVfsRpcOwnerHandle {
    bound_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<String>>>,
    join: Option<JoinHandle<()>>,
}

impl ClusterVfsRpcOwnerHandle {
    /// Bind the Control endpoint before publishing a live service handle.
    pub fn start(config: ClusterVfsRpcOwnerConfig) -> Result<Self, String> {
        config.validate()?;

        let local_identity = config.local_credential.public_identity().into_identity();
        let local_keypair = config
            .local_credential
            .keypair()
            .map_err(|error| format!("load cluster VFS_RPC local credential: {error}"))?;
        let mut known_identities = NodeKeyStore::new();
        known_identities
            .register(local_identity.clone())
            .map_err(|error| format!("register cluster VFS_RPC local identity: {error}"))?;
        for identity in &config.trusted_peer_identities {
            known_identities
                .register(identity.identity().clone())
                .map_err(|error| {
                    format!(
                        "register trusted cluster VFS_RPC peer {}: {error}",
                        identity.node_id()
                    )
                })?;
        }
        let lease_epoch = config
            .writer_fence
            .lock()
            .map_err(|_| "cluster VFS_RPC writer fence lock is poisoned".to_string())?
            .epoch;
        let mut transport = Transport::new(config.local_owner_node)
            .with_attestation(local_keypair, local_identity)
            .with_known_identities(known_identities)
            .with_epoch(lease_epoch);
        transport.set_endpoint_family(EndpointFamily::Control);
        transport.set_attestation_bootstrap_from_handshake(false);
        transport
            .bind(TransportAddr::Tcp(config.bind_addr))
            .map_err(|error| {
                format!(
                    "bind cluster VFS_RPC owner at {}: {error}",
                    config.bind_addr
                )
            })?;
        let bound_addr = match transport.bind_addr {
            Some(TransportAddr::Tcp(addr)) => addr,
            Some(other) => {
                return Err(format!(
                    "cluster VFS_RPC owner bound unexpected transport address {other:?}"
                ));
            }
            None => return Err("cluster VFS_RPC owner did not publish its bound address".into()),
        };

        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(Mutex::new(None));
        let thread_stop = Arc::clone(&stop);
        let thread_shutdown = Arc::clone(&config.shutdown);
        let handle_shutdown = Arc::clone(&config.shutdown);
        let thread_failure = Arc::clone(&failure);
        let join = thread::Builder::new()
            .name("tidefs-cluster-vfs-rpc-owner".to_string())
            .spawn(move || {
                if let Err(error) = run_owner(transport, config, &thread_stop) {
                    *thread_failure
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
                    thread_shutdown.store(true, Ordering::Release);
                }
            })
            .map_err(|error| format!("start cluster VFS_RPC owner thread: {error}"))?;

        Ok(Self {
            bound_addr,
            stop,
            shutdown: handle_shutdown,
            failure,
            join: Some(join),
        })
    }

    #[must_use]
    pub const fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// Report a fatal owner-thread failure to the mount lifecycle.
    pub fn check_health(&self) -> Result<(), String> {
        if let Some(error) = self
            .failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        {
            return Err(error);
        }
        if self.join.as_ref().is_some_and(JoinHandle::is_finished)
            && !self.stop.load(Ordering::Acquire)
            && !self.shutdown.load(Ordering::Acquire)
        {
            return Err("cluster VFS_RPC owner stopped unexpectedly".to_string());
        }
        Ok(())
    }

    /// Stop accepting/dispatching remote requests and join the owner thread.
    pub fn stop(&mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| "cluster VFS_RPC owner thread panicked".to_string())?;
        }
        self.check_health()
    }
}

impl Drop for ClusterVfsRpcOwnerHandle {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn run_owner(
    mut transport: Transport,
    config: ClusterVfsRpcOwnerConfig,
    stop: &AtomicBool,
) -> Result<(), String> {
    let initial_fence = *config
        .writer_fence
        .lock()
        .map_err(|_| "cluster VFS_RPC writer fence lock is poisoned".to_string())?;
    let mut bridge = VfsEngineBridge::new(initial_fence.bridge_writer(config.dataset_id));
    let admitted_peer_nodes = config.trusted_peer_nodes();
    let dispatch = PoolBackedEngineDispatch {
        engine: Arc::clone(&config.engine),
    };
    let mut sessions = Vec::new();
    transport
        .set_nonblocking(true)
        .map_err(|error| format!("set cluster VFS_RPC owner nonblocking: {error}"))?;

    while !stop.load(Ordering::Acquire) && !config.shutdown.load(Ordering::Acquire) {
        let writer = config.current_writer_fence()?;
        bridge.update_writer(writer.bridge_writer(config.dataset_id));
        let mut made_progress = false;
        match transport.accept_incoming() {
            Ok(session_id) => {
                made_progress = true;
                transport
                    .set_nonblocking(false)
                    .map_err(|error| format!("set cluster VFS_RPC handshake blocking: {error}"))?;
                let admitted = admit_session(
                    &mut transport,
                    session_id,
                    &admitted_peer_nodes,
                    &config,
                    writer,
                );
                transport.set_nonblocking(true).map_err(|error| {
                    format!("restore cluster VFS_RPC owner nonblocking: {error}")
                })?;
                if let Some(session) = admitted {
                    sessions.push(session);
                }
            }
            Err(TransportError::Generic(message)) if message == NO_PENDING_CONNECTIONS => {}
            Err(error) => return Err(format!("accept cluster VFS_RPC peer: {error}")),
        }

        let mut index = 0;
        while index < sessions.len() {
            let progress = match serve_session_once(
                &mut transport,
                &mut sessions[index],
                &mut bridge,
                &dispatch,
            ) {
                Ok(progress) => progress,
                Err(error) => {
                    eprintln!(
                        "cluster VFS_RPC: closing failed session {} for peer {}: {error}",
                        sessions[index].session_id, sessions[index].peer.0
                    );
                    SessionProgress::Closed
                }
            };
            match progress {
                SessionProgress::Idle => index += 1,
                SessionProgress::Served => {
                    made_progress = true;
                    index += 1;
                }
                SessionProgress::Closed => {
                    let session = sessions.swap_remove(index);
                    let _ = transport
                        .close_session(session.session_id, SessionCloseReason::TransportError);
                    made_progress = true;
                }
            }
        }

        if !made_progress {
            thread::sleep(OWNER_POLL_INTERVAL);
        }
    }

    for session in sessions {
        let _ = transport.close_session(session.session_id, SessionCloseReason::LocalShutdown);
    }
    Ok(())
}

fn admit_session(
    transport: &mut Transport,
    session_id: SessionId,
    admitted_peer_nodes: &BTreeSet<u64>,
    config: &ClusterVfsRpcOwnerConfig,
    writer: ClusterVfsRpcWriterFence,
) -> Option<OwnerSession> {
    if let Err(error) = transport.perform_handshake(session_id) {
        let _ = transport.close_session(session_id, SessionCloseReason::TransportError);
        eprintln!("cluster VFS_RPC: rejected failed peer handshake: {error}");
        return None;
    }

    let Some(peer_node) = transport.peer_node(session_id) else {
        let _ = transport.close_session(session_id, SessionCloseReason::AuthFailed);
        eprintln!("cluster VFS_RPC: rejected handshake without a peer identity");
        return None;
    };
    if !admitted_peer_nodes.contains(&peer_node) {
        let _ = transport.close_session(session_id, SessionCloseReason::AuthFailed);
        eprintln!("cluster VFS_RPC: rejected unprovisioned transport peer node {peer_node}");
        return None;
    }
    if !transport.session_has_authenticated_confidentiality(session_id) {
        let _ = transport.close_session(session_id, SessionCloseReason::AuthFailed);
        eprintln!(
            "cluster VFS_RPC session {session_id} failed to install authenticated confidentiality"
        );
        return None;
    }

    match OwnerSession::start(transport, session_id, PeerId(peer_node), config, writer) {
        Ok(session) => Some(session),
        Err(error) => {
            let _ = transport.close_session(session_id, SessionCloseReason::TransportError);
            eprintln!(
                "cluster VFS_RPC: rejected session {session_id} for peer {peer_node}: {error}"
            );
            None
        }
    }
}

struct OwnerSession {
    session_id: SessionId,
    peer: PeerId,
    adapter: VfsRpcTransportAdapter,
    response_sequence: u64,
}

impl OwnerSession {
    fn start(
        transport: &mut Transport,
        session_id: SessionId,
        peer: PeerId,
        config: &ClusterVfsRpcOwnerConfig,
        fence: ClusterVfsRpcWriterFence,
    ) -> Result<Self, String> {
        let mut sessions = TransportSessionSet::new();
        sessions.add_binding_with_epoch(peer.0, session_id, fence.epoch);
        sessions.mark_healthy(session_id);
        let adapter =
            VfsRpcTransportAdapter::new(VfsRpcTransportAdapterConfig::default(), sessions);
        let authority = VfsRpcSessionAuthority::new(
            config.pool_guid,
            config.dataset_id,
            fence.writer_node,
            fence.term,
            fence.epoch,
        )
        .map_err(|error| format!("build cluster VFS_RPC session authority: {error}"))?;
        let (mut authority_envelope, authority_payload) = adapter
            .wrap_session_authority_for_session(
                session_id,
                &authority,
                VfsRpcEnvelopeContext {
                    sequence_number: 0,
                    ..VfsRpcEnvelopeContext::default()
                },
            )
            .map_err(|error| format!("wrap cluster VFS_RPC session authority: {error}"))?;
        transport
            .send_envelope(&mut authority_envelope, &authority_payload)
            .map_err(|error| format!("send cluster VFS_RPC session authority: {error}"))?;
        Ok(Self {
            session_id,
            peer,
            adapter,
            response_sequence: 1,
        })
    }
}

enum SessionProgress {
    Idle,
    Served,
    Closed,
}

fn serve_session_once(
    transport: &mut Transport,
    session: &mut OwnerSession,
    bridge: &mut VfsEngineBridge,
    dispatch: &PoolBackedEngineDispatch,
) -> Result<SessionProgress, String> {
    let (envelope, payload) = match transport.recv_envelope(session.session_id) {
        Ok(frame) => frame,
        Err(TransportError::WouldBlock(_)) => return Ok(SessionProgress::Idle),
        Err(_) => return Ok(SessionProgress::Closed),
    };
    let response_context = VfsRpcEnvelopeContext {
        cohort_id: envelope.cohort_id,
        sequence_number: session.response_sequence,
        ack_floor: envelope.sequence_number,
        visibility_class: tidefs_transport::VisibilityClass::Internal,
    };
    session.response_sequence = session.response_sequence.saturating_add(1);

    let inbound = match session.adapter.unwrap_inbound(
        Instant::now(),
        session.session_id,
        &envelope,
        &payload,
    ) {
        Ok(inbound) => inbound,
        Err(VfsRpcTransportAdapterError::BulkUnsupported {
            op_id,
            method,
            direction: VfsRpcFrameDirection::Request,
        }) => {
            let response =
                VfsRpcResponse::error(op_id, method, tidefs_types_vfs_core::Errno::EOPNOTSUPP)
                    .map_err(|error| format!("encode VFS_RPC BULK refusal: {error}"))?;
            send_response(
                transport,
                &session.adapter,
                session.peer,
                session.session_id,
                &response,
                response_context,
            )?;
            return Ok(SessionProgress::Served);
        }
        Err(VfsRpcTransportAdapterError::PeerIdentityMismatch { expected, found }) => {
            eprintln!(
                "cluster VFS_RPC: rejected credentials for peer {}; transport authenticated {}",
                found.0, expected.0
            );
            return Ok(SessionProgress::Closed);
        }
        Err(error) => {
            eprintln!("cluster VFS_RPC: rejected inbound service frame: {error}");
            return Ok(SessionProgress::Closed);
        }
    };

    let VfsRpcInboundFrame::Request { request, .. } = inbound else {
        eprintln!("cluster VFS_RPC: rejected unsolicited response on owner endpoint");
        return Ok(SessionProgress::Closed);
    };
    let response = bridge
        .dispatch(session.peer, &request, dispatch)
        .map_err(|error| format!("dispatch Pool-backed VFS_RPC request: {error}"))?;
    send_response(
        transport,
        &session.adapter,
        session.peer,
        session.session_id,
        &response,
        response_context,
    )?;
    Ok(SessionProgress::Served)
}

fn send_response(
    transport: &mut Transport,
    adapter: &VfsRpcTransportAdapter,
    peer: PeerId,
    session_id: SessionId,
    response: &VfsRpcResponse,
    context: VfsRpcEnvelopeContext,
) -> Result<(), String> {
    let mut outbound = adapter
        .wrap_response_for_session(peer, session_id, response, context)
        .map_err(|error| format!("wrap cluster VFS_RPC response: {error}"))?;
    transport
        .send_envelope(&mut outbound.envelope, &outbound.payload)
        .map_err(|error| format!("send cluster VFS_RPC response: {error}"))
}
