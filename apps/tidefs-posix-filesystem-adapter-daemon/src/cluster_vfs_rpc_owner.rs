// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pool-owner VFS_RPC service over the authenticated Control transport.
//!
//! This service owns only inline VFS_RPC dispatch. It deliberately refuses
//! BULK descriptors until a same-session production BULK consumer owns their
//! completion and cancellation lifecycle.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tidefs_transport::{
    EndpointFamily, SessionCloseReason, SessionId, Transport, TransportAddr, TransportError,
    TransportSessionSet,
};
use tidefs_vfs_engine::dispatch::VfsEngineDispatchBridge;
use tidefs_vfs_engine::{VfsDispatch, VfsOperation, VfsResponse};
use tidefs_vfs_rpc::transport_adapter::{
    VfsRpcEnvelopeContext, VfsRpcFrameDirection, VfsRpcInboundFrame, VfsRpcTransportAdapter,
    VfsRpcTransportAdapterConfig, VfsRpcTransportAdapterError,
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
    admitted_peer_node: u64,
    dataset_id: DatasetId,
    writer_fence: Arc<Mutex<ClusterVfsRpcWriterFence>>,
    engine: LiveOwnerEngine,
    shutdown: Arc<AtomicBool>,
    authenticated_session_key: Option<[u8; 32]>,
}

impl ClusterVfsRpcOwnerConfig {
    #[must_use]
    pub fn new(
        bind_addr: SocketAddr,
        local_owner_node: u64,
        admitted_peer_node: u64,
        dataset_id: DatasetId,
        writer_fence: Arc<Mutex<ClusterVfsRpcWriterFence>>,
        engine: LiveOwnerEngine,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            bind_addr,
            local_owner_node,
            admitted_peer_node,
            dataset_id,
            writer_fence,
            engine,
            shutdown,
            authenticated_session_key: None,
        }
    }

    /// Consume one session key supplied by the authenticated cluster session
    /// authority. This service never generates, distributes, or reuses it.
    #[must_use]
    pub fn with_authenticated_session_key(mut self, key: [u8; 32]) -> Self {
        self.authenticated_session_key = Some(key);
        self
    }

    fn validate(&self) -> Result<(), String> {
        if self.local_owner_node == 0 {
            return Err("cluster VFS_RPC owner node must be nonzero".to_string());
        }
        if self.admitted_peer_node == 0 {
            return Err("cluster VFS_RPC admitted peer node must be nonzero".to_string());
        }
        if self.dataset_id.0 == 0 {
            return Err("cluster VFS_RPC dataset identity must be nonzero".to_string());
        }
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
        if self.authenticated_session_key.is_none() {
            return Err(
                "cluster VFS_RPC owner requires externally supplied authenticated session key material"
                    .to_string(),
            );
        }
        Ok(())
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

        let mut transport = Transport::new(config.local_owner_node);
        transport.set_endpoint_family(EndpointFamily::Control);
        transport
            .configure_generated_attestation(true)
            .map_err(|error| format!("configure cluster VFS_RPC attestation: {error}"))?;
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
    mut config: ClusterVfsRpcOwnerConfig,
    stop: &AtomicBool,
) -> Result<(), String> {
    let initial_fence = *config
        .writer_fence
        .lock()
        .map_err(|_| "cluster VFS_RPC writer fence lock is poisoned".to_string())?;
    let mut bridge = VfsEngineBridge::new(initial_fence.bridge_writer(config.dataset_id));

    while !stop.load(Ordering::Acquire) && !config.shutdown.load(Ordering::Acquire) {
        let session_id = match transport.accept_incoming() {
            Ok(session_id) => session_id,
            Err(TransportError::Generic(message)) if message == NO_PENDING_CONNECTIONS => {
                thread::sleep(OWNER_POLL_INTERVAL);
                continue;
            }
            Err(error) => return Err(format!("accept cluster VFS_RPC peer: {error}")),
        };

        if let Err(error) = transport.perform_handshake(session_id) {
            let _ = transport.close_session(session_id, SessionCloseReason::AuthFailed);
            if stop.load(Ordering::Acquire) || config.shutdown.load(Ordering::Acquire) {
                break;
            }
            eprintln!("cluster VFS_RPC: rejected failed peer handshake: {error}");
            continue;
        }

        let peer_node = transport.peer_node(session_id).ok_or_else(|| {
            "cluster VFS_RPC handshake completed without a peer identity".to_string()
        })?;
        if peer_node != config.admitted_peer_node {
            let _ = transport.close_session(session_id, SessionCloseReason::AuthFailed);
            eprintln!(
                "cluster VFS_RPC: rejected transport peer node {peer_node}; admitted peer is {}",
                config.admitted_peer_node
            );
            continue;
        }

        let Some(mut session_key) = config.authenticated_session_key.take() else {
            let _ = transport.close_session(session_id, SessionCloseReason::AuthFailed);
            eprintln!(
                "cluster VFS_RPC: refused session {session_id}; fresh authenticated session key material is required"
            );
            continue;
        };
        let Some(session) = transport.sessions.get(&session_id) else {
            session_key.fill(0);
            return Err(format!(
                "cluster VFS_RPC session {session_id} disappeared after authentication"
            ));
        };
        let install_result = session
            .lock()
            .map_err(|_| format!("cluster VFS_RPC session {session_id} lock is poisoned"))
            .map(|mut session| session.init_ciphers_from_key(&session_key, false));
        session_key.fill(0);
        install_result?;
        if !transport.session_has_authenticated_confidentiality(session_id) {
            let _ = transport.close_session(session_id, SessionCloseReason::AuthFailed);
            return Err(format!(
                "cluster VFS_RPC session {session_id} failed to install authenticated confidentiality"
            ));
        }

        transport
            .set_nonblocking(true)
            .map_err(|error| format!("set cluster VFS_RPC session nonblocking: {error}"))?;
        serve_session(
            &mut transport,
            session_id,
            PeerId(peer_node),
            &config,
            stop,
            &mut bridge,
        )?;
        let _ = transport.close_session(session_id, SessionCloseReason::TransportError);
        transport
            .set_nonblocking(false)
            .map_err(|error| format!("restore cluster VFS_RPC handshake mode: {error}"))?;
    }

    Ok(())
}

fn serve_session(
    transport: &mut Transport,
    session_id: SessionId,
    peer: PeerId,
    config: &ClusterVfsRpcOwnerConfig,
    stop: &AtomicBool,
    bridge: &mut VfsEngineBridge,
) -> Result<(), String> {
    let fence = *config
        .writer_fence
        .lock()
        .map_err(|_| "cluster VFS_RPC writer fence lock is poisoned".to_string())?;
    let mut sessions = TransportSessionSet::new();
    sessions.add_binding_with_epoch(peer.0, session_id, fence.epoch);
    sessions.mark_healthy(session_id);
    let mut adapter =
        VfsRpcTransportAdapter::new(VfsRpcTransportAdapterConfig::default(), sessions);
    let mut response_sequence = 0_u64;
    let dispatch = PoolBackedEngineDispatch {
        engine: Arc::clone(&config.engine),
    };

    while !stop.load(Ordering::Acquire) && !config.shutdown.load(Ordering::Acquire) {
        let (envelope, payload) = match transport.recv_envelope(session_id) {
            Ok(frame) => frame,
            Err(TransportError::WouldBlock(_)) => {
                thread::sleep(OWNER_POLL_INTERVAL);
                continue;
            }
            Err(_) => return Ok(()),
        };
        let response_context = VfsRpcEnvelopeContext {
            cohort_id: envelope.cohort_id,
            sequence_number: response_sequence,
            ack_floor: envelope.sequence_number,
            visibility_class: tidefs_transport::VisibilityClass::Internal,
        };
        response_sequence = response_sequence.saturating_add(1);

        let inbound = match adapter.unwrap_inbound(Instant::now(), &envelope, &payload) {
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
                    &adapter,
                    peer,
                    session_id,
                    &response,
                    response_context,
                )?;
                continue;
            }
            Err(VfsRpcTransportAdapterError::PeerIdentityMismatch { expected, found }) => {
                eprintln!(
                    "cluster VFS_RPC: rejected credentials for peer {}; transport authenticated {}",
                    found.0, expected.0
                );
                return Ok(());
            }
            Err(error) => {
                eprintln!("cluster VFS_RPC: rejected inbound service frame: {error}");
                return Ok(());
            }
        };

        let VfsRpcInboundFrame::Request { request, .. } = inbound else {
            eprintln!("cluster VFS_RPC: rejected unsolicited response on owner endpoint");
            return Ok(());
        };
        let writer = *config
            .writer_fence
            .lock()
            .map_err(|_| "cluster VFS_RPC writer fence lock is poisoned".to_string())?;
        bridge.update_writer(writer.bridge_writer(config.dataset_id));
        let response = bridge
            .dispatch(peer, &request, &dispatch)
            .map_err(|error| format!("dispatch Pool-backed VFS_RPC request: {error}"))?;
        send_response(
            transport,
            &adapter,
            peer,
            session_id,
            &response,
            response_context,
        )?;
    }
    Ok(())
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
