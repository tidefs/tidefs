// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Same-session VFS_RPC WRITE orchestration over CONTROL and BULK services.
//!
//! This runtime binds VFS_RPC service `0x06` to the authenticated BULK DATA
//! service `0x07` for incoming WRITE uploads. A BULK descriptor is admitted
//! before the request is retained, VFS Engine dispatch happens only after the
//! matching DONE event, and ABORT or local timeout paths retire the descriptor
//! before returning a fail-closed VFS_RPC error. READ sender orchestration is
//! deliberately outside this write-upload runtime.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tidefs_bulk_service::{
    AbortedBulkTransfer, BulkAbortReason, BulkDataServiceHandler, BulkDataServiceTerminal,
    BulkError, BulkMetadata, BulkToken, BulkTransferDirection, CompletedBulkTransfer, ConnectionId,
    StreamId, VfsRpcBulkAbort, VfsRpcBulkCompletion, VfsRpcBulkHandoff, VfsRpcBulkHandoffError,
    VfsRpcBulkMethod, BULK_SERVICE_ID,
};
use tidefs_transport::{
    ConnectionReceiver, ControlServiceDispatch, ControlServiceDispatchError,
    ControlServiceDispatchOutcome, ControlServiceFrame, ControlServiceHandler,
    ControlServiceReplySink, DataServiceDispatch, DataServiceDispatchError,
    DataServiceDispatchOutcome, DataServiceFrame, DataServiceHandler, DataServiceReplySink,
    SessionId,
};
use tidefs_types_vfs_core::Errno;
use tidefs_vfs_engine::VfsDispatch;

use crate::transport_adapter::{
    VfsRpcFrameDirection, VfsRpcInboundFrame, VfsRpcTransportAdapter, VfsRpcTransportAdapterError,
};
use crate::vfs_engine_bridge::VfsEngineBridge;
use crate::{
    InlineOrBulk, OpId, PeerId, VfsRpcError, VfsRpcRequest, VfsRpcRequestPayload, VfsRpcResponse,
    VfsRpcTransportFrame, REQ_FLAG_BULK_PENDING, VFS_RPC_SERVICE_ID,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PendingWriteKey {
    connection_id: ConnectionId,
    token: BulkToken,
}

#[derive(Clone, Debug)]
struct PendingWrite {
    peer: PeerId,
    request: VfsRpcRequest,
    stream_id: StreamId,
    admitted_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActiveWriteState {
    Pending(PendingWriteKey),
    Dispatching { connection_id: ConnectionId },
}

struct VfsRpcBulkWriteRuntimeState {
    adapter: VfsRpcTransportAdapter,
    pending_writes: BTreeMap<PendingWriteKey, PendingWrite>,
    active_write_ops: BTreeMap<(PeerId, OpId), ActiveWriteState>,
}

/// Errors from the write-upload runtime orchestration.
#[derive(Debug)]
pub enum VfsRpcBulkWriteRuntimeError {
    Adapter(VfsRpcTransportAdapterError),
    Bulk(VfsRpcBulkHandoffError),
    BulkData(BulkError),
    ControlReply(ControlServiceDispatchError),
    VfsRpc(VfsRpcError),
    MissingActiveTransfer {
        connection_id: ConnectionId,
        token: BulkToken,
    },
    ConflictingPendingWrite {
        connection_id: ConnectionId,
        token: BulkToken,
    },
    MissingPendingWrite {
        connection_id: ConnectionId,
        token: BulkToken,
    },
    TerminalTransferIsNotWriteUpload {
        connection_id: ConnectionId,
        token: BulkToken,
    },
}

impl fmt::Display for VfsRpcBulkWriteRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adapter(error) => write!(f, "{error}"),
            Self::Bulk(error) => write!(f, "{error}"),
            Self::BulkData(error) => write!(f, "{error}"),
            Self::ControlReply(error) => write!(f, "{error}"),
            Self::VfsRpc(error) => write!(f, "{error}"),
            Self::MissingActiveTransfer {
                connection_id, ..
            } => write!(
                f,
                "VFS_RPC BULK WRITE token is no longer active on connection {connection_id}"
            ),
            Self::ConflictingPendingWrite {
                connection_id, ..
            } => write!(
                f,
                "VFS_RPC BULK WRITE token conflicts with a pending request on connection {connection_id}"
            ),
            Self::MissingPendingWrite {
                connection_id, ..
            } => write!(
                f,
                "VFS_RPC BULK WRITE terminal event has no pending request on connection {connection_id}"
            ),
            Self::TerminalTransferIsNotWriteUpload {
                connection_id, ..
            } => write!(
                f,
                "BULK terminal event on connection {connection_id} is not a VFS_RPC WRITE upload"
            ),
        }
    }
}

impl std::error::Error for VfsRpcBulkWriteRuntimeError {}

impl From<VfsRpcTransportAdapterError> for VfsRpcBulkWriteRuntimeError {
    fn from(value: VfsRpcTransportAdapterError) -> Self {
        Self::Adapter(value)
    }
}

impl From<VfsRpcBulkHandoffError> for VfsRpcBulkWriteRuntimeError {
    fn from(value: VfsRpcBulkHandoffError) -> Self {
        Self::Bulk(value)
    }
}

impl From<BulkError> for VfsRpcBulkWriteRuntimeError {
    fn from(value: BulkError) -> Self {
        Self::BulkData(value)
    }
}

impl From<VfsRpcError> for VfsRpcBulkWriteRuntimeError {
    fn from(value: VfsRpcError) -> Self {
        Self::VfsRpc(value)
    }
}

/// Authenticated VFS_RPC/BULK WRITE runtime for one server-side dispatch
/// target.
///
/// The supplied [`BulkDataServiceHandler`] is dedicated to this runtime's
/// service `0x07` binding. Each DATA dispatch returns its terminal record
/// directly so a concurrent frame cannot consume another frame's DONE/ABORT.
pub struct VfsRpcBulkWriteRuntime<T> {
    state: Mutex<VfsRpcBulkWriteRuntimeState>,
    bridge: Mutex<VfsEngineBridge>,
    target: T,
    bulk: Arc<BulkDataServiceHandler>,
    control_reply_sink: Arc<dyn ControlServiceReplySink>,
}

impl<T> VfsRpcBulkWriteRuntime<T>
where
    T: VfsDispatch + Send + Sync + 'static,
{
    #[must_use]
    pub fn new(
        adapter: VfsRpcTransportAdapter,
        bridge: VfsEngineBridge,
        bulk: Arc<BulkDataServiceHandler>,
        target: T,
        control_reply_sink: Arc<dyn ControlServiceReplySink>,
    ) -> Self {
        Self {
            state: Mutex::new(VfsRpcBulkWriteRuntimeState {
                adapter,
                pending_writes: BTreeMap::new(),
                active_write_ops: BTreeMap::new(),
            }),
            bridge: Mutex::new(bridge),
            target,
            bulk,
            control_reply_sink,
        }
    }

    /// Build the CONTROL service registry for VFS_RPC service `0x06`.
    #[must_use]
    pub fn control_dispatch(self: &Arc<Self>) -> ControlServiceDispatch {
        let dispatch = ControlServiceDispatch::new();
        dispatch.register(VFS_RPC_SERVICE_ID, self.clone());
        dispatch
    }

    /// Build the DATA service registry for BULK service `0x07`.
    #[must_use]
    pub fn data_dispatch(self: &Arc<Self>) -> DataServiceDispatch {
        let dispatch = DataServiceDispatch::new();
        dispatch.register(BULK_SERVICE_ID, self.clone());
        dispatch
    }

    /// Attach both service registries to one authenticated receive loop.
    #[must_use]
    pub fn install_on_receiver(
        self: &Arc<Self>,
        receiver: ConnectionReceiver,
        session_id: SessionId,
        data_reply_sink: Arc<dyn DataServiceReplySink>,
    ) -> ConnectionReceiver {
        let runtime = self.clone();
        receiver
            .with_data_service_dispatch(session_id, self.data_dispatch(), data_reply_sink)
            .with_control_service_dispatch(
                session_id,
                self.control_dispatch(),
                self.control_reply_sink.clone(),
            )
            .with_exit_hook(
                session_id,
                Arc::new(move |session_id| runtime.connection_lost(session_id)),
            )
    }

    #[must_use]
    pub fn pending_write_count(&self) -> usize {
        self.state.lock().unwrap().pending_writes.len()
    }

    /// Reclaim all BULK and pending-WRITE state when the authenticated
    /// connection can no longer deliver a terminal frame.
    ///
    /// No VFS_RPC reply is attempted because the connection has already
    /// exited. The adapter and runtime records are removed in the same teardown
    /// path as BULK transfer retirement so a reconnect must use fresh transfer
    /// state.
    pub fn connection_lost(&self, session_id: SessionId) {
        let connection_id = session_id.0;
        let mut state = self.state.lock().unwrap();
        let _aborted = self.bulk.connection_lost(connection_id);
        state.adapter.retire_bulk_connection(session_id);
        let pending = state
            .pending_writes
            .iter()
            .filter_map(|(key, pending)| {
                (key.connection_id == connection_id)
                    .then_some((*key, (pending.peer, pending.request.header.op_id)))
            })
            .collect::<Vec<_>>();
        for (key, op_key) in pending {
            state.pending_writes.remove(&key);
            if state.active_write_ops.get(&op_key) == Some(&ActiveWriteState::Pending(key)) {
                state.active_write_ops.remove(&op_key);
            }
        }
    }

    /// Dispatch one already-demultiplexed VFS_RPC CONTROL frame at `now`.
    pub fn handle_control_service_frame_at(
        &self,
        now: Instant,
        session_id: SessionId,
        frame: ControlServiceFrame,
    ) -> Result<ControlServiceDispatchOutcome, VfsRpcBulkWriteRuntimeError> {
        let mut state = self.state.lock().unwrap();
        let (inbound, stream_id) = self.bulk.with_service(|service| {
            let inbound = state
                .adapter
                .unwrap_control_service_frame_with_bulk(now, session_id, frame, service)?;
            let stream_id = match &inbound {
                VfsRpcInboundFrame::Request {
                    request,
                    session_id,
                    ..
                } => write_bulk_token(request)
                    .map(|token| {
                        service.stream_id_for_token(session_id.0, token).ok_or(
                            VfsRpcBulkWriteRuntimeError::MissingActiveTransfer {
                                connection_id: session_id.0,
                                token,
                            },
                        )
                    })
                    .transpose()?,
                VfsRpcInboundFrame::Response { .. } => None,
            };
            Ok::<_, VfsRpcBulkWriteRuntimeError>((inbound, stream_id))
        })?;

        match inbound {
            VfsRpcInboundFrame::Request {
                peer,
                session_id,
                request,
            } => {
                let write_key = write_bulk_token(&request).map(|token| PendingWriteKey {
                    connection_id: session_id.0,
                    token,
                });
                let op_key = (peer, request.header.op_id);
                if let Some(active) = state.active_write_ops.get(&op_key).copied() {
                    if let (ActiveWriteState::Pending(existing_key), Some(key)) =
                        (active, write_key)
                    {
                        if key == existing_key
                            && state
                                .pending_writes
                                .get(&key)
                                .is_some_and(|pending| pending.request == request)
                        {
                            return Ok(ControlServiceDispatchOutcome::Consumed);
                        }
                    }

                    let candidate = write_key.filter(|key| {
                        !matches!(active, ActiveWriteState::Pending(existing) if existing == *key)
                    });
                    drop(state);
                    if let Some(key) = candidate {
                        self.retire_conflicting_write_admission(peer, session_id, key, &request)?;
                    }
                    let response = VfsRpcResponse::error(
                        request.header.op_id,
                        request.header.method,
                        Errno::EALREADY,
                    )?;
                    return Ok(ControlServiceDispatchOutcome::Reply(
                        control_response_frame(&response)?,
                    ));
                }

                if let Some(key) = write_key {
                    let pending = PendingWrite {
                        peer,
                        request: request.clone(),
                        stream_id: stream_id.ok_or(
                            VfsRpcBulkWriteRuntimeError::MissingActiveTransfer {
                                connection_id: key.connection_id,
                                token: key.token,
                            },
                        )?,
                        admitted_at: now,
                    };
                    match state.pending_writes.get(&key) {
                        Some(existing) if existing.request == request => {
                            return Ok(ControlServiceDispatchOutcome::Consumed);
                        }
                        Some(_) => {
                            return Err(VfsRpcBulkWriteRuntimeError::ConflictingPendingWrite {
                                connection_id: key.connection_id,
                                token: key.token,
                            });
                        }
                        None => {
                            state.pending_writes.insert(key, pending);
                            state
                                .active_write_ops
                                .insert(op_key, ActiveWriteState::Pending(key));
                            return Ok(ControlServiceDispatchOutcome::Consumed);
                        }
                    }
                }

                drop(state);
                let response =
                    self.bridge
                        .lock()
                        .unwrap()
                        .dispatch(peer, &request, &self.target)?;
                Ok(ControlServiceDispatchOutcome::Reply(
                    control_response_frame(&response)?,
                ))
            }
            VfsRpcInboundFrame::Response { .. } => Ok(ControlServiceDispatchOutcome::Consumed),
        }
    }

    fn retire_conflicting_write_admission(
        &self,
        peer: PeerId,
        session_id: SessionId,
        key: PendingWriteKey,
        request: &VfsRpcRequest,
    ) -> Result<(), VfsRpcBulkWriteRuntimeError> {
        let abort = self.bulk.abort_vfs_rpc_handoff(
            key.connection_id,
            key.token,
            request.header.op_id.0,
            VfsRpcBulkHandoff::WriteUpload,
            BulkAbortReason::ProtocolError,
        )?;
        let record = self
            .state
            .lock()
            .unwrap()
            .adapter
            .abort_bulk_handoff(&abort)?;
        ensure_write_upload(
            record.connection_id,
            record.token,
            record.direction,
            record.handoff,
        )?;
        if record.peer != peer
            || record.session_id != session_id
            || record.op_id != request.header.op_id
            || record.method != request.header.method
        {
            return Err(VfsRpcBulkWriteRuntimeError::ConflictingPendingWrite {
                connection_id: key.connection_id,
                token: key.token,
            });
        }
        Ok(())
    }

    /// Retire locally timed-out incoming BULK transfers and report admitted
    /// WRITE failures after reclaiming their active BULK tokens.
    ///
    /// Accepted OFFERs that never receive a matching VFS_RPC CONTROL request
    /// are reclaimed at the BULK deadline without attempting a CONTROL reply.
    pub fn expire_write_timeouts(
        &self,
        now: Instant,
    ) -> Result<usize, VfsRpcBulkWriteRuntimeError> {
        let mut first_error = self.process_terminal_events().err();
        let mut bulk_write_timeouts = 0usize;
        for aborted in self.bulk.expire_timed_out(now) {
            let key = PendingWriteKey {
                connection_id: aborted.connection_id,
                token: aborted.token,
            };
            let has_pending_write = self.state.lock().unwrap().pending_writes.contains_key(&key);
            if !has_pending_write {
                continue;
            }
            bulk_write_timeouts = bulk_write_timeouts.saturating_add(1);
            if let Err(error) =
                self.process_terminal_event(BulkDataServiceTerminal::Aborted(aborted))
            {
                first_error.get_or_insert(error);
            }
        }
        let expired = {
            let state = self.state.lock().unwrap();
            let timeout = state.adapter.config().request_timeout;
            state
                .pending_writes
                .iter()
                .filter_map(|(key, pending)| {
                    (now.saturating_duration_since(pending.admitted_at) >= timeout)
                        .then_some((*key, pending.clone()))
                })
                .collect::<Vec<_>>()
        };

        for (key, pending) in &expired {
            if let Err(error) = self.expire_write_timeout(*key, pending) {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(bulk_write_timeouts.saturating_add(expired.len())),
        }
    }

    fn expire_write_timeout(
        &self,
        key: PendingWriteKey,
        pending: &PendingWrite,
    ) -> Result<(), VfsRpcBulkWriteRuntimeError> {
        let abort = self.bulk.abort_vfs_rpc_handoff(
            key.connection_id,
            key.token,
            pending.request.header.op_id.0,
            VfsRpcBulkHandoff::WriteUpload,
            BulkAbortReason::Timeout,
        )?;
        let response = {
            let mut state = self.state.lock().unwrap();
            let record = state.adapter.abort_bulk_handoff(&abort)?;
            ensure_write_upload(
                record.connection_id,
                record.token,
                record.direction,
                record.handoff,
            )?;
            let removed = state.pending_writes.remove(&key).ok_or(
                VfsRpcBulkWriteRuntimeError::MissingPendingWrite {
                    connection_id: key.connection_id,
                    token: key.token,
                },
            )?;
            let op_key = (removed.peer, removed.request.header.op_id);
            let active = state.active_write_ops.remove(&op_key);
            if removed.peer != record.peer
                || removed.stream_id != abort.stream_id
                || removed.request != pending.request
                || active != Some(ActiveWriteState::Pending(key))
            {
                return Err(VfsRpcBulkWriteRuntimeError::ConflictingPendingWrite {
                    connection_id: key.connection_id,
                    token: key.token,
                });
            }
            VfsRpcResponse::error(
                removed.request.header.op_id,
                removed.request.header.method,
                Errno::ETIMEDOUT,
            )?
        };
        self.send_control_reply(key.connection_id, control_response_frame(&response)?)
    }

    fn process_terminal_events(&self) -> Result<(), VfsRpcBulkWriteRuntimeError> {
        let mut first_error = None;
        for completed in self.bulk.drain_completed() {
            let result = self.process_terminal_event(BulkDataServiceTerminal::Completed(completed));
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        for aborted in self.bulk.drain_aborted() {
            let result = self.process_terminal_event(BulkDataServiceTerminal::Aborted(aborted));
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn process_terminal_event(
        &self,
        terminal: BulkDataServiceTerminal,
    ) -> Result<(), VfsRpcBulkWriteRuntimeError> {
        match terminal {
            BulkDataServiceTerminal::Completed(completed) => vfs_write_completion(completed)
                .and_then(|completion| self.complete_write(completion)),
            BulkDataServiceTerminal::Aborted(aborted) => {
                vfs_write_abort(aborted).and_then(|abort| self.abort_write(abort))
            }
        }
    }

    fn complete_write(
        &self,
        completion: VfsRpcBulkCompletion,
    ) -> Result<(), VfsRpcBulkWriteRuntimeError> {
        let (session_id, peer, op_key, key, request) = {
            let mut state = self.state.lock().unwrap();
            let record = state.adapter.complete_bulk_handoff(&completion)?;
            ensure_write_upload(
                record.connection_id,
                record.token,
                record.direction,
                record.handoff,
            )?;
            let key = PendingWriteKey {
                connection_id: record.connection_id,
                token: record.token,
            };
            let pending = state.pending_writes.remove(&key).ok_or(
                VfsRpcBulkWriteRuntimeError::MissingPendingWrite {
                    connection_id: key.connection_id,
                    token: key.token,
                },
            )?;
            let op_key = (pending.peer, pending.request.header.op_id);
            let active = state.active_write_ops.remove(&op_key);
            if pending.peer != record.peer
                || pending.stream_id != completion.stream_id
                || pending.request.header.op_id != record.op_id
                || completion.op_id != record.op_id.0
                || active != Some(ActiveWriteState::Pending(key))
            {
                return Err(VfsRpcBulkWriteRuntimeError::ConflictingPendingWrite {
                    connection_id: key.connection_id,
                    token: key.token,
                });
            }
            state.active_write_ops.insert(
                op_key,
                ActiveWriteState::Dispatching {
                    connection_id: record.connection_id,
                },
            );
            (record.session_id, record.peer, op_key, key, pending.request)
        };
        let response = self.bridge.lock().unwrap().dispatch_done_verified_write(
            peer,
            &request,
            completion,
            &self.target,
        );
        {
            let mut state = self.state.lock().unwrap();
            match state.active_write_ops.remove(&op_key) {
                Some(ActiveWriteState::Dispatching { connection_id })
                    if connection_id == session_id.0 => {}
                Some(active) => {
                    state.active_write_ops.insert(op_key, active);
                    return Err(VfsRpcBulkWriteRuntimeError::ConflictingPendingWrite {
                        connection_id: key.connection_id,
                        token: key.token,
                    });
                }
                None => {
                    return Err(VfsRpcBulkWriteRuntimeError::ConflictingPendingWrite {
                        connection_id: key.connection_id,
                        token: key.token,
                    });
                }
            }
        }
        let response = response?;
        self.send_control_reply(session_id.0, control_response_frame(&response)?)
    }

    fn abort_write(&self, abort: VfsRpcBulkAbort) -> Result<(), VfsRpcBulkWriteRuntimeError> {
        let (session_id, response) = {
            let mut state = self.state.lock().unwrap();
            let record = state.adapter.abort_bulk_handoff(&abort)?;
            ensure_write_upload(
                record.connection_id,
                record.token,
                record.direction,
                record.handoff,
            )?;
            let key = PendingWriteKey {
                connection_id: record.connection_id,
                token: record.token,
            };
            let pending = state.pending_writes.remove(&key).ok_or(
                VfsRpcBulkWriteRuntimeError::MissingPendingWrite {
                    connection_id: key.connection_id,
                    token: key.token,
                },
            )?;
            let op_key = (pending.peer, pending.request.header.op_id);
            let active = state.active_write_ops.remove(&op_key);
            if pending.peer != record.peer
                || pending.stream_id != abort.stream_id
                || pending.request.header.op_id != record.op_id
                || active != Some(ActiveWriteState::Pending(key))
            {
                return Err(VfsRpcBulkWriteRuntimeError::ConflictingPendingWrite {
                    connection_id: key.connection_id,
                    token: key.token,
                });
            }
            let errno = if abort.reason == BulkAbortReason::Timeout {
                Errno::ETIMEDOUT
            } else {
                Errno::ECANCELED
            };
            let response = VfsRpcResponse::error(
                pending.request.header.op_id,
                pending.request.header.method,
                errno,
            )?;
            (record.session_id, response)
        };
        self.send_control_reply(session_id.0, control_response_frame(&response)?)
    }

    fn send_control_reply(
        &self,
        connection_id: ConnectionId,
        frame: ControlServiceFrame,
    ) -> Result<(), VfsRpcBulkWriteRuntimeError> {
        self.control_reply_sink
            .send_control_service_reply(SessionId::new(connection_id), frame)
            .map_err(VfsRpcBulkWriteRuntimeError::ControlReply)
    }
}

impl<T> ControlServiceHandler for VfsRpcBulkWriteRuntime<T>
where
    T: VfsDispatch + Send + Sync + 'static,
{
    fn handle_control_service_frame(
        &self,
        session_id: SessionId,
        frame: ControlServiceFrame,
    ) -> Result<ControlServiceDispatchOutcome, ControlServiceDispatchError> {
        self.handle_control_service_frame_at(Instant::now(), session_id, frame)
            .map_err(control_runtime_error)
    }
}

impl<T> DataServiceHandler for VfsRpcBulkWriteRuntime<T>
where
    T: VfsDispatch + Send + Sync + 'static,
{
    fn handle_data_service_frame(
        &self,
        session_id: SessionId,
        frame: DataServiceFrame,
    ) -> Result<DataServiceDispatchOutcome, DataServiceDispatchError> {
        let (outcome, terminal) = self
            .bulk
            .handle_data_service_frame_with_terminal(session_id, frame);
        let terminal = terminal
            .map(|terminal| self.process_terminal_event(terminal))
            .transpose()
            .map_err(data_runtime_error);
        match (outcome, terminal) {
            (Ok(outcome), Ok(_)) => Ok(outcome),
            (Err(error), Ok(_)) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }
}

fn write_bulk_token(request: &VfsRpcRequest) -> Option<BulkToken> {
    match &request.payload {
        VfsRpcRequestPayload::Write {
            data: InlineOrBulk::Bulk { token, .. },
            ..
        } if request.header.flags & REQ_FLAG_BULK_PENDING != 0 => Some(*token),
        _ => None,
    }
}

fn vfs_write_completion(
    completed: CompletedBulkTransfer,
) -> Result<VfsRpcBulkCompletion, VfsRpcBulkWriteRuntimeError> {
    let (op_id, handoff) = vfs_write_handoff(
        &completed.metadata,
        completed.connection_id,
        completed.token,
    )?;
    let len = u64::try_from(completed.bytes.len()).map_err(|_| {
        VfsRpcBulkWriteRuntimeError::TerminalTransferIsNotWriteUpload {
            connection_id: completed.connection_id,
            token: completed.token,
        }
    })?;
    Ok(VfsRpcBulkCompletion {
        connection_id: completed.connection_id,
        stream_id: completed.stream_id,
        token: completed.token,
        op_id,
        handoff,
        len,
        bytes: completed.bytes,
    })
}

fn vfs_write_abort(
    aborted: AbortedBulkTransfer,
) -> Result<VfsRpcBulkAbort, VfsRpcBulkWriteRuntimeError> {
    let (op_id, handoff) =
        vfs_write_handoff(&aborted.metadata, aborted.connection_id, aborted.token)?;
    Ok(VfsRpcBulkAbort {
        connection_id: aborted.connection_id,
        stream_id: aborted.stream_id,
        token: aborted.token,
        op_id,
        handoff,
        reason: aborted.reason,
    })
}

fn vfs_write_handoff(
    metadata: &BulkMetadata,
    connection_id: ConnectionId,
    token: BulkToken,
) -> Result<(u64, VfsRpcBulkHandoff), VfsRpcBulkWriteRuntimeError> {
    match metadata {
        BulkMetadata::VfsRpc {
            method: VfsRpcBulkMethod::Write,
            op_id,
            direction: BulkTransferDirection::WriteUpload,
        } => Ok((*op_id, VfsRpcBulkHandoff::WriteUpload)),
        _ => Err(
            VfsRpcBulkWriteRuntimeError::TerminalTransferIsNotWriteUpload {
                connection_id,
                token,
            },
        ),
    }
}

fn ensure_write_upload(
    connection_id: ConnectionId,
    token: BulkToken,
    direction: VfsRpcFrameDirection,
    handoff: VfsRpcBulkHandoff,
) -> Result<(), VfsRpcBulkWriteRuntimeError> {
    if direction == VfsRpcFrameDirection::Request && handoff == VfsRpcBulkHandoff::WriteUpload {
        Ok(())
    } else {
        Err(
            VfsRpcBulkWriteRuntimeError::TerminalTransferIsNotWriteUpload {
                connection_id,
                token,
            },
        )
    }
}

fn control_response_frame(
    response: &VfsRpcResponse,
) -> Result<ControlServiceFrame, VfsRpcBulkWriteRuntimeError> {
    let frame = VfsRpcTransportFrame::from_response(response)?;
    Ok(ControlServiceFrame::new(
        frame.service_id,
        frame.message_type,
        frame.body,
    ))
}

fn control_runtime_error(error: VfsRpcBulkWriteRuntimeError) -> ControlServiceDispatchError {
    ControlServiceDispatchError::HandlerRejected {
        service_id: VFS_RPC_SERVICE_ID,
        reason: error.to_string(),
    }
}

fn data_runtime_error(error: VfsRpcBulkWriteRuntimeError) -> DataServiceDispatchError {
    DataServiceDispatchError::HandlerRejected {
        service_id: BULK_SERVICE_ID,
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Barrier, Mutex};
    use std::thread;
    use std::time::Duration;

    use tidefs_bulk_service::{
        BulkAcceptResult, BulkCreditRequestFrame, BulkCreditResult, BulkDoneFrame, BulkFrame,
        BulkMode, BulkOfferFrame, BulkPriority, BulkService, BulkServiceConfig, BulkTcpChunkFrame,
    };
    use tidefs_transport::{ControlServiceReplySink, TransportSessionSet};
    use tidefs_types_vfs_core::{
        EngineFileHandle, FileHandleId, Generation, InodeAttr, InodeFlags, InodeId, NodeKind,
        PosixAttrs, S_IFREG,
    };
    use tidefs_vfs_engine::operation as engine_op;
    use tidefs_vfs_engine::{VfsOperation, VfsResponse};

    use super::*;
    use crate::transport_adapter::VfsRpcTransportAdapterConfig;
    use crate::vfs_engine_bridge::VfsEngineBridgeWriter;
    use crate::{DatasetId, OpId, PeerId, VfsRpcCredentials, VfsRpcResponsePayload};

    const PEER: PeerId = PeerId(9);
    const SESSION_ID: SessionId = SessionId::new(33);

    type WriteProbe = Arc<dyn Fn() + Send + Sync>;

    #[derive(Clone, Default)]
    struct RecordingDispatch {
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
        write_probe: Arc<Mutex<Option<WriteProbe>>>,
    }

    impl RecordingDispatch {
        fn writes(&self) -> Vec<Vec<u8>> {
            self.writes.lock().unwrap().clone()
        }

        fn set_write_probe(&self, probe: impl Fn() + Send + Sync + 'static) {
            *self.write_probe.lock().unwrap() = Some(Arc::new(probe));
        }

        fn attr() -> InodeAttr {
            InodeAttr::new(
                InodeId::new(100),
                Generation::new(7),
                NodeKind::File,
                PosixAttrs {
                    mode: S_IFREG | 0o644,
                    uid: 0,
                    gid: 0,
                    nlink: 1,
                    rdev: 0,
                    atime_ns: 0,
                    mtime_ns: 0,
                    ctime_ns: 0,
                    btime_ns: 0,
                    size: 0,
                    blocks_512: 0,
                    blksize: 4096,
                },
                InodeFlags::default(),
                11,
                22,
            )
        }
    }

    impl VfsDispatch for RecordingDispatch {
        fn dispatch(&self, op: VfsOperation) -> Result<VfsResponse, Errno> {
            match op {
                VfsOperation::Create(request) => {
                    Ok(VfsResponse::Create(engine_op::CreateResponse {
                        attr: Self::attr(),
                        fh: EngineFileHandle::new(
                            InodeId::new(100),
                            request.flags,
                            FileHandleId::new(44),
                            0,
                        ),
                    }))
                }
                VfsOperation::Write(request) => {
                    let probe = self.write_probe.lock().unwrap().clone();
                    if let Some(probe) = probe {
                        probe();
                    }
                    self.writes.lock().unwrap().push(request.data.clone());
                    Ok(VfsResponse::Write(engine_op::WriteResponse {
                        written: request.data.len() as u32,
                    }))
                }
                _ => Ok(VfsResponse::Err(Errno::ENOSYS)),
            }
        }
    }

    #[derive(Default)]
    struct RecordingControlReplySink {
        replies: Mutex<Vec<(SessionId, ControlServiceFrame)>>,
        failures_remaining: Mutex<usize>,
    }

    impl RecordingControlReplySink {
        fn replies(&self) -> Vec<(SessionId, ControlServiceFrame)> {
            self.replies.lock().unwrap().clone()
        }

        fn fail_next_replies(&self, count: usize) {
            *self.failures_remaining.lock().unwrap() = count;
        }
    }

    impl ControlServiceReplySink for RecordingControlReplySink {
        fn send_control_service_reply(
            &self,
            session_id: SessionId,
            frame: ControlServiceFrame,
        ) -> Result<(), ControlServiceDispatchError> {
            let mut failures_remaining = self.failures_remaining.lock().unwrap();
            if *failures_remaining > 0 {
                *failures_remaining -= 1;
                return Err(ControlServiceDispatchError::ReplyRejected {
                    reason: "injected reply failure".to_string(),
                });
            }
            drop(failures_remaining);
            self.replies.lock().unwrap().push((session_id, frame));
            Ok(())
        }
    }

    fn runtime(
        request_timeout: Duration,
    ) -> (
        Arc<VfsRpcBulkWriteRuntime<RecordingDispatch>>,
        RecordingDispatch,
        Arc<RecordingControlReplySink>,
    ) {
        runtime_with_bulk_deadline(request_timeout, BulkServiceConfig::default().bulk_deadline)
    }

    fn runtime_with_bulk_deadline(
        request_timeout: Duration,
        bulk_deadline: Duration,
    ) -> (
        Arc<VfsRpcBulkWriteRuntime<RecordingDispatch>>,
        RecordingDispatch,
        Arc<RecordingControlReplySink>,
    ) {
        let mut sessions = TransportSessionSet::new();
        sessions.add_binding(PEER.0, SESSION_ID);
        sessions.mark_healthy(SESSION_ID);
        let adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig {
                request_timeout,
                ..VfsRpcTransportAdapterConfig::default()
            },
            sessions,
        );
        let bridge = VfsEngineBridge::new(VfsEngineBridgeWriter::new(42, DatasetId::new(99), 3, 5));
        let bulk = Arc::new(BulkDataServiceHandler::new(BulkService::new(
            BulkServiceConfig {
                receiver_node_id: 42,
                max_transfer_len: 64,
                max_pinned_bytes: 64,
                max_chunk: 8,
                bulk_deadline,
                ..BulkServiceConfig::default()
            },
        )));
        let target = RecordingDispatch::default();
        let sink = Arc::new(RecordingControlReplySink::default());
        let runtime = Arc::new(VfsRpcBulkWriteRuntime::new(
            adapter,
            bridge,
            bulk,
            target.clone(),
            sink.clone(),
        ));
        (runtime, target, sink)
    }

    fn credentials() -> VfsRpcCredentials {
        VfsRpcCredentials::root(PEER)
    }

    fn control_request(request: &VfsRpcRequest) -> ControlServiceFrame {
        let frame = VfsRpcTransportFrame::from_request(request).expect("request frame");
        ControlServiceFrame::new(frame.service_id, frame.message_type, frame.body)
    }

    fn response(frame: ControlServiceFrame) -> VfsRpcResponse {
        VfsRpcTransportFrame {
            service_id: frame.service_id,
            message_type: frame.message_type,
            body: frame.body,
        }
        .decode_response()
        .expect("response")
    }

    fn dispatch_data(
        dispatch: &DataServiceDispatch,
        frame: BulkFrame,
    ) -> Result<DataServiceDispatchOutcome, DataServiceDispatchError> {
        let encoded = frame
            .to_data_service_frame()
            .expect("data service frame")
            .encode()
            .expect("data service encoding");
        dispatch.dispatch(SESSION_ID, &encoded)
    }

    fn create_handle(
        runtime: &Arc<VfsRpcBulkWriteRuntime<RecordingDispatch>>,
    ) -> crate::VfsRpcHandle {
        let request = VfsRpcRequest::new(
            OpId(1),
            3,
            5,
            0,
            VfsRpcRequestPayload::Create {
                parent: InodeId::new(1),
                name: b"file".to_vec(),
                mode: 0o644,
                flags: 0o2,
            },
            Some(credentials()),
        )
        .expect("create request");
        let outcome = runtime
            .handle_control_service_frame_at(Instant::now(), SESSION_ID, control_request(&request))
            .expect("create");
        let response = match outcome {
            ControlServiceDispatchOutcome::Reply(frame) => response(frame),
            ControlServiceDispatchOutcome::Consumed => panic!("create needs response"),
        };
        match response.payload {
            VfsRpcResponsePayload::Created { handle, .. } => handle,
            other => panic!("unexpected create response: {other:?}"),
        }
    }

    fn accept_write_transfer(
        dispatch: &DataServiceDispatch,
        op_id: u64,
        stream_id: StreamId,
        len: u64,
    ) -> BulkToken {
        let outcome = dispatch_data(
            dispatch,
            BulkFrame::Offer(BulkOfferFrame {
                stream_id,
                total_len: len,
                mode: BulkMode::TcpStream,
                priority: BulkPriority::Bulk,
                metadata: BulkMetadata::vfs_rpc_write_upload(op_id),
            }),
        )
        .expect("offer");
        let reply = match outcome {
            DataServiceDispatchOutcome::Reply(frame) => {
                BulkFrame::from_data_service_frame(frame).expect("accept")
            }
            DataServiceDispatchOutcome::Consumed => panic!("offer needs accept"),
        };
        match reply {
            BulkFrame::Accept(accept) => {
                assert_eq!(accept.result, BulkAcceptResult::Accepted);
                accept.token.expect("token")
            }
            other => panic!("unexpected offer reply: {other:?}"),
        }
    }

    fn admitted_write(
        runtime: &Arc<VfsRpcBulkWriteRuntime<RecordingDispatch>>,
        handle: crate::VfsRpcHandle,
        token: BulkToken,
        len: u64,
        now: Instant,
    ) -> VfsRpcRequest {
        admitted_write_for_op(runtime, handle, token, len, 2, now)
    }

    fn admitted_write_for_op(
        runtime: &Arc<VfsRpcBulkWriteRuntime<RecordingDispatch>>,
        handle: crate::VfsRpcHandle,
        token: BulkToken,
        len: u64,
        op_id: u64,
        now: Instant,
    ) -> VfsRpcRequest {
        let request = bulk_write_request(handle, token, len, op_id, 0);
        assert_eq!(
            runtime
                .handle_control_service_frame_at(now, SESSION_ID, control_request(&request))
                .expect("admit write"),
            ControlServiceDispatchOutcome::Consumed
        );
        request
    }

    fn bulk_write_request(
        handle: crate::VfsRpcHandle,
        token: BulkToken,
        len: u64,
        op_id: u64,
        offset: u64,
    ) -> VfsRpcRequest {
        VfsRpcRequest::new(
            OpId(op_id),
            3,
            5,
            REQ_FLAG_BULK_PENDING,
            VfsRpcRequestPayload::Write {
                handle,
                offset,
                data: InlineOrBulk::Bulk { token, len },
            },
            Some(credentials()),
        )
        .expect("write request")
    }

    fn grant_and_write(
        dispatch: &DataServiceDispatch,
        stream_id: StreamId,
        token: BulkToken,
        bytes: &[u8],
    ) {
        let outcome = dispatch_data(
            dispatch,
            BulkFrame::CreditRequest(BulkCreditRequestFrame {
                stream_id,
                token,
                chunk_seq: 0,
                len: u32::try_from(bytes.len()).expect("chunk len"),
            }),
        )
        .expect("credit request");
        let grant = match outcome {
            DataServiceDispatchOutcome::Reply(frame) => {
                BulkFrame::from_data_service_frame(frame).expect("credit grant")
            }
            DataServiceDispatchOutcome::Consumed => panic!("credit needs reply"),
        };
        let grant = match grant {
            BulkFrame::CreditGrant(grant) => {
                assert_eq!(grant.result, BulkCreditResult::Granted);
                grant
            }
            other => panic!("unexpected credit reply: {other:?}"),
        };
        assert_eq!(
            dispatch_data(
                dispatch,
                BulkFrame::TcpChunk(
                    BulkTcpChunkFrame::new(
                        stream_id,
                        token,
                        grant.chunk_seq,
                        grant.offset,
                        bytes.to_vec(),
                    )
                    .expect("chunk"),
                ),
            )
            .expect("chunk write"),
            DataServiceDispatchOutcome::Consumed
        );
    }

    #[test]
    fn bulk_write_dispatches_only_after_done_and_replies_on_control_service() {
        let (runtime, target, sink) = runtime(Duration::from_secs(1));
        let handle = create_handle(&runtime);
        let data_dispatch = runtime.data_dispatch();
        let token = accept_write_transfer(&data_dispatch, 2, 11, 3);
        admitted_write(&runtime, handle, token, 3, Instant::now());

        assert!(target.writes().is_empty());
        assert_eq!(runtime.pending_write_count(), 1);
        grant_and_write(&data_dispatch, 11, token, b"abc");
        assert!(target.writes().is_empty());

        assert_eq!(
            dispatch_data(
                &data_dispatch,
                BulkFrame::Done(BulkDoneFrame {
                    stream_id: 11,
                    token,
                    total_transferred: 3,
                    checksum32: 0x364b_3fb7,
                }),
            )
            .expect("done"),
            DataServiceDispatchOutcome::Consumed
        );

        assert_eq!(target.writes(), vec![b"abc".to_vec()]);
        assert_eq!(runtime.pending_write_count(), 0);
        let replies = sink.replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].0, SESSION_ID);
        assert_eq!(
            response(replies[0].1.clone()).payload,
            VfsRpcResponsePayload::BytesWritten(3)
        );
    }

    #[test]
    fn duplicate_active_write_op_retires_only_the_new_bulk_token() {
        let (runtime, target, sink) = runtime(Duration::from_secs(1));
        let handle = create_handle(&runtime);
        let data_dispatch = runtime.data_dispatch();
        let first = accept_write_transfer(&data_dispatch, 2, 28, 3);
        let second = accept_write_transfer(&data_dispatch, 2, 29, 3);
        admitted_write(&runtime, handle.clone(), first, 3, Instant::now());
        grant_and_write(&data_dispatch, 29, second, b"xyz");

        let conflicting = bulk_write_request(handle, second, 3, 2, 1);
        let outcome = runtime
            .handle_control_service_frame_at(
                Instant::now(),
                SESSION_ID,
                control_request(&conflicting),
            )
            .expect("duplicate op reply");
        let reply = match outcome {
            ControlServiceDispatchOutcome::Reply(frame) => response(frame),
            ControlServiceDispatchOutcome::Consumed => panic!("duplicate op must be refused"),
        };

        assert_eq!(reply.header.errno, Errno::EALREADY);
        assert_eq!(runtime.pending_write_count(), 1);
        assert_eq!(runtime.bulk.active_transfer_count(SESSION_ID.0), 1);
        assert_eq!(runtime.bulk.pinned_bytes(SESSION_ID.0), 0);
        assert_eq!(runtime.state.lock().unwrap().adapter.pending_bulk_len(), 1);
        assert!(target.writes().is_empty());

        grant_and_write(&data_dispatch, 28, first, b"abc");
        dispatch_data(
            &data_dispatch,
            BulkFrame::Done(BulkDoneFrame {
                stream_id: 28,
                token: first,
                total_transferred: 3,
                checksum32: 0x364b_3fb7,
            }),
        )
        .expect("first done");

        assert_eq!(target.writes(), vec![b"abc".to_vec()]);
        assert_eq!(runtime.pending_write_count(), 0);
        assert_eq!(sink.replies().len(), 1);
    }

    #[test]
    fn inline_request_cannot_prime_dedup_for_pending_bulk_write() {
        let (runtime, target, sink) = runtime(Duration::from_secs(1));
        let handle = create_handle(&runtime);
        let data_dispatch = runtime.data_dispatch();
        let token = accept_write_transfer(&data_dispatch, 2, 30, 3);
        admitted_write(&runtime, handle.clone(), token, 3, Instant::now());

        let inline = VfsRpcRequest::new(
            OpId(2),
            3,
            5,
            0,
            VfsRpcRequestPayload::Write {
                handle,
                offset: 1,
                data: InlineOrBulk::Inline(b"xyz".to_vec()),
            },
            Some(credentials()),
        )
        .expect("inline collision");
        let outcome = runtime
            .handle_control_service_frame_at(Instant::now(), SESSION_ID, control_request(&inline))
            .expect("inline collision reply");
        let reply = match outcome {
            ControlServiceDispatchOutcome::Reply(frame) => response(frame),
            ControlServiceDispatchOutcome::Consumed => panic!("inline collision must be refused"),
        };

        assert_eq!(reply.header.errno, Errno::EALREADY);
        assert!(target.writes().is_empty());
        assert_eq!(runtime.pending_write_count(), 1);

        grant_and_write(&data_dispatch, 30, token, b"abc");
        dispatch_data(
            &data_dispatch,
            BulkFrame::Done(BulkDoneFrame {
                stream_id: 30,
                token,
                total_transferred: 3,
                checksum32: 0x364b_3fb7,
            }),
        )
        .expect("bulk done");

        assert_eq!(target.writes(), vec![b"abc".to_vec()]);
        assert_eq!(sink.replies().len(), 1);
    }

    #[test]
    fn write_op_stays_reserved_until_done_dispatch_finishes() {
        let (runtime, target, sink) = runtime(Duration::from_secs(1));
        let handle = create_handle(&runtime);
        let retry_handle = handle.clone();
        let data_dispatch = runtime.data_dispatch();
        let token = accept_write_transfer(&data_dispatch, 2, 31, 3);
        admitted_write(&runtime, handle, token, 3, Instant::now());
        grant_and_write(&data_dispatch, 31, token, b"abc");

        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let entered_probe = entered.clone();
        let release_probe = release.clone();
        target.set_write_probe(move || {
            entered_probe.wait();
            release_probe.wait();
        });

        let done = BulkFrame::Done(BulkDoneFrame {
            stream_id: 31,
            token,
            total_transferred: 3,
            checksum32: 0x364b_3fb7,
        })
        .to_data_service_frame()
        .expect("done frame");
        let runtime_for_done = runtime.clone();
        let done_thread =
            thread::spawn(move || runtime_for_done.handle_data_service_frame(SESSION_ID, done));
        entered.wait();

        let retry = accept_write_transfer(&data_dispatch, 2, 32, 3);
        let retry_request = bulk_write_request(retry_handle, retry, 3, 2, 0);
        let retry_outcome = runtime.handle_control_service_frame_at(
            Instant::now(),
            SESSION_ID,
            control_request(&retry_request),
        );
        let active_transfers = runtime.bulk.active_transfer_count(SESSION_ID.0);
        let adapter_pending = runtime.state.lock().unwrap().adapter.pending_bulk_len();

        release.wait();
        let done_outcome = done_thread.join().expect("done thread").expect("done");
        let retry_outcome = retry_outcome.expect("retry collision reply");
        let retry_reply = match retry_outcome {
            ControlServiceDispatchOutcome::Reply(frame) => response(frame),
            ControlServiceDispatchOutcome::Consumed => panic!("dispatching op must stay reserved"),
        };

        assert_eq!(retry_reply.header.errno, Errno::EALREADY);
        assert_eq!(active_transfers, 0);
        assert_eq!(adapter_pending, 0);
        assert_eq!(done_outcome, DataServiceDispatchOutcome::Consumed);
        assert_eq!(target.writes(), vec![b"abc".to_vec()]);
        assert_eq!(sink.replies().len(), 1);
        assert!(runtime.state.lock().unwrap().active_write_ops.is_empty());
    }

    #[test]
    fn bulk_write_dispatch_does_not_hold_runtime_state_lock() {
        let (runtime, target, _) = runtime(Duration::from_secs(1));
        let handle = create_handle(&runtime);
        let data_dispatch = runtime.data_dispatch();
        let token = accept_write_transfer(&data_dispatch, 2, 23, 3);
        admitted_write(&runtime, handle, token, 3, Instant::now());
        grant_and_write(&data_dispatch, 23, token, b"abc");

        let runtime_ref = Arc::downgrade(&runtime);
        target.set_write_probe(move || {
            let runtime = runtime_ref.upgrade().expect("runtime remains live");
            assert!(
                runtime.state.try_lock().is_ok(),
                "VFS dispatch must not hold adapter and pending-write state"
            );
        });

        dispatch_data(
            &data_dispatch,
            BulkFrame::Done(BulkDoneFrame {
                stream_id: 23,
                token,
                total_transferred: 3,
                checksum32: 0x364b_3fb7,
            }),
        )
        .expect("done");

        assert_eq!(target.writes(), vec![b"abc".to_vec()]);
        assert_eq!(runtime.pending_write_count(), 0);
    }

    #[test]
    fn bulk_abort_retires_write_and_returns_canceled() {
        let (runtime, target, sink) = runtime(Duration::from_secs(1));
        let handle = create_handle(&runtime);
        let data_dispatch = runtime.data_dispatch();
        let token = accept_write_transfer(&data_dispatch, 2, 12, 3);
        let request = admitted_write(&runtime, handle, token, 3, Instant::now());

        assert_eq!(
            dispatch_data(
                &data_dispatch,
                BulkFrame::Abort(tidefs_bulk_service::BulkAbortFrame {
                    stream_id: 12,
                    token,
                    reason: BulkAbortReason::SenderCancel,
                }),
            )
            .expect("abort"),
            DataServiceDispatchOutcome::Consumed
        );

        assert!(target.writes().is_empty());
        assert_eq!(runtime.pending_write_count(), 0);
        let replies = sink.replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(
            response(replies[0].1.clone()).header.errno,
            Errno::ECANCELED
        );
        assert!(runtime
            .handle_control_service_frame_at(Instant::now(), SESSION_ID, control_request(&request))
            .is_err());
    }

    #[test]
    fn connection_loss_reclaims_admitted_and_orphan_transfers() {
        let (runtime, target, sink) = runtime(Duration::from_secs(1));
        let handle = create_handle(&runtime);
        let data_dispatch = runtime.data_dispatch();
        let admitted = accept_write_transfer(&data_dispatch, 2, 26, 3);
        let _request = admitted_write(&runtime, handle, admitted, 3, Instant::now());
        let orphan = accept_write_transfer(&data_dispatch, 77, 27, 5);
        grant_and_write(&data_dispatch, 26, admitted, b"abc");
        grant_and_write(&data_dispatch, 27, orphan, b"abcde");

        assert_eq!(runtime.pending_write_count(), 1);
        assert_eq!(runtime.bulk.active_transfer_count(SESSION_ID.0), 2);
        assert_eq!(runtime.bulk.pinned_bytes(SESSION_ID.0), 8);
        assert_eq!(runtime.state.lock().unwrap().adapter.pending_bulk_len(), 1);

        runtime.connection_lost(SESSION_ID);

        assert_eq!(runtime.pending_write_count(), 0);
        assert_eq!(runtime.bulk.active_transfer_count(SESSION_ID.0), 0);
        assert_eq!(runtime.bulk.pinned_bytes(SESSION_ID.0), 0);
        assert_eq!(runtime.state.lock().unwrap().adapter.pending_bulk_len(), 0);
        assert!(target.writes().is_empty());
        assert!(sink.replies().is_empty());

        runtime.connection_lost(SESSION_ID);
        assert_eq!(runtime.pending_write_count(), 0);
    }

    #[test]
    fn bulk_deadline_reclaims_admitted_and_orphan_transfers() {
        let (runtime, target, sink) =
            runtime_with_bulk_deadline(Duration::from_secs(1), Duration::ZERO);
        let handle = create_handle(&runtime);
        let data_dispatch = runtime.data_dispatch();
        let admitted = accept_write_transfer(&data_dispatch, 2, 28, 3);
        admitted_write(&runtime, handle, admitted, 3, Instant::now());
        accept_write_transfer(&data_dispatch, 77, 29, 5);

        assert_eq!(runtime.pending_write_count(), 1);
        assert_eq!(runtime.bulk.active_transfer_count(SESSION_ID.0), 2);
        assert_eq!(
            runtime
                .expire_write_timeouts(Instant::now())
                .expect("bulk deadline"),
            1
        );

        assert_eq!(runtime.pending_write_count(), 0);
        assert_eq!(runtime.bulk.active_transfer_count(SESSION_ID.0), 0);
        assert_eq!(runtime.bulk.pinned_bytes(SESSION_ID.0), 0);
        assert_eq!(runtime.state.lock().unwrap().adapter.pending_bulk_len(), 0);
        assert!(target.writes().is_empty());
        let replies = sink.replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(
            response(replies[0].1.clone()).header.errno,
            Errno::ETIMEDOUT
        );
    }

    #[test]
    fn timeout_aborts_active_write_and_returns_timed_out() {
        let (runtime, target, sink) = runtime(Duration::from_millis(10));
        let handle = create_handle(&runtime);
        let data_dispatch = runtime.data_dispatch();
        let token = accept_write_transfer(&data_dispatch, 2, 13, 3);
        let now = Instant::now();
        let request = admitted_write(&runtime, handle, token, 3, now);

        assert_eq!(
            runtime
                .expire_write_timeouts(now + Duration::from_millis(10))
                .expect("timeout"),
            1
        );
        assert!(target.writes().is_empty());
        assert_eq!(runtime.pending_write_count(), 0);
        let replies = sink.replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(
            response(replies[0].1.clone()).header.errno,
            Errno::ETIMEDOUT
        );
        assert!(runtime
            .handle_control_service_frame_at(Instant::now(), SESSION_ID, control_request(&request))
            .is_err());
    }

    #[test]
    fn wrong_done_stream_preserves_pending_write_for_matching_done() {
        let (runtime, target, sink) = runtime(Duration::from_secs(1));
        let handle = create_handle(&runtime);
        let data_dispatch = runtime.data_dispatch();
        let token = accept_write_transfer(&data_dispatch, 2, 14, 3);
        admitted_write(&runtime, handle, token, 3, Instant::now());
        grant_and_write(&data_dispatch, 14, token, b"abc");

        assert!(dispatch_data(
            &data_dispatch,
            BulkFrame::Done(BulkDoneFrame {
                stream_id: 15,
                token,
                total_transferred: 3,
                checksum32: 0x364b_3fb7,
            }),
        )
        .is_err());
        assert_eq!(runtime.pending_write_count(), 1);
        assert!(target.writes().is_empty());

        dispatch_data(
            &data_dispatch,
            BulkFrame::Done(BulkDoneFrame {
                stream_id: 14,
                token,
                total_transferred: 3,
                checksum32: 0x364b_3fb7,
            }),
        )
        .expect("matching done");

        assert_eq!(runtime.pending_write_count(), 0);
        assert_eq!(target.writes(), vec![b"abc".to_vec()]);
        assert_eq!(sink.replies().len(), 1);
    }

    #[test]
    fn bad_done_checksum_retires_write_and_returns_canceled() {
        let (runtime, target, sink) = runtime(Duration::from_secs(1));
        let handle = create_handle(&runtime);
        let data_dispatch = runtime.data_dispatch();
        let token = accept_write_transfer(&data_dispatch, 2, 16, 3);
        let request = admitted_write(&runtime, handle, token, 3, Instant::now());
        grant_and_write(&data_dispatch, 16, token, b"abc");

        assert!(dispatch_data(
            &data_dispatch,
            BulkFrame::Done(BulkDoneFrame {
                stream_id: 16,
                token,
                total_transferred: 3,
                checksum32: 0,
            }),
        )
        .is_err());

        assert!(target.writes().is_empty());
        assert_eq!(runtime.pending_write_count(), 0);
        assert_eq!(runtime.bulk.active_transfer_count(SESSION_ID.0), 0);
        assert_eq!(
            runtime
                .expire_write_timeouts(Instant::now() + Duration::from_secs(2))
                .expect("retired transfer has no timeout work"),
            0
        );
        let replies = sink.replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(
            response(replies[0].1.clone()).header.errno,
            Errno::ECANCELED
        );
        assert!(runtime
            .handle_control_service_frame_at(Instant::now(), SESSION_ID, control_request(&request))
            .is_err());
    }

    #[test]
    fn terminal_error_does_not_drop_later_matching_completion() {
        let (runtime, target, sink) = runtime(Duration::from_secs(1));
        let handle = create_handle(&runtime);
        let data_dispatch = runtime.data_dispatch();
        let orphan = accept_write_transfer(&data_dispatch, 77, 17, 3);
        let admitted = accept_write_transfer(&data_dispatch, 2, 18, 3);
        admitted_write(&runtime, handle, admitted, 3, Instant::now());
        grant_and_write(&data_dispatch, 17, orphan, b"bad");
        grant_and_write(&data_dispatch, 18, admitted, b"abc");

        for (stream_id, token, checksum32) in
            [(17, orphan, 0x3c48_33b6), (18, admitted, 0x364b_3fb7)]
        {
            runtime
                .bulk
                .handle_data_service_frame(
                    SESSION_ID,
                    BulkFrame::Done(BulkDoneFrame {
                        stream_id,
                        token,
                        total_transferred: 3,
                        checksum32,
                    })
                    .to_data_service_frame()
                    .expect("done frame"),
                )
                .expect("queue completion");
        }

        assert!(runtime.process_terminal_events().is_err());
        assert_eq!(target.writes(), vec![b"abc".to_vec()]);
        assert_eq!(runtime.pending_write_count(), 0);
        assert_eq!(sink.replies().len(), 1);
    }

    #[test]
    fn frame_scoped_dispatch_does_not_drain_another_calls_terminal() {
        let (runtime, target, sink) = runtime(Duration::from_secs(1));
        let data_dispatch = runtime.data_dispatch();
        let orphan = accept_write_transfer(&data_dispatch, 77, 24, 3);
        grant_and_write(&data_dispatch, 24, orphan, b"bad");

        // Model another receive call after it publishes a terminal record but
        // before the old runtime path could drain the handler-global queue.
        runtime
            .bulk
            .handle_data_service_frame(
                SESSION_ID,
                BulkFrame::Done(BulkDoneFrame {
                    stream_id: 24,
                    token: orphan,
                    total_transferred: 3,
                    checksum32: 0x3c48_33b6,
                })
                .to_data_service_frame()
                .expect("done frame"),
            )
            .expect("queue orphan completion");

        let _unrelated = accept_write_transfer(&data_dispatch, 78, 25, 3);

        assert!(target.writes().is_empty());
        assert!(sink.replies().is_empty());
        let queued = runtime.bulk.drain_completed();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].token, orphan);
    }

    #[test]
    fn terminal_error_does_not_block_expired_write_retirement() {
        let (runtime, target, sink) = runtime(Duration::from_millis(10));
        let handle = create_handle(&runtime);
        let data_dispatch = runtime.data_dispatch();
        let orphan = accept_write_transfer(&data_dispatch, 77, 19, 3);
        let admitted = accept_write_transfer(&data_dispatch, 2, 20, 3);
        let now = Instant::now();
        admitted_write(&runtime, handle, admitted, 3, now);
        grant_and_write(&data_dispatch, 19, orphan, b"bad");

        runtime
            .bulk
            .handle_data_service_frame(
                SESSION_ID,
                BulkFrame::Done(BulkDoneFrame {
                    stream_id: 19,
                    token: orphan,
                    total_transferred: 3,
                    checksum32: 0x3c48_33b6,
                })
                .to_data_service_frame()
                .expect("done frame"),
            )
            .expect("queue orphan completion");

        assert!(runtime
            .expire_write_timeouts(now + Duration::from_millis(10))
            .is_err());
        assert!(target.writes().is_empty());
        assert_eq!(runtime.pending_write_count(), 0);
        assert_eq!(runtime.bulk.active_transfer_count(SESSION_ID.0), 0);
        let replies = sink.replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(
            response(replies[0].1.clone()).header.errno,
            Errno::ETIMEDOUT
        );
    }

    #[test]
    fn timeout_reply_error_does_not_block_later_retirement() {
        let (runtime, target, sink) = runtime(Duration::from_millis(10));
        let handle = create_handle(&runtime);
        let data_dispatch = runtime.data_dispatch();
        let first = accept_write_transfer(&data_dispatch, 2, 21, 3);
        let second = accept_write_transfer(&data_dispatch, 3, 22, 3);
        let now = Instant::now();
        admitted_write_for_op(&runtime, handle.clone(), first, 3, 2, now);
        admitted_write_for_op(&runtime, handle, second, 3, 3, now);
        sink.fail_next_replies(1);

        assert!(runtime
            .expire_write_timeouts(now + Duration::from_millis(10))
            .is_err());
        assert!(target.writes().is_empty());
        assert_eq!(runtime.pending_write_count(), 0);
        assert_eq!(runtime.bulk.active_transfer_count(SESSION_ID.0), 0);
        assert_eq!(runtime.state.lock().unwrap().adapter.pending_bulk_len(), 0);
        assert_eq!(sink.replies().len(), 1);
    }
}
