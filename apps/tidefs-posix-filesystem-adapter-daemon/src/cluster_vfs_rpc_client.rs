// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Clustered mounted-filesystem client over authenticated inline VFS_RPC.
//!
//! The client consumes an already-configured [`Transport`] and an established
//! Control session. It does not generate keys, configure attestation, connect,
//! or accept writer/dataset/lease authority from an endpoint or command-line
//! value; those values come from the authenticated owner-issued preface.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use tidefs_transport::{
    EndpointFamily, SessionCloseReason, SessionId, SessionState, Transport, TransportError,
    TransportSessionSet,
};
use tidefs_types_vfs_core::{
    DirHandleId, EngineDirHandle, EngineFileHandle, Errno, FileHandleId, InodeId, RequestCtx,
};
use tidefs_vfs_engine::operation as engine_op;
use tidefs_vfs_engine::{VfsDispatch, VfsOperation, VfsResponse};
use tidefs_vfs_rpc::transport_adapter::{
    decode_session_authority_frame, VfsRpcEnvelopeContext, VfsRpcInboundFrame,
    VfsRpcSessionAuthorityError, VfsRpcTransportAdapter, VfsRpcTransportAdapterConfig,
};
use tidefs_vfs_rpc::{
    DatasetId, InlineOrBulk, PeerId, VfsRpcClient, VfsRpcCredentials, VfsRpcHandle,
    VfsRpcHandleType, VfsRpcRequestPayload, VfsRpcResponse, VfsRpcResponsePayload,
    DEFAULT_INLINE_THRESHOLD,
};

const CLIENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CLIENT_AUTHORITY_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_RETRY_INTERVAL: Duration = Duration::from_millis(1);

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
    MissingActiveConnection(SessionId),
    UnauthenticatedSession(SessionId),
    ConfigureNonblocking(String),
    AuthorityTimeout(SessionId),
    AuthorityTransport(String),
    MalformedAuthority(VfsRpcSessionAuthorityError),
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
            Self::CloseFailed(error) => write!(f, "close cluster VFS_RPC client: {error}"),
        }
    }
}

impl std::error::Error for ClusterVfsRpcClientError {}

/// Synchronous dispatch client installed behind [`FuseVfsAdapter`].
///
/// [`FuseVfsAdapter`]: crate::fuse_vfs_adapter::FuseVfsAdapter
pub struct ClusterVfsRpcClient {
    state: Mutex<ClientState>,
}

impl ClusterVfsRpcClient {
    /// Consume an already-authenticated Control transport/session and derive
    /// request authority from its owner-issued preface.
    pub fn new(
        mut transport: Transport,
        session_id: SessionId,
        expected_pool_guid: [u8; 16],
    ) -> Result<Self, ClusterVfsRpcClientError> {
        let authenticated_peer = validate_construction_session(&transport, session_id)?;
        transport
            .set_nonblocking(true)
            .map_err(|error| ClusterVfsRpcClientError::ConfigureNonblocking(error.to_string()))?;
        let authority = receive_session_authority(&mut transport, session_id)?;
        authority
            .validate_for_client(expected_pool_guid, authenticated_peer)
            .map_err(map_session_authority_error)?;

        let writer = authority.writer_node();
        let dataset_id = authority.dataset_id();
        let local_node = transport.local_node_id;
        let mut sessions = TransportSessionSet::new();
        sessions.add_binding_with_epoch(writer, session_id, authority.epoch());
        sessions.mark_healthy(session_id);

        Ok(Self {
            state: Mutex::new(ClientState {
                transport,
                session_id,
                local_node,
                writer,
                dataset_id,
                rpc: VfsRpcClient::new(
                    writer,
                    dataset_id,
                    authority.term(),
                    authority.epoch(),
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
            }),
        })
    }

    /// Close the client session before the owner/Pool lifecycle is torn down.
    pub fn close(&self) -> Result<(), ClusterVfsRpcClientError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ClusterVfsRpcClientError::SessionLockPoisoned(SessionId::new(0)))?;
        state.close().map_err(|error| {
            ClusterVfsRpcClientError::CloseFailed(format!("session {}: {error}", state.session_id))
        })
    }
}

impl VfsDispatch for ClusterVfsRpcClient {
    fn dispatch(&self, operation: VfsOperation) -> Result<VfsResponse, Errno> {
        self.state
            .lock()
            .map_err(|_| Errno::EIO)?
            .dispatch(operation)
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
}

impl ClientState {
    fn dispatch(&mut self, operation: VfsOperation) -> Result<VfsResponse, Errno> {
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
        self.validate_live_session()?;
        let now = Instant::now();
        let request = self
            .rpc
            .begin_request(now, 0, payload, Some(credentials))
            .map_err(|_| Errno::EPROTO)?;
        let context = VfsRpcEnvelopeContext {
            sequence_number: self.next_sequence,
            ..VfsRpcEnvelopeContext::default()
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        let mut outbound = self
            .adapter
            .begin_request(PeerId(self.writer), &request, now, context)
            .map_err(|error| error.errno())?;
        self.transport
            .send_envelope(&mut outbound.envelope, &outbound.payload)
            .map_err(map_transport_error)?;

        let deadline = now + CLIENT_REQUEST_TIMEOUT;
        loop {
            let (envelope, payload) = match self.transport.recv_envelope(self.session_id) {
                Ok(frame) => frame,
                Err(TransportError::WouldBlock(_)) if Instant::now() < deadline => {
                    thread::sleep(CLIENT_RETRY_INTERVAL);
                    continue;
                }
                Err(TransportError::WouldBlock(_)) => {
                    let _ = self.close();
                    return Err(Errno::EIO);
                }
                Err(error) => return Err(map_transport_error(error)),
            };
            let received_at = Instant::now();
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
            self.validate_live_session()?;
            return response_payload(response);
        }
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
) -> Result<tidefs_vfs_rpc::transport_adapter::VfsRpcSessionAuthority, ClusterVfsRpcClientError> {
    let deadline = Instant::now() + CLIENT_AUTHORITY_TIMEOUT;
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

fn map_transport_error(error: TransportError) -> Errno {
    match error {
        TransportError::WouldBlock(_) | TransportError::SendBufferFull { .. } => Errno::EAGAIN,
        TransportError::SessionNotFound { .. }
        | TransportError::SessionInWrongState { .. }
        | TransportError::SendBufferShutdown { .. } => Errno::ESTALE,
        _ => Errno::EIO,
    }
}
