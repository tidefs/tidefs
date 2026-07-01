// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Writer-side VFS_RPC-to-VFS-Engine forwarding bridge.
//!
//! The bridge consumes transport-admitted [`VfsRpcRequest`] values, verifies
//! the transport peer against VFS_RPC credentials, checks the writer lease for
//! operations that can mutate writer-local state, resolves transferable
//! handles, dispatches inline operations through [`VfsDispatch`], and encodes a
//! typed [`VfsRpcResponse`]. BULK WRITE bytes may only enter the engine through
//! a DONE-verified BULK completion, and READ bulk responses only format a
//! descriptor that the transport/BULK runtime has already admitted.

use std::collections::BTreeMap;

use tidefs_bulk_service::{VfsRpcBulkCompletion, VfsRpcBulkDescriptor, VfsRpcBulkHandoff};
use tidefs_types_vfs_core::{
    EngineDirHandle, EngineFileHandle, Errno, Generation, InodeAttr, InodeId, LockSpec, RequestCtx,
    SetAttr, StatFs, FATTR_SIZE, F_RDLCK, F_WRLCK, SEEK_SET,
};
use tidefs_vfs_engine::operation as engine_op;
use tidefs_vfs_engine::{VfsDispatch, VfsOperation, VfsResponse};

use crate::{
    DatasetId, InlineOrBulk, PeerId, VfsRpcCredentials, VfsRpcDedupWindow, VfsRpcError,
    VfsRpcHandle, VfsRpcHandleType, VfsRpcRequest, VfsRpcRequestPayload, VfsRpcResponse,
    VfsRpcResponsePayload, VfsRpcStats, DEFAULT_INLINE_THRESHOLD, REQ_FLAG_BULK_PENDING,
    REQ_FLAG_NO_DEDUP, RESP_FLAG_BULK,
};

/// Errno returned for VFS_RPC methods that are valid on the wire but not
/// supported by the current bridge/dispatch contract.
pub const BRIDGE_FORWARDING_UNSUPPORTED: Errno = Errno::ENOSYS;

/// Default server-side replay window from the VFS_RPC wire protocol.
pub const DEFAULT_BRIDGE_DEDUP_WINDOW: usize = 65_536;

/// Dispatch target type consumed by the VFS_RPC bridge.
pub type VfsEngineDispatchTarget = dyn VfsDispatch;

/// Writer lease and dataset identity supplied by membership/runtime authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VfsEngineBridgeWriter {
    pub writer_node: u64,
    pub dataset_id: DatasetId,
    pub term: u64,
    pub epoch: u64,
}

impl VfsEngineBridgeWriter {
    #[must_use]
    pub const fn new(writer_node: u64, dataset_id: DatasetId, term: u64, epoch: u64) -> Self {
        Self {
            writer_node,
            dataset_id,
            term,
            epoch,
        }
    }

    #[must_use]
    pub fn matches_request(self, request: &VfsRpcRequest) -> bool {
        request.header.term == self.term && request.header.epoch == self.epoch
    }
}

/// Writer-side bridge configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VfsEngineBridgeConfig {
    pub writer: VfsEngineBridgeWriter,
    pub dedup_window_entries: usize,
    pub max_inline_response_bytes: usize,
}

impl VfsEngineBridgeConfig {
    #[must_use]
    pub const fn new(writer: VfsEngineBridgeWriter) -> Self {
        Self {
            writer,
            dedup_window_entries: DEFAULT_BRIDGE_DEDUP_WINDOW,
            max_inline_response_bytes: DEFAULT_INLINE_THRESHOLD,
        }
    }
}

/// VFS_RPC bridge state for one writer-side dispatch surface.
#[derive(Clone, Debug)]
pub struct VfsEngineBridge {
    config: VfsEngineBridgeConfig,
    dedup: VfsRpcDedupWindow,
    handles: BTreeMap<BridgeHandleKey, BridgeHandleRecord>,
}

impl VfsEngineBridge {
    #[must_use]
    pub fn new(writer: VfsEngineBridgeWriter) -> Self {
        Self::with_config(VfsEngineBridgeConfig::new(writer))
    }

    #[must_use]
    pub fn with_config(config: VfsEngineBridgeConfig) -> Self {
        Self {
            dedup: VfsRpcDedupWindow::new(config.dedup_window_entries),
            handles: BTreeMap::new(),
            config,
        }
    }

    #[must_use]
    pub const fn writer(&self) -> VfsEngineBridgeWriter {
        self.config.writer
    }

    #[must_use]
    pub fn dedup_stats(&self) -> VfsRpcStats {
        self.dedup.stats()
    }

    #[must_use]
    pub fn handle_count(&self) -> usize {
        self.handles.len()
    }

    /// Refresh the writer lease from membership/runtime authority.
    ///
    /// A writer, dataset, term, or epoch change invalidates replay and handle
    /// state because both are scoped to the previous writer lease.
    pub fn update_writer(&mut self, writer: VfsEngineBridgeWriter) {
        if self.config.writer != writer {
            self.config.writer = writer;
            self.dedup = VfsRpcDedupWindow::new(self.config.dedup_window_entries);
            self.handles.clear();
        }
    }

    /// Forward one transport-admitted VFS_RPC request to a writer-side target.
    pub fn dispatch(
        &mut self,
        peer: PeerId,
        request: &VfsRpcRequest,
        target: &VfsEngineDispatchTarget,
    ) -> Result<VfsRpcResponse, VfsRpcError> {
        let ctx = match request_context(peer, request) {
            Ok(ctx) => ctx,
            Err(errno) => return error_response(request, errno),
        };

        if let Err(errno) = reject_bulk_request(request) {
            return error_response(request, errno);
        }

        if requires_fence(&request.payload) && !self.config.writer.matches_request(request) {
            return error_response(request, Errno::ESTALE);
        }

        if dedup_eligible(&request.payload) {
            if let Some(response) = self.dedup.lookup(peer, request) {
                return Ok(response);
            }
        }

        let response = self.forward_payload(peer, request, target, &ctx)?;
        if should_cache_response(request) {
            self.dedup.insert(peer, response.clone());
        }
        Ok(response)
    }

    /// Forward a WRITE whose bytes were verified by BULK DONE.
    ///
    /// Failed, aborted, timed-out, or descriptor-only transfers must never call
    /// this path; they continue to use the normal fail-closed response path and
    /// are not inserted into the dedup cache as success.
    pub fn dispatch_done_verified_write(
        &mut self,
        peer: PeerId,
        request: &VfsRpcRequest,
        completion: VfsRpcBulkCompletion,
        target: &VfsEngineDispatchTarget,
    ) -> Result<VfsRpcResponse, VfsRpcError> {
        let (handle, offset, token, len) = match &request.payload {
            VfsRpcRequestPayload::Write {
                handle,
                offset,
                data: InlineOrBulk::Bulk { token, len },
            } => (handle.clone(), *offset, *token, *len),
            _ => return error_response(request, Errno::EPROTO),
        };
        if request.header.flags & REQ_FLAG_BULK_PENDING == 0
            || completion.handoff != VfsRpcBulkHandoff::WriteUpload
            || completion.op_id != request.header.op_id.0
            || completion.token != token
            || completion.len != len
        {
            return error_response(request, Errno::EPROTO);
        }

        let inline_request = VfsRpcRequest::new(
            request.header.op_id,
            request.header.term,
            request.header.epoch,
            request.header.flags & !REQ_FLAG_BULK_PENDING,
            VfsRpcRequestPayload::Write {
                handle,
                offset,
                data: InlineOrBulk::Inline(completion.bytes),
            },
            request.credentials.clone(),
        )?;
        self.dispatch(peer, &inline_request, target)
    }

    /// Format a READ response around a BULK descriptor already admitted on the
    /// same transport session.
    pub fn read_bulk_response(
        request: &VfsRpcRequest,
        descriptor: VfsRpcBulkDescriptor,
    ) -> Result<VfsRpcResponse, VfsRpcError> {
        if !matches!(request.payload, VfsRpcRequestPayload::Read { .. }) {
            return error_response(request, Errno::EPROTO);
        }
        VfsRpcResponse::ok(
            request.header.op_id,
            request.header.method,
            RESP_FLAG_BULK,
            VfsRpcResponsePayload::Data(InlineOrBulk::Bulk {
                token: descriptor.token,
                len: descriptor.len,
            }),
        )
    }

    fn forward_payload(
        &mut self,
        peer: PeerId,
        request: &VfsRpcRequest,
        target: &VfsEngineDispatchTarget,
        ctx: &RequestCtx,
    ) -> Result<VfsRpcResponse, VfsRpcError> {
        match &request.payload {
            VfsRpcRequestPayload::Lookup { parent, name } => response_for(
                request,
                dispatch_attr(
                    target,
                    VfsOperation::Lookup(engine_op::LookupRequest {
                        parent: *parent,
                        name: name.clone(),
                        ctx: ctx.clone(),
                    }),
                ),
                |attr| {
                    Ok(VfsRpcResponsePayload::Lookup {
                        inode: attr.inode_id,
                        attr,
                    })
                },
            ),
            VfsRpcRequestPayload::Mknod {
                parent,
                name,
                mode,
                rdev,
            } => response_for(
                request,
                dispatch_attr(
                    target,
                    VfsOperation::Mknod(engine_op::MknodRequest {
                        parent: *parent,
                        name: name.clone(),
                        mode: *mode,
                        rdev: *rdev,
                        ctx: ctx.clone(),
                    }),
                ),
                |attr| Ok(VfsRpcResponsePayload::Attr(attr)),
            ),
            VfsRpcRequestPayload::Mkdir { parent, name, mode } => response_for(
                request,
                dispatch_attr(
                    target,
                    VfsOperation::Mkdir(engine_op::MkdirRequest {
                        parent: *parent,
                        name: name.clone(),
                        mode: *mode,
                        ctx: ctx.clone(),
                    }),
                ),
                |attr| Ok(VfsRpcResponsePayload::Attr(attr)),
            ),
            VfsRpcRequestPayload::Unlink { parent, name } => response_for(
                request,
                dispatch_unit(
                    target,
                    VfsOperation::Unlink(engine_op::UnlinkRequest {
                        parent: *parent,
                        name: name.clone(),
                        ctx: ctx.clone(),
                    }),
                ),
                |()| Ok(VfsRpcResponsePayload::Empty),
            ),
            VfsRpcRequestPayload::Rmdir { parent, name } => response_for(
                request,
                dispatch_unit(
                    target,
                    VfsOperation::Rmdir(engine_op::RmdirRequest {
                        parent: *parent,
                        name: name.clone(),
                        ctx: ctx.clone(),
                    }),
                ),
                |()| Ok(VfsRpcResponsePayload::Empty),
            ),
            VfsRpcRequestPayload::Symlink { .. } => {
                error_response(request, BRIDGE_FORWARDING_UNSUPPORTED)
            }
            VfsRpcRequestPayload::Readlink { inode } => response_for(
                request,
                dispatch_bytes(
                    target,
                    VfsOperation::ReadLink(engine_op::ReadLinkRequest {
                        inode: *inode,
                        ctx: ctx.clone(),
                    }),
                ),
                |data| inline_data_payload(data, self.config.max_inline_response_bytes),
            ),
            VfsRpcRequestPayload::Rename {
                old_parent,
                old_name,
                new_parent,
                new_name,
                flags,
            } => response_for(
                request,
                dispatch_unit(
                    target,
                    VfsOperation::Rename(engine_op::RenameRequest {
                        old_parent: *old_parent,
                        old_name: old_name.clone(),
                        new_parent: *new_parent,
                        new_name: new_name.clone(),
                        flags: *flags,
                        ctx: ctx.clone(),
                    }),
                ),
                |()| Ok(VfsRpcResponsePayload::Empty),
            ),
            VfsRpcRequestPayload::Link { .. } => {
                error_response(request, BRIDGE_FORWARDING_UNSUPPORTED)
            }
            VfsRpcRequestPayload::Getxattr { inode, name, size } => response_for(
                request,
                dispatch_bytes(
                    target,
                    VfsOperation::GetXattr(engine_op::GetXattrRequest {
                        inode: *inode,
                        name: name.clone(),
                        ctx: ctx.clone(),
                    }),
                )
                .and_then(|data| enforce_buffer_size(data, *size)),
                |data| inline_data_payload(data, self.config.max_inline_response_bytes),
            ),
            VfsRpcRequestPayload::Setxattr {
                inode,
                name,
                value,
                flags,
            } => response_for(
                request,
                dispatch_unit(
                    target,
                    VfsOperation::SetXattr(engine_op::SetXattrRequest {
                        inode: *inode,
                        name: name.clone(),
                        value: value.clone(),
                        flags: *flags,
                        ctx: ctx.clone(),
                    }),
                ),
                |()| Ok(VfsRpcResponsePayload::Empty),
            ),
            VfsRpcRequestPayload::Listxattr { inode, size } => response_for(
                request,
                dispatch_bytes(
                    target,
                    VfsOperation::ListXattr(engine_op::ListXattrRequest {
                        inode: *inode,
                        ctx: ctx.clone(),
                    }),
                )
                .and_then(|data| enforce_buffer_size(data, *size)),
                |data| Ok(VfsRpcResponsePayload::XattrList(split_xattr_names(data))),
            ),
            VfsRpcRequestPayload::Removexattr { inode, name } => response_for(
                request,
                dispatch_unit(
                    target,
                    VfsOperation::RemoveXattr(engine_op::RemoveXattrRequest {
                        inode: *inode,
                        name: name.clone(),
                        ctx: ctx.clone(),
                    }),
                ),
                |()| Ok(VfsRpcResponsePayload::Empty),
            ),
            VfsRpcRequestPayload::Access { .. } => {
                error_response(request, BRIDGE_FORWARDING_UNSUPPORTED)
            }
            VfsRpcRequestPayload::Create {
                parent,
                name,
                mode,
                flags,
            } => response_for(
                request,
                dispatch_create(
                    target,
                    VfsOperation::Create(engine_op::CreateRequest {
                        parent: *parent,
                        name: name.clone(),
                        mode: *mode,
                        flags: *flags,
                        ctx: ctx.clone(),
                    }),
                ),
                |(attr, fh)| {
                    let handle = self.register_file_handle(peer, attr, fh);
                    Ok(VfsRpcResponsePayload::Created {
                        inode: attr.inode_id,
                        attr,
                        handle,
                    })
                },
            ),
            VfsRpcRequestPayload::Getattr { inode } => response_for(
                request,
                dispatch_attr(
                    target,
                    VfsOperation::GetAttr(engine_op::GetAttrRequest {
                        inode: *inode,
                        handle: None,
                        ctx: ctx.clone(),
                    }),
                ),
                |attr| Ok(VfsRpcResponsePayload::Attr(attr)),
            ),
            VfsRpcRequestPayload::Setattr { inode, attr } => response_for(
                request,
                dispatch_attr(
                    target,
                    VfsOperation::SetAttr(engine_op::SetAttrRequest {
                        inode: *inode,
                        attr: *attr,
                        handle: None,
                        ctx: ctx.clone(),
                    }),
                ),
                |attr| Ok(VfsRpcResponsePayload::Attr(attr)),
            ),
            VfsRpcRequestPayload::Open {
                inode,
                flags,
                lock_owner,
            } => response_for(
                request,
                dispatch_open(
                    target,
                    VfsOperation::Open(engine_op::OpenRequest {
                        inode: *inode,
                        flags: *flags,
                        ctx: ctx.clone(),
                    }),
                ),
                |mut fh| {
                    fh.lock_owner = *lock_owner;
                    let attr = self.fetch_attr_for_file(target, fh, ctx)?;
                    let handle = self.register_file_handle(peer, attr, fh);
                    Ok(VfsRpcResponsePayload::FileHandle(handle))
                },
            ),
            VfsRpcRequestPayload::Close { handle }
            | VfsRpcRequestPayload::Release { handle, .. } => {
                let key = BridgeHandleKey::file(handle.handle_cookie);
                let result = self.resolve_file_handle(peer, handle).and_then(|fh| {
                    dispatch_unit(
                        target,
                        VfsOperation::Release(engine_op::ReleaseRequest { fh }),
                    )
                });
                let response =
                    response_for(request, result, |()| Ok(VfsRpcResponsePayload::Empty))?;
                if response.header.errno.is_success() {
                    self.handles.remove(&key);
                }
                Ok(response)
            }
            VfsRpcRequestPayload::Opendir { inode } => response_for(
                request,
                dispatch_dir_handle(
                    target,
                    VfsOperation::OpenDir(engine_op::OpenDirRequest {
                        inode: *inode,
                        ctx: ctx.clone(),
                    }),
                ),
                |dh| {
                    let attr = self.fetch_attr_for_dir(target, dh, ctx)?;
                    let handle = self.register_dir_handle(peer, attr, dh);
                    Ok(VfsRpcResponsePayload::DirHandle(handle))
                },
            ),
            VfsRpcRequestPayload::Closedir { handle }
            | VfsRpcRequestPayload::Releasedir { handle } => {
                let key = BridgeHandleKey::dir(handle.handle_cookie);
                let result = self.resolve_dir_handle(peer, handle).and_then(|dh| {
                    dispatch_unit(
                        target,
                        VfsOperation::ReleaseDir(engine_op::ReleaseDirRequest { dh }),
                    )
                });
                let response =
                    response_for(request, result, |()| Ok(VfsRpcResponsePayload::Empty))?;
                if response.header.errno.is_success() {
                    self.handles.remove(&key);
                }
                Ok(response)
            }
            VfsRpcRequestPayload::Readdir {
                handle,
                offset,
                max_entries,
            }
            | VfsRpcRequestPayload::Readdirplus {
                handle,
                offset,
                max_entries,
            } => {
                let result = self.resolve_dir_handle(peer, handle).and_then(|dh| {
                    dispatch_dir_entries(
                        target,
                        VfsOperation::ReadDir(engine_op::ReadDirRequest {
                            dh,
                            offset: *offset,
                            ctx: ctx.clone(),
                        }),
                    )
                    .map(|mut entries| {
                        let max_entries = *max_entries as usize;
                        if max_entries != 0 && entries.len() > max_entries {
                            entries.truncate(max_entries);
                        }
                        entries
                    })
                });
                response_for(request, result, |entries| {
                    Ok(VfsRpcResponsePayload::DirEntries(entries))
                })
            }
            VfsRpcRequestPayload::Statfs { inode } => response_for(
                request,
                dispatch_statfs(
                    target,
                    VfsOperation::StatFs(engine_op::StatFsRequest {
                        inode: *inode,
                        ctx: ctx.clone(),
                    }),
                ),
                |statfs| Ok(VfsRpcResponsePayload::Statfs(statfs)),
            ),
            VfsRpcRequestPayload::Flush { handle, lock_owner } => {
                let result = self.resolve_file_handle(peer, handle).and_then(|mut fh| {
                    fh.lock_owner = *lock_owner;
                    dispatch_unit(
                        target,
                        VfsOperation::Flush(engine_op::FlushRequest {
                            fh,
                            ctx: ctx.clone(),
                        }),
                    )
                });
                response_for(request, result, |()| Ok(VfsRpcResponsePayload::Empty))
            }
            VfsRpcRequestPayload::Forget { .. } | VfsRpcRequestPayload::BatchForget { .. } => {
                error_response(request, BRIDGE_FORWARDING_UNSUPPORTED)
            }
            VfsRpcRequestPayload::DirRev { handle } => {
                let result = self.resolve_dir_handle(peer, handle).and_then(|dh| {
                    dispatch_attr(
                        target,
                        VfsOperation::GetAttr(engine_op::GetAttrRequest {
                            inode: dh.inode_id,
                            handle: None,
                            ctx: ctx.clone(),
                        }),
                    )
                    .map(|attr| attr.dir_rev)
                });
                response_for(request, result, |dir_rev| {
                    Ok(VfsRpcResponsePayload::DirRev(dir_rev))
                })
            }
            VfsRpcRequestPayload::Read {
                handle,
                offset,
                length,
            } => {
                let size = match u32::try_from(*length) {
                    Ok(size) => size,
                    Err(_) => return error_response(request, Errno::EINVAL),
                };
                let result = self.resolve_file_handle(peer, handle).and_then(|fh| {
                    dispatch_read(
                        target,
                        VfsOperation::Read(engine_op::ReadRequest {
                            fh,
                            offset: *offset,
                            size,
                            ctx: ctx.clone(),
                        }),
                    )
                });
                response_for(request, result, |data| {
                    inline_data_payload(data, self.config.max_inline_response_bytes)
                })
            }
            VfsRpcRequestPayload::Write {
                handle,
                offset,
                data,
            } => {
                let data = match data {
                    InlineOrBulk::Inline(data) => data.clone(),
                    InlineOrBulk::Bulk { .. } => return error_response(request, Errno::EOPNOTSUPP),
                };
                let result = self.resolve_file_handle(peer, handle).and_then(|fh| {
                    dispatch_write(
                        target,
                        VfsOperation::Write(engine_op::WriteRequest {
                            fh,
                            offset: *offset,
                            data,
                            ctx: ctx.clone(),
                        }),
                    )
                });
                response_for(request, result, |written| {
                    Ok(VfsRpcResponsePayload::BytesWritten(u64::from(written)))
                })
            }
            VfsRpcRequestPayload::Fsync { handle, datasync } => {
                let result = self.resolve_file_handle(peer, handle).and_then(|fh| {
                    dispatch_unit(
                        target,
                        VfsOperation::Fsync(engine_op::FsyncRequest {
                            fh,
                            datasync: *datasync,
                            ctx: ctx.clone(),
                        }),
                    )
                });
                response_for(request, result, |()| Ok(VfsRpcResponsePayload::Empty))
            }
            VfsRpcRequestPayload::Fallocate {
                handle,
                mode,
                offset,
                length,
            } => {
                let result = self.resolve_file_handle(peer, handle).and_then(|fh| {
                    dispatch_unit(
                        target,
                        VfsOperation::Fallocate(engine_op::FallocateRequest {
                            fh,
                            mode: *mode,
                            offset: *offset,
                            length: *length,
                            ctx: ctx.clone(),
                        }),
                    )
                });
                response_for(request, result, |()| Ok(VfsRpcResponsePayload::Empty))
            }
            VfsRpcRequestPayload::LseekData { .. }
            | VfsRpcRequestPayload::LseekHole { .. }
            | VfsRpcRequestPayload::Fiemap { .. } => {
                error_response(request, BRIDGE_FORWARDING_UNSUPPORTED)
            }
            VfsRpcRequestPayload::Truncate { inode, length } => {
                let mut attr = SetAttr::new();
                attr.valid = FATTR_SIZE;
                attr.size = *length;
                response_for(
                    request,
                    dispatch_attr(
                        target,
                        VfsOperation::SetAttr(engine_op::SetAttrRequest {
                            inode: *inode,
                            attr,
                            handle: None,
                            ctx: ctx.clone(),
                        }),
                    ),
                    |_| Ok(VfsRpcResponsePayload::Empty),
                )
            }
            VfsRpcRequestPayload::CopyFileRange {
                src,
                src_offset,
                dst,
                dst_offset,
                length,
                flags,
            } => {
                if *flags != 0 {
                    return error_response(request, Errno::EINVAL);
                }
                let result = self.resolve_file_handle(peer, src).and_then(|source_fh| {
                    self.resolve_file_handle(peer, dst).and_then(|dest_fh| {
                        dispatch_copy_file_range(
                            target,
                            VfsOperation::CopyFileRange(engine_op::CopyFileRangeRequest {
                                source_fh,
                                offset_in: *src_offset,
                                dest_fh,
                                offset_out: *dst_offset,
                                length: *length,
                                ctx: ctx.clone(),
                            }),
                        )
                    })
                });
                response_for(request, result, |copied| {
                    Ok(VfsRpcResponsePayload::BytesWritten(u64::from(copied)))
                })
            }
            VfsRpcRequestPayload::LockGet { .. } => {
                error_response(request, BRIDGE_FORWARDING_UNSUPPORTED)
            }
            VfsRpcRequestPayload::LockSet {
                handle,
                owner,
                start,
                end,
                write,
                block,
            } => {
                let pid = match u32::try_from(*owner) {
                    Ok(pid) => pid,
                    Err(_) => return error_response(request, Errno::EINVAL),
                };
                let result = self.resolve_file_handle(peer, handle).and_then(|fh| {
                    let typ = if *write { F_WRLCK } else { F_RDLCK };
                    let lock = LockSpec::new(typ, SEEK_SET, *start, *end, pid);
                    let op = if *block {
                        VfsOperation::SetLkw(engine_op::SetLkwRequest {
                            inode: fh.inode_id,
                            lock,
                            ctx: ctx.clone(),
                        })
                    } else {
                        VfsOperation::SetLk(engine_op::SetLkRequest {
                            inode: fh.inode_id,
                            lock,
                            ctx: ctx.clone(),
                        })
                    };
                    dispatch_unit(target, op)
                });
                response_for(request, result, |()| Ok(VfsRpcResponsePayload::Empty))
            }
        }
    }

    fn register_file_handle(
        &mut self,
        peer: PeerId,
        attr: InodeAttr,
        handle: EngineFileHandle,
    ) -> VfsRpcHandle {
        let rpc_handle = VfsRpcHandle::from_file_handle(
            self.config.writer.dataset_id,
            self.config.writer.writer_node,
            handle,
            attr.generation,
        );
        self.handles.insert(
            BridgeHandleKey::file(rpc_handle.handle_cookie),
            BridgeHandleRecord {
                peer,
                dataset_id: rpc_handle.dataset_id,
                writer_node: rpc_handle.writer_node,
                inode: rpc_handle.inode,
                generation: rpc_handle.generation,
                state: BridgeHandleState::File(handle),
            },
        );
        rpc_handle
    }

    fn register_dir_handle(
        &mut self,
        peer: PeerId,
        attr: InodeAttr,
        handle: EngineDirHandle,
    ) -> VfsRpcHandle {
        let rpc_handle = VfsRpcHandle::from_dir_handle(
            self.config.writer.dataset_id,
            self.config.writer.writer_node,
            handle,
            attr.generation,
        );
        self.handles.insert(
            BridgeHandleKey::dir(rpc_handle.handle_cookie),
            BridgeHandleRecord {
                peer,
                dataset_id: rpc_handle.dataset_id,
                writer_node: rpc_handle.writer_node,
                inode: rpc_handle.inode,
                generation: rpc_handle.generation,
                state: BridgeHandleState::Dir(handle),
            },
        );
        rpc_handle
    }

    fn resolve_file_handle(
        &self,
        peer: PeerId,
        handle: &VfsRpcHandle,
    ) -> Result<EngineFileHandle, Errno> {
        if handle.handle_type != VfsRpcHandleType::File {
            return Err(Errno::EBADF);
        }
        match self
            .resolve_handle_record(peer, handle, BridgeHandleKey::file(handle.handle_cookie))?
            .state
        {
            BridgeHandleState::File(file) => Ok(file),
            BridgeHandleState::Dir(_) => Err(Errno::EBADF),
        }
    }

    fn resolve_dir_handle(
        &self,
        peer: PeerId,
        handle: &VfsRpcHandle,
    ) -> Result<EngineDirHandle, Errno> {
        if handle.handle_type != VfsRpcHandleType::Dir {
            return Err(Errno::EBADF);
        }
        match self
            .resolve_handle_record(peer, handle, BridgeHandleKey::dir(handle.handle_cookie))?
            .state
        {
            BridgeHandleState::Dir(dir) => Ok(dir),
            BridgeHandleState::File(_) => Err(Errno::EBADF),
        }
    }

    fn resolve_handle_record(
        &self,
        peer: PeerId,
        handle: &VfsRpcHandle,
        key: BridgeHandleKey,
    ) -> Result<&BridgeHandleRecord, Errno> {
        if handle.writer_node != self.config.writer.writer_node
            || handle.dataset_id != self.config.writer.dataset_id
        {
            return Err(Errno::ESTALE);
        }
        let record = self.handles.get(&key).ok_or(Errno::EBADF)?;
        if record.peer != peer {
            return Err(Errno::EACCES);
        }
        if record.writer_node != handle.writer_node
            || record.dataset_id != handle.dataset_id
            || record.inode != handle.inode
            || record.generation != handle.generation
        {
            return Err(Errno::ESTALE);
        }
        Ok(record)
    }

    fn fetch_attr_for_file(
        &self,
        target: &VfsEngineDispatchTarget,
        handle: EngineFileHandle,
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        dispatch_attr(
            target,
            VfsOperation::GetAttr(engine_op::GetAttrRequest {
                inode: handle.inode_id,
                handle: Some(handle),
                ctx: ctx.clone(),
            }),
        )
    }

    fn fetch_attr_for_dir(
        &self,
        target: &VfsEngineDispatchTarget,
        handle: EngineDirHandle,
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        dispatch_attr(
            target,
            VfsOperation::GetAttr(engine_op::GetAttrRequest {
                inode: handle.inode_id,
                handle: None,
                ctx: ctx.clone(),
            }),
        )
    }
}

/// Build the historical fail-closed response for callers that explicitly want
/// the old bridge hook behavior.
pub fn unavailable_response(request: &VfsRpcRequest) -> Result<VfsRpcResponse, VfsRpcError> {
    error_response(request, BRIDGE_FORWARDING_UNSUPPORTED)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct BridgeHandleKey {
    handle_type: u8,
    cookie: u64,
}

impl BridgeHandleKey {
    const fn file(cookie: u64) -> Self {
        Self {
            handle_type: VfsRpcHandleType::File as u8,
            cookie,
        }
    }

    const fn dir(cookie: u64) -> Self {
        Self {
            handle_type: VfsRpcHandleType::Dir as u8,
            cookie,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct BridgeHandleRecord {
    peer: PeerId,
    dataset_id: DatasetId,
    writer_node: u64,
    inode: InodeId,
    generation: Generation,
    state: BridgeHandleState,
}

#[derive(Clone, Copy, Debug)]
enum BridgeHandleState {
    File(EngineFileHandle),
    Dir(EngineDirHandle),
}

fn request_context(peer: PeerId, request: &VfsRpcRequest) -> Result<RequestCtx, Errno> {
    let credentials = request.credentials.as_ref().ok_or(Errno::EACCES)?;
    if credentials.peer_id != peer {
        return Err(Errno::EACCES);
    }
    Ok(ctx_from_credentials(credentials))
}

fn ctx_from_credentials(credentials: &VfsRpcCredentials) -> RequestCtx {
    let groups = if credentials.groups.is_empty() {
        vec![credentials.gid]
    } else {
        credentials.groups.clone()
    };
    RequestCtx::new(credentials.uid, credentials.gid, 0, 0, groups)
}

fn reject_bulk_request(request: &VfsRpcRequest) -> Result<(), Errno> {
    if request.header.flags & REQ_FLAG_BULK_PENDING != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if matches!(
        &request.payload,
        VfsRpcRequestPayload::Write {
            data: InlineOrBulk::Bulk { .. },
            ..
        }
    ) {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(())
}

fn requires_fence(payload: &VfsRpcRequestPayload) -> bool {
    matches!(
        payload,
        VfsRpcRequestPayload::Mknod { .. }
            | VfsRpcRequestPayload::Mkdir { .. }
            | VfsRpcRequestPayload::Unlink { .. }
            | VfsRpcRequestPayload::Rmdir { .. }
            | VfsRpcRequestPayload::Symlink { .. }
            | VfsRpcRequestPayload::Rename { .. }
            | VfsRpcRequestPayload::Link { .. }
            | VfsRpcRequestPayload::Setxattr { .. }
            | VfsRpcRequestPayload::Removexattr { .. }
            | VfsRpcRequestPayload::Create { .. }
            | VfsRpcRequestPayload::Setattr { .. }
            | VfsRpcRequestPayload::Open { .. }
            | VfsRpcRequestPayload::Close { .. }
            | VfsRpcRequestPayload::Opendir { .. }
            | VfsRpcRequestPayload::Closedir { .. }
            | VfsRpcRequestPayload::Flush { .. }
            | VfsRpcRequestPayload::Release { .. }
            | VfsRpcRequestPayload::Releasedir { .. }
            | VfsRpcRequestPayload::Write { .. }
            | VfsRpcRequestPayload::Fsync { .. }
            | VfsRpcRequestPayload::Fallocate { .. }
            | VfsRpcRequestPayload::Truncate { .. }
            | VfsRpcRequestPayload::CopyFileRange { .. }
            | VfsRpcRequestPayload::LockSet { .. }
    )
}

fn dedup_eligible(payload: &VfsRpcRequestPayload) -> bool {
    matches!(
        payload,
        VfsRpcRequestPayload::Mknod { .. }
            | VfsRpcRequestPayload::Mkdir { .. }
            | VfsRpcRequestPayload::Unlink { .. }
            | VfsRpcRequestPayload::Rmdir { .. }
            | VfsRpcRequestPayload::Symlink { .. }
            | VfsRpcRequestPayload::Rename { .. }
            | VfsRpcRequestPayload::Link { .. }
            | VfsRpcRequestPayload::Setxattr { .. }
            | VfsRpcRequestPayload::Removexattr { .. }
            | VfsRpcRequestPayload::Create { .. }
            | VfsRpcRequestPayload::Setattr { .. }
            | VfsRpcRequestPayload::Open { .. }
            | VfsRpcRequestPayload::Opendir { .. }
            | VfsRpcRequestPayload::Write { .. }
            | VfsRpcRequestPayload::Fsync { .. }
            | VfsRpcRequestPayload::Fallocate { .. }
            | VfsRpcRequestPayload::Truncate { .. }
            | VfsRpcRequestPayload::CopyFileRange { .. }
            | VfsRpcRequestPayload::LockSet { .. }
    )
}

fn should_cache_response(request: &VfsRpcRequest) -> bool {
    dedup_eligible(&request.payload) && request.header.flags & REQ_FLAG_NO_DEDUP == 0
}

fn response_for<T>(
    request: &VfsRpcRequest,
    result: Result<T, Errno>,
    map: impl FnOnce(T) -> Result<VfsRpcResponsePayload, Errno>,
) -> Result<VfsRpcResponse, VfsRpcError> {
    match result.and_then(map) {
        Ok(payload) => ok_response(request, payload),
        Err(errno) => error_response(request, errno),
    }
}

fn ok_response(
    request: &VfsRpcRequest,
    payload: VfsRpcResponsePayload,
) -> Result<VfsRpcResponse, VfsRpcError> {
    VfsRpcResponse::ok(request.header.op_id, request.header.method, 0, payload)
}

fn error_response(request: &VfsRpcRequest, errno: Errno) -> Result<VfsRpcResponse, VfsRpcError> {
    VfsRpcResponse::error(request.header.op_id, request.header.method, errno)
}

fn normalize_dispatch(result: Result<VfsResponse, Errno>) -> Result<VfsResponse, Errno> {
    match result {
        Ok(VfsResponse::Err(errno)) => Err(errno),
        other => other,
    }
}

fn dispatch_attr(target: &VfsEngineDispatchTarget, op: VfsOperation) -> Result<InodeAttr, Errno> {
    match normalize_dispatch(target.dispatch(op))? {
        VfsResponse::InodeAttr(response) => Ok(response.attr),
        _ => Err(Errno::EPROTO),
    }
}

fn dispatch_unit(target: &VfsEngineDispatchTarget, op: VfsOperation) -> Result<(), Errno> {
    match normalize_dispatch(target.dispatch(op))? {
        VfsResponse::Unit(_) => Ok(()),
        _ => Err(Errno::EPROTO),
    }
}

fn dispatch_create(
    target: &VfsEngineDispatchTarget,
    op: VfsOperation,
) -> Result<(InodeAttr, EngineFileHandle), Errno> {
    match normalize_dispatch(target.dispatch(op))? {
        VfsResponse::Create(response) => Ok((response.attr, response.fh)),
        _ => Err(Errno::EPROTO),
    }
}

fn dispatch_open(
    target: &VfsEngineDispatchTarget,
    op: VfsOperation,
) -> Result<EngineFileHandle, Errno> {
    match normalize_dispatch(target.dispatch(op))? {
        VfsResponse::Open(response) => Ok(response.fh),
        _ => Err(Errno::EPROTO),
    }
}

fn dispatch_read(target: &VfsEngineDispatchTarget, op: VfsOperation) -> Result<Vec<u8>, Errno> {
    match normalize_dispatch(target.dispatch(op))? {
        VfsResponse::Read(response) => Ok(response.data),
        _ => Err(Errno::EPROTO),
    }
}

fn dispatch_write(target: &VfsEngineDispatchTarget, op: VfsOperation) -> Result<u32, Errno> {
    match normalize_dispatch(target.dispatch(op))? {
        VfsResponse::Write(response) => Ok(response.written),
        _ => Err(Errno::EPROTO),
    }
}

fn dispatch_copy_file_range(
    target: &VfsEngineDispatchTarget,
    op: VfsOperation,
) -> Result<u32, Errno> {
    match normalize_dispatch(target.dispatch(op))? {
        VfsResponse::CopyFileRange(response) => Ok(response.copied),
        _ => Err(Errno::EPROTO),
    }
}

fn dispatch_bytes(target: &VfsEngineDispatchTarget, op: VfsOperation) -> Result<Vec<u8>, Errno> {
    match normalize_dispatch(target.dispatch(op))? {
        VfsResponse::BytePayload(response) => Ok(response.data),
        _ => Err(Errno::EPROTO),
    }
}

fn dispatch_dir_handle(
    target: &VfsEngineDispatchTarget,
    op: VfsOperation,
) -> Result<EngineDirHandle, Errno> {
    match normalize_dispatch(target.dispatch(op))? {
        VfsResponse::OpenDir(response) => Ok(response.dh),
        _ => Err(Errno::EPROTO),
    }
}

fn dispatch_dir_entries(
    target: &VfsEngineDispatchTarget,
    op: VfsOperation,
) -> Result<Vec<tidefs_types_vfs_core::DirEntry>, Errno> {
    match normalize_dispatch(target.dispatch(op))? {
        VfsResponse::ReadDir(response) => Ok(response.entries),
        _ => Err(Errno::EPROTO),
    }
}

fn dispatch_statfs(target: &VfsEngineDispatchTarget, op: VfsOperation) -> Result<StatFs, Errno> {
    match normalize_dispatch(target.dispatch(op))? {
        VfsResponse::StatFs(response) => Ok(response.stat),
        _ => Err(Errno::EPROTO),
    }
}

fn inline_data_payload(
    data: Vec<u8>,
    max_inline_bytes: usize,
) -> Result<VfsRpcResponsePayload, Errno> {
    if data.len() > max_inline_bytes {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(VfsRpcResponsePayload::Data(InlineOrBulk::Inline(data)))
}

fn enforce_buffer_size(data: Vec<u8>, size: u32) -> Result<Vec<u8>, Errno> {
    if size != 0 && data.len() > size as usize {
        return Err(Errno::ERANGE);
    }
    Ok(data)
}

fn split_xattr_names(data: Vec<u8>) -> Vec<Vec<u8>> {
    data.split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| name.to_vec())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use tidefs_types_vfs_core::{
        DirHandleId, EngineDirHandle, EngineFileHandle, FileHandleId, InodeFlags, NodeKind,
        PosixAttrs, StatFs, S_IFDIR, S_IFREG,
    };
    use tidefs_vfs_engine::operation as engine_op;

    use super::*;
    use crate::{
        OpId, VfsRpcCredentials, VfsRpcRequestPayload, VfsRpcResponsePayload,
        RESP_FLAG_DEDUP_REPLAY,
    };

    const PEER: PeerId = PeerId(7);

    struct RecordingDispatch {
        writes: RefCell<Vec<Vec<u8>>>,
        releases: Cell<u32>,
        reads: Cell<u32>,
        links: Cell<u32>,
        symlinks: Cell<u32>,
    }

    impl RecordingDispatch {
        fn new() -> Self {
            Self {
                writes: RefCell::new(Vec::new()),
                releases: Cell::new(0),
                reads: Cell::new(0),
                links: Cell::new(0),
                symlinks: Cell::new(0),
            }
        }

        fn attr(inode: u64, kind: NodeKind) -> InodeAttr {
            InodeAttr::new(
                InodeId::new(inode),
                Generation::new(if inode == 1 { 1 } else { 7 }),
                kind,
                PosixAttrs {
                    mode: match kind {
                        NodeKind::Dir => S_IFDIR | 0o755,
                        _ => S_IFREG | 0o644,
                    },
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
                VfsOperation::Lookup(_) => {
                    Ok(VfsResponse::InodeAttr(engine_op::InodeAttrResponse {
                        attr: Self::attr(100, NodeKind::File),
                    }))
                }
                VfsOperation::Link(_) => {
                    self.links.set(self.links.get() + 1);
                    Ok(VfsResponse::InodeAttr(engine_op::InodeAttrResponse {
                        attr: Self::attr(100, NodeKind::File),
                    }))
                }
                VfsOperation::Symlink(_) => {
                    self.symlinks.set(self.symlinks.get() + 1);
                    Ok(VfsResponse::InodeAttr(engine_op::InodeAttrResponse {
                        attr: Self::attr(100, NodeKind::Symlink),
                    }))
                }
                VfsOperation::GetAttr(req) => {
                    Ok(VfsResponse::InodeAttr(engine_op::InodeAttrResponse {
                        attr: Self::attr(req.inode.get(), NodeKind::File),
                    }))
                }
                VfsOperation::Create(req) => Ok(VfsResponse::Create(engine_op::CreateResponse {
                    attr: Self::attr(100, NodeKind::File),
                    fh: EngineFileHandle::new(
                        InodeId::new(100),
                        req.flags,
                        FileHandleId::new(44),
                        0,
                    ),
                })),
                VfsOperation::Open(req) => Ok(VfsResponse::Open(engine_op::OpenResponse {
                    fh: EngineFileHandle::new(req.inode, req.flags, FileHandleId::new(44), 0),
                })),
                VfsOperation::Read(req) => {
                    self.reads.set(self.reads.get() + 1);
                    Ok(VfsResponse::Read(engine_op::ReadResponse {
                        data: vec![b'r'; req.size as usize],
                    }))
                }
                VfsOperation::Write(req) => {
                    self.writes.borrow_mut().push(req.data.clone());
                    Ok(VfsResponse::Write(engine_op::WriteResponse {
                        written: req.data.len() as u32,
                    }))
                }
                VfsOperation::Release(_) => {
                    self.releases.set(self.releases.get() + 1);
                    Ok(VfsResponse::Unit(engine_op::UnitResponse))
                }
                VfsOperation::OpenDir(req) => {
                    Ok(VfsResponse::OpenDir(engine_op::OpenDirResponse {
                        dh: EngineDirHandle::new(req.inode, DirHandleId::new(55)),
                    }))
                }
                VfsOperation::ReleaseDir(_) => Ok(VfsResponse::Unit(engine_op::UnitResponse)),
                VfsOperation::ReadDir(_) => Ok(VfsResponse::ReadDir(engine_op::ReadDirResponse {
                    entries: Vec::new(),
                    has_more: false,
                })),
                VfsOperation::StatFs(_) => Ok(VfsResponse::StatFs(engine_op::StatFsResponse {
                    stat: StatFs::new(4096, 4096, 100, 90, 80, 10, 9, 255, 1, 2),
                })),
                _ => Ok(VfsResponse::Err(Errno::ENOSYS)),
            }
        }
    }

    fn bridge() -> VfsEngineBridge {
        VfsEngineBridge::new(VfsEngineBridgeWriter::new(42, DatasetId::new(99), 3, 5))
    }

    fn creds(peer: PeerId) -> VfsRpcCredentials {
        VfsRpcCredentials {
            peer_id: peer,
            auth_tag: [0; 16],
            uid: 1000,
            gid: 1000,
            groups: vec![1000, 1001],
        }
    }

    fn request(op_id: u64, flags: u16, payload: VfsRpcRequestPayload) -> VfsRpcRequest {
        VfsRpcRequest::new(OpId(op_id), 3, 5, flags, payload, Some(creds(PEER))).unwrap()
    }

    fn create_handle(bridge: &mut VfsEngineBridge, target: &RecordingDispatch) -> VfsRpcHandle {
        let response = bridge
            .dispatch(
                PEER,
                &request(
                    1,
                    0,
                    VfsRpcRequestPayload::Create {
                        parent: InodeId::new(1),
                        name: b"file".to_vec(),
                        mode: 0o644,
                        flags: 0o2,
                    },
                ),
                target,
            )
            .unwrap();
        match response.payload {
            VfsRpcResponsePayload::Created { handle, .. } => handle,
            other => panic!("unexpected create payload: {other:?}"),
        }
    }

    #[test]
    fn bridge_hook_fails_closed_when_requested_directly() {
        let request = request(
            42,
            0,
            VfsRpcRequestPayload::Lookup {
                parent: InodeId::new(1),
                name: b"child".to_vec(),
            },
        );

        let response = unavailable_response(&request).unwrap();

        assert_eq!(BRIDGE_FORWARDING_UNSUPPORTED, Errno::ENOSYS);
        assert_eq!(response.method, request.header.method);
        assert_eq!(response.header.op_id, request.header.op_id);
        assert_eq!(response.header.errno, Errno::ENOSYS);
        assert_eq!(response.payload, VfsRpcResponsePayload::Empty);
    }

    #[test]
    fn inline_write_dispatches_and_replays_completed_response() {
        let mut bridge = bridge();
        let target = RecordingDispatch::new();
        let handle = create_handle(&mut bridge, &target);
        let write = request(
            2,
            0,
            VfsRpcRequestPayload::Write {
                handle,
                offset: 0,
                data: InlineOrBulk::Inline(b"abc".to_vec()),
            },
        );

        let first = bridge.dispatch(PEER, &write, &target).unwrap();
        let replay = bridge.dispatch(PEER, &write, &target).unwrap();

        assert_eq!(first.payload, VfsRpcResponsePayload::BytesWritten(3));
        assert_eq!(replay.payload, first.payload);
        assert_ne!(replay.header.flags & RESP_FLAG_DEDUP_REPLAY, 0);
        assert_eq!(target.writes.borrow().len(), 1);
        assert_eq!(bridge.dedup_stats().dedup_hits, 1);
    }

    #[test]
    fn no_dedup_flag_reexecutes_mutation() {
        let mut bridge = bridge();
        let target = RecordingDispatch::new();
        let handle = create_handle(&mut bridge, &target);
        let write = request(
            2,
            REQ_FLAG_NO_DEDUP,
            VfsRpcRequestPayload::Write {
                handle,
                offset: 0,
                data: InlineOrBulk::Inline(b"abc".to_vec()),
            },
        );

        bridge.dispatch(PEER, &write, &target).unwrap();
        bridge.dispatch(PEER, &write, &target).unwrap();

        assert_eq!(target.writes.borrow().len(), 2);
        assert_eq!(bridge.dedup_stats().dedup_hits, 0);
    }

    #[test]
    fn stale_fenced_retry_does_not_replay_cached_mutation() {
        let mut bridge = bridge();
        let target = RecordingDispatch::new();
        let handle = create_handle(&mut bridge, &target);
        let payload = VfsRpcRequestPayload::Write {
            handle,
            offset: 0,
            data: InlineOrBulk::Inline(b"abc".to_vec()),
        };
        let current = request(2, 0, payload.clone());
        let stale = VfsRpcRequest::new(OpId(2), 2, 5, 0, payload, Some(creds(PEER))).unwrap();

        let first = bridge.dispatch(PEER, &current, &target).unwrap();
        let second = bridge.dispatch(PEER, &stale, &target).unwrap();

        assert_eq!(first.payload, VfsRpcResponsePayload::BytesWritten(3));
        assert_eq!(second.header.errno, Errno::ESTALE);
        assert_eq!(second.header.flags & RESP_FLAG_DEDUP_REPLAY, 0);
        assert_eq!(target.writes.borrow().len(), 1);
    }

    #[test]
    fn stale_writer_lease_rejects_mutation_before_dispatch() {
        let mut bridge = bridge();
        let target = RecordingDispatch::new();
        let stale = VfsRpcRequest::new(
            OpId(7),
            2,
            5,
            0,
            VfsRpcRequestPayload::Create {
                parent: InodeId::new(1),
                name: b"file".to_vec(),
                mode: 0o644,
                flags: 0,
            },
            Some(creds(PEER)),
        )
        .unwrap();

        let response = bridge.dispatch(PEER, &stale, &target).unwrap();

        assert_eq!(response.header.errno, Errno::ESTALE);
        assert_eq!(bridge.handle_count(), 0);
    }

    #[test]
    fn unsupported_attr_returning_methods_fail_before_side_effect() {
        let mut bridge = bridge();
        let target = RecordingDispatch::new();

        let symlink = bridge
            .dispatch(
                PEER,
                &request(
                    10,
                    0,
                    VfsRpcRequestPayload::Symlink {
                        parent: InodeId::new(1),
                        name: b"link".to_vec(),
                        target: b"target".to_vec(),
                    },
                ),
                &target,
            )
            .unwrap();
        let link = bridge
            .dispatch(
                PEER,
                &request(
                    11,
                    0,
                    VfsRpcRequestPayload::Link {
                        inode: InodeId::new(2),
                        new_parent: InodeId::new(1),
                        new_name: b"hard".to_vec(),
                    },
                ),
                &target,
            )
            .unwrap();

        assert_eq!(symlink.header.errno, BRIDGE_FORWARDING_UNSUPPORTED);
        assert_eq!(link.header.errno, BRIDGE_FORWARDING_UNSUPPORTED);
        assert_eq!(target.symlinks.get(), 0);
        assert_eq!(target.links.get(), 0);
    }

    #[test]
    fn credentials_must_match_transport_peer() {
        let mut bridge = bridge();
        let target = RecordingDispatch::new();
        let bad = VfsRpcRequest::new(
            OpId(1),
            3,
            5,
            0,
            VfsRpcRequestPayload::Lookup {
                parent: InodeId::new(1),
                name: b"a".to_vec(),
            },
            Some(creds(PeerId(99))),
        )
        .unwrap();

        let response = bridge.dispatch(PEER, &bad, &target).unwrap();

        assert_eq!(response.header.errno, Errno::EACCES);
    }

    #[test]
    fn handle_resolution_enforces_writer_generation_and_peer_scope() {
        let mut bridge = bridge();
        let target = RecordingDispatch::new();
        let handle = create_handle(&mut bridge, &target);

        let mut wrong_writer = handle.clone();
        wrong_writer.writer_node = 43;
        let stale = bridge
            .dispatch(
                PEER,
                &request(
                    2,
                    0,
                    VfsRpcRequestPayload::Read {
                        handle: wrong_writer,
                        offset: 0,
                        length: 1,
                    },
                ),
                &target,
            )
            .unwrap();
        assert_eq!(stale.header.errno, Errno::ESTALE);

        let mut wrong_generation = handle.clone();
        wrong_generation.generation = Generation::new(8);
        let stale = bridge
            .dispatch(
                PEER,
                &request(
                    3,
                    0,
                    VfsRpcRequestPayload::Read {
                        handle: wrong_generation,
                        offset: 0,
                        length: 1,
                    },
                ),
                &target,
            )
            .unwrap();
        assert_eq!(stale.header.errno, Errno::ESTALE);

        let other_peer = VfsRpcRequest::new(
            OpId(4),
            3,
            5,
            0,
            VfsRpcRequestPayload::Read {
                handle,
                offset: 0,
                length: 1,
            },
            Some(creds(PeerId(8))),
        )
        .unwrap();
        let denied = bridge.dispatch(PeerId(8), &other_peer, &target).unwrap();
        assert_eq!(denied.header.errno, Errno::EACCES);
    }

    #[test]
    fn release_removes_handle_and_retry_misses_registry() {
        let mut bridge = bridge();
        let target = RecordingDispatch::new();
        let handle = create_handle(&mut bridge, &target);
        let release = request(2, 0, VfsRpcRequestPayload::Release { handle, flags: 0 });

        let first = bridge.dispatch(PEER, &release, &target).unwrap();
        let second = bridge.dispatch(PEER, &release, &target).unwrap();

        assert_eq!(first.header.errno, Errno::SUCCESS);
        assert_eq!(second.header.errno, Errno::EBADF);
        assert_eq!(target.releases.get(), 1);
    }

    #[test]
    fn bulk_write_descriptor_is_explicitly_unsupported() {
        let mut bridge = bridge();
        let target = RecordingDispatch::new();
        let handle = create_handle(&mut bridge, &target);
        let bulk = request(
            2,
            REQ_FLAG_BULK_PENDING,
            VfsRpcRequestPayload::Write {
                handle,
                offset: 0,
                data: InlineOrBulk::Bulk {
                    token: [1; 32],
                    len: 4096,
                },
            },
        );

        let response = bridge.dispatch(PEER, &bulk, &target).unwrap();

        assert_eq!(response.header.errno, Errno::EOPNOTSUPP);
        assert!(target.writes.borrow().is_empty());
    }

    #[test]
    fn done_verified_bulk_write_reaches_engine_once() {
        let mut bridge = bridge();
        let target = RecordingDispatch::new();
        let handle = create_handle(&mut bridge, &target);
        let token = [8; 32];
        let bulk = request(
            2,
            REQ_FLAG_BULK_PENDING,
            VfsRpcRequestPayload::Write {
                handle,
                offset: 7,
                data: InlineOrBulk::Bulk { token, len: 3 },
            },
        );
        let completion = VfsRpcBulkCompletion {
            connection_id: 33,
            stream_id: 11,
            token,
            op_id: 2,
            handoff: VfsRpcBulkHandoff::WriteUpload,
            len: 3,
            bytes: b"abc".to_vec(),
        };

        let response = bridge
            .dispatch_done_verified_write(PEER, &bulk, completion, &target)
            .unwrap();
        let replay = bridge
            .dispatch_done_verified_write(
                PEER,
                &bulk,
                VfsRpcBulkCompletion {
                    connection_id: 33,
                    stream_id: 11,
                    token,
                    op_id: 2,
                    handoff: VfsRpcBulkHandoff::WriteUpload,
                    len: 3,
                    bytes: b"abc".to_vec(),
                },
                &target,
            )
            .unwrap();

        assert_eq!(response.payload, VfsRpcResponsePayload::BytesWritten(3));
        assert_eq!(
            replay.header.flags & RESP_FLAG_DEDUP_REPLAY,
            RESP_FLAG_DEDUP_REPLAY
        );
        assert_eq!(target.writes.borrow().as_slice(), &[b"abc".to_vec()]);
    }

    #[test]
    fn read_bulk_response_formats_descriptor_and_flag() {
        let mut bridge = bridge();
        let target = RecordingDispatch::new();
        let handle = create_handle(&mut bridge, &target);
        let read = request(
            3,
            0,
            VfsRpcRequestPayload::Read {
                handle,
                offset: 0,
                length: 8192,
            },
        );
        let descriptor = VfsRpcBulkDescriptor {
            token: [9; 32],
            len: 8192,
        };

        let response = VfsEngineBridge::read_bulk_response(&read, descriptor).unwrap();

        assert_eq!(response.header.flags & RESP_FLAG_BULK, RESP_FLAG_BULK);
        assert_eq!(
            response.payload,
            VfsRpcResponsePayload::Data(InlineOrBulk::Bulk {
                token: descriptor.token,
                len: descriptor.len,
            })
        );
    }

    #[test]
    fn forwarded_reads_do_not_require_current_term_epoch() {
        let mut bridge = bridge();
        let target = RecordingDispatch::new();
        let handle = create_handle(&mut bridge, &target);
        let read = VfsRpcRequest::new(
            OpId(9),
            1,
            1,
            0,
            VfsRpcRequestPayload::Read {
                handle,
                offset: 0,
                length: 2,
            },
            Some(creds(PEER)),
        )
        .unwrap();

        let response = bridge.dispatch(PEER, &read, &target).unwrap();

        assert_eq!(response.header.errno, Errno::SUCCESS);
        assert_eq!(
            response.payload,
            VfsRpcResponsePayload::Data(InlineOrBulk::Inline(vec![b'r', b'r']))
        );
        assert_eq!(target.reads.get(), 1);
    }
}
