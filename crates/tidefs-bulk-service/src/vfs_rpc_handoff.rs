// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

//! BULK-side helpers for the VFS_RPC `InlineOrBulk::Bulk` handoff.
//!
//! The helpers in this module bind VFS_RPC READ/WRITE metadata to the
//! connection-scoped BULK state machine. They deliberately do not dispatch
//! VFS_RPC frames or execute VFS Engine operations; callers must only consume the
//! returned bytes after DONE has verified the matching op_id, direction, length,
//! and CRC32C checksum.

use std::fmt;

use crate::{
    AbortedBulkTransfer, BulkAbortReason, BulkAccept, BulkAcceptResult, BulkError, BulkMetadata,
    BulkMode, BulkOffer, BulkPriority, BulkService, BulkToken, BulkTransferDirection,
    CompletedBulkTransfer, ConnectionId, OpId, StreamId, VfsRpcBulkMethod,
};

/// VFS_RPC operation direction represented by a BULK transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VfsRpcBulkHandoff {
    WriteUpload,
    ReadDownload,
}

impl VfsRpcBulkHandoff {
    #[must_use]
    pub const fn method(self) -> VfsRpcBulkMethod {
        match self {
            Self::WriteUpload => VfsRpcBulkMethod::Write,
            Self::ReadDownload => VfsRpcBulkMethod::Read,
        }
    }

    #[must_use]
    pub const fn direction(self) -> BulkTransferDirection {
        match self {
            Self::WriteUpload => BulkTransferDirection::WriteUpload,
            Self::ReadDownload => BulkTransferDirection::ReadDownload,
        }
    }

    #[must_use]
    pub const fn metadata(self, op_id: OpId) -> BulkMetadata {
        match self {
            Self::WriteUpload => BulkMetadata::vfs_rpc_write_upload(op_id),
            Self::ReadDownload => BulkMetadata::vfs_rpc_read_download(op_id),
        }
    }

    #[must_use]
    pub fn offer(
        self,
        connection_id: ConnectionId,
        stream_id: StreamId,
        op_id: OpId,
        total_len: u64,
        priority: BulkPriority,
    ) -> BulkOffer {
        BulkOffer {
            connection_id,
            stream_id,
            total_len,
            mode: BulkMode::TcpStream,
            priority,
            metadata: self.metadata(op_id),
        }
    }
}

/// Descriptor data copied into VFS_RPC `InlineOrBulk::Bulk`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VfsRpcBulkDescriptor {
    pub token: BulkToken,
    pub len: u64,
}

impl VfsRpcBulkDescriptor {
    pub fn from_accept(accept: &BulkAccept, len: u64) -> Result<Self, VfsRpcBulkHandoffError> {
        if accept.result != BulkAcceptResult::Accepted {
            return Err(VfsRpcBulkHandoffError::AcceptRejected {
                result: accept.result,
            });
        }
        let token = accept
            .token
            .ok_or(VfsRpcBulkHandoffError::MissingAcceptedToken)?;
        Ok(Self { token, len })
    }
}

/// DONE-verified VFS_RPC transfer bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VfsRpcBulkCompletion {
    pub connection_id: ConnectionId,
    pub stream_id: StreamId,
    pub token: BulkToken,
    pub op_id: OpId,
    pub handoff: VfsRpcBulkHandoff,
    pub len: u64,
    pub bytes: Vec<u8>,
}

/// ABORT-verified VFS_RPC transfer retirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VfsRpcBulkAbort {
    pub connection_id: ConnectionId,
    pub stream_id: StreamId,
    pub token: BulkToken,
    pub op_id: OpId,
    pub handoff: VfsRpcBulkHandoff,
    pub reason: BulkAbortReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VfsRpcBulkDoneCheck {
    op_id: OpId,
    handoff: VfsRpcBulkHandoff,
    expected_len: u64,
    total_transferred: u64,
    checksum32: u32,
}

/// Errors emitted by the VFS_RPC/BULK handoff adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VfsRpcBulkHandoffError {
    Bulk(BulkError),
    AcceptRejected {
        result: BulkAcceptResult,
    },
    MissingAcceptedToken,
    NonVfsRpcMetadata {
        metadata: BulkMetadata,
    },
    UnexpectedVfsRpcMetadata {
        expected: VfsRpcBulkHandoff,
        method: VfsRpcBulkMethod,
        direction: BulkTransferDirection,
    },
    OpIdMismatch {
        expected: OpId,
        actual: OpId,
    },
    LengthMismatch {
        expected: u64,
        actual: u64,
    },
}

impl fmt::Display for VfsRpcBulkHandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bulk(err) => write!(f, "{err}"),
            Self::AcceptRejected { result } => {
                write!(f, "BULK ACCEPT rejected VFS_RPC handoff with {result:?}")
            }
            Self::MissingAcceptedToken => write!(f, "accepted BULK handoff has no BulkToken"),
            Self::NonVfsRpcMetadata { .. } => write!(f, "BULK transfer is not VFS_RPC metadata"),
            Self::UnexpectedVfsRpcMetadata {
                expected,
                method,
                direction,
            } => write!(
                f,
                "BULK transfer metadata {method:?}/{direction:?} does not match {expected:?}"
            ),
            Self::OpIdMismatch { expected, actual } => {
                write!(f, "BULK op_id {actual} does not match expected {expected}")
            }
            Self::LengthMismatch { expected, actual } => {
                write!(
                    f,
                    "BULK length {actual} does not match VFS_RPC descriptor {expected}"
                )
            }
        }
    }
}

impl std::error::Error for VfsRpcBulkHandoffError {}

impl From<BulkError> for VfsRpcBulkHandoffError {
    fn from(error: BulkError) -> Self {
        Self::Bulk(error)
    }
}

impl BulkService {
    /// Accept a VFS_RPC WRITE upload OFFER on the receiver/writer side.
    pub fn accept_vfs_rpc_write_upload(
        &mut self,
        connection_id: ConnectionId,
        stream_id: StreamId,
        op_id: OpId,
        total_len: u64,
        priority: BulkPriority,
    ) -> BulkAccept {
        self.offer(VfsRpcBulkHandoff::WriteUpload.offer(
            connection_id,
            stream_id,
            op_id,
            total_len,
            priority,
        ))
    }

    /// Accept a VFS_RPC READ download OFFER on the receiver/client side.
    pub fn accept_vfs_rpc_read_download(
        &mut self,
        connection_id: ConnectionId,
        stream_id: StreamId,
        op_id: OpId,
        total_len: u64,
        priority: BulkPriority,
    ) -> BulkAccept {
        self.offer(VfsRpcBulkHandoff::ReadDownload.offer(
            connection_id,
            stream_id,
            op_id,
            total_len,
            priority,
        ))
    }

    /// Verify a completed WRITE upload before a VFS Engine write may consume it.
    pub fn finish_vfs_rpc_write_upload(
        &mut self,
        connection_id: ConnectionId,
        token: BulkToken,
        op_id: OpId,
        expected_len: u64,
        total_transferred: u64,
        checksum32: u32,
    ) -> Result<VfsRpcBulkCompletion, VfsRpcBulkHandoffError> {
        self.finish_vfs_rpc_handoff(
            connection_id,
            token,
            VfsRpcBulkDoneCheck {
                op_id,
                handoff: VfsRpcBulkHandoff::WriteUpload,
                expected_len,
                total_transferred,
                checksum32,
            },
        )
    }

    /// Verify a completed READ download before read bytes may be returned.
    pub fn finish_vfs_rpc_read_download(
        &mut self,
        connection_id: ConnectionId,
        token: BulkToken,
        op_id: OpId,
        expected_len: u64,
        total_transferred: u64,
        checksum32: u32,
    ) -> Result<VfsRpcBulkCompletion, VfsRpcBulkHandoffError> {
        self.finish_vfs_rpc_handoff(
            connection_id,
            token,
            VfsRpcBulkDoneCheck {
                op_id,
                handoff: VfsRpcBulkHandoff::ReadDownload,
                expected_len,
                total_transferred,
                checksum32,
            },
        )
    }

    /// Abort a VFS_RPC BULK transfer and validate the retired metadata.
    pub fn abort_vfs_rpc_handoff(
        &mut self,
        connection_id: ConnectionId,
        token: BulkToken,
        op_id: OpId,
        handoff: VfsRpcBulkHandoff,
        reason: BulkAbortReason,
    ) -> Result<VfsRpcBulkAbort, VfsRpcBulkHandoffError> {
        let aborted = self.abort(connection_id, token, reason)?;
        validate_vfs_rpc_abort(aborted, handoff, op_id)
    }

    fn finish_vfs_rpc_handoff(
        &mut self,
        connection_id: ConnectionId,
        token: BulkToken,
        check: VfsRpcBulkDoneCheck,
    ) -> Result<VfsRpcBulkCompletion, VfsRpcBulkHandoffError> {
        let completed = self.done(
            connection_id,
            token,
            check.total_transferred,
            check.checksum32,
        )?;
        validate_vfs_rpc_completion(completed, check)
    }
}

fn validate_vfs_rpc_completion(
    completed: CompletedBulkTransfer,
    check: VfsRpcBulkDoneCheck,
) -> Result<VfsRpcBulkCompletion, VfsRpcBulkHandoffError> {
    let (handoff, op_id) = validate_metadata(completed.metadata, check.handoff, check.op_id)?;
    let actual_len = completed.bytes.len() as u64;
    if actual_len != check.expected_len {
        return Err(VfsRpcBulkHandoffError::LengthMismatch {
            expected: check.expected_len,
            actual: actual_len,
        });
    }

    Ok(VfsRpcBulkCompletion {
        connection_id: completed.connection_id,
        stream_id: completed.stream_id,
        token: completed.token,
        op_id,
        handoff,
        len: actual_len,
        bytes: completed.bytes,
    })
}

fn validate_vfs_rpc_abort(
    aborted: AbortedBulkTransfer,
    expected_handoff: VfsRpcBulkHandoff,
    expected_op_id: OpId,
) -> Result<VfsRpcBulkAbort, VfsRpcBulkHandoffError> {
    let (handoff, op_id) = validate_metadata(aborted.metadata, expected_handoff, expected_op_id)?;
    Ok(VfsRpcBulkAbort {
        connection_id: aborted.connection_id,
        stream_id: aborted.stream_id,
        token: aborted.token,
        op_id,
        handoff,
        reason: aborted.reason,
    })
}

fn validate_metadata(
    metadata: BulkMetadata,
    expected_handoff: VfsRpcBulkHandoff,
    expected_op_id: OpId,
) -> Result<(VfsRpcBulkHandoff, OpId), VfsRpcBulkHandoffError> {
    let (method, op_id, direction) = match metadata {
        BulkMetadata::VfsRpc {
            method,
            op_id,
            direction,
        } => (method, op_id, direction),
        metadata => return Err(VfsRpcBulkHandoffError::NonVfsRpcMetadata { metadata }),
    };

    if method != expected_handoff.method() || direction != expected_handoff.direction() {
        return Err(VfsRpcBulkHandoffError::UnexpectedVfsRpcMetadata {
            expected: expected_handoff,
            method,
            direction,
        });
    }
    if op_id != expected_op_id {
        return Err(VfsRpcBulkHandoffError::OpIdMismatch {
            expected: expected_op_id,
            actual: op_id,
        });
    }
    Ok((expected_handoff, op_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BulkServiceConfig;

    fn service() -> BulkService {
        BulkService::new(BulkServiceConfig {
            receiver_node_id: 42,
            max_pinned_bytes: 64,
            max_transfer_len: 64,
            max_chunk: 8,
            max_pending_credits_per_stream: 2,
            ..BulkServiceConfig::default()
        })
    }

    fn complete_chunks(service: &mut BulkService, token: BulkToken, bytes: &[u8]) {
        let mut offset = 0;
        for (chunk_seq, chunk) in bytes.chunks(8).enumerate() {
            let chunk_seq = u32::try_from(chunk_seq).unwrap();
            let chunk_len = u32::try_from(chunk.len()).unwrap();
            let grant = service.credit(7, token, chunk_seq, chunk_len).unwrap();
            assert_eq!(grant.offset, offset);
            service
                .write_tcp_chunk(7, token, chunk_seq, grant.offset, chunk)
                .unwrap();
            offset += u64::try_from(chunk.len()).unwrap();
        }
    }

    fn payload_len(bytes: &[u8]) -> u64 {
        u64::try_from(bytes.len()).unwrap()
    }

    #[test]
    fn write_upload_handoff_verifies_op_id_direction_length_and_bytes() {
        let mut service = service();
        let op_id = 99;
        let bytes = b"hello world";
        let len = payload_len(bytes);
        let accept = service.accept_vfs_rpc_write_upload(7, 11, op_id, len, BulkPriority::Bulk);
        let descriptor = VfsRpcBulkDescriptor::from_accept(&accept, len).unwrap();

        complete_chunks(&mut service, descriptor.token, bytes);
        let completed = service
            .finish_vfs_rpc_write_upload(
                7,
                descriptor.token,
                op_id,
                descriptor.len,
                len,
                crc32c::crc32c(bytes),
            )
            .unwrap();

        assert_eq!(completed.op_id, op_id);
        assert_eq!(completed.handoff, VfsRpcBulkHandoff::WriteUpload);
        assert_eq!(completed.bytes.as_slice(), bytes);
        assert_eq!(service.active_transfer_count(7), 0);
    }

    #[test]
    fn read_download_handoff_rejects_wrong_op_id_after_discard() {
        let mut service = service();
        let bytes = b"read bytes";
        let len = payload_len(bytes);
        let accept = service.accept_vfs_rpc_read_download(7, 12, 55, len, BulkPriority::Bulk);
        let descriptor = VfsRpcBulkDescriptor::from_accept(&accept, len).unwrap();

        complete_chunks(&mut service, descriptor.token, bytes);
        assert_eq!(
            service.finish_vfs_rpc_read_download(
                7,
                descriptor.token,
                56,
                descriptor.len,
                len,
                crc32c::crc32c(bytes),
            ),
            Err(VfsRpcBulkHandoffError::OpIdMismatch {
                expected: 56,
                actual: 55,
            })
        );
        assert_eq!(service.active_transfer_count(7), 0);
    }

    #[test]
    fn failed_done_discards_bytes_before_vfs_rpc_completion() {
        let mut service = service();
        let bytes = b"bad";
        let len = payload_len(bytes);
        let accept = service.accept_vfs_rpc_write_upload(7, 13, 77, len, BulkPriority::Bulk);
        let descriptor = VfsRpcBulkDescriptor::from_accept(&accept, len).unwrap();

        complete_chunks(&mut service, descriptor.token, bytes);
        assert!(matches!(
            service.finish_vfs_rpc_write_upload(7, descriptor.token, 77, descriptor.len, 3, 0,),
            Err(VfsRpcBulkHandoffError::Bulk(
                BulkError::ChecksumMismatch { .. }
            ))
        ));
        assert_eq!(service.active_transfer_count(7), 0);
    }

    #[test]
    fn abort_vfs_rpc_handoff_validates_metadata_and_retires_token() {
        let mut service = service();
        let accept = service.accept_vfs_rpc_write_upload(7, 14, 88, 3, BulkPriority::Bulk);
        let descriptor = VfsRpcBulkDescriptor::from_accept(&accept, 3).unwrap();

        let aborted = service
            .abort_vfs_rpc_handoff(
                7,
                descriptor.token,
                88,
                VfsRpcBulkHandoff::WriteUpload,
                BulkAbortReason::Timeout,
            )
            .unwrap();

        assert_eq!(aborted.op_id, 88);
        assert_eq!(aborted.reason, BulkAbortReason::Timeout);
        assert_eq!(service.active_transfer_count(7), 0);
    }

    #[test]
    fn rejected_accept_cannot_create_vfs_rpc_descriptor() {
        let mut service = service();
        let accept = service.accept_vfs_rpc_write_upload(7, 15, 1, 1024, BulkPriority::Bulk);

        assert_eq!(
            VfsRpcBulkDescriptor::from_accept(&accept, 1024),
            Err(VfsRpcBulkHandoffError::AcceptRejected {
                result: BulkAcceptResult::Rejected,
            })
        );
    }
}
