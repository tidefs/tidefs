// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! BULK service state for connection-scoped byte movement.
//!
//! This crate provides the first live `service_id = 0x07` surface for the
//! cluster BULK plane. It is intentionally a service/state-machine API rather
//! than a transport dispatcher: callers supply already-authenticated
//! connection identifiers, drive OFFER/ACCEPT/CREDIT/data/DONE/ABORT ordering,
//! and receive completed TCP_STREAM payloads only after length and CRC32C
//! verification. RDMA modes remain rejected until their security, memory,
//! credit-lifecycle, cleanup, and runtime evidence gates have a byte-mover
//! implementation to consume them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use tidefs_transport::{bulk_deadline_default, BULK_CHUNK_SIZE_DEFAULT, MAX_INFLIGHT_BULK_TOKENS};

/// Stable transport service id for the BULK plane.
pub const BULK_SERVICE_ID: u8 = 0x07;
/// Current BULK service API version.
pub const BULK_SERVICE_VERSION: u8 = 1;
/// Default per-connection receive/pinned-byte budget: 16 MiB.
pub const DEFAULT_MAX_PINNED_BYTES: u64 = 16 * 1024 * 1024;
/// Default maximum pending credits per stream.
pub const DEFAULT_MAX_PENDING_CREDITS_PER_STREAM: u8 = 4;

/// Opaque connection-scoped token echoed by VFS_RPC `InlineOrBulk::Bulk`.
pub type BulkToken = [u8; 32];
/// Transport-session identifier owned by the caller's authenticated transport.
pub type ConnectionId = u64;
/// Sender-assigned stream identifier unique within one active connection.
pub type StreamId = u32;
/// VFS_RPC idempotency key carried in BULK metadata.
pub type OpId = u64;

/// BULK data movement mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BulkMode {
    TcpStream = 0,
    RdmaWrite = 1,
    RdmaRead = 2,
}

impl BulkMode {
    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::TcpStream),
            1 => Some(Self::RdmaWrite),
            2 => Some(Self::RdmaRead),
            _ => None,
        }
    }

    #[must_use]
    pub const fn to_wire(self) -> u8 {
        self as u8
    }
}

/// BULK scheduler priority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum BulkPriority {
    Control = 0,
    Metadata = 1,
    Bulk = 2,
    Background = 3,
}

impl BulkPriority {
    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Control),
            1 => Some(Self::Metadata),
            2 => Some(Self::Bulk),
            3 => Some(Self::Background),
            _ => None,
        }
    }

    #[must_use]
    pub const fn to_wire(self) -> u8 {
        self as u8
    }
}

/// VFS_RPC method represented in BULK metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum VfsRpcBulkMethod {
    Write = 0,
    Read = 1,
}

/// Direction of the VFS_RPC/BULK handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BulkTransferDirection {
    WriteUpload = 0,
    ReadDownload = 1,
}

/// Higher-layer metadata bound to a BULK offer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BulkMetadata {
    VfsRpc {
        method: VfsRpcBulkMethod,
        op_id: OpId,
        direction: BulkTransferDirection,
    },
    Opaque(Vec<u8>),
}

impl BulkMetadata {
    #[must_use]
    pub const fn vfs_rpc_write_upload(op_id: OpId) -> Self {
        Self::VfsRpc {
            method: VfsRpcBulkMethod::Write,
            op_id,
            direction: BulkTransferDirection::WriteUpload,
        }
    }

    #[must_use]
    pub const fn vfs_rpc_read_download(op_id: OpId) -> Self {
        Self::VfsRpc {
            method: VfsRpcBulkMethod::Read,
            op_id,
            direction: BulkTransferDirection::ReadDownload,
        }
    }
}

/// Evidence gates required before any RDMA-capable BULK mode can be admitted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RdmaEvidence {
    pub transport_peer_security: bool,
    pub pinned_memory_accounting: bool,
    pub rkey_addr_credit_lifecycle: bool,
    pub abort_cleanup: bool,
    pub runtime_validation: bool,
}

impl RdmaEvidence {
    #[must_use]
    pub const fn complete(self) -> bool {
        self.transport_peer_security
            && self.pinned_memory_accounting
            && self.rkey_addr_credit_lifecycle
            && self.abort_cleanup
            && self.runtime_validation
    }
}

/// Runtime configuration for one BULK service instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkServiceConfig {
    pub receiver_node_id: u64,
    pub max_inflight_tokens: usize,
    pub max_pinned_bytes: u64,
    pub max_transfer_len: u64,
    pub max_chunk: u32,
    pub max_pending_credits_per_stream: u8,
    pub bulk_deadline: Duration,
    pub rdma_evidence: RdmaEvidence,
}

impl Default for BulkServiceConfig {
    fn default() -> Self {
        Self {
            receiver_node_id: 0,
            max_inflight_tokens: usize::from(MAX_INFLIGHT_BULK_TOKENS),
            max_pinned_bytes: DEFAULT_MAX_PINNED_BYTES,
            max_transfer_len: DEFAULT_MAX_PINNED_BYTES,
            max_chunk: BULK_CHUNK_SIZE_DEFAULT,
            max_pending_credits_per_stream: DEFAULT_MAX_PENDING_CREDITS_PER_STREAM,
            bulk_deadline: bulk_deadline_default(),
            rdma_evidence: RdmaEvidence::default(),
        }
    }
}

/// A sender's OFFER request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkOffer {
    pub connection_id: ConnectionId,
    pub stream_id: StreamId,
    pub total_len: u64,
    pub mode: BulkMode,
    pub priority: BulkPriority,
    pub metadata: BulkMetadata,
}

/// Receiver ACCEPT result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkAccept {
    pub stream_id: StreamId,
    pub result: BulkAcceptResult,
    pub token: Option<BulkToken>,
    pub max_chunk: u32,
    pub retry_after: Option<Duration>,
}

/// Wire-level ACCEPT status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BulkAcceptResult {
    Accepted = 0,
    NoCredits = 1,
    ModeUnsupported = 2,
    Rejected = 3,
}

/// CREDIT grant for a TCP_STREAM chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BulkCreditGrant {
    pub stream_id: StreamId,
    pub token: BulkToken,
    pub chunk_seq: u32,
    pub offset: u64,
    pub len: u32,
}

/// Terminal transfer returned after DONE verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedBulkTransfer {
    pub connection_id: ConnectionId,
    pub stream_id: StreamId,
    pub token: BulkToken,
    pub metadata: BulkMetadata,
    pub bytes: Vec<u8>,
}

/// Terminal transfer returned after explicit or implicit ABORT.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbortedBulkTransfer {
    pub connection_id: ConnectionId,
    pub stream_id: StreamId,
    pub token: BulkToken,
    pub metadata: BulkMetadata,
    pub reason: BulkAbortReason,
}

/// ABORT reason values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BulkAbortReason {
    SenderCancel = 0,
    ReceiverCancel = 1,
    Timeout = 2,
    ProtocolError = 3,
    ConnectionLost = 4,
}

/// Public BULK service state.
#[derive(Debug)]
pub struct BulkService {
    config: BulkServiceConfig,
    connections: BTreeMap<ConnectionId, ConnectionState>,
    next_transfer_id: u64,
    next_nonce: u64,
}

impl BulkService {
    #[must_use]
    pub fn new(config: BulkServiceConfig) -> Self {
        Self {
            config,
            connections: BTreeMap::new(),
            next_transfer_id: 1,
            next_nonce: 0x9e37_79b9_7f4a_7c15,
        }
    }

    #[must_use]
    pub fn config(&self) -> &BulkServiceConfig {
        &self.config
    }

    /// Process an OFFER and reserve a connection-scoped token slot on accept.
    pub fn offer(&mut self, offer: BulkOffer) -> BulkAccept {
        if offer.mode != BulkMode::TcpStream {
            return self.accept_reject(offer.stream_id, BulkAcceptResult::ModeUnsupported);
        }
        if offer.total_len > self.config.max_transfer_len {
            return self.accept_reject(offer.stream_id, BulkAcceptResult::Rejected);
        }
        if offer.total_len > usize::MAX as u64 {
            return self.accept_reject(offer.stream_id, BulkAcceptResult::Rejected);
        }

        if self
            .connections
            .get(&offer.connection_id)
            .is_some_and(|connection| connection.transfers.contains_key(&offer.stream_id))
        {
            return self.accept_reject(offer.stream_id, BulkAcceptResult::Rejected);
        }
        let active = self
            .connections
            .get(&offer.connection_id)
            .map_or(0, |connection| connection.transfers.len());
        if active >= self.config.max_inflight_tokens {
            return self.accept_reject(offer.stream_id, BulkAcceptResult::NoCredits);
        }

        let transfer_id = self.next_transfer_id;
        self.next_transfer_id = self.next_transfer_id.saturating_add(1);
        self.next_nonce = self
            .next_nonce
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let token = make_token(
            offer.connection_id,
            transfer_id,
            self.next_nonce,
            self.config.receiver_node_id,
        );
        let total_len = offer.total_len;
        let connection = self.connections.entry(offer.connection_id).or_default();
        let transfer = TransferState::new(offer, token);
        connection.token_index.insert(token, transfer.stream_id);
        connection.transfers.insert(transfer.stream_id, transfer);

        BulkAccept {
            stream_id: connection.token_index[&token],
            result: BulkAcceptResult::Accepted,
            token: Some(token),
            max_chunk: self
                .config
                .max_chunk
                .min(total_len.min(u64::from(u32::MAX)) as u32),
            retry_after: None,
        }
    }

    /// Request credit for the next TCP_STREAM chunk.
    pub fn credit(
        &mut self,
        connection_id: ConnectionId,
        token: BulkToken,
        chunk_seq: u32,
        len: u32,
    ) -> Result<BulkCreditGrant, BulkError> {
        if len == 0 {
            return Err(BulkError::ZeroLengthChunk);
        }
        if len > self.config.max_chunk {
            return Err(BulkError::ChunkTooLarge {
                len,
                max_chunk: self.config.max_chunk,
            });
        }
        let connection = self
            .connections
            .get_mut(&connection_id)
            .ok_or(BulkError::UnknownToken)?;
        let stream_id = *connection
            .token_index
            .get(&token)
            .ok_or(BulkError::UnknownToken)?;
        if connection.pinned_bytes.saturating_add(u64::from(len)) > self.config.max_pinned_bytes {
            return Err(BulkError::NoCredits);
        }
        let grant = {
            let transfer = connection
                .transfers
                .get_mut(&stream_id)
                .ok_or(BulkError::UnknownToken)?;
            transfer.credit(
                token,
                chunk_seq,
                len,
                self.config.max_pending_credits_per_stream,
            )?
        };
        connection.pinned_bytes = connection.pinned_bytes.saturating_add(u64::from(len));
        Ok(grant)
    }

    /// Write a granted TCP_STREAM chunk into the receiver reassembly buffer.
    pub fn write_tcp_chunk(
        &mut self,
        connection_id: ConnectionId,
        token: BulkToken,
        chunk_seq: u32,
        offset: u64,
        payload: &[u8],
    ) -> Result<(), BulkError> {
        let connection = self
            .connections
            .get_mut(&connection_id)
            .ok_or(BulkError::UnknownToken)?;
        let stream_id = *connection
            .token_index
            .get(&token)
            .ok_or(BulkError::UnknownToken)?;
        let transfer = connection
            .transfers
            .get_mut(&stream_id)
            .ok_or(BulkError::UnknownToken)?;
        transfer.write_tcp_chunk(token, chunk_seq, offset, payload)
    }

    /// Verify DONE and retire the token. Failed transfers are discarded.
    pub fn done(
        &mut self,
        connection_id: ConnectionId,
        token: BulkToken,
        total_transferred: u64,
        checksum32: u32,
    ) -> Result<CompletedBulkTransfer, BulkError> {
        let connection = self
            .connections
            .get_mut(&connection_id)
            .ok_or(BulkError::UnknownToken)?;
        let stream_id = *connection
            .token_index
            .get(&token)
            .ok_or(BulkError::UnknownToken)?;

        match connection
            .transfers
            .get(&stream_id)
            .ok_or(BulkError::UnknownToken)?
            .validate_done(total_transferred, checksum32)
        {
            Ok(()) => {
                let transfer = connection
                    .remove_transfer(stream_id)
                    .ok_or(BulkError::UnknownToken)?;
                Ok(CompletedBulkTransfer {
                    connection_id,
                    stream_id,
                    token,
                    metadata: transfer.offer.metadata,
                    bytes: transfer.buffer,
                })
            }
            Err(err) => {
                connection.remove_transfer(stream_id);
                Err(err)
            }
        }
    }

    /// Explicitly abort a transfer and discard any buffered bytes.
    pub fn abort(
        &mut self,
        connection_id: ConnectionId,
        token: BulkToken,
        reason: BulkAbortReason,
    ) -> Result<AbortedBulkTransfer, BulkError> {
        let connection = self
            .connections
            .get_mut(&connection_id)
            .ok_or(BulkError::UnknownToken)?;
        let stream_id = *connection
            .token_index
            .get(&token)
            .ok_or(BulkError::UnknownToken)?;
        let transfer = connection
            .remove_transfer(stream_id)
            .ok_or(BulkError::UnknownToken)?;
        Ok(AbortedBulkTransfer {
            connection_id,
            stream_id,
            token,
            metadata: transfer.offer.metadata,
            reason,
        })
    }

    /// Implicitly abort all active transfers for a closed connection.
    pub fn connection_lost(&mut self, connection_id: ConnectionId) -> Vec<AbortedBulkTransfer> {
        let Some(mut connection) = self.connections.remove(&connection_id) else {
            return Vec::new();
        };
        let mut aborted = Vec::new();
        for (_, transfer) in std::mem::take(&mut connection.transfers) {
            aborted.push(AbortedBulkTransfer {
                connection_id,
                stream_id: transfer.stream_id,
                token: transfer.token,
                metadata: transfer.offer.metadata,
                reason: BulkAbortReason::ConnectionLost,
            });
        }
        aborted
    }

    #[must_use]
    pub fn active_transfer_count(&self, connection_id: ConnectionId) -> usize {
        self.connections
            .get(&connection_id)
            .map_or(0, |connection| connection.transfers.len())
    }

    #[must_use]
    pub fn pinned_bytes(&self, connection_id: ConnectionId) -> u64 {
        self.connections
            .get(&connection_id)
            .map_or(0, |connection| connection.pinned_bytes)
    }

    fn accept_reject(&self, stream_id: StreamId, result: BulkAcceptResult) -> BulkAccept {
        BulkAccept {
            stream_id,
            result,
            token: None,
            max_chunk: 0,
            retry_after: (result == BulkAcceptResult::NoCredits)
                .then_some(self.config.bulk_deadline),
        }
    }
}

impl Default for BulkService {
    fn default() -> Self {
        Self::new(BulkServiceConfig::default())
    }
}

#[derive(Debug, Default)]
struct ConnectionState {
    transfers: BTreeMap<StreamId, TransferState>,
    token_index: BTreeMap<BulkToken, StreamId>,
    pinned_bytes: u64,
}

impl ConnectionState {
    fn remove_transfer(&mut self, stream_id: StreamId) -> Option<TransferState> {
        let transfer = self.transfers.remove(&stream_id)?;
        self.token_index.remove(&transfer.token);
        self.pinned_bytes = self.pinned_bytes.saturating_sub(transfer.pinned_bytes);
        Some(transfer)
    }
}

#[derive(Debug)]
struct TransferState {
    offer: BulkOffer,
    token: BulkToken,
    stream_id: StreamId,
    next_credit_seq: u32,
    next_offset: u64,
    pinned_bytes: u64,
    buffer: Vec<u8>,
    grants: BTreeMap<u32, GrantedChunk>,
    received_chunks: BTreeSet<u32>,
    received_bytes: u64,
}

impl TransferState {
    fn new(offer: BulkOffer, token: BulkToken) -> Self {
        let total_len = offer.total_len as usize;
        Self {
            stream_id: offer.stream_id,
            offer,
            token,
            next_credit_seq: 0,
            next_offset: 0,
            pinned_bytes: 0,
            buffer: vec![0; total_len],
            grants: BTreeMap::new(),
            received_chunks: BTreeSet::new(),
            received_bytes: 0,
        }
    }

    fn credit(
        &mut self,
        token: BulkToken,
        chunk_seq: u32,
        len: u32,
        max_pending_credits: u8,
    ) -> Result<BulkCreditGrant, BulkError> {
        if token != self.token {
            return Err(BulkError::UnknownToken);
        }
        if chunk_seq != self.next_credit_seq {
            return Err(BulkError::InvalidChunkSequence {
                expected: self.next_credit_seq,
                actual: chunk_seq,
            });
        }
        let pending = self.grants.len().saturating_sub(self.received_chunks.len());
        if pending >= usize::from(max_pending_credits) {
            return Err(BulkError::TooManyPendingCredits {
                pending,
                max_pending: max_pending_credits,
            });
        }
        let end = self
            .next_offset
            .checked_add(u64::from(len))
            .ok_or(BulkError::TransferOverflow)?;
        if end > self.offer.total_len {
            return Err(BulkError::LengthMismatch {
                expected: self.offer.total_len,
                actual: end,
            });
        }
        let grant = BulkCreditGrant {
            stream_id: self.stream_id,
            token,
            chunk_seq,
            offset: self.next_offset,
            len,
        };
        self.grants.insert(
            chunk_seq,
            GrantedChunk {
                offset: self.next_offset,
                len,
            },
        );
        self.next_credit_seq = self.next_credit_seq.saturating_add(1);
        self.next_offset = end;
        self.pinned_bytes = self.pinned_bytes.saturating_add(u64::from(len));
        Ok(grant)
    }

    fn write_tcp_chunk(
        &mut self,
        token: BulkToken,
        chunk_seq: u32,
        offset: u64,
        payload: &[u8],
    ) -> Result<(), BulkError> {
        if token != self.token {
            return Err(BulkError::UnknownToken);
        }
        let grant = self
            .grants
            .get(&chunk_seq)
            .ok_or(BulkError::UnknownCredit { chunk_seq })?;
        if offset != grant.offset {
            return Err(BulkError::OffsetMismatch {
                expected: grant.offset,
                actual: offset,
            });
        }
        if payload.len() != grant.len as usize {
            return Err(BulkError::ChunkLengthMismatch {
                expected: grant.len,
                actual: payload.len() as u32,
            });
        }
        if !self.received_chunks.insert(chunk_seq) {
            return Err(BulkError::DuplicateChunk { chunk_seq });
        }
        let start = usize::try_from(offset).map_err(|_| BulkError::TransferOverflow)?;
        let end = start
            .checked_add(payload.len())
            .ok_or(BulkError::TransferOverflow)?;
        if end > self.buffer.len() {
            return Err(BulkError::TransferOverflow);
        }
        self.buffer[start..end].copy_from_slice(payload);
        self.received_bytes = self
            .received_bytes
            .checked_add(payload.len() as u64)
            .ok_or(BulkError::TransferOverflow)?;
        Ok(())
    }

    fn validate_done(&self, total_transferred: u64, checksum32: u32) -> Result<(), BulkError> {
        if total_transferred != self.offer.total_len {
            return Err(BulkError::LengthMismatch {
                expected: self.offer.total_len,
                actual: total_transferred,
            });
        }
        if self.received_bytes != self.offer.total_len {
            return Err(BulkError::IncompleteTransfer {
                expected: self.offer.total_len,
                actual: self.received_bytes,
            });
        }
        let actual = crc32c::crc32c(&self.buffer);
        if checksum32 != actual {
            return Err(BulkError::ChecksumMismatch {
                expected: actual,
                actual: checksum32,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GrantedChunk {
    offset: u64,
    len: u32,
}

/// Errors emitted by the BULK service state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BulkError {
    UnknownToken,
    NoCredits,
    ZeroLengthChunk,
    ChunkTooLarge { len: u32, max_chunk: u32 },
    TooManyPendingCredits { pending: usize, max_pending: u8 },
    InvalidChunkSequence { expected: u32, actual: u32 },
    UnknownCredit { chunk_seq: u32 },
    OffsetMismatch { expected: u64, actual: u64 },
    ChunkLengthMismatch { expected: u32, actual: u32 },
    DuplicateChunk { chunk_seq: u32 },
    LengthMismatch { expected: u64, actual: u64 },
    IncompleteTransfer { expected: u64, actual: u64 },
    ChecksumMismatch { expected: u32, actual: u32 },
    TransferOverflow,
}

impl fmt::Display for BulkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownToken => write!(f, "unknown connection-scoped BulkToken"),
            Self::NoCredits => write!(f, "BULK credit budget exhausted"),
            Self::ZeroLengthChunk => write!(f, "BULK credit chunk length must be non-zero"),
            Self::ChunkTooLarge { len, max_chunk } => {
                write!(f, "BULK chunk length {len} exceeds max_chunk {max_chunk}")
            }
            Self::TooManyPendingCredits {
                pending,
                max_pending,
            } => write!(
                f,
                "BULK stream has {pending} pending credits, max {max_pending}"
            ),
            Self::InvalidChunkSequence { expected, actual } => {
                write!(
                    f,
                    "BULK chunk sequence {actual} does not match expected {expected}"
                )
            }
            Self::UnknownCredit { chunk_seq } => {
                write!(f, "BULK data chunk {chunk_seq} has no granted credit")
            }
            Self::OffsetMismatch { expected, actual } => {
                write!(
                    f,
                    "BULK chunk offset {actual} does not match expected {expected}"
                )
            }
            Self::ChunkLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "BULK chunk length {actual} does not match granted {expected}"
                )
            }
            Self::DuplicateChunk { chunk_seq } => write!(f, "duplicate BULK chunk {chunk_seq}"),
            Self::LengthMismatch { expected, actual } => {
                write!(
                    f,
                    "BULK transfer length {actual} does not match expected {expected}"
                )
            }
            Self::IncompleteTransfer { expected, actual } => {
                write!(
                    f,
                    "BULK transfer received {actual} bytes, expected {expected}"
                )
            }
            Self::ChecksumMismatch { expected, actual } => {
                write!(
                    f,
                    "BULK CRC32C {actual:#010x} does not match expected {expected:#010x}"
                )
            }
            Self::TransferOverflow => write!(f, "BULK transfer arithmetic overflow"),
        }
    }
}

impl std::error::Error for BulkError {}

fn make_token(
    connection_id: ConnectionId,
    transfer_id: u64,
    nonce: u64,
    receiver_node_id: u64,
) -> BulkToken {
    let mut token = [0; 32];
    token[0..8].copy_from_slice(&connection_id.to_le_bytes());
    token[8..16].copy_from_slice(&transfer_id.to_le_bytes());
    token[16..24].copy_from_slice(&nonce.to_le_bytes());
    token[24..32].copy_from_slice(&receiver_node_id.to_le_bytes());
    token
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn offer(connection_id: ConnectionId, stream_id: StreamId, len: u64) -> BulkOffer {
        BulkOffer {
            connection_id,
            stream_id,
            total_len: len,
            mode: BulkMode::TcpStream,
            priority: BulkPriority::Bulk,
            metadata: BulkMetadata::vfs_rpc_write_upload(99),
        }
    }

    #[test]
    fn accepts_tcp_offer_with_connection_scoped_token() {
        let mut service = service();
        let accept = service.offer(offer(7, 11, 5));

        assert_eq!(accept.result, BulkAcceptResult::Accepted);
        assert_eq!(accept.stream_id, 11);
        assert_eq!(accept.max_chunk, 5);
        assert!(accept.token.is_some());
        assert_eq!(service.active_transfer_count(7), 1);
    }

    #[test]
    fn rejects_rdma_modes_without_evidence_or_byte_mover() {
        let mut service = service();
        let accept = service.offer(BulkOffer {
            mode: BulkMode::RdmaWrite,
            ..offer(7, 12, 5)
        });

        assert_eq!(accept.result, BulkAcceptResult::ModeUnsupported);
        assert_eq!(service.active_transfer_count(7), 0);
        assert!(!service.config().rdma_evidence.complete());
    }

    #[test]
    fn rejects_duplicate_stream_and_token_pressure() {
        let mut service = BulkService::new(BulkServiceConfig {
            max_inflight_tokens: 1,
            ..BulkServiceConfig::default()
        });

        assert_eq!(
            service.offer(offer(7, 1, 1)).result,
            BulkAcceptResult::Accepted
        );
        assert_eq!(
            service.offer(offer(7, 1, 1)).result,
            BulkAcceptResult::Rejected
        );
        assert_eq!(
            service.offer(offer(7, 2, 1)).result,
            BulkAcceptResult::NoCredits
        );
    }

    #[test]
    fn credit_data_and_done_complete_tcp_stream() {
        let mut service = service();
        let token = service.offer(offer(7, 11, 11)).token.unwrap();

        let first = service.credit(7, token, 0, 8).unwrap();
        let second = service.credit(7, token, 1, 3).unwrap();
        assert_eq!(first.offset, 0);
        assert_eq!(second.offset, 8);
        assert_eq!(service.pinned_bytes(7), 11);

        service
            .write_tcp_chunk(7, token, 1, second.offset, b"rld")
            .unwrap();
        service
            .write_tcp_chunk(7, token, 0, first.offset, b"hello wo")
            .unwrap();
        let bytes = b"hello world".to_vec();
        let completed = service
            .done(7, token, bytes.len() as u64, crc32c::crc32c(&bytes))
            .unwrap();

        assert_eq!(completed.bytes, bytes);
        assert_eq!(completed.metadata, BulkMetadata::vfs_rpc_write_upload(99));
        assert_eq!(service.active_transfer_count(7), 0);
        assert_eq!(service.pinned_bytes(7), 0);
        assert_eq!(
            service.done(7, token, 11, crc32c::crc32c(b"hello world")),
            Err(BulkError::UnknownToken)
        );
    }

    #[test]
    fn done_discards_failed_transfer_on_checksum_mismatch() {
        let mut service = service();
        let token = service.offer(offer(7, 11, 3)).token.unwrap();
        let grant = service.credit(7, token, 0, 3).unwrap();
        service
            .write_tcp_chunk(7, token, 0, grant.offset, b"bad")
            .unwrap();

        assert_eq!(
            service.done(7, token, 3, 0),
            Err(BulkError::ChecksumMismatch {
                expected: crc32c::crc32c(b"bad"),
                actual: 0,
            })
        );
        assert_eq!(service.active_transfer_count(7), 0);
        assert_eq!(service.pinned_bytes(7), 0);
    }

    #[test]
    fn abort_discards_bytes_and_retry_uses_fresh_token() {
        let mut service = service();
        let token = service.offer(offer(7, 11, 3)).token.unwrap();
        let grant = service.credit(7, token, 0, 3).unwrap();
        service
            .write_tcp_chunk(7, token, 0, grant.offset, b"old")
            .unwrap();

        let aborted = service.abort(7, token, BulkAbortReason::Timeout).unwrap();
        assert_eq!(aborted.reason, BulkAbortReason::Timeout);
        assert_eq!(service.pinned_bytes(7), 0);

        let retry = service.offer(offer(7, 11, 3)).token.unwrap();
        assert_ne!(token, retry);
    }

    #[test]
    fn connection_loss_aborts_all_active_transfers() {
        let mut service = service();
        let token_a = service.offer(offer(7, 1, 1)).token.unwrap();
        let token_b = service.offer(offer(7, 2, 1)).token.unwrap();
        service.credit(7, token_a, 0, 1).unwrap();
        service.credit(7, token_b, 0, 1).unwrap();

        let aborted = service.connection_lost(7);
        assert_eq!(aborted.len(), 2);
        assert!(aborted
            .iter()
            .all(|transfer| transfer.reason == BulkAbortReason::ConnectionLost));
        assert_eq!(service.active_transfer_count(7), 0);
        assert_eq!(service.pinned_bytes(7), 0);
    }

    #[test]
    fn pending_credit_window_is_bounded() {
        let mut service = service();
        let token = service.offer(offer(7, 11, 24)).token.unwrap();
        service.credit(7, token, 0, 8).unwrap();
        service.credit(7, token, 1, 8).unwrap();

        assert_eq!(
            service.credit(7, token, 2, 8),
            Err(BulkError::TooManyPendingCredits {
                pending: 2,
                max_pending: 2,
            })
        );
    }
}
