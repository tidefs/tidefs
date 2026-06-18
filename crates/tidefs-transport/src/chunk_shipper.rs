// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeMap;

use crate::backend::TransportBackendKind;
use crate::error::{ChunkError, ChunkTransferError};
use crate::types::{ChunkId, ChunkTransferId, FenceVersion, Hash, HlcTimestamp, SessionId};

// ---------------------------------------------------------------------------
// ChunkShipper: immutable payload transport
// ---------------------------------------------------------------------------

/// The ChunkShipper moves immutable chunk payloads between nodes.
/// Unlike message transport (small, metadata-heavy), chunk shipping is
/// optimized for large byte payloads with:
/// - Progressive checksumming (chunk verified while in flight)
/// - Resume capability (partial transfer recovery)
/// - Pipelining (multiple chunks in flight on same session)
/// - Freshness fencing (refuse chunks peer already has at newer version)
pub struct ChunkShipper {
    /// Active chunk transfers indexed by transfer ID.
    pub active_transfers: BTreeMap<ChunkTransferId, ChunkTransfer>,

    /// The transport backend carrier for this shipper's session
    /// (Tcp, Tls, or Rdma). Set at construction and never changed.
    pub backend_kind: TransportBackendKind,

    /// Session id used for chunk shipping.
    pub session_id: SessionId,

    /// Maximum concurrent chunk transfers on this session.
    pub max_concurrent: usize,

    /// Maximum chunk size in bytes for shipping (default 64 MiB).
    pub max_chunk_size: u64,

    /// Next transfer ID counter.
    next_transfer_id: u64,
}

impl ChunkShipper {
    #[must_use]
    /// Create a new ChunkShipper for the given session and backend kind.
    pub fn new(session_id: SessionId, backend_kind: TransportBackendKind) -> Self {
        Self {
            active_transfers: BTreeMap::new(),
            backend_kind,
            session_id,
            max_concurrent: 8,
            max_chunk_size: 64 * 1024 * 1024, // 64MB default
            next_transfer_id: 1,
        }
    }

    /// Return the transport backend kind for this shipper's session.
    #[must_use]
    pub fn backend_kind(&self) -> TransportBackendKind {
        self.backend_kind
    }

    /// Whether the carrier is RDMA (not TCP fallback).
    #[must_use]
    pub fn is_rdma(&self) -> bool {
        self.backend_kind.is_rdma()
    }

    /// Queue a chunk for sending. Returns the transfer ID.
    pub fn send_chunk(
        &mut self,
        chunk_id: ChunkId,
        total_bytes: u64,
    ) -> Result<ChunkTransferId, ChunkError> {
        if self.active_transfers.len() >= self.max_concurrent {
            return Err(ChunkError::MaxConcurrentReached {
                max: self.max_concurrent,
                session_id: self.session_id,
            });
        }

        let transfer_id = ChunkTransferId::new(self.next_transfer_id);
        self.next_transfer_id += 1;

        let transfer = ChunkTransfer {
            transfer_id,
            chunk_id,
            direction: TransferDirection::Send,
            total_bytes,
            transferred_bytes: 0,
            checksum_state: ChecksumState::Idle,
            resume_offset: None,
            state: ChunkTransferState::Queued,
        };

        self.active_transfers.insert(transfer_id, transfer);
        Ok(transfer_id)
    }

    /// Accept an incoming chunk transfer (receive side).
    pub fn accept_chunk(
        &mut self,
        header: &ChunkTransferHeader,
    ) -> Result<ChunkTransferId, ChunkError> {
        if self.active_transfers.len() >= self.max_concurrent {
            return Err(ChunkError::MaxConcurrentReached {
                max: self.max_concurrent,
                session_id: self.session_id,
            });
        }

        let transfer_id = ChunkTransferId::new(self.next_transfer_id);
        self.next_transfer_id += 1;

        let transfer = ChunkTransfer {
            transfer_id,
            chunk_id: header.chunk_id,
            direction: TransferDirection::Receive,
            total_bytes: header.chunk_size,
            transferred_bytes: 0,
            checksum_state: ChecksumState::Idle,
            resume_offset: header.resume_from,
            state: ChunkTransferState::Transferring {
                started_at: HlcTimestamp::default(),
            },
        };

        self.active_transfers.insert(transfer_id, transfer);
        Ok(transfer_id)
    }

    /// Pause a transfer due to backpressure.
    pub fn pause(&mut self, transfer_id: ChunkTransferId) -> Result<(), ChunkError> {
        let transfer = self
            .active_transfers
            .get_mut(&transfer_id)
            .ok_or(ChunkError::TransferNotFound { transfer_id })?;

        if let ChunkTransferState::Transferring { .. } = &transfer.state {
            transfer.state = ChunkTransferState::Paused {
                at_offset: transfer.transferred_bytes,
            };
            Ok(())
        } else {
            Err(ChunkError::TransferInWrongState {
                transfer_id,
                state: "not_transferring",
            })
        }
    }

    /// Resume a paused transfer.
    pub fn resume(&mut self, transfer_id: ChunkTransferId) -> Result<(), ChunkError> {
        let transfer = self
            .active_transfers
            .get_mut(&transfer_id)
            .ok_or(ChunkError::TransferNotFound { transfer_id })?;

        match &transfer.state {
            ChunkTransferState::Paused { at_offset } => {
                transfer.resume_offset = Some(*at_offset);
                transfer.state = ChunkTransferState::Transferring {
                    started_at: HlcTimestamp::default(),
                };
                Ok(())
            }
            _ => Err(ChunkError::TransferInWrongState {
                transfer_id,
                state: "not_paused",
            }),
        }
    }

    /// Mark a transfer as complete with the verified checksum.
    pub fn complete(
        &mut self,
        transfer_id: ChunkTransferId,
        checksum: Hash,
    ) -> Result<(), ChunkError> {
        let transfer = self
            .active_transfers
            .get_mut(&transfer_id)
            .ok_or(ChunkError::TransferNotFound { transfer_id })?;

        transfer.state = ChunkTransferState::Complete { checksum };
        Ok(())
    }

    /// Mark a transfer as failed.
    pub fn fail(
        &mut self,
        transfer_id: ChunkTransferId,
        error: ChunkTransferError,
    ) -> Result<(), ChunkError> {
        let transfer = self
            .active_transfers
            .get_mut(&transfer_id)
            .ok_or(ChunkError::TransferNotFound { transfer_id })?;

        let at_offset = transfer.transferred_bytes;
        transfer.state = ChunkTransferState::Failed { error, at_offset };
        Ok(())
    }

    /// Remove a completed or failed transfer from the active set.
    pub fn remove(&mut self, transfer_id: ChunkTransferId) -> Option<ChunkTransfer> {
        self.active_transfers.remove(&transfer_id)
    }

    /// Get a reference to a transfer.
    #[must_use]
    pub fn get(&self, transfer_id: ChunkTransferId) -> Option<&ChunkTransfer> {
        self.active_transfers.get(&transfer_id)
    }
}

impl std::fmt::Debug for ChunkShipper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkShipper")
            .field("session_id", &self.session_id)
            .field("active", &self.active_transfers.len())
            .field("backend_kind", &self.backend_kind)
            .field("max_concurrent", &self.max_concurrent)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ChunkTransfer: single chunk movement
// ---------------------------------------------------------------------------

#[derive(Debug)]
/// Represents an in-flight chunk transfer between two nodes.
pub struct ChunkTransfer {
    /// Locally-unique identifier for this transfer.
    pub transfer_id: ChunkTransferId,
    /// Content-addressable identifier for the chunk being transferred.
    pub chunk_id: ChunkId,
    /// Whether this node is sending or receiving the chunk.
    pub direction: TransferDirection,
    /// Total bytes to transfer.
    pub total_bytes: u64,
    /// Bytes transferred so far.
    pub transferred_bytes: u64,
    /// Checksum state (progressive).
    pub checksum_state: ChecksumState,
    /// For resume: offset to resume from.
    pub resume_offset: Option<u64>,
    /// Transfer state machine.
    pub state: ChunkTransferState,
}

// ---------------------------------------------------------------------------
// Transfer direction
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Direction of a chunk transfer.
pub enum TransferDirection {
    /// This node is the sender; it pushes data to the peer.
    Send,
    /// This node is the receiver; it accepts data from the peer.
    Receive,
}

// ---------------------------------------------------------------------------
// ChunkTransferState
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
/// State of an in-flight chunk transfer.
pub enum ChunkTransferState {
    /// Transfer queued, not started
    Queued,
    /// Header sent, awaiting acceptance
    AwaitingAccept,
    /// Data in flight
    Transferring { started_at: HlcTimestamp },
    /// Transfer paused (backpressure)
    Paused { at_offset: u64 },
    /// Transfer complete, checksum verified
    Complete { checksum: Hash },
    /// Transfer failed
    Failed {
        error: ChunkTransferError,
        at_offset: u64,
    },
}

// ---------------------------------------------------------------------------
// Progressive checksum state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
/// Progressive checksum computation state for chunk transfers.
pub enum ChecksumState {
    /// No checksum computation has started.
    #[default]
    Idle,
    /// Checksum is being computed; `bytes_hashed` bytes have been processed.
    Computing {
        /// Number of bytes hashed so far.
        bytes_hashed: u64,
    },
    /// Checksum is complete with the final digest.
    Complete {
        /// The computed SHA-256 digest of the chunk data.
        digest: Hash,
    },
}

// ---------------------------------------------------------------------------
// ChunkTransferHeader
// ---------------------------------------------------------------------------

/// Sent before chunk data: peer decides accept/refuse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkTransferHeader {
    pub chunk_id: ChunkId,
    pub chunk_size: u64,
    pub chunk_digest: Hash,
    pub segment_count: u32,
    pub transfer_id: ChunkTransferId,
    /// For resume: "I already have up to this offset"
    pub resume_from: Option<u64>,
    /// Freshness fence: refuse if you already have version >= this
    pub freshness_fence: FenceVersion,
}

impl ChunkTransferHeader {
    #[must_use]
    /// Create a new ChunkTransferHeader with a fresh transfer ID.
    pub fn new(
        chunk_id: ChunkId,
        chunk_size: u64,
        chunk_digest: Hash,
        transfer_id: ChunkTransferId,
        freshness_fence: FenceVersion,
    ) -> Self {
        Self {
            chunk_id,
            chunk_size,
            chunk_digest,
            segment_count: 1,
            transfer_id,
            resume_from: None,
            freshness_fence,
        }
    }

    #[must_use]
    /// Set the resume offset for partial transfer recovery.
    pub fn with_resume(mut self, offset: u64) -> Self {
        self.resume_from = Some(offset);
        self
    }
}

// ---------------------------------------------------------------------------
// RefuseReason
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
/// Reason a chunk transfer was refused by the peer.
pub enum RefuseReason {
    AlreadyHave { version: FenceVersion },
    NoSpace { available: u64, needed: u64 },
    SessionClosing,
    FenceViolated,
}

impl std::fmt::Display for RefuseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyHave { version } => write!(f, "already_have(v{})", version.0),
            Self::NoSpace { available, needed } => {
                write!(f, "no_space(avail={available}, need={needed})")
            }
            Self::SessionClosing => write!(f, "session_closing"),
            Self::FenceViolated => write!(f, "fence_violated"),
        }
    }
}
