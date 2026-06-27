// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]
#![deny(dead_code)]
#![deny(unused_imports)]

//! Receive-stream chunk decoding with BLAKE3 verification and object reassembly.
//!
//! This crate completes the send/receive transport pair for multi-node
//! state transfer. It decodes wire-format chunk frames produced by
//! [`tidefs_send_stream::framer::ChunkFramer`], verifies BLAKE3-256
//! domain-separated authentication tags under the `TransferStream` domain,
//! reassembles ordered chunks into complete objects, and dispatches
//! received objects to local storage through the [`ReceiveDispatch`] trait.
//!
//! # Architecture
//!
//! ```text
//! Wire bytes --> ChunkDecoder --> FramedChunk (verified)
//!                                     |
//!                                     v
//!                               ObjectAssembler
//!                                     |
//!                                     v
//!                              ReceiveDispatch
//!                                     |
//!                                     v
//!                              Local storage
//! ```

pub mod assembler;
pub mod decoder;
pub mod dispatch;
pub mod receive_persistence;
pub mod session;

use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};

/// Schema family for receive-stream chunk framing (matches send-stream family 7).
pub const RECV_CHUNK_FAMILY: SchemaFamilyId = SchemaFamilyId(7);
/// Schema type for a framed data chunk within the receive-stream family.
pub const RECV_CHUNK_TYPE: SchemaTypeId = SchemaTypeId(1);
/// Schema version for receive-stream chunk framing v1.0.
pub const RECV_CHUNK_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

/// Domain tag for TransferStream BLAKE3 domain separation.
pub const TRANSFER_STREAM_DOMAIN: DomainTag = DomainTag::TransferStream;

/// Wire-format magic bytes for a TransferStream chunk frame ("VSCR" LE).
pub const CHUNK_MAGIC: u32 = 0x5653_4352;

/// Size of the fixed chunk wire header in bytes.
pub const CHUNK_HEADER_BYTES: usize = 64;

/// Size of the BLAKE3-256 auth tag in bytes.
pub const AUTH_TAG_BYTES: usize = 32;

/// Total frame overhead before payload (header + auth tag).
pub const CHUNK_FRAME_OVERHEAD: usize = CHUNK_HEADER_BYTES + AUTH_TAG_BYTES;

// Re-export core types for convenience.
pub use assembler::{AssemblerError, ObjectAssembler};
pub use decoder::{ChunkDecodeError, ChunkDecoder, FramedChunk};
pub use dispatch::{receive_object, NoOpDispatch, ReceiveDispatch};
pub use receive_persistence::{
    BaseRootPinLookup, ReceiveContract, ReceivePersistenceBridge, ReceivePersistenceError,
};
pub use session::{
    decode_receive_checkpoint, encode_receive_checkpoint, ExpectedSenderAuthority,
    InMemoryReceiveCheckpointStore, ReceiveCheckpointCodecError, ReceiveCheckpointStore,
    ReceiveCheckpointStoreError, ReceiveSession, ReceiveSessionError, ReceiveSessionKey,
    ReceiveSessionOutcome, ReceiverAdmission, ReceiverAuthorityView, ReceiverFeatureSupport,
    ReceiverRecoveryAction, ReceiverRefusal, ReceiverRefusalEvidence, ReceiverRefusalReason,
    StaticReceiverAuthorityView,
};
