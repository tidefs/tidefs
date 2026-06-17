#![deny(dead_code)]
#![deny(unused_imports)]
#![cfg_attr(all(feature = "kernel-storage", not(feature = "std")), no_std)]

//! TideFS Transaction Group (commit_group) Subsystem
//!
//! # Overview
//!
//! `tidefs-commit_group` is the central write-path funnel: it accumulates dirty pages
//! and metadata mutations into ordered transaction groups, commits them
//! atomically to the object store via [`CommitGroupCommit`], and provides
//! `fsync`/`fdatasync`/`syncfs` durability through [`CommitGroupSync`].
//!
//! # Architecture
//!
//! ```text
//! write() / setattr() / link() / unlink()
//!         │
//!         ▼
//!   DirtyTracker ──► CommitGroupAccumulator (open commit_group)
//!         │                    │
//!         │              CommitGroupCommit::commit()
//!         │                    │
//!         │         ┌─────────┼──────────┐
//!         │         ▼         ▼          ▼
//!         │   ObjectStore  ExtentMap  InodeTable
//!         │         │         │          │
//!         │         └─────────┼──────────┘
//!         │                   ▼
//!         │            Journal Record
//!         │                   │
//!         ▼                   ▼
//!   CommitGroupSync::fsync()    Durable (fsync complete)
//! ```
//!
//! # Key Types
//!
//! - [`CommitGroupId`] — monotonically increasing transaction group identifier.
//! - [`DirtyTracker`] — per-inode dirty page bitmaps and metadata flags.
//! - [`CommitGroupAccumulator`] — collects writes, setattrs, links, and unlinks for
//!   one open commit_group.
//! - [`CommitGroupCommit`] — orchestrates the atomic commit of an accumulator.
//! - [`CommitGroupSync`] — `fsync`/`syncfs` entry points that block until the
//!   requested commit_group is durable.
//! - [`CommitGroupRecovery`] — mount-time replay of the commit_group journal.
//! - [`CommitGroupStore`] — trait abstracting named blob storage (implemented by
//!   `tidefs-local-object-store`).

#![allow(clippy::nonminimal_bool)]
#![allow(clippy::needless_range_loop)]
#![forbid(unsafe_code)]

#[cfg(any(feature = "kernel-storage", not(feature = "std")))]
extern crate alloc;

#[cfg(feature = "std")]
mod accumulator;
#[cfg(feature = "std")]
mod commit;
#[cfg(feature = "std")]
mod coordinator;
#[cfg(feature = "std")]
mod dirty;
#[cfg(feature = "std")]
mod epoch;
#[cfg(feature = "kernel-storage")]
pub mod kernel_storage;
#[cfg(feature = "std")]
mod pipeline;
#[cfg(feature = "std")]
pub mod reader;
#[cfg(feature = "std")]
mod recovery;
#[cfg(feature = "std")]
pub mod state_machine;
#[cfg(feature = "std")]
pub mod store;
#[cfg(feature = "std")]
pub mod superblock_secondary;
#[cfg(feature = "std")]
mod sync;
#[cfg(feature = "std")]
pub mod txg;
#[cfg(feature = "kernel-storage")]
pub mod txg_sequence;
pub mod types;
mod writer;

// Re-export public types at the crate root.
#[cfg(feature = "std")]
pub use accumulator::{
    CommitGroupAccumulator, QueuedLink, QueuedSetattr, QueuedUnlink, QueuedWrite,
};
#[cfg(feature = "std")]
pub use commit::{
    CommitGroupCommit, InodeTableCommit, NamespaceCommit, NoopInodeTable, NoopNamespace,
};
#[cfg(feature = "std")]
pub use coordinator::CommitGroupCoordinator;
#[cfg(feature = "std")]
pub use dirty::DirtyTracker;
#[cfg(feature = "std")]
pub use epoch::{
    seal_commit_hash, verify_commit_record, CommitGroupEpoch, CommitGroupStateMachine,
    CommitRecord, EpochState,
};
#[cfg(feature = "kernel-storage")]
pub use kernel_storage::{
    read_committed_root_block, read_committed_root_pointer, read_current_committed_root,
    seal_and_write_committed_root_block, write_committed_root_pointer,
    write_current_committed_root, CommittedRootCommit, CommittedRootPointer,
    KernelCommittedRootFlush, KernelCommittedRootWrite,
};
#[cfg(feature = "std")]
pub use pipeline::{CommitGroup, CommitGroupBuilder};
#[cfg(feature = "std")]
pub use reader::CommitGroupReader;
#[cfg(feature = "std")]
pub use recovery::{CommitGroupRecovery, RecoveryResult};
#[cfg(feature = "std")]
pub use state_machine::{
    compute_chain_digest, determine_replay_txgs, GroupCommitState, GroupCommitStateMachine,
    TxgHandle,
};
#[cfg(feature = "std")]
pub use store::{CommitGroupKey, CommitGroupStore};
#[cfg(feature = "std")]
pub use superblock_secondary::{
    read_superblock_with_fallback, write_superblock_secondary, SuperblockReadError,
    SuperblockSecondaryHeader,
};
#[cfg(feature = "std")]
pub use sync::{CommitGroupSync, SyncGate};
#[cfg(feature = "std")]
pub use tidefs_intent_log::{IntentLogBuffer, IntentLogFrame, IntentLogRecord, XattrNamespace};
#[cfg(feature = "std")]
pub use txg::{TxGroupHandle, TxGroupLifecycle, TxGroupState, TX_GROUP_STATE_MAGIC};
#[cfg(feature = "kernel-storage")]
pub use txg_sequence::{TxgSequenceCounter, TxgSequenceError};
pub use types::{
    CommitGroupEpochFence, CommitGroupError, CommitGroupId, CommitGroupPhase, CommitGroupState,
    DirtyMetaFlags, DirtyRange, RootPointer,
};
pub use writer::{CommitGroupWriter, CommittedRootBlock};
