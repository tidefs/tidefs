#![forbid(unsafe_code)]

//! CleanupEngine: BLAKE3-verified deferred cleanup execution engine.
//!
//! The cleanup engine iterates the persistent B+tree-backed cleanup
//! queue, dispatches deferred unlink, rmdir, and extent-free operations
//! to per-kind job executors, and records progress via BLAKE3-verified
//! sealed-blob checkpointing for crash-safe resume.
//!
//! ## Module overview
//!
//! - [`engine`] — `CleanupEngine` struct: `run_cycle()`, `run_to_completion()`,
//!   `run_with_deadline()`, and progress persistence.
//! - [`job_executor`] — `JobExecutor` trait and concrete per-kind
//!   executors (`DeferredUnlinkExecutor`, `DeferredRmdirExecutor`,
//!   `DeferredFreeExtentExecutor`, `CompositeJobExecutor`).
//! - [`progress`] — `CleanupProgress` with BLAKE3-verified sealed-blob
//!   format `[hash:32][entry_id:8]` for crash-safe resume.
//! - [`receipts`] — per-entry replay decision receipts for engine-local
//!   execute/skip/defer/reject evidence.
//!
//! ## Crash-safety contract
//!
//! The engine does not write to the intent log directly. The caller is
//! responsible for persisting the progress blob (via [`CleanupEngine::seal_progress`])
//! alongside a TXG commit. On crash, resume from the last persisted blob;
//! all items up to the recorded `last_processed_entry_id` are safely
//! skipped.

pub mod engine;
pub mod job_executor;
pub mod orphan;
pub mod progress;
pub mod receipts;
pub mod reclaim;

pub use engine::{CleanupEngine, EngineStats};
pub use job_executor::{
    CompositeJobExecutor, DeferredFreeExtentExecutor, DeferredRmdirExecutor,
    DeferredUnlinkExecutor, DirAccess, ExtentMapAccess, JobExecutor, LinkCountAccess,
    OrphanIndexAccess, SpaceAccess,
};
pub use progress::{CleanupProgress, ProgressError, SEALED_BLOB_SIZE};
pub use receipts::{
    CleanupReplayDecision, CleanupReplayDecisionReceipt, CleanupReplayReceiptError,
    CleanupReplayRequiredEvidence, CleanupReplayValidationTier, CLEANUP_REPLAY_ARTIFACT_DIGEST_LEN,
};
