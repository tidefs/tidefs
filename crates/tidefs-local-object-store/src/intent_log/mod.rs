// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Object-store-level write-ahead log: records object mutations before
//! they are applied to the main object store.
//!
//! # Authority boundary
//!
//! This module implements the **object-store write-ahead log** — a
//! low-level durability mechanism that records raw object mutations
//! (`WritePayload`) with transaction boundaries
//! (`TxBegin`/`TxCommit`/`TxAbort`) and an `ExportTerminal` clean-shutdown
//! marker.
//!
//! It is distinct from [`tidefs_intent_log`], which defines the
//! **canonical filesystem-level intent-record family**:
//!
//! | Property          | `tidefs-intent-log`                   | `tidefs-local-object-store::intent_log` |
//! |-------------------|---------------------------------------|----------------------------------------|
//! | Authority         | Filesystem mutations (VFS ops)        | Object-store mutations (raw payloads)   |
//! | Persistence root  | Commit-group segment files            | Per-pool intent-log segment files       |
//! | Replay owner      | CommitGroupRecovery / IntentLogReader | store.rs / segment_replay.rs            |
//! | Validation gate     | Mounted FUSE/POSIX crash replay       | Object-store integrity verification     |
//! | Record family     | `tidefs_intent_log::IntentLogRecord`  | `crate::intent_log::record::IntentLogRecord` |
//!
//! This module **must not accept, record, or silently skip filesystem-level
//! records** (Create, Unlink, Rename, Mkdir, Rmdir, Fsync, SetAttr,
//! XattrSet, XattrRemove). Filesystem consumers must use
//! [`tidefs_intent_log::IntentLogRecord`] (re-exported by
//! [`tidefs_commit_group`]) and [`tidefs_intent_log::IntentLogBuffer`].
//!
//!
//! **Nonclaim boundary**: validation produced through this module (segment
//! replay, integrity verification) must not close mounted filesystem
//! crash-replay gates.  Filesystem crash replay is owned by
//! `tidefs_intent_log` / `tidefs_commit_group`.  The
//! `decode_rejects_filesystem_discriminants` test in [`record`]
//! enforces the discriminant-level boundary; domain-separated BLAKE3
//! checksums in both record families provide a second integrity gate.
//! # Modules
//!
//! - [`record`]: The object-store `IntentLogRecord` enum with binary
//!   encode/decode and BLAKE3-256 per-record checksums. Contains only
//!   object-store mutation variants: `WritePayload`, `TxBegin`, `TxCommit`,
//!   `TxAbort`, `ExportTerminal`.
//! - [`buffer`]: The `InMemoryIntentLog` ring buffer with transaction
//!   boundary tracking and commit-region flush.
//! - [`sync_write`]: The `IntentLog` wrapper struct with sync-write fast
//!   path that bypasses the ring buffer for durability-critical writes,
//!   writing directly to a segment with a BLAKE3 commit marker and an
//!   `IntegrityTrailerV2` footer.
//! - [`framing`]: Binary-schema envelope framing for intent-log segments,
//!   using [`tidefs_binary_schema_framing`] for on-disk and wire transport.
//! - [`serialization`]: Conversion between object-store intent records
//!   and transaction mutation types.
//! - [`segment_replay`]: Segment-level discovery and ordered replay of
//!   intent-log segments at pool open time.

pub mod buffer;
pub mod framing;
pub mod record;
pub mod segment_replay;
pub mod serialization;
pub mod sync_write;
