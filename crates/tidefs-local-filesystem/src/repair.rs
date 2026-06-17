//! Corruption resolver and repair outcome recording (PC-019B.3).
//!
//! The resolver consumes scrub violations and produces repair strategies
//! based on available redundancy surface, block type, and corruption
//! severity. Repair outcomes are recorded in a `RepairLog` for audit
//! and recovery.

use crate::scrub::{RepairStrategy, ScrubBlockId, ScrubBlockKind, ScrubReport, ScrubViolation};
use crate::types::InodeRecord;
use std::sync::Arc;

// ── Repair outcome recording ──────────────────────────────────────────

/// Outcome of applying a single repair action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairEntry {
    pub block_id: ScrubBlockId,
    pub strategy: RepairStrategy,
    pub outcome: RepairOutcome,
}

/// What happened after repair was applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepairOutcome {
    /// File truncated to the given byte size.
    Truncated { new_size: u64 },
    /// Block marked as corrupt; reads will return I/O errors.
    MarkedCorrupt,
    /// Reconstructed from erasure-coding parity and durably written back to the object store.
    Reconstructed { bytes_written: usize },
    /// Repair was not possible; no action taken.
    Skipped,
}

/// Log of repairs applied during a resolver pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RepairLog {
    pub entries: Vec<RepairEntry>,
}

impl RepairLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn record(&mut self, entry: RepairEntry) {
        self.entries.push(entry);
    }
}

// ── Resolver ──────────────────────────────────────────────────────────

/// Context available to the resolver for making repair decisions.
#[derive(Clone, Copy, Debug, Default)]
pub struct ResolverContext {
    /// Whether redundancy/replication is available for reconstruction.
    pub redundancy_available: bool,
}

/// Resolve a single scrub violation into a repair strategy.
///
/// Strategy selection logic:
/// - If `redundancy_available` → `Reconstruct`
/// - If the corrupt block is a content chunk after the first one →
///   `Truncate` (preserve known-good data)
/// - Otherwise → `MarkCorrupt`
pub fn resolve_violation(violation: &ScrubViolation, ctx: ResolverContext) -> RepairStrategy {
    if ctx.redundancy_available {
        return RepairStrategy::Reconstruct;
    }

    match &violation.block_id.kind {
        ScrubBlockKind::ContentChunk { chunk_index } if *chunk_index > 0 => {
            RepairStrategy::Truncate
        }
        ScrubBlockKind::ContentChunk { .. } => RepairStrategy::MarkCorrupt,
        ScrubBlockKind::InlineContent | ScrubBlockKind::ContentManifest => {
            RepairStrategy::MarkCorrupt
        }
    }
}

/// Compute the byte offset at which a file should be truncated to
/// remove a corrupt chunk and all chunks after it.
///
/// Returns `None` if the corrupt chunk is at index 0 (nothing to keep).
pub fn truncate_offset_for_chunk(
    _inode: &InodeRecord,
    corrupt_chunk_index: u64,
    known_chunk_sizes: &[u32],
) -> Option<u64> {
    if corrupt_chunk_index == 0 {
        return None;
    }
    let idx = corrupt_chunk_index as usize;
    if idx > known_chunk_sizes.len() {
        return None;
    }
    let offset: u64 = known_chunk_sizes[..idx].iter().map(|&s| s as u64).sum();
    Some(offset)
}

/// Resolve all violations from a scrub report into a repair log.
///
/// Each violation is analyzed and a repair entry is recorded with
/// `RepairOutcome::Skipped`. The caller must apply repairs via
/// `apply_repair_entries()` to produce actual outcomes.
#[allow(dead_code)]
pub fn resolve_all(report: &ScrubReport, ctx: ResolverContext) -> RepairLog {
    let mut log = RepairLog::new();

    for violation in &report.violations {
        let strategy = resolve_violation(violation, ctx);
        log.record(RepairEntry {
            block_id: violation.block_id.clone(),
            strategy,
            outcome: RepairOutcome::Skipped,
        });
    }

    log
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scrub::{ScrubBlockId, ScrubBlockKind, ScrubBlockOutcome, ScrubViolation};
    use crate::types::InodeRecord;
    use tidefs_local_object_store::IntegrityDigest64;
    use tidefs_types_vfs_core::{Generation, InodeId, NodeKind};

    fn make_violation_with_kind(kind: ScrubBlockKind) -> ScrubViolation {
        ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 42,
                data_version: 3,
                kind,
            },
            key_hex: "deadbeef00000000".into(),
            outcome: ScrubBlockOutcome::Corrupt {
                expected: IntegrityDigest64(0xAAAA),
                actual: IntegrityDigest64(0xBBBB),
            },
        }
    }

    fn make_inode(size: u64) -> InodeRecord {
        InodeRecord {
            rdev: 0,
            inode_id: InodeId::new(42),
            generation: Generation(1),
            facets: NodeKind::File.to_facets(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            nlink: 1,
            size,
            data_version: 3,
            metadata_version: 3,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattrs: Default::default(),
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
        }
    }

    // ── Resolver strategy tests ──────────────────────────────────────

    #[test]
    fn chunk0_corrupt_returns_mark_corrupt() {
        let v = make_violation_with_kind(ScrubBlockKind::ContentChunk { chunk_index: 0 });
        let ctx = ResolverContext::default();
        assert_eq!(resolve_violation(&v, ctx), RepairStrategy::MarkCorrupt);
    }

    #[test]
    fn chunk_nonzero_corrupt_returns_truncate() {
        let v = make_violation_with_kind(ScrubBlockKind::ContentChunk { chunk_index: 3 });
        let ctx = ResolverContext::default();
        assert_eq!(resolve_violation(&v, ctx), RepairStrategy::Truncate);
    }

    #[test]
    fn inline_content_corrupt_returns_mark_corrupt() {
        let v = make_violation_with_kind(ScrubBlockKind::InlineContent);
        let ctx = ResolverContext::default();
        assert_eq!(resolve_violation(&v, ctx), RepairStrategy::MarkCorrupt);
    }

    #[test]
    fn manifest_corrupt_returns_mark_corrupt() {
        let v = make_violation_with_kind(ScrubBlockKind::ContentManifest);
        let ctx = ResolverContext::default();
        assert_eq!(resolve_violation(&v, ctx), RepairStrategy::MarkCorrupt);
    }

    #[test]
    fn redundancy_available_returns_reconstruct() {
        let v = make_violation_with_kind(ScrubBlockKind::ContentChunk { chunk_index: 5 });
        let ctx = ResolverContext {
            redundancy_available: true,
        };
        assert_eq!(resolve_violation(&v, ctx), RepairStrategy::Reconstruct);
    }

    #[test]
    fn redundancy_overrides_even_for_inline() {
        let v = make_violation_with_kind(ScrubBlockKind::InlineContent);
        let ctx = ResolverContext {
            redundancy_available: true,
        };
        assert_eq!(resolve_violation(&v, ctx), RepairStrategy::Reconstruct);
    }

    // ── Truncate offset tests ────────────────────────────────────────

    #[test]
    fn truncate_offset_chunk_0_returns_none() {
        let inode = make_inode(100);
        assert_eq!(truncate_offset_for_chunk(&inode, 0, &[50, 50]), None);
    }

    #[test]
    fn truncate_offset_chunk_1_sums_preceding() {
        let inode = make_inode(100);
        let sizes = vec![50u32, 50];
        assert_eq!(truncate_offset_for_chunk(&inode, 1, &sizes), Some(50));
    }

    #[test]
    fn truncate_offset_chunk_2_sums_two_preceding() {
        let inode = make_inode(300);
        let sizes = vec![100u32, 100, 100];
        assert_eq!(truncate_offset_for_chunk(&inode, 2, &sizes), Some(200));
    }

    #[test]
    fn truncate_offset_index_beyond_sizes_returns_none() {
        let inode = make_inode(200);
        assert_eq!(truncate_offset_for_chunk(&inode, 5, &[100, 100]), None);
    }

    // ── Repair log tests ─────────────────────────────────────────────

    #[test]
    fn repair_log_new_is_empty() {
        let log = RepairLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn repair_log_records_entries() {
        let mut log = RepairLog::new();
        let v = make_violation_with_kind(ScrubBlockKind::ContentChunk { chunk_index: 0 });
        log.record(RepairEntry {
            block_id: v.block_id.clone(),
            strategy: RepairStrategy::MarkCorrupt,
            outcome: RepairOutcome::Skipped,
        });
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn resolve_all_produces_one_entry_per_violation() {
        let v = make_violation_with_kind(ScrubBlockKind::ContentChunk { chunk_index: 2 });
        let mut report = crate::scrub::ScrubReport::empty();
        report.violations.push(v.clone());
        report.violations.push(v);
        let ctx = ResolverContext::default();
        let log = resolve_all(&report, ctx);
        assert_eq!(log.len(), 2);
    }
}

// ── Repair application ────────────────────────────────────────────────

use std::collections::BTreeMap;
use tidefs_local_object_store::LocalObjectStore;
use tidefs_types_vfs_core::InodeId;

use crate::content::read_content_layout_from_store;
use crate::records::ContentLayout;
use crate::FileSystemState;

/// Apply repair entries to the filesystem state and object store.
///
/// Returns a new `RepairLog` with actual outcomes recorded.
#[allow(dead_code)]
pub fn apply_repair_entries(
    log: &RepairLog,
    state: &mut FileSystemState,
    store: &mut LocalObjectStore,
    content_layout_cache: &mut BTreeMap<InodeId, ContentLayout>,
) -> RepairLog {
    let mut applied = RepairLog::new();

    for entry in &log.entries {
        let outcome = apply_one_repair(entry, state, store, content_layout_cache);
        applied.record(RepairEntry {
            block_id: entry.block_id.clone(),
            strategy: entry.strategy,
            outcome,
        });
    }

    applied
}

pub(crate) fn apply_one_repair(
    entry: &RepairEntry,
    state: &mut FileSystemState,
    store: &mut LocalObjectStore,
    content_layout_cache: &mut BTreeMap<InodeId, ContentLayout>,
) -> RepairOutcome {
    let inode_id = InodeId::new(entry.block_id.inode_id);

    match entry.strategy {
        crate::scrub::RepairStrategy::Reconstruct => {
            apply_reconstruct(inode_id, entry.block_id.data_version, state, store)
        }
        crate::scrub::RepairStrategy::Truncate => {
            apply_truncate(inode_id, entry, state, store, content_layout_cache)
        }
        crate::scrub::RepairStrategy::MarkCorrupt => {
            state.corrupted_inodes.insert(inode_id);
            RepairOutcome::MarkedCorrupt
        }
    }
}

fn apply_truncate(
    inode_id: InodeId,
    entry: &RepairEntry,
    state: &mut FileSystemState,
    store: &mut LocalObjectStore,
    content_layout_cache: &mut BTreeMap<InodeId, ContentLayout>,
) -> RepairOutcome {
    let corrupt_index = match &entry.block_id.kind {
        crate::scrub::ScrubBlockKind::ContentChunk { chunk_index } => *chunk_index,
        _ => return RepairOutcome::Skipped,
    };

    // Clone inode to release state borrow before I/O
    let inode = match state.inodes.get(&inode_id).cloned() {
        Some(i) => i,
        None => return RepairOutcome::Skipped,
    };

    // Read content layout from store
    let layout = match read_content_layout_from_store(store, inode_id, &inode, true) {
        Ok(layout) => {
            content_layout_cache.insert(inode_id, layout.clone());
            layout
        }
        Err(_) => return RepairOutcome::Skipped,
    };

    let chunk_sizes: Vec<u32> = match &layout {
        ContentLayout::Chunked(manifest) => manifest.chunks.iter().map(|c| c.len).collect(),
        _ => return RepairOutcome::Skipped,
    };

    if let Some(truncate_offset) =
        crate::repair::truncate_offset_for_chunk(&inode, corrupt_index, &chunk_sizes)
    {
        {
            let inodes = Arc::make_mut(&mut state.inodes);
            if let Some(inode_record) = inodes.get_mut(&inode_id) {
                inode_record.size = truncate_offset;
            }
        }
        state.dirty_inodes.insert(inode_id);
        state.dirty_content.insert(inode_id);
        RepairOutcome::Truncated {
            new_size: truncate_offset,
        }
    } else {
        // Chunk 0 corrupt — nothing to preserve
        RepairOutcome::Skipped
    }
}

/// Attempt to reconstruct a corrupt content object from erasure coding parity.
///
/// Reads the stored content object and checks for an erasure-coding header
/// (9-byte prefix: stripe_width u16 LE, data_shards u16 LE, parity_count u8,
/// shard_len u32 LE). If found, collects surviving shards and calls the
/// erasure coding engine's `reconstruct()` to rebuild the payload.
///
/// Returns `Skipped` when the content was never erasure-encoded.
fn apply_reconstruct(
    inode_id: InodeId,
    data_version: u64,
    state: &mut FileSystemState,
    store: &mut LocalObjectStore,
) -> RepairOutcome {
    let content_key = crate::object_keys::content_object_key_for_version(inode_id, data_version);
    let raw = match store.get(content_key) {
        Ok(Some(bytes)) => bytes,
        _ => return RepairOutcome::Skipped,
    };

    // Minimum erasure-coding header is 9 bytes:
    // [stripe_width: u16 LE][data_shards: u16 LE][parity_shards: u8][shard_len: u32 LE]
    if raw.len() < 9 {
        return RepairOutcome::Skipped;
    }

    let stripe_width = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let data_shards = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    let parity_count_raw = raw[4];
    let shard_len = u32::from_le_bytes([raw[5], raw[6], raw[7], raw[8]]) as usize;

    if parity_count_raw == 0 || data_shards == 0 || shard_len == 0 {
        return RepairOutcome::Skipped;
    }
    if stripe_width != data_shards + parity_count_raw as usize {
        return RepairOutcome::Skipped;
    }

    let parity_count = match parity_count_raw {
        1 => 1,
        2 => 2,
        3 => 3,
        _ => return RepairOutcome::Skipped,
    };

    let config = tidefs_erasure_coding::StripeConfig {
        data_shards,
        parity_shards: parity_count,
        shard_len,
    };

    let header_size = 9;
    let total_shards = stripe_width;
    let available_shards: Vec<Option<tidefs_erasure_coding::ErasureShard>> = (0..total_shards)
        .map(|idx| {
            let offset = header_size + idx * shard_len;
            if offset + shard_len > raw.len() {
                return None;
            }
            let kind = if idx < data_shards {
                tidefs_erasure_coding::ShardKind::Data
            } else {
                tidefs_erasure_coding::ShardKind::Parity
            };
            Some(tidefs_erasure_coding::ErasureShard {
                index: idx,
                kind,
                bytes: raw[offset..offset + shard_len].to_vec(),
            })
        })
        .collect();

    match tidefs_erasure_coding::reconstruct(&config, &available_shards, None) {
        Some(reconstruction) => {
            // Write reconstructed payload back to the object store so the
            // repair is durable. A subsequent commit will publish it.
            match store.put(content_key, &reconstruction.payload) {
                Ok(_stored) => {
                    state.dirty_content.insert(inode_id);
                    RepairOutcome::Reconstructed {
                        bytes_written: reconstruction.payload.len(),
                    }
                }
                Err(_) => RepairOutcome::Skipped,
            }
        }
        None => RepairOutcome::Skipped,
    }
}

#[cfg(test)]
mod apply_tests {
    use super::*;
    use crate::scrub::{
        RepairStrategy, ScrubBlockId, ScrubBlockKind, ScrubBlockOutcome, ScrubViolation,
    };

    fn make_violation(chunk_index: u64) -> (ScrubViolation, InodeId) {
        let inode_id = 100;
        (
            ScrubViolation {
                block_id: ScrubBlockId {
                    inode_id,
                    data_version: 1,
                    kind: ScrubBlockKind::ContentChunk { chunk_index },
                },
                key_hex: "deadbeef".into(),
                outcome: ScrubBlockOutcome::Corrupt {
                    expected: tidefs_local_object_store::IntegrityDigest64(0xAAAA),
                    actual: tidefs_local_object_store::IntegrityDigest64(0xBBBB),
                },
            },
            InodeId::new(inode_id),
        )
    }

    #[test]
    fn mark_corrupt_adds_to_corrupted_inodes() {
        let (v, _inode_id) = make_violation(0);
        let entry = RepairEntry {
            block_id: v.block_id,
            strategy: RepairStrategy::MarkCorrupt,
            outcome: RepairOutcome::Skipped,
        };

        let mut state = crate::recovery::initial_state();
        let outcome = apply_one_repair(
            &entry,
            &mut state,
            &mut unreachable_store(),
            &mut BTreeMap::new(),
        );

        assert_eq!(outcome, RepairOutcome::MarkedCorrupt);
        assert!(state.corrupted_inodes.contains(&InodeId::new(100)));
    }

    #[test]
    fn truncate_unknown_inode_returns_skipped() {
        let (v, _) = make_violation(1);
        let entry = RepairEntry {
            block_id: v.block_id,
            strategy: RepairStrategy::Truncate,
            outcome: RepairOutcome::Skipped,
        };

        let mut state = crate::recovery::initial_state();
        let outcome = apply_one_repair(
            &entry,
            &mut state,
            &mut unreachable_store(),
            &mut BTreeMap::new(),
        );

        assert_eq!(outcome, RepairOutcome::Skipped);
    }

    #[test]
    fn reconstruct_on_non_ec_object_returns_skipped() {
        let (v, _) = make_violation(3);
        let entry = RepairEntry {
            block_id: v.block_id.clone(),
            strategy: RepairStrategy::Reconstruct,
            outcome: RepairOutcome::Skipped,
        };

        let mut state = crate::recovery::initial_state();
        let mut store = unreachable_store();
        // Store plain (non-erasure-coded) content for the inode
        let content_key = crate::object_keys::content_object_key_for_version(
            InodeId::new(v.block_id.inode_id),
            v.block_id.data_version,
        );
        store.put(content_key, b"plain file content").unwrap();

        let outcome = apply_one_repair(&entry, &mut state, &mut store, &mut BTreeMap::new());

        assert_eq!(outcome, RepairOutcome::Skipped);
    }

    #[test]
    fn reconstruct_on_erasure_coded_object_succeeds() {
        let (v, _) = make_violation(3);
        let entry = RepairEntry {
            block_id: v.block_id.clone(),
            strategy: RepairStrategy::Reconstruct,
            outcome: RepairOutcome::Skipped,
        };

        let config = tidefs_erasure_coding::StripeConfig {
            data_shards: 2,
            parity_shards: 1,
            shard_len: 8,
        };
        let payload: Vec<u8> = (0..16).collect(); // 16 bytes -> 2x8-byte data shards
        let encoded = tidefs_erasure_coding::encode(&config, &payload).unwrap();

        // Serialise the encoded stripe into header + shards format
        let mut raw = Vec::new();
        raw.extend_from_slice(&(config.stripe_width() as u16).to_le_bytes());
        raw.extend_from_slice(&(config.data_shards as u16).to_le_bytes());
        raw.push(config.parity_shards as u8);
        raw.extend_from_slice(&(config.shard_len as u32).to_le_bytes());
        for shard in &encoded.shards {
            raw.extend_from_slice(&shard.bytes);
        }

        let mut state = crate::recovery::initial_state();
        let mut store = unreachable_store();
        let content_key = crate::object_keys::content_object_key_for_version(
            InodeId::new(v.block_id.inode_id),
            v.block_id.data_version,
        );
        store.put(content_key, &raw).unwrap();

        let outcome = apply_one_repair(&entry, &mut state, &mut store, &mut BTreeMap::new());

        assert_eq!(outcome, RepairOutcome::Reconstructed { bytes_written: 16 });

        // Verify the reconstructed bytes were durably written back to the store.
        let stored = store.get(content_key).unwrap().unwrap();
        // The stored value is the raw reconstructed payload (no EC header re-wrap).
        assert_eq!(stored, payload);
        assert!(state
            .dirty_content
            .contains(&InodeId::new(v.block_id.inode_id)));
    }

    #[test]
    fn apply_repair_entries_preserves_entry_count() {
        let (v, _) = make_violation(0);
        let mut log = RepairLog::new();
        log.record(RepairEntry {
            block_id: v.block_id.clone(),
            strategy: RepairStrategy::MarkCorrupt,
            outcome: RepairOutcome::Skipped,
        });
        log.record(RepairEntry {
            block_id: v.block_id.clone(),
            strategy: RepairStrategy::MarkCorrupt,
            outcome: RepairOutcome::Skipped,
        });

        let mut state = crate::recovery::initial_state();
        let applied = apply_repair_entries(
            &log,
            &mut state,
            &mut unreachable_store(),
            &mut BTreeMap::new(),
        );

        assert_eq!(applied.len(), 2);
        assert!(state.corrupted_inodes.contains(&InodeId::new(100)));
    }

    fn unreachable_store() -> LocalObjectStore {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT_ID: AtomicU32 = AtomicU32::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("tidefs-repair-test-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).expect("create test store dir");
        LocalObjectStore::open(&dir).expect("open test store")
    }
}
