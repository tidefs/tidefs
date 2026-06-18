// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Block allocator smoke: deterministic allocation, quota, statfs, and flush
//! behavior checks over `tidefs-block-allocator`.
//!
//! Gated on `feature = "block-allocator"`.

use crate::smoke::SmokeHarness;
use crate::trace::{deserialize_trace, serialize_trace, TraceEvent};
use tidefs_block_allocator::{AllocError, BitmapFlushSink, BlockAllocator, Region};
use tidefs_types_vfs_core::InodeId;

#[derive(Default)]
struct RecordingSink {
    region: Option<Region>,
    words: Vec<u64>,
    fail: bool,
}

impl BitmapFlushSink for RecordingSink {
    fn write_bitmap(&mut self, region: Region, words: &[u64]) -> Result<(), AllocError> {
        if self.fail {
            return Err(AllocError::Io);
        }

        self.region = Some(region);
        self.words = words.to_vec();
        Ok(())
    }
}

/// Run the full block allocator smoke sequence and return the harness.
#[must_use]
pub fn run_block_allocator_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("block_allocator/smoke");
    smoke_allocation_and_statfs(&mut h);
    smoke_quota_lifecycle(&mut h);
    smoke_flush_and_restore(&mut h);
    smoke_error_variants(&mut h);
    h.scenario_end("block_allocator/smoke");

    let trace_before_round_trip = h.trace.clone();
    let serialized = serialize_trace(&trace_before_round_trip)
        .expect("block allocator smoke trace should serialize");
    let decoded =
        deserialize_trace(&serialized).expect("block allocator smoke trace should deserialize");
    h.assert_eq_ev(
        "block allocator smoke trace round-trips",
        decoded,
        trace_before_round_trip,
    );

    h
}

fn smoke_allocation_and_statfs(h: &mut SmokeHarness) {
    let allocator = BlockAllocator::with_root_reserve(16, 4096, region(16), 2);
    record_allocator_op(h, "allocator.new", 0, encode_region(region(16)));

    h.assert_eq_ev("allocator exposes block count", allocator.block_count(), 16);
    h.assert_eq_ev("allocator exposes block size", allocator.block_size(), 4096);
    h.assert_eq_ev("allocator starts fully free", allocator.free_count(), 16);
    h.assert_eq_ev(
        "allocator exposes bitmap region",
        allocator.bitmap_region(),
        region(16),
    );

    let initial = allocator.statfs();
    h.assert_eq_ev("statfs reports total blocks", initial.f_blocks, 16);
    h.assert_eq_ev("statfs reports public root reserve", initial.f_bavail, 14);
    h.assert_eq_ev("statfs keeps inode counters zero", initial.f_files, 0);

    record_allocator_op(h, "allocator.alloc", 0, b"4".to_vec());
    let allocated = allocator.alloc(4).expect("alloc should succeed");
    h.assert_eq_ev("alloc returns requested count", allocated.len(), 4);
    h.assert_eq_ev("alloc consumes free blocks", allocator.free_count(), 12);
    h.assert_ev("alloc marks bitmap dirty", allocator.is_dirty());

    record_allocator_op(h, "allocator.alloc_contiguous", 0, b"3".to_vec());
    let contiguous = allocator
        .alloc_contiguous(3)
        .expect("contiguous alloc should succeed");
    h.assert_eq_ev(
        "contiguous alloc returns requested count",
        contiguous.len(),
        3,
    );
    h.assert_eq_ev(
        "contiguous alloc returns adjacent block ids",
        contiguous.windows(2).all(|pair| pair[1] == pair[0] + 1),
        true,
    );

    record_allocator_op(h, "allocator.free", 0, encode_blocks(&allocated));
    allocator.free(&allocated);
    h.assert_eq_ev("free restores allocated blocks", allocator.free_count(), 13);

    record_allocator_op(h, "allocator.free.idempotent", 0, encode_blocks(&allocated));
    allocator.free(&allocated);
    h.assert_eq_ev("free is idempotent", allocator.free_count(), 13);

    let after_alloc = allocator.statfs();
    h.assert_eq_ev(
        "statfs tracks free blocks after allocation",
        after_alloc.f_bfree,
        13,
    );
    h.assert_eq_ev(
        "statfs tracks root-reserved available blocks after allocation",
        after_alloc.f_bavail,
        11,
    );

    h.assert_eq_ev(
        "root reserve rejects allocation past public availability",
        allocator.alloc_any(12),
        Err(AllocError::NoSpace),
    );
}

fn smoke_quota_lifecycle(h: &mut SmokeHarness) {
    let allocator = BlockAllocator::new(32, 4096, region(32));
    let inode = InodeId::new(42);

    record_allocator_op(h, "allocator.quota.limit", inode.get(), b"8".to_vec());
    allocator.set_quota_limit(inode, 8);
    h.assert_eq_ev("quota starts empty", allocator.quota_counts(inode), (0, 0));

    record_allocator_op(h, "allocator.reserve", inode.get(), b"6".to_vec());
    allocator
        .reserve(inode, 6)
        .expect("reserve should fit quota");
    h.assert_eq_ev(
        "reserve records reserved blocks",
        allocator.quota_counts(inode),
        (6, 0),
    );

    record_allocator_op(h, "allocator.commit", inode.get(), b"4".to_vec());
    allocator.commit(inode, 4);
    h.assert_eq_ev(
        "commit moves reserved blocks to committed",
        allocator.quota_counts(inode),
        (2, 4),
    );
    h.assert_eq_ev(
        "total committed follows quota table",
        allocator.total_committed(),
        4,
    );

    record_allocator_op(h, "allocator.release", inode.get(), b"2".to_vec());
    allocator.release(inode, 2);
    h.assert_eq_ev(
        "release drops only reserved blocks",
        allocator.quota_counts(inode),
        (0, 4),
    );

    record_allocator_op(h, "allocator.uncommit", inode.get(), b"3".to_vec());
    allocator.uncommit(inode, 3);
    h.assert_eq_ev(
        "uncommit lowers committed blocks",
        allocator.quota_counts(inode),
        (0, 1),
    );

    h.assert_eq_ev(
        "quota limit rejects excessive reserve",
        allocator.reserve(inode, 8),
        Err(AllocError::QuotaExceeded),
    );
}

fn smoke_flush_and_restore(h: &mut SmokeHarness) {
    let allocator = BlockAllocator::new(64, 4096, region(64));
    let blocks = allocator.alloc_any(5).expect("alloc_any should succeed");
    record_allocator_op(h, "allocator.alloc_any", 0, encode_blocks(&blocks));
    h.assert_ev("alloc_any marks allocator dirty", allocator.is_dirty());

    let words = allocator.flush_words();
    h.assert_ev(
        "flush_words exposes persisted bitmap words",
        !words.is_empty(),
    );

    let mut sink = RecordingSink::default();
    record_allocator_op(h, "allocator.flush_to", 0, encode_region(region(64)));
    allocator
        .flush_to(&mut sink)
        .expect("flush_to should succeed");
    h.assert_eq_ev(
        "flush_to writes configured region",
        sink.region,
        Some(region(64)),
    );
    h.assert_eq_ev("flush_to writes bitmap words", sink.words, words.clone());
    h.assert_ev("flush_to marks allocator clean", !allocator.is_dirty());

    let restored = BlockAllocator::from_persisted(64, 4096, region(64), words);
    h.assert_eq_ev(
        "from_persisted restores free-count state",
        restored.free_count(),
        allocator.free_count(),
    );
    h.assert_ev("from_persisted starts clean", !restored.is_dirty());

    let more = restored
        .alloc_contiguous(1)
        .expect("restored allocator allocates");
    h.assert_ev(
        "restored allocation marks bitmap dirty",
        restored.is_dirty(),
    );
    restored.free(&more);
    restored.flush().expect("flush should mark clean");
    h.assert_ev("flush marks allocator clean", !restored.is_dirty());

    let clean_words = restored.flush_words();
    let mut clean_sink = RecordingSink::default();
    restored
        .flush_to(&mut clean_sink)
        .expect("clean flush_to should be a no-op");
    h.assert_eq_ev("clean flush_to skips sink write", clean_sink.region, None);
    h.assert_eq_ev(
        "clean allocator words remain readable",
        clean_words.len(),
        restored.flush_words().len(),
    );

    let mut failing_sink = RecordingSink {
        fail: true,
        ..RecordingSink::default()
    };
    restored
        .alloc_any(1)
        .expect("dirty restore allocator again");
    h.assert_eq_ev(
        "flush_to propagates sink I/O errors",
        restored.flush_to(&mut failing_sink),
        Err(AllocError::Io),
    );
    h.assert_ev("failed flush_to keeps allocator dirty", restored.is_dirty());
}

fn smoke_error_variants(h: &mut SmokeHarness) {
    record_allocator_op(h, "allocator.error.match", 0, Vec::new());
    let no_space = describe_alloc_error(AllocError::NoSpace);
    let quota = describe_alloc_error(AllocError::QuotaExceeded);
    let io = describe_alloc_error(AllocError::Io);

    h.assert_eq_ev("NoSpace error is matchable", no_space, "no-space");
    h.assert_eq_ev("QuotaExceeded error is matchable", quota, "quota-exceeded");
    h.assert_eq_ev("Io error is matchable", io, "io");
    h.assert_ev(
        "AllocError display exposes stable user-facing text",
        AllocError::NoSpace.to_string().contains("free blocks"),
    );
}

fn describe_alloc_error(error: AllocError) -> &'static str {
    match error {
        AllocError::NoSpace => "no-space",
        AllocError::QuotaExceeded => "quota-exceeded",
        AllocError::Io => "io",
        AllocError::AlignmentViolation => "alignment-violation",
        _ => "other",
    }
}

fn region(block_count: u64) -> Region {
    Region::new(4096, BlockAllocator::required_bitmap_bytes(block_count))
}

fn record_allocator_op(h: &mut SmokeHarness, op_name: &str, inode_id: u64, payload: Vec<u8>) {
    h.record(TraceEvent::FsLifecycleOp {
        inode_id,
        op_name: op_name.to_string(),
        payload,
    });
}

fn encode_region(region: Region) -> Vec<u8> {
    format!("{}:{}", region.offset, region.length).into_bytes()
}

fn encode_blocks(blocks: &[u64]) -> Vec<u8> {
    blocks
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",")
        .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_block_allocator_passes() {
        let h = run_block_allocator_smoke();
        for event in &h.trace {
            if let TraceEvent::Assert {
                passed,
                ref condition,
            } = event
            {
                assert!(passed, "assertion failed: {condition}");
            }
        }
    }
}
